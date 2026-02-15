// Package hotreload provides hot reload functionality for parser patterns.
package hotreload

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/siem-soar-platform/services/parser/internal/config"
	"github.com/siem-soar-platform/services/parser/internal/engine"
)

// PatternUpdate represents a pattern update message.
type PatternUpdate struct {
	Action    string `json:"action"` // add, update, delete
	Type      string `json:"type"`   // grok, regex, cef_mapping
	Name      string `json:"name"`
	Pattern   string `json:"pattern,omitempty"`
	Config    string `json:"config,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// Manager handles hot reload of parser patterns.
type Manager struct {
	cfg     *config.Config
	redis   *redis.Client
	engine  *engine.Engine
	logger  *slog.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	mu      sync.RWMutex

	// Stats
	reloadsReceived int64
	reloadsApplied  int64
	reloadErrors    int64
}

// NewManager creates a new hot reload manager.
func NewManager(cfg *config.Config, eng *engine.Engine, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	return &Manager{
		cfg:    cfg,
		redis:  rdb,
		engine: eng,
		logger: logger.With("component", "hot-reload"),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the hot reload manager.
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	// Test Redis connection
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	if err := m.redis.Ping(ctx).Err(); err != nil {
		m.logger.Warn("Redis not available, hot reload disabled", "error", err)
		return nil
	}

	m.wg.Add(1)
	go m.subscribeLoop()

	m.logger.Info("hot reload manager started", "channel", m.cfg.ReloadChannel)
	return nil
}

// Stop stops the hot reload manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return
	}
	m.started = false
	m.mu.Unlock()

	m.cancel()
	m.wg.Wait()
	m.redis.Close()
	m.logger.Info("hot reload manager stopped")
}

// Stats returns hot reload statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"reloads_received": m.reloadsReceived,
		"reloads_applied":  m.reloadsApplied,
		"reload_errors":    m.reloadErrors,
		"started":          m.started,
	}
}

// PublishUpdate publishes a pattern update.
func (m *Manager) PublishUpdate(update *PatternUpdate) error {
	update.Timestamp = time.Now().UnixMilli()

	data, err := json.Marshal(update)
	if err != nil {
		return err
	}

	return m.redis.Publish(m.ctx, m.cfg.ReloadChannel, data).Err()
}

func (m *Manager) subscribeLoop() {
	defer m.wg.Done()

	pubsub := m.redis.Subscribe(m.ctx, m.cfg.ReloadChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-m.ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			m.handleMessage(msg)
		}
	}
}

func (m *Manager) handleMessage(msg *redis.Message) {
	m.mu.Lock()
	m.reloadsReceived++
	m.mu.Unlock()

	var update PatternUpdate
	if err := json.Unmarshal([]byte(msg.Payload), &update); err != nil {
		m.logger.Error("failed to unmarshal update", "error", err)
		m.mu.Lock()
		m.reloadErrors++
		m.mu.Unlock()
		return
	}

	m.logger.Info("received pattern update",
		"action", update.Action,
		"type", update.Type,
		"name", update.Name,
	)

	var err error
	switch update.Type {
	case "grok":
		err = m.handleGrokUpdate(&update)
	case "regex":
		err = m.handleRegexUpdate(&update)
	default:
		m.logger.Warn("unknown update type", "type", update.Type)
		return
	}

	if err != nil {
		m.logger.Error("failed to apply update",
			"type", update.Type,
			"name", update.Name,
			"error", err,
		)
		m.mu.Lock()
		m.reloadErrors++
		m.mu.Unlock()
		return
	}

	m.mu.Lock()
	m.reloadsApplied++
	m.mu.Unlock()

	m.logger.Info("pattern update applied",
		"action", update.Action,
		"type", update.Type,
		"name", update.Name,
	)
}

func (m *Manager) handleGrokUpdate(update *PatternUpdate) error {
	grokParser := m.engine.GetGrokParser()
	if grokParser == nil {
		return nil
	}

	switch update.Action {
	case "add", "update":
		return grokParser.AddPattern(update.Name, update.Pattern)
	case "delete":
		grokParser.RemovePattern(update.Name)
		return nil
	default:
		return nil
	}
}

func (m *Manager) handleRegexUpdate(update *PatternUpdate) error {
	regexParser := m.engine.GetRegexParser()
	if regexParser == nil {
		return nil
	}

	switch update.Action {
	case "add", "update":
		return regexParser.AddPattern(update.Name, update.Pattern)
	case "delete":
		regexParser.RemovePattern(update.Name)
		return nil
	default:
		return nil
	}
}

// LoadPatternsFromRedis loads patterns from Redis.
func (m *Manager) LoadPatternsFromRedis() error {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	// Load Grok patterns
	grokPatterns, err := m.redis.HGetAll(ctx, "parser:patterns:grok").Result()
	if err != nil && err != redis.Nil {
		return err
	}

	grokParser := m.engine.GetGrokParser()
	for name, pattern := range grokPatterns {
		if err := grokParser.AddPattern(name, pattern); err != nil {
			m.logger.Warn("failed to load grok pattern",
				"name", name,
				"error", err,
			)
		}
	}

	// Load Regex patterns
	regexPatterns, err := m.redis.HGetAll(ctx, "parser:patterns:regex").Result()
	if err != nil && err != redis.Nil {
		return err
	}

	regexParser := m.engine.GetRegexParser()
	for name, pattern := range regexPatterns {
		if err := regexParser.AddPattern(name, pattern); err != nil {
			m.logger.Warn("failed to load regex pattern",
				"name", name,
				"error", err,
			)
		}
	}

	m.logger.Info("loaded patterns from Redis",
		"grok_count", len(grokPatterns),
		"regex_count", len(regexPatterns),
	)

	return nil
}

// SavePatternToRedis saves a pattern to Redis.
func (m *Manager) SavePatternToRedis(patternType, name, pattern string) error {
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	key := "parser:patterns:" + patternType
	return m.redis.HSet(ctx, key, name, pattern).Err()
}

// DeletePatternFromRedis deletes a pattern from Redis.
func (m *Manager) DeletePatternFromRedis(patternType, name string) error {
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	key := "parser:patterns:" + patternType
	return m.redis.HDel(ctx, key, name).Err()
}
