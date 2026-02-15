// Package hotreload provides hot reload management for parsers.
package hotreload

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/siem-soar-platform/services/parser-manager/internal/model"
	"github.com/siem-soar-platform/services/parser-manager/internal/repository"
)

// ReloadMessage represents a hot reload message.
type ReloadMessage struct {
	Action    string      `json:"action"` // deploy, undeploy, reload_all
	ParserID  string      `json:"parser_id,omitempty"`
	Parser    *model.Parser `json:"parser,omitempty"`
	Timestamp int64       `json:"timestamp"`
	Source    string      `json:"source"` // Instance ID
}

// Manager handles hot reload of parsers.
type Manager struct {
	repo        repository.ParserRepository
	redis       *redis.Client
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex

	// Configuration
	channel     string
	stateKey    string
	instanceID  string

	// State
	started          bool
	reloadInProgress bool
	lastReloadAt     time.Time
	pendingParsers   int
	loadedParsers    int
	failedParsers    int
	parserStatuses   map[string]*model.ParserReloadStatus

	// Metrics
	deploymentsTotal int64
	deploymentsOK    int64
	deploymentsFail  int64
}

// Config holds hot reload configuration.
type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Channel       string
	StateKey      string
	InstanceID    string
}

// NewManager creates a new hot reload manager.
func NewManager(cfg *Config, repo repository.ParserRepository, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	channel := cfg.Channel
	if channel == "" {
		channel = "parser:reload"
	}

	stateKey := cfg.StateKey
	if stateKey == "" {
		stateKey = "parser:state"
	}

	return &Manager{
		repo:           repo,
		redis:          rdb,
		logger:         logger.With("component", "hot-reload"),
		ctx:            ctx,
		cancel:         cancel,
		channel:        channel,
		stateKey:       stateKey,
		instanceID:     cfg.InstanceID,
		parserStatuses: make(map[string]*model.ParserReloadStatus),
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

	m.logger.Info("hot reload manager started", "channel", m.channel)
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

// DeployParser deploys a parser to all instances.
func (m *Manager) DeployParser(ctx context.Context, parser *model.Parser, deployedBy string) (*model.ParserDeployResult, error) {
	startTime := time.Now()

	result := &model.ParserDeployResult{
		ParserID:   parser.ID,
		ParserName: parser.Name,
	}

	// Update parser status in database
	if err := m.repo.MarkDeployed(ctx, parser.ID, deployedBy); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Publish reload message
	msg := &ReloadMessage{
		Action:    "deploy",
		ParserID:  parser.ID,
		Parser:    parser,
		Timestamp: time.Now().UnixMilli(),
		Source:    m.instanceID,
	}

	data, _ := json.Marshal(msg)
	if err := m.redis.Publish(ctx, m.channel, data).Err(); err != nil {
		m.logger.Warn("failed to publish deploy message", "error", err)
	}

	// Save parser state to Redis for new instances
	m.saveParserState(ctx, parser)

	result.Success = true
	result.DeployedAt = time.Now()
	result.DurationMs = float64(time.Since(startTime).Microseconds()) / 1000
	result.Instances = m.getInstanceCount(ctx)

	m.mu.Lock()
	m.deploymentsTotal++
	m.deploymentsOK++
	m.lastReloadAt = time.Now()
	m.loadedParsers++
	m.mu.Unlock()

	m.logger.Info("parser deployed",
		"parser_id", parser.ID,
		"parser_name", parser.Name,
		"deployed_by", deployedBy,
		"duration_ms", result.DurationMs,
	)

	return result, nil
}

// UndeployParser undeploys a parser from all instances.
func (m *Manager) UndeployParser(ctx context.Context, parserID string) error {
	msg := &ReloadMessage{
		Action:    "undeploy",
		ParserID:  parserID,
		Timestamp: time.Now().UnixMilli(),
		Source:    m.instanceID,
	}

	data, _ := json.Marshal(msg)
	if err := m.redis.Publish(ctx, m.channel, data).Err(); err != nil {
		return err
	}

	// Remove from state
	m.removeParserState(ctx, parserID)

	m.logger.Info("parser undeployed", "parser_id", parserID)
	return nil
}

// ReloadAll reloads all parsers.
func (m *Manager) ReloadAll(ctx context.Context) error {
	m.mu.Lock()
	m.reloadInProgress = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.reloadInProgress = false
		m.mu.Unlock()
	}()

	msg := &ReloadMessage{
		Action:    "reload_all",
		Timestamp: time.Now().UnixMilli(),
		Source:    m.instanceID,
	}

	data, _ := json.Marshal(msg)
	if err := m.redis.Publish(ctx, m.channel, data).Err(); err != nil {
		return err
	}

	m.mu.Lock()
	m.lastReloadAt = time.Now()
	m.mu.Unlock()

	m.logger.Info("reload all triggered")
	return nil
}

// GetReloadStatus returns the current reload status.
func (m *Manager) GetReloadStatus() *model.ReloadStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statuses := make([]model.ParserReloadStatus, 0, len(m.parserStatuses))
	for _, s := range m.parserStatuses {
		statuses = append(statuses, *s)
	}

	return &model.ReloadStatus{
		LastReloadAt:     m.lastReloadAt,
		ReloadInProgress: m.reloadInProgress,
		PendingParsers:   m.pendingParsers,
		LoadedParsers:    m.loadedParsers,
		FailedParsers:    m.failedParsers,
		ParserStatuses:   statuses,
	}
}

// Stats returns hot reload statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	successRate := float64(0)
	if m.deploymentsTotal > 0 {
		successRate = float64(m.deploymentsOK) / float64(m.deploymentsTotal) * 100
	}

	return map[string]interface{}{
		"deployments_total":   m.deploymentsTotal,
		"deployments_ok":      m.deploymentsOK,
		"deployments_fail":    m.deploymentsFail,
		"success_rate_pct":    successRate,
		"started":             m.started,
		"reload_in_progress":  m.reloadInProgress,
		"last_reload_at":      m.lastReloadAt,
		"loaded_parsers":      m.loadedParsers,
		"failed_parsers":      m.failedParsers,
	}
}

func (m *Manager) subscribeLoop() {
	defer m.wg.Done()

	pubsub := m.redis.Subscribe(m.ctx, m.channel)
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
	var reloadMsg ReloadMessage
	if err := json.Unmarshal([]byte(msg.Payload), &reloadMsg); err != nil {
		m.logger.Error("failed to unmarshal reload message", "error", err)
		return
	}

	// Skip messages from self
	if reloadMsg.Source == m.instanceID {
		return
	}

	m.logger.Debug("received reload message",
		"action", reloadMsg.Action,
		"parser_id", reloadMsg.ParserID,
		"source", reloadMsg.Source,
	)

	switch reloadMsg.Action {
	case "deploy":
		m.handleDeploy(&reloadMsg)
	case "undeploy":
		m.handleUndeploy(&reloadMsg)
	case "reload_all":
		m.handleReloadAll(&reloadMsg)
	}
}

func (m *Manager) handleDeploy(msg *ReloadMessage) {
	m.mu.Lock()
	m.parserStatuses[msg.ParserID] = &model.ParserReloadStatus{
		ParserID:   msg.ParserID,
		ParserName: msg.Parser.Name,
		Status:     "loaded",
		LoadedAt:   time.Now(),
	}
	m.loadedParsers++
	m.mu.Unlock()
}

func (m *Manager) handleUndeploy(msg *ReloadMessage) {
	m.mu.Lock()
	delete(m.parserStatuses, msg.ParserID)
	m.loadedParsers--
	m.mu.Unlock()
}

func (m *Manager) handleReloadAll(msg *ReloadMessage) {
	m.mu.Lock()
	m.parserStatuses = make(map[string]*model.ParserReloadStatus)
	m.loadedParsers = 0
	m.lastReloadAt = time.Now()
	m.mu.Unlock()
}

func (m *Manager) saveParserState(ctx context.Context, parser *model.Parser) {
	data, _ := json.Marshal(parser)
	m.redis.HSet(ctx, m.stateKey, parser.ID, data)
}

func (m *Manager) removeParserState(ctx context.Context, parserID string) {
	m.redis.HDel(ctx, m.stateKey, parserID)
}

func (m *Manager) getInstanceCount(ctx context.Context) int {
	// Get number of subscribers to the channel
	result, err := m.redis.PubSubNumSub(ctx, m.channel).Result()
	if err != nil {
		return 1
	}
	count := result[m.channel]
	if count < 1 {
		count = 1
	}
	return int(count)
}

// LoadParsersFromRedis loads all parser states from Redis.
func (m *Manager) LoadParsersFromRedis(ctx context.Context) ([]*model.Parser, error) {
	result, err := m.redis.HGetAll(ctx, m.stateKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to load parsers from Redis: %w", err)
	}

	parsers := make([]*model.Parser, 0, len(result))
	for _, data := range result {
		var parser model.Parser
		if err := json.Unmarshal([]byte(data), &parser); err != nil {
			m.logger.Warn("failed to unmarshal parser", "error", err)
			continue
		}
		parsers = append(parsers, &parser)
	}

	m.logger.Info("loaded parsers from Redis", "count", len(parsers))
	return parsers, nil
}
