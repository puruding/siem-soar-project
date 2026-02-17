// Package engine provides the core detection engine implementation.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/pkg/udm"
	"github.com/siem-soar-platform/services/detection/internal/rule"
)

// EngineState represents the engine state.
type EngineState string

const (
	StateIdle     EngineState = "idle"
	StateRunning  EngineState = "running"
	StateStopping EngineState = "stopping"
	StateStopped  EngineState = "stopped"
)

// DetectionResult represents a detection match.
type DetectionResult struct {
	RuleID        string                 `json:"rule_id"`
	RuleName      string                 `json:"rule_name"`
	Severity      string                 `json:"severity"`
	MatchedEvents []MatchedEvent         `json:"matched_events"`
	Timestamp     time.Time              `json:"timestamp"`
	Context       map[string]interface{} `json:"context,omitempty"`
	MITRETactics  []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques []string             `json:"mitre_techniques,omitempty"`
}

// MatchedEvent represents an event that matched a rule.
type MatchedEvent struct {
	EventID      string                 `json:"event_id"`
	Timestamp    time.Time              `json:"timestamp"`
	MatchedFields map[string]interface{} `json:"matched_fields"`
}

// Event represents a security event for detection.
type Event struct {
	EventID    string                 `json:"event_id"`
	TenantID   string                 `json:"tenant_id"`
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	Raw        map[string]interface{} `json:"raw,omitempty"`        // Raw data (backward compat with Data)
	UDM        *udm.UDMEvent          `json:"udm,omitempty"`        // UDM normalized data
	Data       map[string]interface{} `json:"data"`                 // Deprecated: use Raw or UDM
	Normalized map[string]interface{} `json:"normalized,omitempty"` // Deprecated: use UDM
}

// GetFieldValue retrieves a field value from the event.
// It first tries UDM fields, then falls back to Raw/Data.
// Path format: "principal.user.user_name" or "principal.ip[0]"
func (e *Event) GetFieldValue(path string) (interface{}, bool) {
	// Try UDM first if available
	if e.UDM != nil {
		value, err := udm.GetField(e.UDM, path)
		if err == nil && value != nil {
			return value, true
		}
	}

	// Fall back to Raw data
	if e.Raw != nil {
		if value, found := getNestedValue(e.Raw, path); found {
			return value, true
		}
	}

	// Fall back to Data (legacy field)
	if e.Data != nil {
		if value, found := getNestedValue(e.Data, path); found {
			return value, true
		}
	}

	return nil, false
}

// GetFieldValueAsString retrieves a field value as a string.
func (e *Event) GetFieldValueAsString(path string) (string, bool) {
	value, found := e.GetFieldValue(path)
	if !found {
		return "", false
	}
	return fmt.Sprintf("%v", value), true
}

// HasUDM checks if the event has UDM data.
func (e *Event) HasUDM() bool {
	return e.UDM != nil
}

// GetEffectiveData returns the best available data map for the event.
// Prefers UDM converted to map, then Raw, then Data.
func (e *Event) GetEffectiveData() map[string]interface{} {
	if e.UDM != nil {
		if m, err := udm.ToMap(e.UDM); err == nil {
			return m
		}
	}
	if e.Raw != nil {
		return e.Raw
	}
	return e.Data
}

// getNestedValue retrieves a value from a nested map using dot notation.
func getNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	parts := splitFieldPath(path)
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part.name]
			if !ok {
				return nil, false
			}
			// Handle array index
			if part.index >= 0 {
				if arr, ok := current.([]interface{}); ok && part.index < len(arr) {
					current = arr[part.index]
				} else {
					return nil, false
				}
			}
		case []interface{}:
			if part.index >= 0 && part.index < len(v) {
				current = v[part.index]
			} else {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

// fieldPart represents a part of a field path.
type fieldPart struct {
	name  string
	index int // -1 if no index
}

// splitFieldPath splits a field path into parts, handling array notation.
func splitFieldPath(path string) []fieldPart {
	var parts []fieldPart
	var current string
	var inBracket bool
	var bracketContent string

	for _, c := range path {
		switch {
		case c == '.' && !inBracket:
			if current != "" {
				parts = append(parts, fieldPart{name: current, index: -1})
				current = ""
			}
		case c == '[':
			inBracket = true
			bracketContent = ""
		case c == ']':
			inBracket = false
			idx := -1
			if n, err := fmt.Sscanf(bracketContent, "%d", &idx); err == nil && n == 1 {
				if current != "" {
					parts = append(parts, fieldPart{name: current, index: idx})
					current = ""
				} else if len(parts) > 0 {
					// Update last part with index
					parts[len(parts)-1].index = idx
				}
			}
		case inBracket:
			bracketContent += string(c)
		default:
			current += string(c)
		}
	}

	if current != "" {
		parts = append(parts, fieldPart{name: current, index: -1})
	}

	return parts
}

// EngineConfig holds engine configuration.
type EngineConfig struct {
	// Worker settings
	NumWorkers      int           `json:"num_workers"`
	BufferSize      int           `json:"buffer_size"`
	ProcessTimeout  time.Duration `json:"process_timeout"`

	// Batch settings
	BatchSize       int           `json:"batch_size"`
	BatchTimeout    time.Duration `json:"batch_timeout"`

	// Rule settings
	RuleReloadInterval time.Duration `json:"rule_reload_interval"`
	MaxConcurrentRules int           `json:"max_concurrent_rules"`
}

// DefaultEngineConfig returns default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		NumWorkers:         8,
		BufferSize:         10000,
		ProcessTimeout:     5 * time.Second,
		BatchSize:          100,
		BatchTimeout:       time.Second,
		RuleReloadInterval: time.Minute,
		MaxConcurrentRules: 50,
	}
}

// Engine is the core detection engine.
type Engine struct {
	config      EngineConfig
	ruleLoader  *rule.Loader
	scheduler   *Scheduler
	executor    *Executor

	eventCh     chan *Event
	resultCh    chan *DetectionResult

	rules       []*rule.Rule
	rulesMu     sync.RWMutex

	state       atomic.Value
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	logger      *slog.Logger

	// Metrics
	eventsProcessed atomic.Uint64
	detections      atomic.Uint64
	ruleExecutions  atomic.Uint64
	errors          atomic.Uint64
}

// NewEngine creates a new detection engine.
func NewEngine(cfg EngineConfig, ruleLoader *rule.Loader, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	e := &Engine{
		config:     cfg,
		ruleLoader: ruleLoader,
		eventCh:    make(chan *Event, cfg.BufferSize),
		resultCh:   make(chan *DetectionResult, cfg.BufferSize),
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger.With("component", "detection-engine"),
	}

	e.state.Store(StateIdle)
	e.scheduler = NewScheduler(cfg.RuleReloadInterval, logger)
	e.executor = NewExecutor(cfg.MaxConcurrentRules, cfg.ProcessTimeout, logger)

	return e
}

// Start starts the detection engine.
func (e *Engine) Start() error {
	if e.state.Load().(EngineState) == StateRunning {
		return fmt.Errorf("engine already running")
	}

	e.logger.Info("starting detection engine", "workers", e.config.NumWorkers)

	// Load initial rules
	if err := e.loadRules(); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Start workers
	for i := 0; i < e.config.NumWorkers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// Start rule reload ticker
	e.wg.Add(1)
	go e.ruleReloader()

	// Start scheduler
	e.scheduler.Start()

	e.state.Store(StateRunning)
	e.logger.Info("detection engine started", "rules_loaded", len(e.rules))

	return nil
}

// Stop stops the detection engine.
func (e *Engine) Stop() error {
	if e.state.Load().(EngineState) != StateRunning {
		return nil
	}

	e.logger.Info("stopping detection engine")
	e.state.Store(StateStopping)

	e.cancel()
	close(e.eventCh)

	e.scheduler.Stop()
	e.wg.Wait()

	close(e.resultCh)

	e.state.Store(StateStopped)
	e.logger.Info("detection engine stopped")

	return nil
}

// ProcessEvent submits an event for detection.
func (e *Engine) ProcessEvent(event *Event) error {
	if e.state.Load().(EngineState) != StateRunning {
		return fmt.Errorf("engine not running")
	}

	select {
	case e.eventCh <- event:
		return nil
	case <-time.After(e.config.ProcessTimeout):
		return fmt.Errorf("event channel full, dropping event")
	}
}

// ProcessBatch submits a batch of events for detection.
func (e *Engine) ProcessBatch(events []*Event) error {
	for _, event := range events {
		if err := e.ProcessEvent(event); err != nil {
			e.errors.Add(1)
			e.logger.Warn("failed to process event", "event_id", event.EventID, "error", err)
		}
	}
	return nil
}

// Results returns the results channel.
func (e *Engine) Results() <-chan *DetectionResult {
	return e.resultCh
}

// State returns the current engine state.
func (e *Engine) State() EngineState {
	return e.state.Load().(EngineState)
}

// ReloadRules forces a rule reload.
func (e *Engine) ReloadRules() error {
	return e.loadRules()
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"state":            string(e.state.Load().(EngineState)),
		"events_processed": e.eventsProcessed.Load(),
		"detections":       e.detections.Load(),
		"rule_executions":  e.ruleExecutions.Load(),
		"errors":           e.errors.Load(),
		"rules_count":      len(e.GetRules()),
		"queue_depth":      len(e.eventCh),
	}
}

// GetRules returns all loaded rules.
func (e *Engine) GetRules() []*rule.Rule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()
	return e.rules
}

func (e *Engine) worker(id int) {
	defer e.wg.Done()

	logger := e.logger.With("worker_id", id)
	logger.Debug("worker started")

	for event := range e.eventCh {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		e.processEvent(event)
	}

	logger.Debug("worker stopped")
}

func (e *Engine) processEvent(event *Event) {
	e.eventsProcessed.Add(1)

	rules := e.GetRules()

	for _, r := range rules {
		if !r.IsEnabled || r.Status != rule.StatusActive {
			continue
		}

		e.ruleExecutions.Add(1)

		result, err := e.executor.Execute(e.ctx, r, event)
		if err != nil {
			e.errors.Add(1)
			e.logger.Error("rule execution failed", "rule_id", r.ID, "error", err)
			continue
		}

		if result != nil {
			e.detections.Add(1)
			select {
			case e.resultCh <- result:
			default:
				e.logger.Warn("result channel full, dropping detection")
			}
		}
	}
}

func (e *Engine) loadRules() error {
	rules, err := e.ruleLoader.LoadAll(e.ctx)
	if err != nil {
		return err
	}

	// Validate rules
	validated := make([]*rule.Rule, 0, len(rules))
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			e.logger.Warn("invalid rule, skipping", "rule_id", r.ID, "error", err)
			continue
		}
		validated = append(validated, r)
	}

	e.rulesMu.Lock()
	e.rules = validated
	e.rulesMu.Unlock()

	e.logger.Info("rules loaded", "total", len(rules), "valid", len(validated))

	return nil
}

func (e *Engine) ruleReloader() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.RuleReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.loadRules(); err != nil {
				e.logger.Error("failed to reload rules", "error", err)
			}
		}
	}
}
