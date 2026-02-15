// Package correlation provides correlation-based detection capabilities.
package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/detection/internal/engine"
	"github.com/siem-soar-platform/services/detection/internal/rule"
)

// CorrelationType represents the type of correlation.
type CorrelationType string

const (
	TypeEventCount   CorrelationType = "event_count"
	TypeUniqueCount  CorrelationType = "unique_count"
	TypeSequence     CorrelationType = "sequence"
	TypeThreshold    CorrelationType = "threshold"
	TypeAnomaly      CorrelationType = "anomaly"
)

// CorrelationState holds the state for a correlation rule.
type CorrelationState struct {
	RuleID       string                 `json:"rule_id"`
	GroupKey     string                 `json:"group_key"`
	Events       []*engine.Event        `json:"events"`
	EventIDs     []string               `json:"event_ids"`
	Count        int                    `json:"count"`
	UniqueValues map[string]bool        `json:"unique_values,omitempty"`
	FirstEvent   time.Time              `json:"first_event"`
	LastEvent    time.Time              `json:"last_event"`
	SequencePos  int                    `json:"sequence_pos,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// EngineConfig holds correlation engine configuration.
type EngineConfig struct {
	MaxStates         int           `json:"max_states"`
	StateTimeout      time.Duration `json:"state_timeout"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
	MaxEventsPerState int           `json:"max_events_per_state"`
}

// DefaultEngineConfig returns default correlation engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxStates:         100000,
		StateTimeout:      time.Hour,
		CleanupInterval:   time.Minute,
		MaxEventsPerState: 100,
	}
}

// Engine manages correlation-based detection.
type Engine struct {
	config       EngineConfig
	states       map[string]*CorrelationState // key: ruleID:groupKey
	statesMu     sync.RWMutex
	rules        []*rule.Rule
	rulesMu      sync.RWMutex
	resultCh     chan *engine.DetectionResult
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	logger       *slog.Logger

	// Metrics
	eventsProcessed atomic.Uint64
	statesCreated   atomic.Uint64
	statesExpired   atomic.Uint64
	correlationsFound atomic.Uint64
}

// NewEngine creates a new correlation engine.
func NewEngine(cfg EngineConfig, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		config:   cfg,
		states:   make(map[string]*CorrelationState),
		rules:    make([]*rule.Rule, 0),
		resultCh: make(chan *engine.DetectionResult, 1000),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger.With("component", "correlation-engine"),
	}
}

// Start starts the correlation engine.
func (e *Engine) Start() error {
	e.wg.Add(1)
	go e.cleanupLoop()

	e.logger.Info("correlation engine started")
	return nil
}

// Stop stops the correlation engine.
func (e *Engine) Stop() error {
	e.cancel()
	e.wg.Wait()
	close(e.resultCh)

	e.logger.Info("correlation engine stopped")
	return nil
}

// LoadRules loads correlation rules.
func (e *Engine) LoadRules(rules []*rule.Rule) {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()

	e.rules = make([]*rule.Rule, 0)
	for _, r := range rules {
		if r.Type == rule.TypeCorrelation || r.Type == rule.TypeThreshold || r.Type == rule.TypeSequence {
			e.rules = append(e.rules, r)
		}
	}

	e.logger.Info("correlation rules loaded", "count", len(e.rules))
}

// ProcessEvent processes an event for correlation.
func (e *Engine) ProcessEvent(event *engine.Event) []*engine.DetectionResult {
	e.eventsProcessed.Add(1)
	var results []*engine.DetectionResult

	e.rulesMu.RLock()
	rules := e.rules
	e.rulesMu.RUnlock()

	for _, r := range rules {
		if !r.IsEnabled {
			continue
		}

		// Check if event matches the rule's base conditions
		if !e.matchesBaseConditions(r, event) {
			continue
		}

		// Process based on correlation type
		var result *engine.DetectionResult
		switch {
		case r.Correlation != nil && r.Correlation.Type == string(TypeSequence):
			result = e.processSequence(r, event)
		case r.Correlation != nil:
			result = e.processCorrelation(r, event)
		case r.Threshold != nil:
			result = e.processThreshold(r, event)
		}

		if result != nil {
			results = append(results, result)
			e.correlationsFound.Add(1)
		}
	}

	return results
}

// Results returns the results channel.
func (e *Engine) Results() <-chan *engine.DetectionResult {
	return e.resultCh
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"events_processed":   e.eventsProcessed.Load(),
		"states_active":      len(e.states),
		"states_created":     e.statesCreated.Load(),
		"states_expired":     e.statesExpired.Load(),
		"correlations_found": e.correlationsFound.Load(),
		"rules_loaded":       len(e.rules),
	}
}

func (e *Engine) matchesBaseConditions(r *rule.Rule, event *engine.Event) bool {
	if r.ParsedConditions == nil || len(r.ParsedConditions.Conditions) == 0 {
		return true
	}

	for _, cond := range r.ParsedConditions.Conditions {
		if cond.Required {
			value, found := getNestedValue(event.Data, cond.Field)
			if !found {
				return false
			}
			if !matchesCondition(cond, value) {
				return false
			}
		}
	}

	return true
}

func (e *Engine) processCorrelation(r *rule.Rule, event *engine.Event) *engine.DetectionResult {
	cfg := r.Correlation
	if cfg == nil {
		return nil
	}

	// Build group key
	groupKey := e.buildGroupKey(cfg.GroupBy, event)
	stateKey := fmt.Sprintf("%s:%s", r.ID, groupKey)

	e.statesMu.Lock()
	defer e.statesMu.Unlock()

	// Get or create state
	state, exists := e.states[stateKey]
	if !exists {
		if len(e.states) >= e.config.MaxStates {
			e.logger.Warn("max states reached, dropping new state")
			return nil
		}

		state = &CorrelationState{
			RuleID:       r.ID,
			GroupKey:     groupKey,
			Events:       make([]*engine.Event, 0),
			EventIDs:     make([]string, 0),
			UniqueValues: make(map[string]bool),
			FirstEvent:   event.Timestamp,
			LastEvent:    event.Timestamp,
			Metadata:     make(map[string]interface{}),
		}
		e.states[stateKey] = state
		e.statesCreated.Add(1)
	}

	// Check if state has expired
	if time.Since(state.FirstEvent) > cfg.TimeWindow {
		// Reset state
		state.Events = nil
		state.EventIDs = nil
		state.UniqueValues = make(map[string]bool)
		state.Count = 0
		state.FirstEvent = event.Timestamp
	}

	// Add event to state
	state.Count++
	state.LastEvent = event.Timestamp
	if len(state.Events) < e.config.MaxEventsPerState {
		state.Events = append(state.Events, event)
	}
	state.EventIDs = append(state.EventIDs, event.EventID)

	// Track unique values if needed
	if cfg.DistinctField != "" {
		value, found := getNestedValue(event.Data, cfg.DistinctField)
		if found {
			state.UniqueValues[fmt.Sprintf("%v", value)] = true
		}
	}

	// Check correlation conditions
	var matched bool
	switch cfg.Type {
	case string(TypeEventCount):
		matched = e.checkEventCount(state, cfg)
	case string(TypeUniqueCount):
		matched = e.checkUniqueCount(state, cfg)
	}

	if matched {
		return e.buildCorrelationResult(r, state)
	}

	return nil
}

func (e *Engine) processSequence(r *rule.Rule, event *engine.Event) *engine.DetectionResult {
	cfg := r.Correlation
	if cfg == nil || len(cfg.Sequence) == 0 {
		return nil
	}

	groupKey := e.buildGroupKey(cfg.GroupBy, event)
	stateKey := fmt.Sprintf("%s:%s", r.ID, groupKey)

	e.statesMu.Lock()
	defer e.statesMu.Unlock()

	state, exists := e.states[stateKey]
	if !exists {
		// Check if event matches first step
		if !e.matchesSequenceStep(&cfg.Sequence[0], event) {
			return nil
		}

		if len(e.states) >= e.config.MaxStates {
			return nil
		}

		state = &CorrelationState{
			RuleID:       r.ID,
			GroupKey:     groupKey,
			Events:       []*engine.Event{event},
			EventIDs:     []string{event.EventID},
			FirstEvent:   event.Timestamp,
			LastEvent:    event.Timestamp,
			SequencePos:  1,
			Metadata:     make(map[string]interface{}),
		}
		e.states[stateKey] = state
		e.statesCreated.Add(1)
		return nil
	}

	// Check timeout
	if time.Since(state.FirstEvent) > cfg.TimeWindow {
		delete(e.states, stateKey)
		return nil
	}

	// Check if event matches current sequence step
	if state.SequencePos >= len(cfg.Sequence) {
		return nil
	}

	currentStep := &cfg.Sequence[state.SequencePos]
	if !e.matchesSequenceStep(currentStep, event) {
		return nil
	}

	// Check max span from previous step
	if currentStep.MaxSpan > 0 && time.Since(state.LastEvent) > currentStep.MaxSpan {
		delete(e.states, stateKey)
		return nil
	}

	// Advance sequence
	state.Events = append(state.Events, event)
	state.EventIDs = append(state.EventIDs, event.EventID)
	state.LastEvent = event.Timestamp
	state.SequencePos++

	// Check if sequence is complete
	if state.SequencePos >= len(cfg.Sequence) {
		result := e.buildSequenceResult(r, state)
		delete(e.states, stateKey)
		return result
	}

	return nil
}

func (e *Engine) processThreshold(r *rule.Rule, event *engine.Event) *engine.DetectionResult {
	cfg := r.Threshold
	if cfg == nil {
		return nil
	}

	groupKey := e.buildGroupKey(cfg.GroupBy, event)
	stateKey := fmt.Sprintf("%s:%s", r.ID, groupKey)

	e.statesMu.Lock()
	defer e.statesMu.Unlock()

	state, exists := e.states[stateKey]
	if !exists {
		if len(e.states) >= e.config.MaxStates {
			return nil
		}

		state = &CorrelationState{
			RuleID:     r.ID,
			GroupKey:   groupKey,
			EventIDs:   make([]string, 0),
			FirstEvent: event.Timestamp,
			LastEvent:  event.Timestamp,
			Metadata:   make(map[string]interface{}),
		}
		e.states[stateKey] = state
		e.statesCreated.Add(1)
	}

	// Check timeout
	if time.Since(state.FirstEvent) > cfg.TimeWindow {
		state.Count = 0
		state.EventIDs = nil
		state.FirstEvent = event.Timestamp
	}

	state.Count++
	state.LastEvent = event.Timestamp
	state.EventIDs = append(state.EventIDs, event.EventID)

	if state.Count >= cfg.Threshold {
		result := e.buildThresholdResult(r, state)
		// Reset count
		state.Count = 0
		state.EventIDs = nil
		state.FirstEvent = time.Now()
		return result
	}

	return nil
}

func (e *Engine) matchesSequenceStep(step *rule.SequenceStep, event *engine.Event) bool {
	for _, cond := range step.Conditions {
		value, found := getNestedValue(event.Data, cond.Field)
		if !found {
			return false
		}
		if !matchesCondition(cond, value) {
			return false
		}
	}
	return true
}

func (e *Engine) checkEventCount(state *CorrelationState, cfg *rule.CorrelationConfig) bool {
	if cfg.MinCount > 0 && state.Count < cfg.MinCount {
		return false
	}
	if cfg.MaxCount > 0 && state.Count > cfg.MaxCount {
		return false
	}
	return cfg.MinCount > 0 && state.Count >= cfg.MinCount
}

func (e *Engine) checkUniqueCount(state *CorrelationState, cfg *rule.CorrelationConfig) bool {
	uniqueCount := len(state.UniqueValues)
	return cfg.MinDistinct > 0 && uniqueCount >= cfg.MinDistinct
}

func (e *Engine) buildGroupKey(fields []string, event *engine.Event) string {
	if len(fields) == 0 {
		return "default"
	}

	var parts []string
	for _, field := range fields {
		value, found := getNestedValue(event.Data, field)
		if found {
			parts = append(parts, fmt.Sprintf("%v", value))
		} else {
			parts = append(parts, "")
		}
	}

	return fmt.Sprintf("%v", parts)
}

func (e *Engine) buildCorrelationResult(r *rule.Rule, state *CorrelationState) *engine.DetectionResult {
	matchedEvents := make([]engine.MatchedEvent, len(state.EventIDs))
	for i, eventID := range state.EventIDs {
		matchedEvents[i] = engine.MatchedEvent{
			EventID: eventID,
		}
	}

	return &engine.DetectionResult{
		RuleID:          r.ID,
		RuleName:        r.Name,
		Severity:        r.Severity,
		MatchedEvents:   matchedEvents,
		Timestamp:       time.Now(),
		MITRETactics:    r.MITRETactics,
		MITRETechniques: r.MITRETechniques,
		Context: map[string]interface{}{
			"correlation_type": r.Correlation.Type,
			"group_key":        state.GroupKey,
			"event_count":      state.Count,
			"unique_count":     len(state.UniqueValues),
			"time_span":        state.LastEvent.Sub(state.FirstEvent).String(),
		},
	}
}

func (e *Engine) buildSequenceResult(r *rule.Rule, state *CorrelationState) *engine.DetectionResult {
	matchedEvents := make([]engine.MatchedEvent, len(state.Events))
	for i, evt := range state.Events {
		matchedEvents[i] = engine.MatchedEvent{
			EventID:   evt.EventID,
			Timestamp: evt.Timestamp,
		}
	}

	return &engine.DetectionResult{
		RuleID:          r.ID,
		RuleName:        r.Name,
		Severity:        r.Severity,
		MatchedEvents:   matchedEvents,
		Timestamp:       time.Now(),
		MITRETactics:    r.MITRETactics,
		MITRETechniques: r.MITRETechniques,
		Context: map[string]interface{}{
			"correlation_type": "sequence",
			"group_key":        state.GroupKey,
			"sequence_length":  state.SequencePos,
			"time_span":        state.LastEvent.Sub(state.FirstEvent).String(),
		},
	}
}

func (e *Engine) buildThresholdResult(r *rule.Rule, state *CorrelationState) *engine.DetectionResult {
	return &engine.DetectionResult{
		RuleID:          r.ID,
		RuleName:        r.Name,
		Severity:        r.Severity,
		Timestamp:       time.Now(),
		MITRETactics:    r.MITRETactics,
		MITRETechniques: r.MITRETechniques,
		Context: map[string]interface{}{
			"correlation_type": "threshold",
			"group_key":        state.GroupKey,
			"event_count":      state.Count,
			"threshold":        r.Threshold.Threshold,
			"time_window":      r.Threshold.TimeWindow.String(),
		},
	}
}

func (e *Engine) cleanupLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.cleanupExpiredStates()
		}
	}
}

func (e *Engine) cleanupExpiredStates() {
	e.statesMu.Lock()
	defer e.statesMu.Unlock()

	now := time.Now()
	for key, state := range e.states {
		if now.Sub(state.LastEvent) > e.config.StateTimeout {
			delete(e.states, key)
			e.statesExpired.Add(1)
		}
	}
}

func getNestedValue(data map[string]interface{}, field string) (interface{}, bool) {
	parts := splitField(field)
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

func splitField(field string) []string {
	var parts []string
	var current string
	inBracket := false

	for _, c := range field {
		if c == '.' && !inBracket {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else if c == '[' {
			inBracket = true
		} else if c == ']' {
			inBracket = false
		} else {
			current += string(c)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

func matchesCondition(cond *rule.Condition, value interface{}) bool {
	switch cond.Operator {
	case rule.OpEquals:
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	case rule.OpContains:
		return containsString(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case rule.OpIn:
		for _, v := range cond.Values {
			if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", v) {
				return true
			}
		}
		return false
	default:
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsString(s[1:], substr) || s[:len(substr)] == substr)
}
