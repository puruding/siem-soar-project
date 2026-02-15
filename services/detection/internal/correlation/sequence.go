// Package correlation provides sequence-based detection capabilities.
package correlation

import (
	"fmt"
	"sync"
	"time"
)

// SequenceState represents the state of a sequence detection.
type SequenceState struct {
	ID           string                 `json:"id"`
	RuleID       string                 `json:"rule_id"`
	GroupKey     string                 `json:"group_key"`
	CurrentStep  int                    `json:"current_step"`
	TotalSteps   int                    `json:"total_steps"`
	MatchedSteps []MatchedStep          `json:"matched_steps"`
	StartTime    time.Time              `json:"start_time"`
	LastUpdate   time.Time              `json:"last_update"`
	Context      map[string]interface{} `json:"context,omitempty"`
	Expired      bool                   `json:"expired"`
}

// MatchedStep represents a matched sequence step.
type MatchedStep struct {
	StepIndex int                    `json:"step_index"`
	StepName  string                 `json:"step_name"`
	EventID   string                 `json:"event_id"`
	Timestamp time.Time              `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// SequenceDefinition defines a sequence pattern.
type SequenceDefinition struct {
	Name          string         `json:"name"`
	Steps         []SequenceStep `json:"steps"`
	MaxSpan       time.Duration  `json:"max_span"`
	MaxStepGap    time.Duration  `json:"max_step_gap"`
	Ordered       bool           `json:"ordered"` // Must steps occur in order?
	SharedFields  []string       `json:"shared_fields"`
}

// SequenceStep defines a step in a sequence.
type SequenceStep struct {
	Name         string                 `json:"name"`
	Conditions   map[string]interface{} `json:"conditions"`
	MaxSpan      time.Duration          `json:"max_span,omitempty"`
	Optional     bool                   `json:"optional"`
	Repeatable   bool                   `json:"repeatable"`
	MinOccur     int                    `json:"min_occur,omitempty"`
	MaxOccur     int                    `json:"max_occur,omitempty"`
	CaptureFields []string              `json:"capture_fields,omitempty"`
}

// SequenceEvent represents an event for sequence matching.
type SequenceEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// SequenceMatch represents a complete sequence match.
type SequenceMatch struct {
	SequenceID   string        `json:"sequence_id"`
	SequenceName string        `json:"sequence_name"`
	GroupKey     string        `json:"group_key"`
	MatchedSteps []MatchedStep `json:"matched_steps"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// SequenceDetector detects multi-step sequences.
type SequenceDetector struct {
	definition   *SequenceDefinition
	states       map[string]*SequenceState // key: group_key
	mu           sync.RWMutex
	maxStates    int
	stateTimeout time.Duration
}

// NewSequenceDetector creates a new sequence detector.
func NewSequenceDetector(definition *SequenceDefinition) *SequenceDetector {
	return &SequenceDetector{
		definition:   definition,
		states:       make(map[string]*SequenceState),
		maxStates:    10000,
		stateTimeout: definition.MaxSpan,
	}
}

// ProcessEvent processes an event for sequence detection.
func (d *SequenceDetector) ProcessEvent(event *SequenceEvent, groupKey string) *SequenceMatch {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get or create state
	state := d.states[groupKey]

	if state != nil && d.isStateExpired(state, event.Timestamp) {
		delete(d.states, groupKey)
		state = nil
	}

	if state == nil {
		// Try to match first step
		if d.matchesStep(&d.definition.Steps[0], event) {
			if len(d.states) >= d.maxStates {
				d.evictOldestState()
			}

			state = &SequenceState{
				ID:           fmt.Sprintf("%s:%s:%d", d.definition.Name, groupKey, time.Now().UnixNano()),
				RuleID:       d.definition.Name,
				GroupKey:     groupKey,
				CurrentStep:  1,
				TotalSteps:   len(d.definition.Steps),
				MatchedSteps: make([]MatchedStep, 0),
				StartTime:    event.Timestamp,
				LastUpdate:   event.Timestamp,
				Context:      make(map[string]interface{}),
			}

			// Record matched step
			state.MatchedSteps = append(state.MatchedSteps, MatchedStep{
				StepIndex: 0,
				StepName:  d.definition.Steps[0].Name,
				EventID:   event.ID,
				Timestamp: event.Timestamp,
				Fields:    d.captureFields(&d.definition.Steps[0], event),
			})

			// Store shared field values
			d.storeSharedFields(state, event)

			d.states[groupKey] = state

			// Check if single-step sequence
			if len(d.definition.Steps) == 1 {
				match := d.buildMatch(state, event.Timestamp)
				delete(d.states, groupKey)
				return match
			}

			return nil
		}
		return nil
	}

	// Check if event matches current expected step
	currentStep := &d.definition.Steps[state.CurrentStep]

	// Check step gap
	if currentStep.MaxSpan > 0 && event.Timestamp.Sub(state.LastUpdate) > currentStep.MaxSpan {
		delete(d.states, groupKey)
		return nil
	}

	if d.definition.MaxStepGap > 0 && event.Timestamp.Sub(state.LastUpdate) > d.definition.MaxStepGap {
		delete(d.states, groupKey)
		return nil
	}

	// Check shared fields match
	if !d.checkSharedFields(state, event) {
		return nil
	}

	if d.matchesStep(currentStep, event) {
		state.LastUpdate = event.Timestamp
		state.MatchedSteps = append(state.MatchedSteps, MatchedStep{
			StepIndex: state.CurrentStep,
			StepName:  currentStep.Name,
			EventID:   event.ID,
			Timestamp: event.Timestamp,
			Fields:    d.captureFields(currentStep, event),
		})

		state.CurrentStep++

		// Check if sequence is complete
		if state.CurrentStep >= len(d.definition.Steps) {
			match := d.buildMatch(state, event.Timestamp)
			delete(d.states, groupKey)
			return match
		}

		return nil
	}

	// If not ordered, check if event matches any future step
	if !d.definition.Ordered {
		for i := state.CurrentStep; i < len(d.definition.Steps); i++ {
			step := &d.definition.Steps[i]
			if d.matchesStep(step, event) {
				// Mark intermediate steps as skipped or optional
				state.CurrentStep = i + 1
				state.LastUpdate = event.Timestamp
				state.MatchedSteps = append(state.MatchedSteps, MatchedStep{
					StepIndex: i,
					StepName:  step.Name,
					EventID:   event.ID,
					Timestamp: event.Timestamp,
					Fields:    d.captureFields(step, event),
				})

				if state.CurrentStep >= len(d.definition.Steps) {
					match := d.buildMatch(state, event.Timestamp)
					delete(d.states, groupKey)
					return match
				}
				return nil
			}
		}
	}

	return nil
}

// GetState returns the current state for a group key.
func (d *SequenceDetector) GetState(groupKey string) *SequenceState {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.states[groupKey]
}

// GetAllStates returns all active states.
func (d *SequenceDetector) GetAllStates() []*SequenceState {
	d.mu.RLock()
	defer d.mu.RUnlock()

	states := make([]*SequenceState, 0, len(d.states))
	for _, s := range d.states {
		states = append(states, s)
	}
	return states
}

// CleanupExpired removes expired states.
func (d *SequenceDetector) CleanupExpired(now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	count := 0
	for key, state := range d.states {
		if d.isStateExpired(state, now) {
			delete(d.states, key)
			count++
		}
	}
	return count
}

// Stats returns detector statistics.
func (d *SequenceDetector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"active_states": len(d.states),
		"max_states":    d.maxStates,
		"sequence_name": d.definition.Name,
		"total_steps":   len(d.definition.Steps),
	}
}

func (d *SequenceDetector) matchesStep(step *SequenceStep, event *SequenceEvent) bool {
	for field, expected := range step.Conditions {
		actual := getFieldValueFromMap(event.Data, field)
		if actual == nil {
			return false
		}

		if !matchValue(actual, expected) {
			return false
		}
	}
	return true
}

func (d *SequenceDetector) isStateExpired(state *SequenceState, now time.Time) bool {
	return now.Sub(state.StartTime) > d.stateTimeout
}

func (d *SequenceDetector) captureFields(step *SequenceStep, event *SequenceEvent) map[string]interface{} {
	if len(step.CaptureFields) == 0 {
		return nil
	}

	fields := make(map[string]interface{})
	for _, field := range step.CaptureFields {
		if value := getFieldValueFromMap(event.Data, field); value != nil {
			fields[field] = value
		}
	}
	return fields
}

func (d *SequenceDetector) storeSharedFields(state *SequenceState, event *SequenceEvent) {
	for _, field := range d.definition.SharedFields {
		if value := getFieldValueFromMap(event.Data, field); value != nil {
			state.Context[field] = value
		}
	}
}

func (d *SequenceDetector) checkSharedFields(state *SequenceState, event *SequenceEvent) bool {
	for _, field := range d.definition.SharedFields {
		expected, hasExpected := state.Context[field]
		if !hasExpected {
			continue
		}

		actual := getFieldValueFromMap(event.Data, field)
		if actual == nil || fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected) {
			return false
		}
	}
	return true
}

func (d *SequenceDetector) buildMatch(state *SequenceState, endTime time.Time) *SequenceMatch {
	return &SequenceMatch{
		SequenceID:   state.ID,
		SequenceName: d.definition.Name,
		GroupKey:     state.GroupKey,
		MatchedSteps: state.MatchedSteps,
		StartTime:    state.StartTime,
		EndTime:      endTime,
		Duration:     endTime.Sub(state.StartTime),
		Context:      state.Context,
	}
}

func (d *SequenceDetector) evictOldestState() {
	var oldestKey string
	var oldestTime time.Time

	for key, state := range d.states {
		if oldestKey == "" || state.LastUpdate.Before(oldestTime) {
			oldestKey = key
			oldestTime = state.LastUpdate
		}
	}

	if oldestKey != "" {
		delete(d.states, oldestKey)
	}
}

func getFieldValueFromMap(data map[string]interface{}, field string) interface{} {
	return getFieldValue(data, field)
}

func matchValue(actual, expected interface{}) bool {
	// Handle list of expected values (OR)
	if list, ok := expected.([]interface{}); ok {
		actualStr := fmt.Sprintf("%v", actual)
		for _, item := range list {
			if actualStr == fmt.Sprintf("%v", item) {
				return true
			}
		}
		return false
	}

	// Simple equality
	return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
}
