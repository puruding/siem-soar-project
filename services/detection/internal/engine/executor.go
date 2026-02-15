// Package engine provides the core detection engine implementation.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/detection/internal/rule"
)

// Executor executes detection rules against events.
type Executor struct {
	maxConcurrent int
	timeout       time.Duration
	semaphore     chan struct{}
	logger        *slog.Logger

	// Compiled patterns cache
	patternCache   map[string]*regexp.Regexp
	patternCacheMu sync.RWMutex

	// Metrics
	executions     atomic.Uint64
	matches        atomic.Uint64
	errors         atomic.Uint64
	timeouts       atomic.Uint64
}

// NewExecutor creates a new rule executor.
func NewExecutor(maxConcurrent int, timeout time.Duration, logger *slog.Logger) *Executor {
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Executor{
		maxConcurrent: maxConcurrent,
		timeout:       timeout,
		semaphore:     make(chan struct{}, maxConcurrent),
		logger:        logger.With("component", "executor"),
		patternCache:  make(map[string]*regexp.Regexp),
	}
}

// Execute runs a rule against an event.
func (e *Executor) Execute(ctx context.Context, r *rule.Rule, event *Event) (*DetectionResult, error) {
	// Acquire semaphore
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(e.timeout):
		e.timeouts.Add(1)
		return nil, fmt.Errorf("timeout waiting for executor slot")
	}

	e.executions.Add(1)

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Execute based on rule type
	var matched bool
	var matchedFields map[string]interface{}
	var err error

	switch r.Type {
	case rule.TypeSimple:
		matched, matchedFields, err = e.executeSimpleRule(execCtx, r, event)
	case rule.TypeSigma:
		matched, matchedFields, err = e.executeSigmaRule(execCtx, r, event)
	case rule.TypeCorrelation:
		matched, matchedFields, err = e.executeCorrelationRule(execCtx, r, event)
	case rule.TypeThreshold:
		matched, matchedFields, err = e.executeThresholdRule(execCtx, r, event)
	default:
		return nil, fmt.Errorf("unsupported rule type: %s", r.Type)
	}

	if err != nil {
		e.errors.Add(1)
		return nil, err
	}

	if !matched {
		return nil, nil
	}

	e.matches.Add(1)

	// Build detection result
	result := &DetectionResult{
		RuleID:    r.ID,
		RuleName:  r.Name,
		Severity:  r.Severity,
		Timestamp: time.Now(),
		MatchedEvents: []MatchedEvent{{
			EventID:       event.EventID,
			Timestamp:     event.Timestamp,
			MatchedFields: matchedFields,
		}},
		MITRETactics:    r.MITRETactics,
		MITRETechniques: r.MITRETechniques,
	}

	return result, nil
}

// ExecuteBatch runs a rule against multiple events.
func (e *Executor) ExecuteBatch(ctx context.Context, r *rule.Rule, events []*Event) ([]*DetectionResult, error) {
	results := make([]*DetectionResult, 0)

	for _, event := range events {
		result, err := e.Execute(ctx, r, event)
		if err != nil {
			e.logger.Warn("rule execution failed", "rule_id", r.ID, "event_id", event.EventID, "error", err)
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// Stats returns executor statistics.
func (e *Executor) Stats() map[string]interface{} {
	return map[string]interface{}{
		"executions": e.executions.Load(),
		"matches":    e.matches.Load(),
		"errors":     e.errors.Load(),
		"timeouts":   e.timeouts.Load(),
	}
}

func (e *Executor) executeSimpleRule(ctx context.Context, r *rule.Rule, event *Event) (bool, map[string]interface{}, error) {
	conditions := r.ParsedConditions
	if conditions == nil {
		return false, nil, fmt.Errorf("rule has no conditions")
	}

	matchedFields := make(map[string]interface{})

	// Evaluate each condition
	for _, cond := range conditions.Conditions {
		matched, value := e.evaluateCondition(cond, event.Data)
		if !matched && cond.Required {
			return false, nil, nil
		}
		if matched {
			matchedFields[cond.Field] = value
		}
	}

	// All required conditions matched
	return len(matchedFields) > 0, matchedFields, nil
}

func (e *Executor) executeSigmaRule(ctx context.Context, r *rule.Rule, event *Event) (bool, map[string]interface{}, error) {
	// Sigma rules are converted to conditions during loading
	return e.executeSimpleRule(ctx, r, event)
}

func (e *Executor) executeCorrelationRule(ctx context.Context, r *rule.Rule, event *Event) (bool, map[string]interface{}, error) {
	// Correlation rules require state management
	// This is a simplified implementation
	// Full implementation would track events in a time window

	conditions := r.ParsedConditions
	if conditions == nil {
		return false, nil, fmt.Errorf("rule has no conditions")
	}

	matchedFields := make(map[string]interface{})

	// For correlation, we check if the event matches the pattern
	for _, cond := range conditions.Conditions {
		matched, value := e.evaluateCondition(cond, event.Data)
		if matched {
			matchedFields[cond.Field] = value
		}
	}

	// Basic match - correlation state handled by CorrelationEngine
	return len(matchedFields) > 0, matchedFields, nil
}

func (e *Executor) executeThresholdRule(ctx context.Context, r *rule.Rule, event *Event) (bool, map[string]interface{}, error) {
	// Threshold rules require counting
	// This is a simplified implementation
	return e.executeSimpleRule(ctx, r, event)
}

func (e *Executor) evaluateCondition(cond *rule.Condition, data map[string]interface{}) (bool, interface{}) {
	value, found := e.getFieldValue(cond.Field, data)
	if !found {
		return false, nil
	}

	switch cond.Operator {
	case rule.OpEquals:
		return e.compareEquals(value, cond.Value), value
	case rule.OpNotEquals:
		return !e.compareEquals(value, cond.Value), value
	case rule.OpContains:
		return e.contains(value, cond.Value), value
	case rule.OpStartsWith:
		return e.startsWith(value, cond.Value), value
	case rule.OpEndsWith:
		return e.endsWith(value, cond.Value), value
	case rule.OpRegex:
		return e.matchesRegex(value, cond.Value), value
	case rule.OpIn:
		return e.inList(value, cond.Values), value
	case rule.OpNotIn:
		return !e.inList(value, cond.Values), value
	case rule.OpGreaterThan:
		return e.compareNumeric(value, cond.Value, ">"), value
	case rule.OpLessThan:
		return e.compareNumeric(value, cond.Value, "<"), value
	case rule.OpGreaterOrEqual:
		return e.compareNumeric(value, cond.Value, ">="), value
	case rule.OpLessOrEqual:
		return e.compareNumeric(value, cond.Value, "<="), value
	case rule.OpExists:
		return found, value
	case rule.OpNotExists:
		return !found, nil
	default:
		return false, nil
	}
}

func (e *Executor) getFieldValue(field string, data map[string]interface{}) (interface{}, bool) {
	// Support nested fields with dot notation
	parts := strings.Split(field, ".")

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

func (e *Executor) compareEquals(value, expected interface{}) bool {
	// Handle string comparison (case-insensitive option)
	if vs, ok := value.(string); ok {
		if es, ok := expected.(string); ok {
			return strings.EqualFold(vs, es)
		}
	}
	return value == expected
}

func (e *Executor) contains(value, substr interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := substr.(string)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(vs), strings.ToLower(ss))
}

func (e *Executor) startsWith(value, prefix interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ps, ok := prefix.(string)
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.ToLower(vs), strings.ToLower(ps))
}

func (e *Executor) endsWith(value, suffix interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := suffix.(string)
	if !ok {
		return false
	}
	return strings.HasSuffix(strings.ToLower(vs), strings.ToLower(ss))
}

func (e *Executor) matchesRegex(value, pattern interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ps, ok := pattern.(string)
	if !ok {
		return false
	}

	// Check cache
	e.patternCacheMu.RLock()
	re, cached := e.patternCache[ps]
	e.patternCacheMu.RUnlock()

	if !cached {
		var err error
		re, err = regexp.Compile(ps)
		if err != nil {
			return false
		}

		e.patternCacheMu.Lock()
		e.patternCache[ps] = re
		e.patternCacheMu.Unlock()
	}

	return re.MatchString(vs)
}

func (e *Executor) inList(value interface{}, list []interface{}) bool {
	for _, item := range list {
		if e.compareEquals(value, item) {
			return true
		}
	}
	return false
}

func (e *Executor) compareNumeric(value, threshold interface{}, op string) bool {
	// Convert to float64 for comparison
	v := e.toFloat64(value)
	t := e.toFloat64(threshold)

	if v == nil || t == nil {
		return false
	}

	switch op {
	case ">":
		return *v > *t
	case "<":
		return *v < *t
	case ">=":
		return *v >= *t
	case "<=":
		return *v <= *t
	default:
		return false
	}
}

func (e *Executor) toFloat64(value interface{}) *float64 {
	var result float64

	switch v := value.(type) {
	case float64:
		result = v
	case float32:
		result = float64(v)
	case int:
		result = float64(v)
	case int64:
		result = float64(v)
	case int32:
		result = float64(v)
	case string:
		var err error
		result, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return nil
		}
	default:
		return nil
	}

	return &result
}

// ClearPatternCache clears the regex pattern cache.
func (e *Executor) ClearPatternCache() {
	e.patternCacheMu.Lock()
	defer e.patternCacheMu.Unlock()
	e.patternCache = make(map[string]*regexp.Regexp)
}
