// Package routing provides event routing functionality.
package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// Event represents an event to be routed.
type Event struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	SourceType string                 `json:"source_type"`
	Severity   string                 `json:"severity"`
	Fields     map[string]interface{} `json:"fields"`
	RawData    []byte                 `json:"raw_data,omitempty"`
}

// RouteResult represents the result of routing an event.
type RouteResult struct {
	EventID      string   `json:"event_id"`
	Destinations []string `json:"destinations"`
	Filtered     bool     `json:"filtered"`
	Sampled      bool     `json:"sampled"`
	Error        string   `json:"error,omitempty"`
}

// RouterConfig holds router configuration.
type RouterConfig struct {
	DefaultDestination string
	MaxConcurrent      int
	EnableMetrics      bool
}

// Router routes events to destinations based on rules.
type Router struct {
	config       RouterConfig
	rules        []*RoutingRule
	destinations map[string]Destination
	logger       *slog.Logger
	mu           sync.RWMutex

	// Metrics
	eventsRouted    atomic.Uint64
	eventsFiltered  atomic.Uint64
	eventsSampled   atomic.Uint64
	routeErrors     atomic.Uint64
}

// RoutingRule defines a routing rule.
type RoutingRule struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
	Conditions   []Condition     `json:"conditions"`
	Destinations []string        `json:"destinations"`
	Actions      []Action        `json:"actions"`
	StopOnMatch  bool            `json:"stop_on_match"`
	SampleRate   float64         `json:"sample_rate"` // 0.0-1.0, 1.0 = no sampling
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// Condition defines a rule condition.
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // eq, neq, contains, regex, gt, lt, gte, lte, exists, not_exists, in, not_in
	Value    interface{} `json:"value"`
}

// Action defines a rule action.
type Action struct {
	Type   string                 `json:"type"` // filter, sample, transform, enrich, tag
	Config map[string]interface{} `json:"config"`
}

// Destination is the interface for routing destinations.
type Destination interface {
	Name() string
	Type() string
	Send(ctx context.Context, events []*Event) error
	IsHealthy() bool
	Close() error
}

// NewRouter creates a new router.
func NewRouter(cfg RouterConfig, logger *slog.Logger) *Router {
	return &Router{
		config:       cfg,
		rules:        make([]*RoutingRule, 0),
		destinations: make(map[string]Destination),
		logger:       logger.With("component", "router"),
	}
}

// AddRule adds a routing rule.
func (r *Router) AddRule(rule *RoutingRule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Insert in priority order
	inserted := false
	for i, existing := range r.rules {
		if rule.Priority < existing.Priority {
			r.rules = append(r.rules[:i], append([]*RoutingRule{rule}, r.rules[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		r.rules = append(r.rules, rule)
	}

	r.logger.Info("added routing rule", "rule_id", rule.ID, "name", rule.Name)
}

// RemoveRule removes a routing rule.
func (r *Router) RemoveRule(ruleID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, rule := range r.rules {
		if rule.ID == ruleID {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
			r.logger.Info("removed routing rule", "rule_id", ruleID)
			return true
		}
	}
	return false
}

// GetRules returns all routing rules.
func (r *Router) GetRules() []*RoutingRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]*RoutingRule, len(r.rules))
	copy(rules, r.rules)
	return rules
}

// RegisterDestination registers a destination.
func (r *Router) RegisterDestination(dest Destination) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.destinations[dest.Name()] = dest
	r.logger.Info("registered destination", "name", dest.Name(), "type", dest.Type())
}

// UnregisterDestination removes a destination.
func (r *Router) UnregisterDestination(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if dest, ok := r.destinations[name]; ok {
		if err := dest.Close(); err != nil {
			return err
		}
		delete(r.destinations, name)
		r.logger.Info("unregistered destination", "name", name)
	}
	return nil
}

// Route routes an event to appropriate destinations.
func (r *Router) Route(ctx context.Context, event *Event) *RouteResult {
	result := &RouteResult{
		EventID:      event.ID,
		Destinations: []string{},
	}

	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()

	destinationSet := make(map[string]bool)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Evaluate conditions
		if !r.evaluateConditions(event, rule.Conditions) {
			continue
		}

		// Apply actions
		if r.applyActions(event, rule.Actions) {
			// Event was filtered
			result.Filtered = true
			r.eventsFiltered.Add(1)
			return result
		}

		// Apply sampling
		if rule.SampleRate < 1.0 {
			if !r.shouldSample(rule.SampleRate) {
				result.Sampled = true
				r.eventsSampled.Add(1)
				continue
			}
		}

		// Add destinations
		for _, dest := range rule.Destinations {
			destinationSet[dest] = true
		}

		if rule.StopOnMatch {
			break
		}
	}

	// If no rules matched, use default destination
	if len(destinationSet) == 0 && r.config.DefaultDestination != "" {
		destinationSet[r.config.DefaultDestination] = true
	}

	// Send to destinations
	for destName := range destinationSet {
		r.mu.RLock()
		dest, ok := r.destinations[destName]
		r.mu.RUnlock()

		if !ok {
			r.logger.Warn("destination not found", "destination", destName)
			continue
		}

		if !dest.IsHealthy() {
			r.logger.Warn("destination unhealthy", "destination", destName)
			continue
		}

		if err := dest.Send(ctx, []*Event{event}); err != nil {
			r.routeErrors.Add(1)
			result.Error = err.Error()
			r.logger.Error("failed to send to destination",
				"destination", destName,
				"event_id", event.ID,
				"error", err)
		} else {
			result.Destinations = append(result.Destinations, destName)
		}
	}

	r.eventsRouted.Add(1)
	return result
}

// RouteBatch routes a batch of events.
func (r *Router) RouteBatch(ctx context.Context, events []*Event) []*RouteResult {
	results := make([]*RouteResult, len(events))

	var wg sync.WaitGroup
	sem := make(chan struct{}, r.config.MaxConcurrent)

	for i, event := range events {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, evt *Event) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				results[idx] = &RouteResult{
					EventID: evt.ID,
					Error:   ctx.Err().Error(),
				}
				return
			default:
			}

			results[idx] = r.Route(ctx, evt)
		}(i, event)
	}

	wg.Wait()
	return results
}

// evaluateConditions evaluates all conditions for an event.
func (r *Router) evaluateConditions(event *Event, conditions []Condition) bool {
	for _, cond := range conditions {
		if !r.evaluateCondition(event, cond) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition.
func (r *Router) evaluateCondition(event *Event, cond Condition) bool {
	value := r.getFieldValue(event, cond.Field)

	switch cond.Operator {
	case "eq":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	case "neq":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case "regex":
		if pattern, ok := cond.Value.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(fmt.Sprintf("%v", value))
		}
		return false
	case "gt":
		return compareNumbers(value, cond.Value) > 0
	case "lt":
		return compareNumbers(value, cond.Value) < 0
	case "gte":
		return compareNumbers(value, cond.Value) >= 0
	case "lte":
		return compareNumbers(value, cond.Value) <= 0
	case "exists":
		return value != nil
	case "not_exists":
		return value == nil
	case "in":
		if list, ok := cond.Value.([]interface{}); ok {
			for _, item := range list {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", item) {
					return true
				}
			}
		}
		return false
	case "not_in":
		if list, ok := cond.Value.([]interface{}); ok {
			for _, item := range list {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", item) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

// getFieldValue gets a field value from an event.
func (r *Router) getFieldValue(event *Event, field string) interface{} {
	// Check top-level fields first
	switch field {
	case "tenant_id":
		return event.TenantID
	case "event_type":
		return event.EventType
	case "source_type":
		return event.SourceType
	case "severity":
		return event.Severity
	case "timestamp":
		return event.Timestamp
	}

	// Check nested fields
	if event.Fields != nil {
		return getNestedValue(event.Fields, field)
	}

	return nil
}

// getNestedValue gets a nested value using dot notation.
func getNestedValue(data map[string]interface{}, path string) interface{} {
	current := interface{}(data)

	for _, part := range splitPath(path) {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
		if current == nil {
			return nil
		}
	}

	return current
}

func splitPath(path string) []string {
	var parts []string
	var current string
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && regexp.MustCompile(regexp.QuoteMeta(substr)).MatchString(s)
}

func compareNumbers(a, b interface{}) int {
	aFloat := toFloat64(a)
	bFloat := toFloat64(b)

	if aFloat < bFloat {
		return -1
	} else if aFloat > bFloat {
		return 1
	}
	return 0
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case float64:
		return val
	case float32:
		return float64(val)
	case json.Number:
		f, _ := val.Float64()
		return f
	}
	return 0
}

// applyActions applies actions to an event. Returns true if event should be filtered.
func (r *Router) applyActions(event *Event, actions []Action) bool {
	for _, action := range actions {
		switch action.Type {
		case "filter":
			return true
		case "transform":
			r.applyTransform(event, action.Config)
		case "tag":
			r.applyTag(event, action.Config)
		}
	}
	return false
}

func (r *Router) applyTransform(event *Event, config map[string]interface{}) {
	// Apply field transformations
	if transforms, ok := config["transforms"].([]interface{}); ok {
		for _, t := range transforms {
			if transform, ok := t.(map[string]interface{}); ok {
				field := transform["field"].(string)
				operation := transform["operation"].(string)

				switch operation {
				case "set":
					if event.Fields == nil {
						event.Fields = make(map[string]interface{})
					}
					event.Fields[field] = transform["value"]
				case "delete":
					delete(event.Fields, field)
				case "rename":
					if val, exists := event.Fields[field]; exists {
						newField := transform["new_field"].(string)
						event.Fields[newField] = val
						delete(event.Fields, field)
					}
				}
			}
		}
	}
}

func (r *Router) applyTag(event *Event, config map[string]interface{}) {
	if tags, ok := config["tags"].([]interface{}); ok {
		if event.Fields == nil {
			event.Fields = make(map[string]interface{})
		}
		existingTags, _ := event.Fields["_tags"].([]string)
		for _, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				existingTags = append(existingTags, tagStr)
			}
		}
		event.Fields["_tags"] = existingTags
	}
}

// shouldSample returns true if an event should be included based on sample rate.
func (r *Router) shouldSample(rate float64) bool {
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}
	// Use event counter as pseudo-random for deterministic sampling
	return r.eventsRouted.Load()%uint64(1.0/rate) == 0
}

// Stats returns router statistics.
func (r *Router) Stats() map[string]interface{} {
	r.mu.RLock()
	numRules := len(r.rules)
	numDests := len(r.destinations)

	destHealth := make(map[string]bool)
	for name, dest := range r.destinations {
		destHealth[name] = dest.IsHealthy()
	}
	r.mu.RUnlock()

	return map[string]interface{}{
		"events_routed":      r.eventsRouted.Load(),
		"events_filtered":    r.eventsFiltered.Load(),
		"events_sampled":     r.eventsSampled.Load(),
		"route_errors":       r.routeErrors.Load(),
		"num_rules":          numRules,
		"num_destinations":   numDests,
		"destination_health": destHealth,
	}
}

// Close closes all destinations.
func (r *Router) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for name, dest := range r.destinations {
		if err := dest.Close(); err != nil {
			lastErr = err
			r.logger.Error("failed to close destination", "name", name, "error", err)
		}
	}
	return lastErr
}
