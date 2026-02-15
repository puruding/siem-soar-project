// Package detection_test provides unit tests for the correlation engine.
package detection_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Event represents a normalized security event.
type Event struct {
	ID        string
	Timestamp time.Time
	Source    string
	Type      string
	Principal struct {
		IP       string
		Hostname string
		User     string
	}
	Target struct {
		IP   string
		Port int
	}
	Metadata map[string]interface{}
}

// Window represents a time-based window for correlation.
type Window struct {
	Duration time.Duration
	events   []Event
	mu       sync.RWMutex
}

func NewWindow(duration time.Duration) *Window {
	return &Window{
		Duration: duration,
		events:   make([]Event, 0),
	}
}

func (w *Window) Add(event Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, event)
}

func (w *Window) GetEvents() []Event {
	w.mu.RLock()
	defer w.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-w.Duration)

	var result []Event
	for _, e := range w.events {
		if e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}

func (w *Window) Count() int {
	return len(w.GetEvents())
}

func (w *Window) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = make([]Event, 0)
}

// AggregationRule defines aggregation-based detection.
type AggregationRule struct {
	ID        string
	Name      string
	GroupBy   []string
	Threshold int
	Window    time.Duration
	Condition string
}

// SequenceRule defines sequence-based detection.
type SequenceRule struct {
	ID       string
	Name     string
	Steps    []SequenceStep
	Window   time.Duration
	MaxSpan  time.Duration
}

type SequenceStep struct {
	Name      string
	Condition map[string]interface{}
	Required  bool
}

// CorrelationEngine manages correlation rules.
type CorrelationEngine struct {
	windows map[string]*Window
	mu      sync.RWMutex
}

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		windows: make(map[string]*Window),
	}
}

func (e *CorrelationEngine) GetOrCreateWindow(key string, duration time.Duration) *Window {
	e.mu.Lock()
	defer e.mu.Unlock()

	if w, ok := e.windows[key]; ok {
		return w
	}

	w := NewWindow(duration)
	e.windows[key] = w
	return w
}

func (e *CorrelationEngine) ProcessEvent(event Event) {
	// Simple processing - add to all relevant windows
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, w := range e.windows {
		w.Add(event)
	}
}

// TestCorrelationWindow tests the sliding window implementation.
func TestCorrelationWindow(t *testing.T) {
	window := NewWindow(5 * time.Minute)

	// Add events
	for i := 0; i < 10; i++ {
		event := Event{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: time.Now(),
			Type:      "login_attempt",
		}
		window.Add(event)
	}

	assert.Equal(t, 10, window.Count())
}

// TestCorrelationWindowExpiry tests event expiry in window.
func TestCorrelationWindowExpiry(t *testing.T) {
	window := NewWindow(100 * time.Millisecond)

	// Add event
	event := Event{
		ID:        "old-event",
		Timestamp: time.Now().Add(-200 * time.Millisecond), // Already expired
		Type:      "test",
	}
	window.Add(event)

	// Should be filtered out
	assert.Equal(t, 0, window.Count())

	// Add current event
	current := Event{
		ID:        "current-event",
		Timestamp: time.Now(),
		Type:      "test",
	}
	window.Add(current)

	assert.Equal(t, 1, window.Count())
}

// TestAggregationRule tests count-based aggregation detection.
func TestAggregationRule(t *testing.T) {
	rule := AggregationRule{
		ID:        "brute-force-detection",
		Name:      "Brute Force Login Detection",
		GroupBy:   []string{"source.ip"},
		Threshold: 5,
		Window:    5 * time.Minute,
		Condition: "count > threshold",
	}

	window := NewWindow(rule.Window)

	// Simulate 6 failed login attempts from same IP
	for i := 0; i < 6; i++ {
		event := Event{
			ID:        "login-" + string(rune('0'+i)),
			Timestamp: time.Now(),
			Type:      "failed_login",
		}
		event.Principal.IP = "192.168.1.100"
		window.Add(event)
	}

	// Check if threshold exceeded
	assert.Greater(t, window.Count(), rule.Threshold)
}

// TestSequenceRule tests sequence-based detection.
func TestSequenceRule(t *testing.T) {
	rule := SequenceRule{
		ID:   "lateral-movement",
		Name: "Lateral Movement Detection",
		Steps: []SequenceStep{
			{
				Name:      "initial_access",
				Condition: map[string]interface{}{"type": "login"},
				Required:  true,
			},
			{
				Name:      "discovery",
				Condition: map[string]interface{}{"type": "process_scan"},
				Required:  true,
			},
			{
				Name:      "lateral_movement",
				Condition: map[string]interface{}{"type": "remote_execution"},
				Required:  true,
			},
		},
		Window:  30 * time.Minute,
		MaxSpan: 1 * time.Hour,
	}

	assert.Len(t, rule.Steps, 3)
	assert.Equal(t, "initial_access", rule.Steps[0].Name)
	assert.True(t, rule.Steps[0].Required)
}

// TestCorrelationEngine tests the correlation engine.
func TestCorrelationEngine(t *testing.T) {
	engine := NewCorrelationEngine()

	// Create windows
	window1 := engine.GetOrCreateWindow("login-attempts", 5*time.Minute)
	window2 := engine.GetOrCreateWindow("process-events", 10*time.Minute)

	// Add event
	event := Event{
		ID:        "test-event",
		Timestamp: time.Now(),
		Type:      "login",
	}
	window1.Add(event)
	window2.Add(event)

	assert.Equal(t, 1, window1.Count())
	assert.Equal(t, 1, window2.Count())
}

// TestCorrelationGroupBy tests grouping logic.
func TestCorrelationGroupBy(t *testing.T) {
	// Group events by source IP
	events := []Event{
		{ID: "1", Principal: struct{ IP, Hostname, User string }{IP: "192.168.1.1"}},
		{ID: "2", Principal: struct{ IP, Hostname, User string }{IP: "192.168.1.1"}},
		{ID: "3", Principal: struct{ IP, Hostname, User string }{IP: "192.168.1.2"}},
		{ID: "4", Principal: struct{ IP, Hostname, User string }{IP: "192.168.1.1"}},
	}

	groups := make(map[string][]Event)
	for _, e := range events {
		key := e.Principal.IP
		groups[key] = append(groups[key], e)
	}

	assert.Len(t, groups["192.168.1.1"], 3)
	assert.Len(t, groups["192.168.1.2"], 1)
}

// TestCorrelationConcurrency tests thread-safety.
func TestCorrelationConcurrency(t *testing.T) {
	window := NewWindow(5 * time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			event := Event{
				ID:        "concurrent-" + string(rune(idx)),
				Timestamp: time.Now(),
				Type:      "test",
			}
			window.Add(event)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 100, window.Count())
}

// TestSequenceMatching tests sequence pattern matching.
func TestSequenceMatching(t *testing.T) {
	steps := []SequenceStep{
		{Name: "step1", Condition: map[string]interface{}{"type": "A"}},
		{Name: "step2", Condition: map[string]interface{}{"type": "B"}},
		{Name: "step3", Condition: map[string]interface{}{"type": "C"}},
	}

	events := []Event{
		{ID: "1", Type: "A", Timestamp: time.Now().Add(-3 * time.Minute)},
		{ID: "2", Type: "B", Timestamp: time.Now().Add(-2 * time.Minute)},
		{ID: "3", Type: "C", Timestamp: time.Now().Add(-1 * time.Minute)},
	}

	// Check sequence order
	matched := true
	for i, step := range steps {
		expectedType := step.Condition["type"].(string)
		if events[i].Type != expectedType {
			matched = false
			break
		}
	}

	assert.True(t, matched)
}

// TestAggregationWithTimeRange tests aggregation within time range.
func TestAggregationWithTimeRange(t *testing.T) {
	window := NewWindow(1 * time.Hour)

	// Add events at different times
	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		event := Event{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Type:      "test",
		}
		window.Add(event)
	}

	assert.Equal(t, 10, window.Count())
}

// TestMultipleConditions tests multiple conditions in correlation.
func TestMultipleConditions(t *testing.T) {
	conditions := map[string]interface{}{
		"type":        "failed_login",
		"source.ip":   "192.168.1.100",
		"destination": "auth-server",
	}

	event := Event{
		ID:   "test",
		Type: "failed_login",
	}
	event.Principal.IP = "192.168.1.100"

	// Check conditions
	assert.Equal(t, conditions["type"], event.Type)
	assert.Equal(t, conditions["source.ip"], event.Principal.IP)
}

// Benchmark tests
func BenchmarkWindowAdd(b *testing.B) {
	window := NewWindow(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := Event{
			ID:        "benchmark-event",
			Timestamp: time.Now(),
			Type:      "test",
		}
		window.Add(event)
	}
}

func BenchmarkWindowCount(b *testing.B) {
	window := NewWindow(5 * time.Minute)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		event := Event{
			ID:        "event-" + string(rune(i)),
			Timestamp: time.Now(),
			Type:      "test",
		}
		window.Add(event)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		window.Count()
	}
}

func BenchmarkCorrelationEngine(b *testing.B) {
	engine := NewCorrelationEngine()
	engine.GetOrCreateWindow("test", 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := Event{
			ID:        "benchmark-event",
			Timestamp: time.Now(),
			Type:      "test",
		}
		engine.ProcessEvent(event)
	}
}

// TestWindowClear tests window clearing.
func TestWindowClear(t *testing.T) {
	window := NewWindow(5 * time.Minute)

	for i := 0; i < 10; i++ {
		event := Event{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: time.Now(),
			Type:      "test",
		}
		window.Add(event)
	}

	require.Equal(t, 10, window.Count())

	window.Clear()
	assert.Equal(t, 0, window.Count())
}
