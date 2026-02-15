// Package correlation provides time window management for correlation.
package correlation

import (
	"sync"
	"time"
)

// WindowType represents the type of time window.
type WindowType string

const (
	WindowTumbling WindowType = "tumbling" // Fixed, non-overlapping windows
	WindowSliding  WindowType = "sliding"  // Overlapping windows
	WindowSession  WindowType = "session"  // Gap-based windows
)

// TimeWindow represents a time window for event aggregation.
type TimeWindow struct {
	Type        WindowType    `json:"type"`
	Duration    time.Duration `json:"duration"`
	Slide       time.Duration `json:"slide,omitempty"`       // For sliding windows
	SessionGap  time.Duration `json:"session_gap,omitempty"` // For session windows
	GracePeriod time.Duration `json:"grace_period,omitempty"`
}

// WindowState holds the state for a time window.
type WindowState struct {
	WindowStart time.Time              `json:"window_start"`
	WindowEnd   time.Time              `json:"window_end"`
	Events      []interface{}          `json:"events"`
	Count       int                    `json:"count"`
	Aggregates  map[string]interface{} `json:"aggregates,omitempty"`
	LastEvent   time.Time              `json:"last_event"`
}

// WindowManager manages time windows for event aggregation.
type WindowManager struct {
	windowType  WindowType
	duration    time.Duration
	slide       time.Duration
	sessionGap  time.Duration
	grace       time.Duration
	windows     map[string][]*WindowState // key -> windows
	mu          sync.RWMutex
}

// NewWindowManager creates a new window manager.
func NewWindowManager(window *TimeWindow) *WindowManager {
	wm := &WindowManager{
		windowType: window.Type,
		duration:   window.Duration,
		slide:      window.Slide,
		sessionGap: window.SessionGap,
		grace:      window.GracePeriod,
		windows:    make(map[string][]*WindowState),
	}

	// Set defaults
	if wm.slide == 0 {
		wm.slide = wm.duration
	}
	if wm.sessionGap == 0 {
		wm.sessionGap = 5 * time.Minute
	}
	if wm.grace == 0 {
		wm.grace = time.Minute
	}

	return wm
}

// AddEvent adds an event to the appropriate window(s).
func (wm *WindowManager) AddEvent(key string, eventTime time.Time, event interface{}) []*WindowState {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	switch wm.windowType {
	case WindowTumbling:
		return wm.addToTumblingWindow(key, eventTime, event)
	case WindowSliding:
		return wm.addToSlidingWindow(key, eventTime, event)
	case WindowSession:
		return wm.addToSessionWindow(key, eventTime, event)
	default:
		return wm.addToTumblingWindow(key, eventTime, event)
	}
}

// GetWindow returns the current window state for a key.
func (wm *WindowManager) GetWindow(key string) *WindowState {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	windows := wm.windows[key]
	if len(windows) == 0 {
		return nil
	}
	return windows[len(windows)-1]
}

// GetAllWindows returns all windows for a key.
func (wm *WindowManager) GetAllWindows(key string) []*WindowState {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	return wm.windows[key]
}

// CloseExpiredWindows closes windows that have passed their grace period.
func (wm *WindowManager) CloseExpiredWindows(key string, now time.Time) []*WindowState {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	windows := wm.windows[key]
	var closed []*WindowState
	var remaining []*WindowState

	for _, w := range windows {
		if now.After(w.WindowEnd.Add(wm.grace)) {
			closed = append(closed, w)
		} else {
			remaining = append(remaining, w)
		}
	}

	wm.windows[key] = remaining
	return closed
}

// Cleanup removes all expired windows.
func (wm *WindowManager) Cleanup(now time.Time) int {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	total := 0
	for key, windows := range wm.windows {
		var remaining []*WindowState
		for _, w := range windows {
			if now.Before(w.WindowEnd.Add(wm.grace)) {
				remaining = append(remaining, w)
			} else {
				total++
			}
		}
		if len(remaining) == 0 {
			delete(wm.windows, key)
		} else {
			wm.windows[key] = remaining
		}
	}
	return total
}

func (wm *WindowManager) addToTumblingWindow(key string, eventTime time.Time, event interface{}) []*WindowState {
	// Calculate window boundaries
	windowStart := eventTime.Truncate(wm.duration)
	windowEnd := windowStart.Add(wm.duration)

	windows := wm.windows[key]
	var targetWindow *WindowState

	// Find or create the appropriate window
	for _, w := range windows {
		if w.WindowStart.Equal(windowStart) {
			targetWindow = w
			break
		}
	}

	if targetWindow == nil {
		targetWindow = &WindowState{
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			Events:      make([]interface{}, 0),
			Aggregates:  make(map[string]interface{}),
		}
		wm.windows[key] = append(wm.windows[key], targetWindow)
	}

	targetWindow.Events = append(targetWindow.Events, event)
	targetWindow.Count++
	targetWindow.LastEvent = eventTime

	return []*WindowState{targetWindow}
}

func (wm *WindowManager) addToSlidingWindow(key string, eventTime time.Time, event interface{}) []*WindowState {
	// For sliding windows, event may belong to multiple windows
	var affectedWindows []*WindowState
	windows := wm.windows[key]

	// Calculate all windows this event belongs to
	// The event belongs to window starting at T if T <= eventTime < T + duration
	// Windows start at: floor((eventTime - duration) / slide) * slide + slide
	// up to: floor(eventTime / slide) * slide

	earliestStart := eventTime.Add(-wm.duration + time.Nanosecond).Truncate(wm.slide)
	latestStart := eventTime.Truncate(wm.slide)

	for start := earliestStart; !start.After(latestStart); start = start.Add(wm.slide) {
		windowStart := start
		windowEnd := start.Add(wm.duration)

		// Check if event falls within this window
		if eventTime.Before(windowStart) || !eventTime.Before(windowEnd) {
			continue
		}

		var targetWindow *WindowState
		for _, w := range windows {
			if w.WindowStart.Equal(windowStart) {
				targetWindow = w
				break
			}
		}

		if targetWindow == nil {
			targetWindow = &WindowState{
				WindowStart: windowStart,
				WindowEnd:   windowEnd,
				Events:      make([]interface{}, 0),
				Aggregates:  make(map[string]interface{}),
			}
			wm.windows[key] = append(wm.windows[key], targetWindow)
		}

		targetWindow.Events = append(targetWindow.Events, event)
		targetWindow.Count++
		targetWindow.LastEvent = eventTime
		affectedWindows = append(affectedWindows, targetWindow)
	}

	return affectedWindows
}

func (wm *WindowManager) addToSessionWindow(key string, eventTime time.Time, event interface{}) []*WindowState {
	windows := wm.windows[key]
	var targetWindow *WindowState

	// Find an existing session that this event extends
	for _, w := range windows {
		// Event extends session if it's within sessionGap of the last event
		if eventTime.Sub(w.LastEvent) <= wm.sessionGap {
			targetWindow = w
			break
		}
	}

	if targetWindow == nil {
		// Create new session
		targetWindow = &WindowState{
			WindowStart: eventTime,
			WindowEnd:   eventTime.Add(wm.sessionGap),
			Events:      make([]interface{}, 0),
			Aggregates:  make(map[string]interface{}),
		}
		wm.windows[key] = append(wm.windows[key], targetWindow)
	}

	targetWindow.Events = append(targetWindow.Events, event)
	targetWindow.Count++
	targetWindow.LastEvent = eventTime
	targetWindow.WindowEnd = eventTime.Add(wm.sessionGap) // Extend window

	return []*WindowState{targetWindow}
}

// WindowResult represents the result of window computation.
type WindowResult struct {
	Key         string                 `json:"key"`
	WindowStart time.Time              `json:"window_start"`
	WindowEnd   time.Time              `json:"window_end"`
	Count       int                    `json:"count"`
	Events      []interface{}          `json:"events,omitempty"`
	Aggregates  map[string]interface{} `json:"aggregates"`
}

// ComputeAggregates computes aggregates for a window.
func (ws *WindowState) ComputeAggregates(fieldExtractor func(interface{}) map[string]interface{}) map[string]interface{} {
	aggregates := make(map[string]interface{})

	// Count
	aggregates["count"] = ws.Count

	// Duration
	aggregates["duration_ms"] = ws.WindowEnd.Sub(ws.WindowStart).Milliseconds()

	// Extract field values for additional aggregations
	if fieldExtractor != nil {
		var values []map[string]interface{}
		for _, event := range ws.Events {
			values = append(values, fieldExtractor(event))
		}

		// Compute field-specific aggregates
		aggregates["field_values"] = values
	}

	ws.Aggregates = aggregates
	return aggregates
}

// ToResult converts WindowState to WindowResult.
func (ws *WindowState) ToResult(key string, includeEvents bool) *WindowResult {
	result := &WindowResult{
		Key:         key,
		WindowStart: ws.WindowStart,
		WindowEnd:   ws.WindowEnd,
		Count:       ws.Count,
		Aggregates:  ws.Aggregates,
	}

	if includeEvents {
		result.Events = ws.Events
	}

	return result
}
