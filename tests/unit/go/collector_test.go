package unit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Collector Service Unit Tests
// =============================================================================

// RawEvent represents a raw log event before parsing
type RawEvent struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	SourceIP  string                 `json:"source_ip"`
	Timestamp time.Time              `json:"timestamp"`
	RawData   string                 `json:"raw_data"`
	Format    string                 `json:"format"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// EventBuffer provides buffered event ingestion
type EventBuffer struct {
	mu       sync.Mutex
	events   []RawEvent
	capacity int
	flushFn  func([]RawEvent) error
}

func NewEventBuffer(capacity int, flushFn func([]RawEvent) error) *EventBuffer {
	return &EventBuffer{
		events:   make([]RawEvent, 0, capacity),
		capacity: capacity,
		flushFn:  flushFn,
	}
}

func (b *EventBuffer) Add(event RawEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, event)

	if len(b.events) >= b.capacity {
		return b.flush()
	}

	return nil
}

func (b *EventBuffer) flush() error {
	if len(b.events) == 0 {
		return nil
	}

	events := make([]RawEvent, len(b.events))
	copy(events, b.events)
	b.events = b.events[:0]

	return b.flushFn(events)
}

func (b *EventBuffer) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flush()
}

func (b *EventBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

func TestEventBuffer_Add(t *testing.T) {
	var flushed []RawEvent
	buffer := NewEventBuffer(3, func(events []RawEvent) error {
		flushed = append(flushed, events...)
		return nil
	})

	// Add 2 events - should not flush
	buffer.Add(RawEvent{ID: "1"})
	buffer.Add(RawEvent{ID: "2"})

	assert.Len(t, flushed, 0)
	assert.Equal(t, 2, buffer.Size())

	// Add 3rd event - should flush
	buffer.Add(RawEvent{ID: "3"})

	assert.Len(t, flushed, 3)
	assert.Equal(t, 0, buffer.Size())
}

func TestEventBuffer_ManualFlush(t *testing.T) {
	var flushed []RawEvent
	buffer := NewEventBuffer(100, func(events []RawEvent) error {
		flushed = append(flushed, events...)
		return nil
	})

	buffer.Add(RawEvent{ID: "1"})
	buffer.Add(RawEvent{ID: "2"})

	err := buffer.Flush()
	assert.NoError(t, err)
	assert.Len(t, flushed, 2)
	assert.Equal(t, 0, buffer.Size())
}

// FormatDetector detects log format
type FormatDetector struct{}

const (
	FormatJSON   = "json"
	FormatSyslog = "syslog"
	FormatCEF    = "cef"
	FormatLEEF   = "leef"
	FormatCSV    = "csv"
	FormatKV     = "kv"
	FormatUnknown = "unknown"
)

func (d *FormatDetector) Detect(data string) string {
	data = strings.TrimSpace(data)

	// JSON
	if (strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}")) ||
		(strings.HasPrefix(data, "[") && strings.HasSuffix(data, "]")) {
		return FormatJSON
	}

	// CEF
	if strings.HasPrefix(data, "CEF:") {
		return FormatCEF
	}

	// LEEF
	if strings.HasPrefix(data, "LEEF:") {
		return FormatLEEF
	}

	// Syslog (RFC 3164 or RFC 5424)
	if d.isSyslog(data) {
		return FormatSyslog
	}

	// Key-Value
	if strings.Contains(data, "=") && !strings.Contains(data, ",") {
		return FormatKV
	}

	// CSV (simple heuristic)
	if strings.Count(data, ",") >= 2 {
		return FormatCSV
	}

	return FormatUnknown
}

func (d *FormatDetector) isSyslog(data string) bool {
	// RFC 3164: <priority>timestamp hostname ...
	if len(data) > 0 && data[0] == '<' {
		return true
	}

	// Check for common syslog timestamp format
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for _, month := range months {
		if strings.HasPrefix(data, month) {
			return true
		}
	}

	return false
}

func TestFormatDetector_Detect(t *testing.T) {
	detector := &FormatDetector{}

	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "JSON object",
			data:     `{"key": "value", "number": 123}`,
			expected: FormatJSON,
		},
		{
			name:     "JSON array",
			data:     `[{"event": "test"}]`,
			expected: FormatJSON,
		},
		{
			name:     "CEF format",
			data:     `CEF:0|Security|Firewall|1.0|100|Connection blocked|5|src=10.0.0.1`,
			expected: FormatCEF,
		},
		{
			name:     "LEEF format",
			data:     `LEEF:1.0|Vendor|Product|Version|EventID|`,
			expected: FormatLEEF,
		},
		{
			name:     "Syslog RFC3164",
			data:     `<134>Jan  1 00:00:00 hostname program[1234]: message`,
			expected: FormatSyslog,
		},
		{
			name:     "Syslog BSD",
			data:     `Jan  1 00:00:00 hostname program: message`,
			expected: FormatSyslog,
		},
		{
			name:     "Key-Value",
			data:     `timestamp=2024-01-01 src=10.0.0.1 dst=192.168.1.1`,
			expected: FormatKV,
		},
		{
			name:     "CSV",
			data:     `2024-01-01,10.0.0.1,192.168.1.1,80,443,TCP`,
			expected: FormatCSV,
		},
		{
			name:     "Unknown",
			data:     `random text without structure`,
			expected: FormatUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := detector.Detect(tc.data)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// SyslogParser parses syslog messages
type SyslogParser struct{}

type SyslogMessage struct {
	Priority  int       `json:"priority"`
	Facility  int       `json:"facility"`
	Severity  int       `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	AppName   string    `json:"app_name"`
	ProcID    string    `json:"proc_id"`
	Message   string    `json:"message"`
}

func (p *SyslogParser) Parse(data string) (*SyslogMessage, error) {
	msg := &SyslogMessage{}

	// Parse priority if present
	if len(data) > 0 && data[0] == '<' {
		endPri := strings.Index(data, ">")
		if endPri > 1 {
			var priority int
			fmt.Sscanf(data[1:endPri], "%d", &priority)
			msg.Priority = priority
			msg.Facility = priority / 8
			msg.Severity = priority % 8
			data = data[endPri+1:]
		}
	}

	// Parse timestamp and hostname
	parts := strings.SplitN(data, " ", 5)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid syslog format")
	}

	// Try to parse timestamp (BSD format: "Jan  1 00:00:00")
	timestampStr := strings.Join(parts[0:3], " ")
	timestamp, err := time.Parse("Jan  2 15:04:05", timestampStr)
	if err != nil {
		timestamp, err = time.Parse("Jan 2 15:04:05", timestampStr)
		if err != nil {
			// Use current time if parsing fails
			timestamp = time.Now()
		}
	}
	// Set year to current year
	timestamp = timestamp.AddDate(time.Now().Year()-timestamp.Year(), 0, 0)
	msg.Timestamp = timestamp

	if len(parts) >= 4 {
		msg.Hostname = parts[3]
	}

	if len(parts) >= 5 {
		remaining := parts[4]
		// Parse app name and PID: "program[1234]:"
		if colonIdx := strings.Index(remaining, ":"); colonIdx > 0 {
			appPart := remaining[:colonIdx]
			if bracketIdx := strings.Index(appPart, "["); bracketIdx > 0 {
				msg.AppName = appPart[:bracketIdx]
				msg.ProcID = strings.Trim(appPart[bracketIdx:], "[]")
			} else {
				msg.AppName = appPart
			}
			if colonIdx+2 < len(remaining) {
				msg.Message = strings.TrimSpace(remaining[colonIdx+1:])
			}
		} else {
			msg.Message = remaining
		}
	}

	return msg, nil
}

func TestSyslogParser_Parse(t *testing.T) {
	parser := &SyslogParser{}

	tests := []struct {
		name     string
		data     string
		expected SyslogMessage
	}{
		{
			name: "full syslog with priority",
			data: "<134>Jan  1 12:00:00 myhost sshd[1234]: Failed password for root",
			expected: SyslogMessage{
				Priority: 134,
				Facility: 16,
				Severity: 6,
				Hostname: "myhost",
				AppName:  "sshd",
				ProcID:   "1234",
				Message:  "Failed password for root",
			},
		},
		{
			name: "BSD syslog without priority",
			data: "Jan  1 12:00:00 server nginx: GET /index.html",
			expected: SyslogMessage{
				Priority: 0,
				Hostname: "server",
				AppName:  "nginx",
				Message:  "GET /index.html",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.Parse(tc.data)
			require.NoError(t, err)

			assert.Equal(t, tc.expected.Priority, result.Priority)
			assert.Equal(t, tc.expected.Facility, result.Facility)
			assert.Equal(t, tc.expected.Severity, result.Severity)
			assert.Equal(t, tc.expected.Hostname, result.Hostname)
			assert.Equal(t, tc.expected.AppName, result.AppName)
			assert.Equal(t, tc.expected.ProcID, result.ProcID)
			assert.Equal(t, tc.expected.Message, result.Message)
		})
	}
}

// CEFParser parses CEF (Common Event Format) messages
type CEFParser struct{}

type CEFMessage struct {
	Version    int               `json:"version"`
	DeviceVendor string          `json:"device_vendor"`
	DeviceProduct string         `json:"device_product"`
	DeviceVersion string         `json:"device_version"`
	SignatureID  string          `json:"signature_id"`
	Name        string           `json:"name"`
	Severity    int              `json:"severity"`
	Extensions  map[string]string `json:"extensions"`
}

func (p *CEFParser) Parse(data string) (*CEFMessage, error) {
	if !strings.HasPrefix(data, "CEF:") {
		return nil, fmt.Errorf("not a CEF message")
	}

	// Remove "CEF:" prefix and split by pipe
	data = data[4:]
	parts := strings.SplitN(data, "|", 8)

	if len(parts) < 7 {
		return nil, fmt.Errorf("invalid CEF format: insufficient fields")
	}

	msg := &CEFMessage{
		Extensions: make(map[string]string),
	}

	fmt.Sscanf(parts[0], "%d", &msg.Version)
	msg.DeviceVendor = parts[1]
	msg.DeviceProduct = parts[2]
	msg.DeviceVersion = parts[3]
	msg.SignatureID = parts[4]
	msg.Name = parts[5]
	fmt.Sscanf(parts[6], "%d", &msg.Severity)

	// Parse extensions (key=value pairs)
	if len(parts) > 7 {
		extParts := strings.Split(parts[7], " ")
		for _, part := range extParts {
			if idx := strings.Index(part, "="); idx > 0 {
				key := part[:idx]
				value := part[idx+1:]
				msg.Extensions[key] = value
			}
		}
	}

	return msg, nil
}

func TestCEFParser_Parse(t *testing.T) {
	parser := &CEFParser{}

	t.Run("valid CEF", func(t *testing.T) {
		data := "CEF:0|Security|Firewall|1.0|100|Connection blocked|5|src=10.0.0.1 dst=192.168.1.1 dpt=443"

		result, err := parser.Parse(data)
		require.NoError(t, err)

		assert.Equal(t, 0, result.Version)
		assert.Equal(t, "Security", result.DeviceVendor)
		assert.Equal(t, "Firewall", result.DeviceProduct)
		assert.Equal(t, "1.0", result.DeviceVersion)
		assert.Equal(t, "100", result.SignatureID)
		assert.Equal(t, "Connection blocked", result.Name)
		assert.Equal(t, 5, result.Severity)
		assert.Equal(t, "10.0.0.1", result.Extensions["src"])
		assert.Equal(t, "192.168.1.1", result.Extensions["dst"])
		assert.Equal(t, "443", result.Extensions["dpt"])
	})

	t.Run("not CEF", func(t *testing.T) {
		_, err := parser.Parse("not a CEF message")
		assert.Error(t, err)
	})
}

// SourceManager manages log sources
type SourceManager struct {
	mu      sync.RWMutex
	sources map[string]*LogSource
}

type LogSource struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // syslog, http, kafka, file
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Status    string    `json:"status"` // active, inactive, error
	CreatedAt time.Time `json:"created_at"`
	EventsRx  int64     `json:"events_received"`
	LastEvent time.Time `json:"last_event"`
}

func NewSourceManager() *SourceManager {
	return &SourceManager{
		sources: make(map[string]*LogSource),
	}
}

func (m *SourceManager) AddSource(source *LogSource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if source.ID == "" {
		return fmt.Errorf("source ID is required")
	}

	if _, exists := m.sources[source.ID]; exists {
		return fmt.Errorf("source already exists: %s", source.ID)
	}

	source.CreatedAt = time.Now()
	source.Status = "active"
	m.sources[source.ID] = source
	return nil
}

func (m *SourceManager) GetSource(id string) (*LogSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if source, ok := m.sources[id]; ok {
		return source, nil
	}
	return nil, fmt.Errorf("source not found: %s", id)
}

func (m *SourceManager) UpdateStatus(id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	source, ok := m.sources[id]
	if !ok {
		return fmt.Errorf("source not found: %s", id)
	}

	source.Status = status
	return nil
}

func (m *SourceManager) RecordEvent(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if source, ok := m.sources[id]; ok {
		source.EventsRx++
		source.LastEvent = time.Now()
	}
}

func (m *SourceManager) ListSources() []*LogSource {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*LogSource, 0, len(m.sources))
	for _, source := range m.sources {
		result = append(result, source)
	}
	return result
}

func TestSourceManager(t *testing.T) {
	manager := NewSourceManager()

	t.Run("add source", func(t *testing.T) {
		source := &LogSource{
			ID:   "syslog-1",
			Name: "Main Syslog",
			Type: "syslog",
			Host: "0.0.0.0",
			Port: 514,
		}

		err := manager.AddSource(source)
		assert.NoError(t, err)

		retrieved, err := manager.GetSource("syslog-1")
		assert.NoError(t, err)
		assert.Equal(t, "active", retrieved.Status)
	})

	t.Run("duplicate source", func(t *testing.T) {
		source := &LogSource{
			ID:   "syslog-1",
			Name: "Duplicate",
		}

		err := manager.AddSource(source)
		assert.Error(t, err)
	})

	t.Run("record events", func(t *testing.T) {
		manager.RecordEvent("syslog-1")
		manager.RecordEvent("syslog-1")

		source, _ := manager.GetSource("syslog-1")
		assert.Equal(t, int64(2), source.EventsRx)
		assert.False(t, source.LastEvent.IsZero())
	})

	t.Run("list sources", func(t *testing.T) {
		sources := manager.ListSources()
		assert.Len(t, sources, 1)
	})
}

// EventValidator validates incoming events
type EventValidator struct {
	MaxSize      int
	RequiredFields []string
}

func NewEventValidator() *EventValidator {
	return &EventValidator{
		MaxSize:      1024 * 1024, // 1MB
		RequiredFields: []string{"timestamp"},
	}
}

func (v *EventValidator) Validate(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty event")
	}

	if len(data) > v.MaxSize {
		return fmt.Errorf("event too large: %d bytes (max %d)", len(data), v.MaxSize)
	}

	// Try to parse as JSON if it looks like JSON
	if data[0] == '{' {
		var event map[string]interface{}
		if err := json.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}

		for _, field := range v.RequiredFields {
			if _, ok := event[field]; !ok {
				return fmt.Errorf("missing required field: %s", field)
			}
		}
	}

	return nil
}

func TestEventValidator_Validate(t *testing.T) {
	validator := NewEventValidator()

	tests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "valid JSON event",
			data:        []byte(`{"timestamp": "2024-01-01T00:00:00Z", "message": "test"}`),
			expectError: false,
		},
		{
			name:        "empty event",
			data:        []byte{},
			expectError: true,
		},
		{
			name:        "missing timestamp",
			data:        []byte(`{"message": "test"}`),
			expectError: true,
		},
		{
			name:        "invalid JSON",
			data:        []byte(`{invalid json}`),
			expectError: true,
		},
		{
			name:        "non-JSON event (syslog)",
			data:        []byte(`Jan  1 00:00:00 host program: message`),
			expectError: false, // Non-JSON events are allowed
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.data)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Throughput tracker for EPS measurement
type ThroughputTracker struct {
	mu        sync.Mutex
	counts    []int64
	window    time.Duration
	interval  time.Duration
	startTime time.Time
	current   int64
}

func NewThroughputTracker(window time.Duration) *ThroughputTracker {
	interval := time.Second
	slots := int(window / interval)

	return &ThroughputTracker{
		counts:   make([]int64, slots),
		window:   window,
		interval: interval,
		startTime: time.Now(),
	}
}

func (t *ThroughputTracker) Record(count int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	atomic.AddInt64(&t.current, count)
}

func (t *ThroughputTracker) Tick() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Shift counts
	copy(t.counts[1:], t.counts[:len(t.counts)-1])
	t.counts[0] = atomic.SwapInt64(&t.current, 0)
}

func (t *ThroughputTracker) GetEPS() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	var total int64
	for _, c := range t.counts {
		total += c
	}

	return float64(total) / t.window.Seconds()
}

func TestThroughputTracker(t *testing.T) {
	tracker := NewThroughputTracker(5 * time.Second)

	// Record some events
	tracker.Record(100)
	tracker.Record(200)
	tracker.Tick()

	tracker.Record(150)
	tracker.Tick()

	eps := tracker.GetEPS()
	assert.Greater(t, eps, 0.0)
}

// SyslogReceiver receives syslog over UDP/TCP
type SyslogReceiver struct {
	mu       sync.RWMutex
	addr     string
	protocol string
	running  bool
	handler  func([]byte, net.Addr)
}

func NewSyslogReceiver(addr, protocol string, handler func([]byte, net.Addr)) *SyslogReceiver {
	return &SyslogReceiver{
		addr:     addr,
		protocol: protocol,
		handler:  handler,
	}
}

func (r *SyslogReceiver) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *SyslogReceiver) Start(ctx context.Context) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	// In production, this would start a UDP/TCP listener
	// For testing, we just mark it as running
	go func() {
		<-ctx.Done()
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	return nil
}

func TestSyslogReceiver(t *testing.T) {
	var received [][]byte
	handler := func(data []byte, addr net.Addr) {
		received = append(received, data)
	}

	receiver := NewSyslogReceiver(":514", "udp", handler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := receiver.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, receiver.IsRunning())

	cancel()
	time.Sleep(10 * time.Millisecond)
	assert.False(t, receiver.IsRunning())
}

// HTTPReceiver receives events over HTTP
type HTTPReceiver struct {
	events chan RawEvent
	parser *FormatDetector
}

func NewHTTPReceiver() *HTTPReceiver {
	return &HTTPReceiver{
		events: make(chan RawEvent, 10000),
		parser: &FormatDetector{},
	}
}

func (r *HTTPReceiver) HandleEvent(data io.Reader) error {
	body, err := io.ReadAll(io.LimitReader(data, 1024*1024))
	if err != nil {
		return err
	}

	format := r.parser.Detect(string(body))

	event := RawEvent{
		ID:        fmt.Sprintf("http-%d", time.Now().UnixNano()),
		Source:    "http",
		Timestamp: time.Now(),
		RawData:   string(body),
		Format:    format,
	}

	select {
	case r.events <- event:
		return nil
	default:
		return fmt.Errorf("event buffer full")
	}
}

func (r *HTTPReceiver) Events() <-chan RawEvent {
	return r.events
}

func TestHTTPReceiver(t *testing.T) {
	receiver := NewHTTPReceiver()

	// Send JSON event
	jsonData := `{"timestamp": "2024-01-01", "message": "test"}`
	err := receiver.HandleEvent(bytes.NewReader([]byte(jsonData)))
	assert.NoError(t, err)

	// Send syslog event
	syslogData := "<134>Jan  1 00:00:00 host app: message"
	err = receiver.HandleEvent(bytes.NewReader([]byte(syslogData)))
	assert.NoError(t, err)

	// Check events
	event1 := <-receiver.Events()
	assert.Equal(t, "json", event1.Format)

	event2 := <-receiver.Events()
	assert.Equal(t, "syslog", event2.Format)
}

// Benchmarks
func BenchmarkFormatDetector_Detect(b *testing.B) {
	detector := &FormatDetector{}
	samples := []string{
		`{"key": "value", "number": 123}`,
		`CEF:0|Security|Firewall|1.0|100|Event|5|src=10.0.0.1`,
		`<134>Jan  1 00:00:00 hostname program[1234]: message`,
		`timestamp=2024-01-01 src=10.0.0.1`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(samples[i%len(samples)])
	}
}

func BenchmarkSyslogParser_Parse(b *testing.B) {
	parser := &SyslogParser{}
	data := "<134>Jan  1 12:00:00 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Parse(data)
	}
}

func BenchmarkCEFParser_Parse(b *testing.B) {
	parser := &CEFParser{}
	data := "CEF:0|Security|Firewall|1.0|100|Connection blocked|5|src=10.0.0.1 dst=192.168.1.1 dpt=443 spt=12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Parse(data)
	}
}

func BenchmarkEventBuffer_Add(b *testing.B) {
	buffer := NewEventBuffer(1000, func(events []RawEvent) error {
		return nil
	})

	event := RawEvent{
		ID:      "test",
		RawData: strings.Repeat("x", 1000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buffer.Add(event)
	}
}
