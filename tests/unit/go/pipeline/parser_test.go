// Package pipeline_test provides unit tests for the data pipeline.
package pipeline_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ParsedEvent represents a parsed event.
type ParsedEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
	Format    string                 `json:"format"`
	Raw       string                 `json:"raw"`
}

// Parser interface for different log formats.
type Parser interface {
	Parse(raw string) (*ParsedEvent, error)
	Format() string
}

// JSONParser parses JSON logs.
type JSONParser struct{}

func (p *JSONParser) Format() string { return "json" }

func (p *JSONParser) Parse(raw string) (*ParsedEvent, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}

	event := &ParsedEvent{
		Timestamp: time.Now(),
		Source:    "json",
		Fields:    data,
		Format:    "json",
		Raw:       raw,
	}

	if msg, ok := data["message"].(string); ok {
		event.Message = msg
	}

	return event, nil
}

// CEFParser parses CEF (Common Event Format) logs.
type CEFParser struct{}

func (p *CEFParser) Format() string { return "cef" }

func (p *CEFParser) Parse(raw string) (*ParsedEvent, error) {
	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	parts := strings.SplitN(raw, "|", 8)
	if len(parts) < 8 {
		return nil, &ParseError{Message: "invalid CEF format"}
	}

	event := &ParsedEvent{
		Timestamp: time.Now(),
		Source:    "cef",
		Format:    "cef",
		Raw:       raw,
		Fields:    make(map[string]interface{}),
	}

	event.Fields["cef_version"] = strings.TrimPrefix(parts[0], "CEF:")
	event.Fields["device_vendor"] = parts[1]
	event.Fields["device_product"] = parts[2]
	event.Fields["device_version"] = parts[3]
	event.Fields["signature_id"] = parts[4]
	event.Fields["name"] = parts[5]
	event.Fields["severity"] = parts[6]
	event.Message = parts[5]

	// Parse extension fields
	if len(parts) >= 8 {
		p.parseExtension(parts[7], event.Fields)
	}

	return event, nil
}

func (p *CEFParser) parseExtension(ext string, fields map[string]interface{}) {
	// Extension format: key=value key=value
	pairs := strings.Split(ext, " ")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
}

// LEEFParser parses LEEF (Log Event Extended Format) logs.
type LEEFParser struct{}

func (p *LEEFParser) Format() string { return "leef" }

func (p *LEEFParser) Parse(raw string) (*ParsedEvent, error) {
	// LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Key=Value
	parts := strings.SplitN(raw, "|", 6)
	if len(parts) < 5 {
		return nil, &ParseError{Message: "invalid LEEF format"}
	}

	event := &ParsedEvent{
		Timestamp: time.Now(),
		Source:    "leef",
		Format:    "leef",
		Raw:       raw,
		Fields:    make(map[string]interface{}),
	}

	event.Fields["leef_version"] = strings.TrimPrefix(parts[0], "LEEF:")
	event.Fields["vendor"] = parts[1]
	event.Fields["product"] = parts[2]
	event.Fields["version"] = parts[3]
	event.Fields["event_id"] = parts[4]

	return event, nil
}

// GrokParser parses logs using Grok patterns.
type GrokParser struct {
	patterns map[string]*regexp.Regexp
}

func NewGrokParser() *GrokParser {
	return &GrokParser{
		patterns: map[string]*regexp.Regexp{
			"syslog": regexp.MustCompile(`^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$`),
			"apache": regexp.MustCompile(`^(?P<clientip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+)$`),
		},
	}
}

func (p *GrokParser) Format() string { return "grok" }

func (p *GrokParser) Parse(raw string) (*ParsedEvent, error) {
	event := &ParsedEvent{
		Timestamp: time.Now(),
		Source:    "grok",
		Format:    "grok",
		Raw:       raw,
		Fields:    make(map[string]interface{}),
	}

	// Try each pattern
	for name, pattern := range p.patterns {
		match := pattern.FindStringSubmatch(raw)
		if match != nil {
			event.Fields["pattern"] = name
			for i, name := range pattern.SubexpNames() {
				if i > 0 && name != "" {
					event.Fields[name] = match[i]
				}
			}
			if msg, ok := event.Fields["message"].(string); ok {
				event.Message = msg
			}
			return event, nil
		}
	}

	return nil, &ParseError{Message: "no matching pattern"}
}

// ParseError represents a parsing error.
type ParseError struct {
	Message string
}

func (e *ParseError) Error() string {
	return e.Message
}

// AutoDetector detects log format automatically.
type AutoDetector struct {
	parsers []Parser
}

func NewAutoDetector() *AutoDetector {
	return &AutoDetector{
		parsers: []Parser{
			&JSONParser{},
			&CEFParser{},
			&LEEFParser{},
			NewGrokParser(),
		},
	}
}

func (d *AutoDetector) Detect(raw string) string {
	raw = strings.TrimSpace(raw)

	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		return "json"
	}
	if strings.HasPrefix(raw, "CEF:") {
		return "cef"
	}
	if strings.HasPrefix(raw, "LEEF:") {
		return "leef"
	}
	return "syslog"
}

// TestJSONParser tests JSON log parsing.
func TestJSONParser(t *testing.T) {
	parser := &JSONParser{}

	jsonLog := `{"timestamp": "2024-01-15T10:30:00Z", "level": "ERROR", "message": "Connection failed", "source_ip": "192.168.1.100"}`

	event, err := parser.Parse(jsonLog)
	require.NoError(t, err)
	require.NotNil(t, event)

	assert.Equal(t, "json", event.Format)
	assert.Equal(t, "Connection failed", event.Message)
	assert.Equal(t, "192.168.1.100", event.Fields["source_ip"])
}

// TestCEFParser tests CEF log parsing.
func TestCEFParser(t *testing.T) {
	parser := &CEFParser{}

	cefLog := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`

	event, err := parser.Parse(cefLog)
	require.NoError(t, err)
	require.NotNil(t, event)

	assert.Equal(t, "cef", event.Format)
	assert.Equal(t, "0", event.Fields["cef_version"])
	assert.Equal(t, "Security", event.Fields["device_vendor"])
	assert.Equal(t, "threatmanager", event.Fields["device_product"])
	assert.Equal(t, "100", event.Fields["signature_id"])
	assert.Equal(t, "10.0.0.1", event.Fields["src"])
}

// TestLEEFParser tests LEEF log parsing.
func TestLEEFParser(t *testing.T) {
	parser := &LEEFParser{}

	leefLog := `LEEF:1.0|Microsoft|MSExchange|4.0|15345|devTime=2024-01-15`

	event, err := parser.Parse(leefLog)
	require.NoError(t, err)
	require.NotNil(t, event)

	assert.Equal(t, "leef", event.Format)
	assert.Equal(t, "1.0", event.Fields["leef_version"])
	assert.Equal(t, "Microsoft", event.Fields["vendor"])
}

// TestGrokParser tests Grok pattern parsing.
func TestGrokParser(t *testing.T) {
	parser := NewGrokParser()

	t.Run("syslog format", func(t *testing.T) {
		syslog := `Jan 15 10:30:00 webserver sshd[12345]: Failed password for root from 192.168.1.100`

		event, err := parser.Parse(syslog)
		require.NoError(t, err)
		require.NotNil(t, event)

		assert.Equal(t, "syslog", event.Fields["pattern"])
		assert.Equal(t, "webserver", event.Fields["host"])
		assert.Equal(t, "sshd", event.Fields["program"])
	})

	t.Run("apache format", func(t *testing.T) {
		apache := `192.168.1.100 - admin [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234`

		event, err := parser.Parse(apache)
		require.NoError(t, err)
		require.NotNil(t, event)

		assert.Equal(t, "apache", event.Fields["pattern"])
		assert.Equal(t, "192.168.1.100", event.Fields["clientip"])
		assert.Equal(t, "200", event.Fields["status"])
	})
}

// TestAutoDetector tests automatic format detection.
func TestAutoDetector(t *testing.T) {
	detector := NewAutoDetector()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"JSON", `{"message": "test"}`, "json"},
		{"CEF", `CEF:0|Test|test|1.0|1|test|1|`, "cef"},
		{"LEEF", `LEEF:1.0|Test|test|1.0|1|`, "leef"},
		{"Syslog", `Jan 15 10:30:00 host sshd: test`, "syslog"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			format := detector.Detect(tc.input)
			assert.Equal(t, tc.expected, format)
		})
	}
}

// TestParserErrors tests error handling.
func TestParserErrors(t *testing.T) {
	t.Run("invalid JSON", func(t *testing.T) {
		parser := &JSONParser{}
		_, err := parser.Parse(`{invalid json}`)
		assert.Error(t, err)
	})

	t.Run("invalid CEF", func(t *testing.T) {
		parser := &CEFParser{}
		_, err := parser.Parse(`not a cef log`)
		assert.Error(t, err)
	})

	t.Run("invalid LEEF", func(t *testing.T) {
		parser := &LEEFParser{}
		_, err := parser.Parse(`not a leef log`)
		assert.Error(t, err)
	})

	t.Run("no matching grok pattern", func(t *testing.T) {
		parser := NewGrokParser()
		_, err := parser.Parse(`random text that doesn't match any pattern`)
		assert.Error(t, err)
	})
}

// TestCEFExtensionParsing tests CEF extension field parsing.
func TestCEFExtensionParsing(t *testing.T) {
	parser := &CEFParser{}

	cefLog := `CEF:0|Test|test|1.0|1|test|1|src=10.0.0.1 dst=10.0.0.2 spt=1234 dpt=443 act=ALLOW`

	event, err := parser.Parse(cefLog)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", event.Fields["src"])
	assert.Equal(t, "10.0.0.2", event.Fields["dst"])
	assert.Equal(t, "1234", event.Fields["spt"])
	assert.Equal(t, "443", event.Fields["dpt"])
	assert.Equal(t, "ALLOW", event.Fields["act"])
}

// TestFieldNormalization tests field normalization.
func TestFieldNormalization(t *testing.T) {
	// Test UDM field mapping
	fieldMap := map[string]string{
		"src":       "principal.ip",
		"dst":       "target.ip",
		"spt":       "principal.port",
		"dpt":       "target.port",
		"user":      "principal.user.name",
		"act":       "security_result.action",
		"cs1":       "additional.fields.cs1",
		"deviceHostname": "principal.hostname",
	}

	assert.Equal(t, "principal.ip", fieldMap["src"])
	assert.Equal(t, "target.ip", fieldMap["dst"])
	assert.Equal(t, "principal.port", fieldMap["spt"])
}

// TestBatchParsing tests batch parsing of multiple logs.
func TestBatchParsing(t *testing.T) {
	parser := &JSONParser{}

	logs := []string{
		`{"message": "log1", "level": "INFO"}`,
		`{"message": "log2", "level": "WARN"}`,
		`{"message": "log3", "level": "ERROR"}`,
	}

	var events []*ParsedEvent
	for _, log := range logs {
		event, err := parser.Parse(log)
		require.NoError(t, err)
		events = append(events, event)
	}

	assert.Len(t, events, 3)
	assert.Equal(t, "log1", events[0].Message)
	assert.Equal(t, "log2", events[1].Message)
	assert.Equal(t, "log3", events[2].Message)
}

// Benchmark tests
func BenchmarkJSONParsing(b *testing.B) {
	parser := &JSONParser{}
	jsonLog := `{"timestamp": "2024-01-15T10:30:00Z", "level": "ERROR", "message": "Test", "source_ip": "192.168.1.100"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(jsonLog)
	}
}

func BenchmarkCEFParsing(b *testing.B) {
	parser := &CEFParser{}
	cefLog := `CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(cefLog)
	}
}

func BenchmarkGrokParsing(b *testing.B) {
	parser := NewGrokParser()
	syslog := `Jan 15 10:30:00 webserver sshd[12345]: Failed password for root`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(syslog)
	}
}

func BenchmarkAutoDetect(b *testing.B) {
	detector := NewAutoDetector()
	logs := []string{
		`{"message": "test"}`,
		`CEF:0|Test|test|1.0|1|test|1|`,
		`Jan 15 10:30:00 host sshd: test`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Detect(logs[i%len(logs)])
	}
}
