// Package engine provides the core parsing engine for log events.
package engine

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RegexParser parses logs using regular expressions.
type RegexParser struct {
	patterns []*CompiledPattern
	mu       sync.RWMutex
}

// CompiledPattern represents a compiled regex pattern with metadata.
type CompiledPattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Priority    int
	SourceTypes []string // Limit to specific source types
	Fields      map[string]FieldConfig
}

// FieldConfig describes how to process a captured field.
type FieldConfig struct {
	Type       string // string, int, float, timestamp, ip, bool
	Format     string // For timestamp parsing
	Required   bool
	Default    interface{}
	Transform  string // uppercase, lowercase, trim
}

// NewRegexParser creates a new regex parser with default patterns.
func NewRegexParser() *RegexParser {
	p := &RegexParser{
		patterns: make([]*CompiledPattern, 0),
	}

	// Load default patterns
	p.loadDefaultPatterns()

	return p
}

// Name returns the parser name.
func (p *RegexParser) Name() string {
	return "regex"
}

// Parse parses raw event using regex patterns.
func (p *RegexParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	data := string(raw.Data)

	p.mu.RLock()
	patterns := p.patterns
	p.mu.RUnlock()

	for _, pattern := range patterns {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Check if pattern applies to this source type
		if len(pattern.SourceTypes) > 0 {
			found := false
			for _, st := range pattern.SourceTypes {
				if st == raw.SourceType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		matches := pattern.Regex.FindStringSubmatch(data)
		if matches == nil {
			continue
		}

		fields := make(map[string]interface{})
		names := pattern.Regex.SubexpNames()

		for i, name := range names {
			if i == 0 || name == "" || i >= len(matches) {
				continue
			}

			value := matches[i]

			// Apply field configuration if exists
			if cfg, ok := pattern.Fields[name]; ok {
				processedValue := p.processField(value, cfg)
				if processedValue != nil {
					fields[name] = processedValue
				}
			} else {
				fields[name] = value
			}
		}

		// Extract timestamp from fields
		timestamp := p.extractTimestamp(fields)
		if timestamp.IsZero() {
			timestamp = raw.Timestamp
		}

		return &ParsedEvent{
			EventID:        raw.EventID,
			TenantID:       raw.TenantID,
			Timestamp:      timestamp,
			ReceivedAt:     time.Now(),
			SourceType:     raw.SourceType,
			Format:         "regex",
			Fields:         fields,
			RawLog:         string(raw.Data),
			ParseSuccess:   true,
			PatternMatched: pattern.Name,
		}, nil
	}

	return nil, fmt.Errorf("no regex pattern matched")
}

// CanParse returns true if the data might be parseable by regex.
func (p *RegexParser) CanParse(data []byte) bool {
	// Regex can parse most text formats except pure JSON
	if len(data) == 0 {
		return false
	}
	return data[0] != '{' && data[0] != '['
}

// AddPattern adds a custom regex pattern (hot reload compatible).
func (p *RegexParser) AddPattern(name, pattern string, args ...interface{}) error {
	var priority int
	var fieldConfigs map[string]FieldConfig

	// Parse variadic args
	for i, arg := range args {
		switch i {
		case 0:
			if v, ok := arg.(int); ok {
				priority = v
			}
		case 1:
			if v, ok := arg.(map[string]FieldConfig); ok {
				fieldConfigs = v
			}
		}
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile pattern: %w", err)
	}

	compiled := &CompiledPattern{
		Name:     name,
		Regex:    regex,
		Priority: priority,
		Fields:   fieldConfigs,
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if pattern exists and update
	for i, existing := range p.patterns {
		if existing.Name == name {
			p.patterns[i] = compiled
			return nil
		}
	}

	// Insert in priority order
	inserted := false
	for i, existing := range p.patterns {
		if priority < existing.Priority {
			p.patterns = append(p.patterns[:i], append([]*CompiledPattern{compiled}, p.patterns[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		p.patterns = append(p.patterns, compiled)
	}

	return nil
}

// RemovePattern removes a regex pattern by name.
func (p *RegexParser) RemovePattern(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, pattern := range p.patterns {
		if pattern.Name == name {
			p.patterns = append(p.patterns[:i], p.patterns[i+1:]...)
			return
		}
	}
}

// GetPatterns returns all pattern names.
func (p *RegexParser) GetPatterns() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	names := make([]string, len(p.patterns))
	for i, pattern := range p.patterns {
		names[i] = pattern.Name
	}
	return names
}

// processField processes a captured value according to field configuration.
func (p *RegexParser) processField(value string, cfg FieldConfig) interface{} {
	// Apply transform
	switch cfg.Transform {
	case "uppercase":
		value = strings.ToUpper(value)
	case "lowercase":
		value = strings.ToLower(value)
	case "trim":
		value = strings.TrimSpace(value)
	}

	// Handle empty values
	if value == "" || value == "-" {
		if cfg.Default != nil {
			return cfg.Default
		}
		if cfg.Required {
			return nil
		}
		return ""
	}

	// Convert to target type
	switch cfg.Type {
	case "int":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return n
		}
		return cfg.Default

	case "float":
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
		return cfg.Default

	case "bool":
		switch strings.ToLower(value) {
		case "true", "yes", "1":
			return true
		case "false", "no", "0":
			return false
		}
		return cfg.Default

	case "timestamp":
		formats := []string{cfg.Format}
		if cfg.Format == "" {
			formats = []string{
				time.RFC3339,
				time.RFC3339Nano,
				"2006-01-02T15:04:05.000Z",
				"2006-01-02 15:04:05",
				"02/Jan/2006:15:04:05 -0700",
				"Jan  2 15:04:05",
				"Jan 2 15:04:05",
			}
		}
		for _, format := range formats {
			if ts, err := time.Parse(format, value); err == nil {
				return ts.Format(time.RFC3339)
			}
		}
		return value

	default:
		return value
	}
}

// extractTimestamp extracts timestamp from parsed fields.
func (p *RegexParser) extractTimestamp(fields map[string]interface{}) time.Time {
	tsFields := []string{"timestamp", "time", "@timestamp", "datetime", "date"}

	for _, field := range tsFields {
		if val, ok := fields[field]; ok {
			switch v := val.(type) {
			case string:
				formats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z",
					"2006-01-02 15:04:05",
					"02/Jan/2006:15:04:05 -0700",
				}
				for _, format := range formats {
					if ts, err := time.Parse(format, v); err == nil {
						return ts
					}
				}
			case time.Time:
				return v
			}
		}
	}

	return time.Time{}
}

// loadDefaultPatterns loads common log patterns.
func (p *RegexParser) loadDefaultPatterns() {
	defaultPatterns := []struct {
		name     string
		pattern  string
		priority int
		fields   map[string]FieldConfig
	}{
		{
			name: "apache_combined",
			pattern: `^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<auth>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<request>\S+)(?:\s+(?P<protocol>\S+))?"\s+(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]+)"\s+"(?P<user_agent>[^"]+)")?`,
			priority: 10,
			fields: map[string]FieldConfig{
				"status": {Type: "int"},
				"bytes":  {Type: "int", Default: 0},
			},
		},
		{
			name: "nginx_combined",
			pattern: `^(?P<client_ip>\S+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+)\s+"(?P<referrer>[^"]+)"\s+"(?P<user_agent>[^"]+)"`,
			priority: 10,
			fields: map[string]FieldConfig{
				"status": {Type: "int"},
				"bytes":  {Type: "int"},
			},
		},
		{
			name: "syslog_rfc3164",
			pattern: `^<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>[^\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$`,
			priority: 20,
			fields: map[string]FieldConfig{
				"priority": {Type: "int"},
				"pid":      {Type: "int"},
			},
		},
		{
			name: "syslog_rfc5424",
			pattern: `^<(?P<priority>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<structured_data>-|\[[^\]]*\])\s*(?P<message>.*)$`,
			priority: 15,
			fields: map[string]FieldConfig{
				"priority": {Type: "int"},
				"version":  {Type: "int"},
			},
		},
		{
			name: "ssh_auth",
			pattern: `^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<action>Accepted|Failed|Invalid)\s+(?P<auth_method>\S+)\s+for(?:\s+invalid\s+user)?\s+(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)`,
			priority: 5,
			fields: map[string]FieldConfig{
				"pid":      {Type: "int"},
				"src_port": {Type: "int"},
				"action":   {Transform: "lowercase"},
			},
		},
		{
			name: "sudo",
			pattern: `^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sudo(?:\[(?P<pid>\d+)\])?:\s+(?P<username>\S+)\s+:\s+(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$`,
			priority: 5,
			fields: map[string]FieldConfig{
				"pid": {Type: "int"},
			},
		},
		{
			name: "iptables",
			pattern: `^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+kernel:.*\[(?P<chain>\S+)\].*SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+).*PROTO=(?P<protocol>\S+)(?:.*SPT=(?P<src_port>\d+))?(?:.*DPT=(?P<dst_port>\d+))?`,
			priority: 10,
			fields: map[string]FieldConfig{
				"src_port": {Type: "int"},
				"dst_port": {Type: "int"},
			},
		},
		{
			name: "windows_event",
			pattern: `^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<level>\S+)\s+(?P<source>\S+)\s+(?P<event_id>\d+)\s+(?P<message>.*)$`,
			priority: 10,
			fields: map[string]FieldConfig{
				"event_id": {Type: "int"},
				"level":    {Transform: "uppercase"},
			},
		},
		{
			name:     "generic_kv",
			pattern:  `^(?P<timestamp>\S+)\s+(?P<level>\S+)\s+(?P<rest>.*)$`,
			priority: 100,
			fields:   map[string]FieldConfig{},
		},
	}

	for _, dp := range defaultPatterns {
		_ = p.AddPattern(dp.name, dp.pattern, dp.priority, dp.fields)
	}
}

// SyslogParser parses syslog messages (RFC 3164 and RFC 5424).
type SyslogParser struct {
	rfc3164Pattern *regexp.Regexp
	rfc5424Pattern *regexp.Regexp
}

// NewSyslogParser creates a new syslog parser.
func NewSyslogParser() *SyslogParser {
	return &SyslogParser{
		rfc3164Pattern: regexp.MustCompile(`^<(?P<priority>\d{1,3})>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$`),
		rfc5424Pattern: regexp.MustCompile(`^<(?P<priority>\d{1,3})>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<structured_data>-|\[.+\])\s*(?P<message>.*)$`),
	}
}

// Name returns the parser name.
func (p *SyslogParser) Name() string {
	return "syslog"
}

// Parse parses a syslog message.
func (p *SyslogParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	data := string(raw.Data)
	fields := make(map[string]interface{})

	// Try RFC 5424 first
	if matches := p.rfc5424Pattern.FindStringSubmatch(data); matches != nil {
		names := p.rfc5424Pattern.SubexpNames()
		for i, name := range names {
			if i > 0 && name != "" && i < len(matches) {
				fields[name] = matches[i]
			}
		}
		fields["rfc"] = "5424"
	} else if matches := p.rfc3164Pattern.FindStringSubmatch(data); matches != nil {
		names := p.rfc3164Pattern.SubexpNames()
		for i, name := range names {
			if i > 0 && name != "" && i < len(matches) {
				fields[name] = matches[i]
			}
		}
		fields["rfc"] = "3164"
	} else {
		return nil, fmt.Errorf("not a valid syslog message")
	}

	// Parse priority into facility and severity
	if pri, ok := fields["priority"].(string); ok {
		if priority, err := strconv.Atoi(pri); err == nil {
			fields["facility"] = priority / 8
			fields["severity"] = priority % 8
		}
	}

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    raw.Timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "syslog",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// CanParse returns true if the data looks like syslog.
func (p *SyslogParser) CanParse(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	return data[0] == '<' && (data[1] >= '0' && data[1] <= '9')
}

// KeyValueParser parses key=value formatted logs.
type KeyValueParser struct {
	delimiter    string
	kvSeparator  string
	quoteChars   []rune
}

// NewKeyValueParser creates a new key-value parser.
func NewKeyValueParser() *KeyValueParser {
	return &KeyValueParser{
		delimiter:   " ",
		kvSeparator: "=",
		quoteChars:  []rune{'"', '\''},
	}
}

// Name returns the parser name.
func (p *KeyValueParser) Name() string {
	return "kv"
}

// Parse parses a key-value formatted log.
func (p *KeyValueParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	data := string(raw.Data)
	fields := p.parseKeyValues(data)

	if len(fields) == 0 {
		return nil, fmt.Errorf("no key-value pairs found")
	}

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    raw.Timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "kv",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// CanParse returns true if the data looks like key-value format.
func (p *KeyValueParser) CanParse(data []byte) bool {
	if len(data) == 0 || data[0] == '{' || data[0] == '[' {
		return false
	}
	// Check for at least one key=value pattern
	return strings.Contains(string(data), "=")
}

// parseKeyValues extracts key-value pairs from string.
func (p *KeyValueParser) parseKeyValues(data string) map[string]interface{} {
	result := make(map[string]interface{})

	// Simple state machine parser
	var key, value strings.Builder
	inKey := true
	inQuote := false
	quoteChar := rune(0)

	for _, c := range data {
		if inKey {
			if c == '=' {
				inKey = false
				continue
			}
			if c == ' ' || c == '\t' {
				// Skip whitespace before key
				if key.Len() == 0 {
					continue
				}
				// End of key-value pair without value
				if key.Len() > 0 {
					result[key.String()] = ""
					key.Reset()
				}
				continue
			}
			key.WriteRune(c)
		} else {
			// In value
			if !inQuote {
				// Check for quote start
				for _, q := range p.quoteChars {
					if c == q && value.Len() == 0 {
						inQuote = true
						quoteChar = c
						continue
					}
				}
				if c == ' ' || c == '\t' {
					// End of unquoted value
					if key.Len() > 0 {
						result[key.String()] = value.String()
						key.Reset()
						value.Reset()
					}
					inKey = true
					continue
				}
			} else {
				// In quote
				if c == quoteChar {
					inQuote = false
					continue
				}
			}
			value.WriteRune(c)
		}
	}

	// Handle remaining key-value
	if key.Len() > 0 {
		result[key.String()] = value.String()
	}

	return result
}
