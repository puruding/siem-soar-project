// Package engine provides the core parsing engine for log events.
package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// GrokPattern represents a named grok pattern.
type GrokPattern struct {
	Name    string
	Pattern string
	Regex   *regexp.Regexp
}

// GrokParser parses logs using grok patterns.
type GrokParser struct {
	patterns   map[string]*GrokPattern
	compiled   map[string]*regexp.Regexp
	cache      *grokCache
	cacheSize  int
	mu         sync.RWMutex
}

// NewGrokParser creates a new grok parser with default patterns.
func NewGrokParser(cacheSize int) *GrokParser {
	p := &GrokParser{
		patterns:  make(map[string]*GrokPattern),
		compiled:  make(map[string]*regexp.Regexp),
		cache:     newGrokCache(cacheSize),
		cacheSize: cacheSize,
	}

	// Load default patterns
	p.loadDefaultPatterns()

	return p
}

// Name returns the parser name.
func (p *GrokParser) Name() string {
	return "grok"
}

// Parse parses raw event using grok patterns.
func (p *GrokParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	// Check cache first
	if cached := p.cache.get(string(raw.Data)); cached != nil {
		result := &ParsedEvent{
			EventID:      raw.EventID,
			TenantID:     raw.TenantID,
			Timestamp:    raw.Timestamp,
			SourceType:   raw.SourceType,
			Format:       "grok",
			Fields:       cached,
			RawLog:       string(raw.Data),
			ParseSuccess: true,
		}
		return result, nil
	}

	// Try to match against compiled patterns
	p.mu.RLock()
	defer p.mu.RUnlock()

	for name, regex := range p.compiled {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		match := regex.FindStringSubmatch(string(raw.Data))
		if match != nil {
			fields := make(map[string]interface{})
			for i, name := range regex.SubexpNames() {
				if i != 0 && name != "" && i < len(match) {
					fields[name] = match[i]
				}
			}

			// Cache the result
			p.cache.set(string(raw.Data), fields)

			return &ParsedEvent{
				EventID:        raw.EventID,
				TenantID:       raw.TenantID,
				Timestamp:      raw.Timestamp,
				SourceType:     raw.SourceType,
				Format:         "grok",
				Fields:         fields,
				RawLog:         string(raw.Data),
				ParseSuccess:   true,
				PatternMatched: name,
			}, nil
		}
	}

	return nil, fmt.Errorf("no grok pattern matched")
}

// CanParse returns true if the data might be parseable by grok.
func (p *GrokParser) CanParse(data []byte) bool {
	// Grok can parse most text formats
	return len(data) > 0 && data[0] != '{' && data[0] != '['
}

// AddPattern adds a grok pattern.
func (p *GrokParser) AddPattern(name, pattern string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Expand pattern references
	expanded := p.expandPattern(pattern)

	// Compile regex
	regex, err := regexp.Compile(expanded)
	if err != nil {
		return fmt.Errorf("failed to compile pattern %s: %w", name, err)
	}

	p.patterns[name] = &GrokPattern{
		Name:    name,
		Pattern: pattern,
		Regex:   regex,
	}
	p.compiled[name] = regex

	return nil
}

// RemovePattern removes a grok pattern.
func (p *GrokParser) RemovePattern(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.patterns, name)
	delete(p.compiled, name)
}

// expandPattern expands grok pattern references like %{PATTERN:name}.
func (p *GrokParser) expandPattern(pattern string) string {
	// Pattern reference format: %{PATTERN:name} or %{PATTERN}
	re := regexp.MustCompile(`%\{(\w+)(?::(\w+))?\}`)

	maxIterations := 100 // Prevent infinite loops
	for i := 0; i < maxIterations; i++ {
		expanded := re.ReplaceAllStringFunc(pattern, func(match string) string {
			parts := re.FindStringSubmatch(match)
			if len(parts) < 2 {
				return match
			}

			patternName := parts[1]
			fieldName := ""
			if len(parts) > 2 {
				fieldName = parts[2]
			}

			// Look up base pattern
			basePattern := p.getBasePattern(patternName)

			// Wrap in named capture group if field name provided
			if fieldName != "" {
				return fmt.Sprintf("(?P<%s>%s)", fieldName, basePattern)
			}
			return basePattern
		})

		if expanded == pattern {
			break
		}
		pattern = expanded
	}

	return pattern
}

// getBasePattern returns the regex for a base pattern name.
func (p *GrokParser) getBasePattern(name string) string {
	if pat, ok := p.patterns[name]; ok {
		return pat.Pattern
	}

	// Return default patterns
	switch name {
	case "WORD":
		return `\w+`
	case "SPACE":
		return `\s*`
	case "NOTSPACE":
		return `\S+`
	case "DATA":
		return `.*?`
	case "GREEDYDATA":
		return `.*`
	case "INT":
		return `(?:[+-]?(?:[0-9]+))`
	case "NUMBER":
		return `(?:[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))`
	case "IP":
		return `(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`
	case "IPV4":
		return `(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`
	case "IPV6":
		return `(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4})`
	case "HOSTNAME":
		return `(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)`
	case "HOST":
		return `(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)`
	case "IPORHOST":
		return `(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)`
	case "USER":
		return `[a-zA-Z0-9._-]+`
	case "USERNAME":
		return `[a-zA-Z0-9._-]+`
	case "MAC":
		return `(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}`
	case "PATH":
		return `(?:/[^\s]*|[A-Za-z]:\\[^\s]*)`
	case "URIPATH":
		return `(?:/[^\s?#]*)?`
	case "URIPARAM":
		return `\?[^\s#]*`
	case "URI":
		return `[A-Za-z][A-Za-z0-9+.-]*://[^\s]*`
	case "MONTH":
		return `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`
	case "MONTHDAY":
		return `(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])`
	case "DAY":
		return `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)`
	case "YEAR":
		return `(?:\d{4}|\d{2})`
	case "HOUR":
		return `(?:2[0123]|[01]?[0-9])`
	case "MINUTE":
		return `(?:[0-5][0-9])`
	case "SECOND":
		return `(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)`
	case "TIME":
		return `(?:[0-2]?[0-9]:[0-5][0-9]:[0-5][0-9])`
	case "TIMESTAMP_ISO8601":
		return `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`
	case "SYSLOGTIMESTAMP":
		return `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?:0[1-9]|[12][0-9]|3[01]|[1-9])\s+(?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:[0-5][0-9])`
	case "PROG":
		return `[\w._/%-]+`
	case "SYSLOGPROG":
		return `[\w._/%-]+(?:\[\d+\])?`
	case "SYSLOGHOST":
		return `[a-zA-Z0-9._-]+`
	case "SYSLOGFACILITY":
		return `<\d+>`
	case "HTTPDATE":
		return `\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}`
	case "LOGLEVEL":
		return `(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|NOTICE|ALERT|EMERG(?:ENCY)?)`
	case "UUID":
		return `[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}`
	case "QUOTEDSTRING":
		return `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`
	default:
		return `\S+`
	}
}

// loadDefaultPatterns loads common grok patterns.
func (p *GrokParser) loadDefaultPatterns() {
	// Common log patterns
	patterns := map[string]string{
		// Apache/Nginx access log
		"COMBINEDAPACHELOG": `%{IPORHOST:client_ip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:http_method} %{NOTSPACE:request}(?: HTTP/%{NUMBER:http_version})?|%{DATA:raw_request})" %{NUMBER:response_code} (?:%{NUMBER:bytes}|-)`,

		// Syslog
		"SYSLOGBASE": `%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{SYSLOGPROG:program}:`,

		// Linux auth log
		"AUTHLOG": `%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{WORD:program}(?:\[%{INT:pid}\])?: %{GREEDYDATA:message}`,

		// SSH login
		"SSHLOGIN": `%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} sshd\[%{INT:pid}\]: %{WORD:action} %{WORD:auth_method} for %{USER:username} from %{IP:src_ip} port %{INT:src_port}`,

		// Windows Event Log (simple)
		"WINEVENTLOG": `%{TIMESTAMP_ISO8601:timestamp}\s+%{WORD:level}\s+%{WORD:source}\s+%{INT:event_id}\s+%{GREEDYDATA:message}`,

		// JSON Log
		"JSONLOG": `\{.*\}`,

		// Firewall log (generic)
		"FIREWALLLOG": `%{TIMESTAMP_ISO8601:timestamp}\s+%{WORD:action}\s+%{WORD:protocol}\s+%{IP:src_ip}:%{INT:src_port}\s*->\s*%{IP:dst_ip}:%{INT:dst_port}`,
	}

	for name, pattern := range patterns {
		if err := p.AddPattern(name, pattern); err != nil {
			// Log but don't fail
			continue
		}
	}
}

// grokCache is a simple LRU cache for grok results.
type grokCache struct {
	items    map[string]map[string]interface{}
	order    []string
	maxSize  int
	mu       sync.RWMutex
}

func newGrokCache(size int) *grokCache {
	return &grokCache{
		items:   make(map[string]map[string]interface{}),
		order:   make([]string, 0, size),
		maxSize: size,
	}
}

func (c *grokCache) get(key string) map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items[key]
}

func (c *grokCache) set(key string, value map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[key]; exists {
		return
	}

	c.items[key] = value
	c.order = append(c.order, key)

	// Evict oldest if over capacity
	if len(c.order) > c.maxSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}

// GrokPatternRegistry stores grok patterns.
type GrokPatternRegistry struct {
	patterns map[string]string
	mu       sync.RWMutex
}

// NewGrokPatternRegistry creates a new pattern registry.
func NewGrokPatternRegistry() *GrokPatternRegistry {
	return &GrokPatternRegistry{
		patterns: make(map[string]string),
	}
}

// Set adds or updates a pattern.
func (r *GrokPatternRegistry) Set(name, pattern string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.patterns[name] = pattern
}

// Get retrieves a pattern.
func (r *GrokPatternRegistry) Get(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.patterns[name]
	return p, ok
}

// Delete removes a pattern.
func (r *GrokPatternRegistry) Delete(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.patterns, name)
}

// List returns all pattern names.
func (r *GrokPatternRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.patterns))
	for name := range r.patterns {
		names = append(names, name)
	}
	return names
}

// List returns all grok pattern names.
func (p *GrokParser) List() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, 0, len(p.patterns))
	for name := range p.patterns {
		names = append(names, name)
	}
	return names
}

// Get returns a pattern by name.
func (p *GrokParser) Get(name string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if pattern, ok := p.patterns[name]; ok {
		return pattern.Pattern, true
	}
	return "", false
}

// LoadFromString loads patterns from a string (one per line, format: PATTERN_NAME pattern).
func (r *GrokPatternRegistry) LoadFromString(content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		r.Set(parts[0], parts[1])
	}
	return nil
}
