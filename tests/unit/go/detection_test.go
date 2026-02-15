package unit_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Detection Engine Unit Tests
// =============================================================================

// SigmaRule represents a Sigma detection rule
type SigmaRule struct {
	ID          string                 `json:"id" yaml:"id"`
	Title       string                 `json:"title" yaml:"title"`
	Status      string                 `json:"status" yaml:"status"`
	Level       string                 `json:"level" yaml:"level"`
	Description string                 `json:"description" yaml:"description"`
	Author      string                 `json:"author" yaml:"author"`
	References  []string               `json:"references" yaml:"references"`
	Tags        []string               `json:"tags" yaml:"tags"`
	LogSource   LogSource              `json:"logsource" yaml:"logsource"`
	Detection   map[string]interface{} `json:"detection" yaml:"detection"`
}

type LogSource struct {
	Category string `json:"category" yaml:"category"`
	Product  string `json:"product" yaml:"product"`
	Service  string `json:"service" yaml:"service"`
}

// Event represents a security event
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	SourcePort  int                    `json:"source_port"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"protocol"`
	EventType   string                 `json:"event_type"`
	Category    string                 `json:"category"`
	Product     string                 `json:"product"`
	Service     string                 `json:"service"`
	CommandLine string                 `json:"command_line"`
	ProcessName string                 `json:"process_name"`
	User        string                 `json:"user"`
	Fields      map[string]interface{} `json:"fields"`
}

// SigmaEngine processes Sigma rules
type SigmaEngine struct {
	mu    sync.RWMutex
	rules []SigmaRule
}

func NewSigmaEngine() *SigmaEngine {
	return &SigmaEngine{
		rules: make([]SigmaRule, 0),
	}
}

func (e *SigmaEngine) LoadRules(rules []SigmaRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rules...)
}

func (e *SigmaEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func (e *SigmaEngine) matchLogSource(rule *SigmaRule, event *Event) bool {
	if rule.LogSource.Category != "" && rule.LogSource.Category != event.Category {
		return false
	}
	if rule.LogSource.Product != "" && rule.LogSource.Product != event.Product {
		return false
	}
	if rule.LogSource.Service != "" && rule.LogSource.Service != event.Service {
		return false
	}
	return true
}

func (e *SigmaEngine) matchCondition(condition interface{}, event *Event) bool {
	switch v := condition.(type) {
	case string:
		// Simple string match in command line or process name
		if strings.Contains(strings.ToLower(event.CommandLine), strings.ToLower(v)) {
			return true
		}
		if strings.Contains(strings.ToLower(event.ProcessName), strings.ToLower(v)) {
			return true
		}
	case []interface{}:
		// Any match in list
		for _, item := range v {
			if e.matchCondition(item, event) {
				return true
			}
		}
	case map[string]interface{}:
		// Field-specific matches
		for field, value := range v {
			eventValue := e.getEventField(event, field)
			if eventValue != "" && e.matchValue(eventValue, value) {
				return true
			}
		}
	}
	return false
}

func (e *SigmaEngine) getEventField(event *Event, field string) string {
	switch strings.ToLower(field) {
	case "commandline", "command_line":
		return event.CommandLine
	case "processname", "process_name", "image":
		return event.ProcessName
	case "user":
		return event.User
	case "source_ip", "sourceip":
		return event.SourceIP
	case "dest_ip", "destip", "destination_ip":
		return event.DestIP
	default:
		if v, ok := event.Fields[field]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func (e *SigmaEngine) matchValue(eventValue string, ruleValue interface{}) bool {
	switch v := ruleValue.(type) {
	case string:
		// Handle wildcards
		if strings.Contains(v, "*") {
			pattern := strings.ReplaceAll(v, "*", ".*")
			matched, _ := regexp.MatchString("(?i)"+pattern, eventValue)
			return matched
		}
		return strings.EqualFold(eventValue, v)
	case []interface{}:
		for _, item := range v {
			if e.matchValue(eventValue, item) {
				return true
			}
		}
	}
	return false
}

func (e *SigmaEngine) Match(event *Event) []SigmaRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []SigmaRule
	for _, rule := range e.rules {
		if !e.matchLogSource(&rule, event) {
			continue
		}

		// Check detection conditions
		if selection, ok := rule.Detection["selection"]; ok {
			if e.matchCondition(selection, event) {
				matches = append(matches, rule)
			}
		}
	}
	return matches
}

func TestSigmaEngine_LoadRules(t *testing.T) {
	engine := NewSigmaEngine()

	rules := []SigmaRule{
		{
			ID:    "rule-1",
			Title: "Test Rule 1",
		},
		{
			ID:    "rule-2",
			Title: "Test Rule 2",
		},
	}

	engine.LoadRules(rules)
	assert.Equal(t, 2, engine.RuleCount())
}

func TestSigmaEngine_Match_ProcessCreation(t *testing.T) {
	engine := NewSigmaEngine()

	rule := SigmaRule{
		ID:    "mimikatz-detection",
		Title: "Mimikatz Process",
		Level: "high",
		LogSource: LogSource{
			Category: "process_creation",
			Product:  "windows",
		},
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{
				"CommandLine": []interface{}{
					"*mimikatz*",
					"*sekurlsa*",
					"*lsadump*",
				},
			},
			"condition": "selection",
		},
	}
	engine.LoadRules([]SigmaRule{rule})

	tests := []struct {
		name        string
		event       Event
		expectMatch bool
	}{
		{
			name: "mimikatz detected",
			event: Event{
				Category:    "process_creation",
				Product:     "windows",
				CommandLine: "mimikatz.exe sekurlsa::logonpasswords",
				ProcessName: "mimikatz.exe",
			},
			expectMatch: true,
		},
		{
			name: "sekurlsa detected",
			event: Event{
				Category:    "process_creation",
				Product:     "windows",
				CommandLine: "powershell.exe -c sekurlsa::minidump",
			},
			expectMatch: true,
		},
		{
			name: "normal process",
			event: Event{
				Category:    "process_creation",
				Product:     "windows",
				CommandLine: "notepad.exe document.txt",
				ProcessName: "notepad.exe",
			},
			expectMatch: false,
		},
		{
			name: "wrong log source",
			event: Event{
				Category:    "network_connection",
				Product:     "windows",
				CommandLine: "mimikatz.exe",
			},
			expectMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := engine.Match(&tc.event)
			if tc.expectMatch {
				assert.Len(t, matches, 1)
				assert.Equal(t, "mimikatz-detection", matches[0].ID)
			} else {
				assert.Empty(t, matches)
			}
		})
	}
}

// CorrelationRule represents a correlation rule
type CorrelationRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Type        string        `json:"type"` // threshold, sequence, aggregation
	TimeWindow  time.Duration `json:"time_window"`
	Threshold   int           `json:"threshold"`
	GroupBy     []string      `json:"group_by"`
	Conditions  []Condition   `json:"conditions"`
}

type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// CorrelationEngine processes correlation rules
type CorrelationEngine struct {
	mu     sync.RWMutex
	rules  []CorrelationRule
	events map[string][]Event // grouped events by rule ID
}

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		rules:  make([]CorrelationRule, 0),
		events: make(map[string][]Event),
	}
}

func (e *CorrelationEngine) AddRule(rule CorrelationRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	e.events[rule.ID] = make([]Event, 0)
}

func (e *CorrelationEngine) ProcessEvent(event Event) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	var triggeredRules []string

	for _, rule := range e.rules {
		if !e.matchConditions(&rule, &event) {
			continue
		}

		// Add event to tracking
		e.events[rule.ID] = append(e.events[rule.ID], event)

		// Clean old events
		e.cleanOldEvents(rule.ID, rule.TimeWindow)

		// Check threshold
		if rule.Type == "threshold" {
			if len(e.events[rule.ID]) >= rule.Threshold {
				triggeredRules = append(triggeredRules, rule.ID)
				// Reset after trigger
				e.events[rule.ID] = make([]Event, 0)
			}
		}
	}

	return triggeredRules
}

func (e *CorrelationEngine) matchConditions(rule *CorrelationRule, event *Event) bool {
	for _, cond := range rule.Conditions {
		value := e.getFieldValue(event, cond.Field)
		if !e.evalCondition(value, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

func (e *CorrelationEngine) getFieldValue(event *Event, field string) interface{} {
	switch field {
	case "source_ip":
		return event.SourceIP
	case "dest_ip":
		return event.DestIP
	case "dest_port":
		return event.DestPort
	case "event_type":
		return event.EventType
	default:
		if v, ok := event.Fields[field]; ok {
			return v
		}
	}
	return nil
}

func (e *CorrelationEngine) evalCondition(fieldValue interface{}, operator string, ruleValue interface{}) bool {
	switch operator {
	case "eq", "==":
		return fieldValue == ruleValue
	case "ne", "!=":
		return fieldValue != ruleValue
	case "in":
		if list, ok := ruleValue.([]interface{}); ok {
			for _, v := range list {
				if fieldValue == v {
					return true
				}
			}
		}
	case "contains":
		if s, ok := fieldValue.(string); ok {
			if pattern, ok := ruleValue.(string); ok {
				return strings.Contains(s, pattern)
			}
		}
	}
	return false
}

func (e *CorrelationEngine) cleanOldEvents(ruleID string, window time.Duration) {
	cutoff := time.Now().Add(-window)
	var validEvents []Event
	for _, ev := range e.events[ruleID] {
		if ev.Timestamp.After(cutoff) {
			validEvents = append(validEvents, ev)
		}
	}
	e.events[ruleID] = validEvents
}

func TestCorrelationEngine_ThresholdRule(t *testing.T) {
	engine := NewCorrelationEngine()

	rule := CorrelationRule{
		ID:         "brute-force",
		Name:       "Brute Force Detection",
		Type:       "threshold",
		TimeWindow: 5 * time.Minute,
		Threshold:  5,
		Conditions: []Condition{
			{Field: "event_type", Operator: "eq", Value: "auth_failure"},
		},
	}
	engine.AddRule(rule)

	// Send 4 events - should not trigger
	for i := 0; i < 4; i++ {
		triggered := engine.ProcessEvent(Event{
			Timestamp: time.Now(),
			SourceIP:  "192.168.1.100",
			EventType: "auth_failure",
		})
		assert.Empty(t, triggered)
	}

	// 5th event should trigger
	triggered := engine.ProcessEvent(Event{
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.100",
		EventType: "auth_failure",
	})
	assert.Contains(t, triggered, "brute-force")
}

func TestCorrelationEngine_ConditionMatching(t *testing.T) {
	engine := NewCorrelationEngine()

	rule := CorrelationRule{
		ID:         "ssh-scan",
		Name:       "SSH Port Scan",
		Type:       "threshold",
		TimeWindow: time.Minute,
		Threshold:  3,
		Conditions: []Condition{
			{Field: "dest_port", Operator: "eq", Value: 22},
			{Field: "event_type", Operator: "eq", Value: "connection"},
		},
	}
	engine.AddRule(rule)

	// Non-matching event
	triggered := engine.ProcessEvent(Event{
		Timestamp: time.Now(),
		DestPort:  80,
		EventType: "connection",
	})
	assert.Empty(t, triggered)

	// Matching events
	for i := 0; i < 3; i++ {
		triggered = engine.ProcessEvent(Event{
			Timestamp: time.Now(),
			DestPort:  22,
			EventType: "connection",
		})
	}
	assert.Contains(t, triggered, "ssh-scan")
}

// ThreatIntelMatcher matches events against threat intelligence
type ThreatIntelMatcher struct {
	mu       sync.RWMutex
	ips      map[string]ThreatInfo
	domains  map[string]ThreatInfo
	hashes   map[string]ThreatInfo
}

type ThreatInfo struct {
	Indicator   string    `json:"indicator"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
}

func NewThreatIntelMatcher() *ThreatIntelMatcher {
	return &ThreatIntelMatcher{
		ips:     make(map[string]ThreatInfo),
		domains: make(map[string]ThreatInfo),
		hashes:  make(map[string]ThreatInfo),
	}
}

func (m *ThreatIntelMatcher) AddIndicator(indicator ThreatInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch indicator.Type {
	case "ip":
		m.ips[indicator.Indicator] = indicator
	case "domain":
		m.domains[indicator.Indicator] = indicator
	case "hash":
		m.hashes[indicator.Indicator] = indicator
	}
}

func (m *ThreatIntelMatcher) MatchIP(ip string) *ThreatInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if info, ok := m.ips[ip]; ok {
		return &info
	}
	return nil
}

func (m *ThreatIntelMatcher) MatchDomain(domain string) *ThreatInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if info, ok := m.domains[domain]; ok {
		return &info
	}
	return nil
}

func (m *ThreatIntelMatcher) MatchHash(hash string) *ThreatInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if info, ok := m.hashes[hash]; ok {
		return &info
	}
	return nil
}

func (m *ThreatIntelMatcher) Count() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]int{
		"ips":     len(m.ips),
		"domains": len(m.domains),
		"hashes":  len(m.hashes),
	}
}

func TestThreatIntelMatcher(t *testing.T) {
	matcher := NewThreatIntelMatcher()

	// Add indicators
	matcher.AddIndicator(ThreatInfo{
		Indicator:   "192.168.1.100",
		Type:        "ip",
		Severity:    "high",
		Source:      "abuse.ch",
		Description: "Known C2 server",
		Tags:        []string{"c2", "apt"},
	})

	matcher.AddIndicator(ThreatInfo{
		Indicator:   "malware.example.com",
		Type:        "domain",
		Severity:    "critical",
		Source:      "misp",
		Description: "Malware distribution domain",
	})

	matcher.AddIndicator(ThreatInfo{
		Indicator:   "abc123def456",
		Type:        "hash",
		Severity:    "medium",
		Source:      "virustotal",
		Description: "Trojan",
	})

	t.Run("match IP", func(t *testing.T) {
		info := matcher.MatchIP("192.168.1.100")
		require.NotNil(t, info)
		assert.Equal(t, "high", info.Severity)
		assert.Contains(t, info.Tags, "c2")
	})

	t.Run("no match IP", func(t *testing.T) {
		info := matcher.MatchIP("10.0.0.1")
		assert.Nil(t, info)
	})

	t.Run("match domain", func(t *testing.T) {
		info := matcher.MatchDomain("malware.example.com")
		require.NotNil(t, info)
		assert.Equal(t, "critical", info.Severity)
	})

	t.Run("match hash", func(t *testing.T) {
		info := matcher.MatchHash("abc123def456")
		require.NotNil(t, info)
		assert.Equal(t, "virustotal", info.Source)
	})

	t.Run("count", func(t *testing.T) {
		count := matcher.Count()
		assert.Equal(t, 1, count["ips"])
		assert.Equal(t, 1, count["domains"])
		assert.Equal(t, 1, count["hashes"])
	})
}

// Alert represents a detection alert
type Alert struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Status      string                 `json:"status"`
	Assignee    string                 `json:"assignee"`
	Tags        []string               `json:"tags"`
}

// AlertService manages alerts
type AlertService struct {
	mu     sync.RWMutex
	alerts map[string]*Alert
}

func NewAlertService() *AlertService {
	return &AlertService{
		alerts: make(map[string]*Alert),
	}
}

func (s *AlertService) CreateAlert(alert *Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.ID == "" {
		return fmt.Errorf("alert ID is required")
	}

	if _, exists := s.alerts[alert.ID]; exists {
		return fmt.Errorf("alert with ID %s already exists", alert.ID)
	}

	if alert.Status == "" {
		alert.Status = "open"
	}

	s.alerts[alert.ID] = alert
	return nil
}

func (s *AlertService) GetAlert(id string) (*Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if alert, ok := s.alerts[id]; ok {
		return alert, nil
	}
	return nil, fmt.Errorf("alert not found: %s", id)
}

func (s *AlertService) UpdateStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}

	validStatuses := map[string]bool{
		"open":        true,
		"in_progress": true,
		"resolved":    true,
		"closed":      true,
		"false_positive": true,
	}

	if !validStatuses[status] {
		return fmt.Errorf("invalid status: %s", status)
	}

	alert.Status = status
	return nil
}

func (s *AlertService) AssignAlert(id, assignee string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}

	alert.Assignee = assignee
	return nil
}

func (s *AlertService) ListAlerts(filter map[string]string) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Alert
	for _, alert := range s.alerts {
		if s.matchFilter(alert, filter) {
			result = append(result, alert)
		}
	}
	return result
}

func (s *AlertService) matchFilter(alert *Alert, filter map[string]string) bool {
	for key, value := range filter {
		switch key {
		case "status":
			if alert.Status != value {
				return false
			}
		case "severity":
			if alert.Severity != value {
				return false
			}
		case "assignee":
			if alert.Assignee != value {
				return false
			}
		}
	}
	return true
}

func TestAlertService(t *testing.T) {
	svc := NewAlertService()

	t.Run("create alert", func(t *testing.T) {
		alert := &Alert{
			ID:        "alert-001",
			RuleID:    "rule-001",
			RuleName:  "Test Rule",
			Severity:  "high",
			Timestamp: time.Now(),
			SourceIP:  "192.168.1.100",
		}

		err := svc.CreateAlert(alert)
		assert.NoError(t, err)

		retrieved, err := svc.GetAlert("alert-001")
		assert.NoError(t, err)
		assert.Equal(t, "open", retrieved.Status)
	})

	t.Run("duplicate alert", func(t *testing.T) {
		alert := &Alert{
			ID:       "alert-001",
			RuleID:   "rule-002",
			Severity: "low",
		}

		err := svc.CreateAlert(alert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("update status", func(t *testing.T) {
		err := svc.UpdateStatus("alert-001", "in_progress")
		assert.NoError(t, err)

		alert, _ := svc.GetAlert("alert-001")
		assert.Equal(t, "in_progress", alert.Status)
	})

	t.Run("invalid status", func(t *testing.T) {
		err := svc.UpdateStatus("alert-001", "invalid")
		assert.Error(t, err)
	})

	t.Run("assign alert", func(t *testing.T) {
		err := svc.AssignAlert("alert-001", "analyst@example.com")
		assert.NoError(t, err)

		alert, _ := svc.GetAlert("alert-001")
		assert.Equal(t, "analyst@example.com", alert.Assignee)
	})

	t.Run("list with filter", func(t *testing.T) {
		// Add another alert
		svc.CreateAlert(&Alert{
			ID:       "alert-002",
			Severity: "low",
			Status:   "open",
		})

		alerts := svc.ListAlerts(map[string]string{"status": "open"})
		assert.Len(t, alerts, 1)
		assert.Equal(t, "alert-002", alerts[0].ID)
	})
}

// RuleValidator validates detection rules
type RuleValidator struct{}

func (v *RuleValidator) ValidateSigmaRule(rule *SigmaRule) []string {
	var errors []string

	if rule.ID == "" {
		errors = append(errors, "rule ID is required")
	}

	if rule.Title == "" {
		errors = append(errors, "rule title is required")
	}

	validLevels := map[string]bool{
		"informational": true,
		"low":           true,
		"medium":        true,
		"high":          true,
		"critical":      true,
	}

	if rule.Level != "" && !validLevels[rule.Level] {
		errors = append(errors, "invalid rule level: "+rule.Level)
	}

	if rule.Detection == nil || len(rule.Detection) == 0 {
		errors = append(errors, "detection section is required")
	}

	if _, ok := rule.Detection["condition"]; !ok {
		errors = append(errors, "detection condition is required")
	}

	return errors
}

func TestRuleValidator(t *testing.T) {
	validator := &RuleValidator{}

	t.Run("valid rule", func(t *testing.T) {
		rule := &SigmaRule{
			ID:    "test-rule",
			Title: "Test Rule",
			Level: "high",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{
					"CommandLine": "*test*",
				},
				"condition": "selection",
			},
		}

		errors := validator.ValidateSigmaRule(rule)
		assert.Empty(t, errors)
	})

	t.Run("missing ID", func(t *testing.T) {
		rule := &SigmaRule{
			Title: "Test Rule",
			Level: "high",
			Detection: map[string]interface{}{
				"condition": "selection",
			},
		}

		errors := validator.ValidateSigmaRule(rule)
		assert.Contains(t, errors, "rule ID is required")
	})

	t.Run("invalid level", func(t *testing.T) {
		rule := &SigmaRule{
			ID:    "test",
			Title: "Test",
			Level: "invalid",
			Detection: map[string]interface{}{
				"condition": "selection",
			},
		}

		errors := validator.ValidateSigmaRule(rule)
		assert.Contains(t, errors, "invalid rule level: invalid")
	})

	t.Run("missing detection", func(t *testing.T) {
		rule := &SigmaRule{
			ID:    "test",
			Title: "Test",
		}

		errors := validator.ValidateSigmaRule(rule)
		assert.Contains(t, errors, "detection section is required")
	})
}

// Benchmark tests
func BenchmarkSigmaEngine_Match(b *testing.B) {
	engine := NewSigmaEngine()

	// Load 100 rules
	for i := 0; i < 100; i++ {
		engine.LoadRules([]SigmaRule{
			{
				ID:    fmt.Sprintf("rule-%d", i),
				Title: fmt.Sprintf("Rule %d", i),
				LogSource: LogSource{
					Category: "process_creation",
					Product:  "windows",
				},
				Detection: map[string]interface{}{
					"selection": map[string]interface{}{
						"CommandLine": fmt.Sprintf("*pattern%d*", i),
					},
					"condition": "selection",
				},
			},
		})
	}

	event := &Event{
		Category:    "process_creation",
		Product:     "windows",
		CommandLine: "cmd.exe /c pattern50",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Match(event)
	}
}

func BenchmarkThreatIntelMatcher_MatchIP(b *testing.B) {
	matcher := NewThreatIntelMatcher()

	// Load 10000 IPs
	for i := 0; i < 10000; i++ {
		matcher.AddIndicator(ThreatInfo{
			Indicator: fmt.Sprintf("192.168.%d.%d", i/256, i%256),
			Type:      "ip",
			Severity:  "high",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.MatchIP("192.168.50.100")
	}
}
