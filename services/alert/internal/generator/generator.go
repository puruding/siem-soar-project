// Package generator provides alert generation capabilities.
package generator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AlertSeverity represents alert severity levels.
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"
)

// AlertStatus represents alert status.
type AlertStatus string

const (
	StatusNew          AlertStatus = "new"
	StatusOpen         AlertStatus = "open"
	StatusAcknowledged AlertStatus = "acknowledged"
	StatusInProgress   AlertStatus = "in_progress"
	StatusResolved     AlertStatus = "resolved"
	StatusClosed       AlertStatus = "closed"
	StatusFalsePositive AlertStatus = "false_positive"
)

// AlertType represents the type of alert.
type AlertType string

const (
	AlertTypeDetection   AlertType = "detection"
	AlertTypeCorrelation AlertType = "correlation"
	AlertTypeThreatIntel AlertType = "threat_intel"
	AlertTypeAnomaly     AlertType = "anomaly"
	AlertTypeCompliance  AlertType = "compliance"
	AlertTypeCustom      AlertType = "custom"
)

// Alert represents a security alert.
type Alert struct {
	ID            string                 `json:"id"`
	ExternalID    string                 `json:"external_id,omitempty"`
	TenantID      string                 `json:"tenant_id"`
	Type          AlertType              `json:"type"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Severity      AlertSeverity          `json:"severity"`
	Status        AlertStatus            `json:"status"`
	Confidence    float64                `json:"confidence"`
	Priority      int                    `json:"priority"`

	// Source information
	RuleID        string                 `json:"rule_id,omitempty"`
	RuleName      string                 `json:"rule_name,omitempty"`
	SourceType    string                 `json:"source_type"`
	SourceID      string                 `json:"source_id,omitempty"`

	// Detection details
	DetectionTime time.Time              `json:"detection_time"`
	EventTime     time.Time              `json:"event_time,omitempty"`
	EventCount    int                    `json:"event_count"`
	Events        []map[string]interface{} `json:"events,omitempty"`

	// Entity information
	Entities      []Entity               `json:"entities,omitempty"`
	Assets        []Asset                `json:"assets,omitempty"`

	// Tactics and techniques
	MITREAttack   []MITREMapping         `json:"mitre_attack,omitempty"`
	KillChain     []string               `json:"kill_chain,omitempty"`

	// Context and enrichment
	Context       map[string]interface{} `json:"context,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Labels        map[string]string      `json:"labels,omitempty"`

	// Investigation
	Assignee      string                 `json:"assignee,omitempty"`
	Notes         []Note                 `json:"notes,omitempty"`

	// Deduplication
	DedupKey      string                 `json:"dedup_key"`
	Fingerprint   string                 `json:"fingerprint"`
	GroupID       string                 `json:"group_id,omitempty"`

	// Aggregation metadata - tracks which fields were used for grouping
	GroupByFields []string          `json:"group_by_fields,omitempty"`
	GroupByValues map[string]string `json:"group_by_values,omitempty"`

	// Timestamps
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	AcknowledgedAt *time.Time            `json:"acknowledged_at,omitempty"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
	TTL           time.Duration          `json:"ttl,omitempty"`
}

// Entity represents an entity involved in an alert.
type Entity struct {
	Type   string                 `json:"type"` // user, host, ip, domain, file, process
	Value  string                 `json:"value"`
	Role   string                 `json:"role,omitempty"` // source, target, actor
	Risk   float64                `json:"risk,omitempty"`
	Labels map[string]string      `json:"labels,omitempty"`
}

// Asset represents an asset involved in an alert.
type Asset struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Hostname string            `json:"hostname,omitempty"`
	IP       string            `json:"ip,omitempty"`
	OS       string            `json:"os,omitempty"`
	Owner    string            `json:"owner,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// MITREMapping represents a MITRE ATT&CK mapping.
type MITREMapping struct {
	TacticID   string `json:"tactic_id"`
	TacticName string `json:"tactic_name"`
	TechniqueID string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	SubtechniqueID string `json:"subtechnique_id,omitempty"`
	SubtechniqueName string `json:"subtechnique_name,omitempty"`
}

// Note represents an alert note.
type Note struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// GeneratorConfig holds generator configuration.
type GeneratorConfig struct {
	MaxEventsPerAlert   int           `json:"max_events_per_alert"`
	DefaultTTL          time.Duration `json:"default_ttl"`
	EnableDedup         bool          `json:"enable_dedup"`
	EnableEnrichment    bool          `json:"enable_enrichment"`
	BatchSize           int           `json:"batch_size"`
	FlushInterval       time.Duration `json:"flush_interval"`
	MaxConcurrent       int           `json:"max_concurrent"`
}

// DefaultGeneratorConfig returns default generator configuration.
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		MaxEventsPerAlert: 100,
		DefaultTTL:        7 * 24 * time.Hour,
		EnableDedup:       true,
		EnableEnrichment:  true,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		MaxConcurrent:     50,
	}
}

// AlertAggregationConfig is a local copy of rule.AlertAggregationConfig for decoupling.
// This avoids circular imports between generator and rule packages.
type AlertAggregationConfig struct {
	GroupBy      []string      `json:"group_by,omitempty"`
	Window       string        `json:"window,omitempty"`
	Action       string        `json:"action,omitempty"` // merge, group, drop
	MaxCount     int           `json:"max_count,omitempty"`
	ParsedWindow time.Duration `json:"-"`
}

// DetectionResult represents a detection result from the detection engine.
type DetectionResult struct {
	RuleID      string                   `json:"rule_id"`
	RuleName    string                   `json:"rule_name"`
	Severity    AlertSeverity            `json:"severity"`
	Confidence  float64                  `json:"confidence"`
	Events      []map[string]interface{} `json:"events"`
	Timestamp   time.Time                `json:"timestamp"`
	MITREAttack []MITREMapping           `json:"mitre_attack,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
	Context     map[string]interface{}   `json:"context,omitempty"`
	TenantID    string                   `json:"tenant_id"`

	// AlertAggregation contains the rule's aggregation configuration for dedup key generation.
	// This is populated by the detection engine from the rule's alert_aggregation section.
	AlertAggregation *AlertAggregationConfig `json:"alert_aggregation,omitempty"`
}

// Generator generates alerts from detection results.
type Generator struct {
	config     GeneratorConfig
	alertCh    chan *Alert
	resultCh   chan *DetectionResult
	logger     *slog.Logger

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// Callbacks
	onAlertGenerated func(*Alert)
	enricher         AlertEnricher

	// Metrics
	totalGenerated atomic.Uint64
	totalFailed    atomic.Uint64
}

// AlertEnricher enriches alerts with additional context.
type AlertEnricher interface {
	Enrich(ctx context.Context, alert *Alert) error
}

// NewGenerator creates a new alert generator.
func NewGenerator(cfg GeneratorConfig, logger *slog.Logger) *Generator {
	ctx, cancel := context.WithCancel(context.Background())

	return &Generator{
		config:   cfg,
		alertCh:  make(chan *Alert, 10000),
		resultCh: make(chan *DetectionResult, 10000),
		logger:   logger.With("component", "alert-generator"),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// SetEnricher sets the alert enricher.
func (g *Generator) SetEnricher(enricher AlertEnricher) {
	g.enricher = enricher
}

// SetOnAlertGenerated sets the callback for generated alerts.
func (g *Generator) SetOnAlertGenerated(fn func(*Alert)) {
	g.onAlertGenerated = fn
}

// Start starts the generator.
func (g *Generator) Start() error {
	// Start worker pool
	for i := 0; i < g.config.MaxConcurrent; i++ {
		g.wg.Add(1)
		go g.worker()
	}

	g.logger.Info("alert generator started", "workers", g.config.MaxConcurrent)
	return nil
}

// Stop stops the generator.
func (g *Generator) Stop() error {
	g.cancel()
	close(g.resultCh)
	g.wg.Wait()
	close(g.alertCh)
	g.logger.Info("alert generator stopped")
	return nil
}

// Submit submits a detection result for alert generation.
func (g *Generator) Submit(result *DetectionResult) {
	select {
	case g.resultCh <- result:
	default:
		g.logger.Warn("alert generator queue full, dropping result")
		g.totalFailed.Add(1)
	}
}

// Alerts returns the channel of generated alerts.
func (g *Generator) Alerts() <-chan *Alert {
	return g.alertCh
}

// Stats returns generator statistics.
func (g *Generator) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_generated": g.totalGenerated.Load(),
		"total_failed":    g.totalFailed.Load(),
		"queue_size":      len(g.resultCh),
	}
}

// worker processes detection results.
func (g *Generator) worker() {
	defer g.wg.Done()

	for {
		select {
		case <-g.ctx.Done():
			return
		case result, ok := <-g.resultCh:
			if !ok {
				return
			}
			g.processResult(result)
		}
	}
}

// processResult processes a detection result and generates an alert.
func (g *Generator) processResult(result *DetectionResult) {
	alert, err := g.generateAlert(result)
	if err != nil {
		g.logger.Error("failed to generate alert", "error", err)
		g.totalFailed.Add(1)
		return
	}

	// Enrich alert if enricher is set
	if g.config.EnableEnrichment && g.enricher != nil {
		if err := g.enricher.Enrich(g.ctx, alert); err != nil {
			g.logger.Warn("failed to enrich alert", "alert_id", alert.ID, "error", err)
		}
	}

	// Send to channel
	select {
	case g.alertCh <- alert:
		g.totalGenerated.Add(1)
	default:
		g.logger.Warn("alert channel full, dropping alert")
		g.totalFailed.Add(1)
	}

	// Call callback if set
	if g.onAlertGenerated != nil {
		g.onAlertGenerated(alert)
	}
}

// generateAlert generates an alert from a detection result.
func (g *Generator) generateAlert(result *DetectionResult) (*Alert, error) {
	now := time.Now()

	alert := &Alert{
		ID:            g.generateAlertID(),
		TenantID:      result.TenantID,
		Type:          AlertTypeDetection,
		Title:         result.RuleName,
		Description:   g.generateDescription(result),
		Severity:      result.Severity,
		Status:        StatusNew,
		Confidence:    result.Confidence,
		Priority:      g.calculatePriority(result.Severity, result.Confidence),
		RuleID:        result.RuleID,
		RuleName:      result.RuleName,
		SourceType:    "detection_engine",
		DetectionTime: result.Timestamp,
		EventCount:    len(result.Events),
		MITREAttack:   result.MITREAttack,
		Tags:          result.Tags,
		Context:       result.Context,
		CreatedAt:     now,
		UpdatedAt:     now,
		TTL:           g.config.DefaultTTL,
	}

	// Add events (limited)
	if len(result.Events) > 0 {
		limit := g.config.MaxEventsPerAlert
		if len(result.Events) < limit {
			limit = len(result.Events)
		}
		alert.Events = result.Events[:limit]

		// Extract event time from first event
		if ts, ok := result.Events[0]["timestamp"].(time.Time); ok {
			alert.EventTime = ts
		}
	}

	// Extract entities from events
	alert.Entities = g.extractEntities(result.Events)

	// Generate dedup key and fingerprint
	// If rule has alert aggregation config, use it for dynamic dedup key generation
	if result.AlertAggregation != nil && len(result.AlertAggregation.GroupBy) > 0 {
		alert.DedupKey, alert.GroupByFields, alert.GroupByValues = g.generateDedupKeyFromAggregation(alert, result)
	} else {
		alert.DedupKey = g.generateDefaultDedupKey(alert)
	}
	alert.Fingerprint = g.generateFingerprint(alert)

	return alert, nil
}

// generateAlertID generates a unique alert ID.
func (g *Generator) generateAlertID() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// generateDescription generates an alert description.
func (g *Generator) generateDescription(result *DetectionResult) string {
	desc := fmt.Sprintf("Alert triggered by rule '%s'", result.RuleName)

	if len(result.Events) > 0 {
		desc += fmt.Sprintf(" with %d events", len(result.Events))
	}

	if len(result.MITREAttack) > 0 {
		techniques := make([]string, len(result.MITREAttack))
		for i, m := range result.MITREAttack {
			techniques[i] = m.TechniqueID
		}
		desc += fmt.Sprintf(" (MITRE: %v)", techniques)
	}

	return desc
}

// calculatePriority calculates alert priority from severity and confidence.
func (g *Generator) calculatePriority(severity AlertSeverity, confidence float64) int {
	// Base priority from severity (1 = highest)
	basePriority := map[AlertSeverity]int{
		SeverityCritical: 1,
		SeverityHigh:     2,
		SeverityMedium:   3,
		SeverityLow:      4,
		SeverityInfo:     5,
	}

	priority := basePriority[severity]

	// Adjust based on confidence
	if confidence < 0.5 {
		priority++
	} else if confidence > 0.9 {
		priority--
	}

	// Clamp to valid range
	if priority < 1 {
		priority = 1
	}
	if priority > 5 {
		priority = 5
	}

	return priority
}

// extractEntities extracts entities from events.
func (g *Generator) extractEntities(events []map[string]interface{}) []Entity {
	entityMap := make(map[string]Entity)

	entityFields := map[string]string{
		"source_ip":      "ip",
		"dest_ip":        "ip",
		"src_ip":         "ip",
		"dst_ip":         "ip",
		"user":           "user",
		"username":       "user",
		"user_name":      "user",
		"hostname":       "host",
		"host":           "host",
		"computer_name":  "host",
		"domain":         "domain",
		"dns_query":      "domain",
		"file_name":      "file",
		"file_path":      "file",
		"process_name":   "process",
		"process":        "process",
		"email":          "email",
		"email_address":  "email",
	}

	roleMapping := map[string]string{
		"source_ip":  "source",
		"src_ip":     "source",
		"dest_ip":    "target",
		"dst_ip":     "target",
		"user":       "actor",
		"username":   "actor",
	}

	for _, event := range events {
		for field, entityType := range entityFields {
			if val, ok := event[field]; ok {
				valStr := fmt.Sprintf("%v", val)
				if valStr == "" {
					continue
				}

				key := fmt.Sprintf("%s:%s", entityType, valStr)
				if _, exists := entityMap[key]; !exists {
					entity := Entity{
						Type:  entityType,
						Value: valStr,
					}
					if role, ok := roleMapping[field]; ok {
						entity.Role = role
					}
					entityMap[key] = entity
				}
			}
		}
	}

	entities := make([]Entity, 0, len(entityMap))
	for _, entity := range entityMap {
		entities = append(entities, entity)
	}

	return entities
}

// generateDedupKey generates a deduplication key using the default logic.
// Deprecated: Use generateDefaultDedupKey or generateDedupKeyFromAggregation instead.
func (g *Generator) generateDedupKey(alert *Alert) string {
	return g.generateDefaultDedupKey(alert)
}

// generateDefaultDedupKey generates a deduplication key using default logic.
// It combines rule ID with primary entities (source, target, actor).
func (g *Generator) generateDefaultDedupKey(alert *Alert) string {
	// Combine rule ID and key entities for dedup
	key := alert.RuleID

	// Add primary entities
	for _, entity := range alert.Entities {
		if entity.Role == "source" || entity.Role == "target" || entity.Role == "actor" {
			key += ":" + entity.Type + ":" + entity.Value
		}
	}

	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// generateDedupKeyFromAggregation generates a deduplication key based on the rule's
// alert aggregation configuration. It extracts values from specified UDM field paths.
func (g *Generator) generateDedupKeyFromAggregation(alert *Alert, result *DetectionResult) (string, []string, map[string]string) {
	if result.AlertAggregation == nil || len(result.AlertAggregation.GroupBy) == 0 {
		return g.generateDefaultDedupKey(alert), nil, nil
	}

	parts := []string{alert.RuleID}
	groupByFields := result.AlertAggregation.GroupBy
	groupByValues := make(map[string]string)

	// Extract values for each group_by field from events
	for _, fieldPath := range groupByFields {
		value := g.extractFieldValueFromEvents(alert.Events, fieldPath)
		if value != "" {
			parts = append(parts, value)
			groupByValues[fieldPath] = value
		}
	}

	h := sha256.New()
	h.Write([]byte(strings.Join(parts, ":")))
	dedupKey := hex.EncodeToString(h.Sum(nil))[:16]

	return dedupKey, groupByFields, groupByValues
}

// extractFieldValueFromEvents extracts a field value from events using a UDM field path.
// It tries to find the value in the first event that has it.
//
// Examples:
//   - extractFieldValueFromEvents(events, "principal.ip") -> "192.168.1.1"
//   - extractFieldValueFromEvents(events, "target.hostname") -> "server01"
//   - extractFieldValueFromEvents(events, "principal.user.user_name") -> "john"
func (g *Generator) extractFieldValueFromEvents(events []map[string]interface{}, fieldPath string) string {
	if len(events) == 0 {
		return ""
	}

	// Try each event until we find a value
	for _, event := range events {
		value := g.extractFieldFromMap(event, fieldPath)
		if value != "" {
			return value
		}
	}

	return ""
}

// extractFieldFromMap extracts a field value from a nested map using dot notation.
// Handles both dot notation (e.g., "principal.ip") and snake_case field names.
func (g *Generator) extractFieldFromMap(data map[string]interface{}, fieldPath string) string {
	parts := strings.Split(fieldPath, ".")
	current := data

	for i, part := range parts {
		// Handle array index notation (e.g., "ip[0]")
		arrayIndex := -1
		if idx := strings.Index(part, "["); idx > 0 {
			if endIdx := strings.Index(part, "]"); endIdx > idx {
				if n, err := strconv.Atoi(part[idx+1 : endIdx]); err == nil {
					arrayIndex = n
				}
				part = part[:idx]
			}
		}

		// Try to get the value
		val, ok := current[part]
		if !ok {
			// Try alternative field names (snake_case <-> camelCase)
			alternativeKey := g.findAlternativeKey(current, part)
			if alternativeKey == "" {
				return ""
			}
			val = current[alternativeKey]
		}

		// Handle the last part
		if i == len(parts)-1 {
			return g.valueToString(val, arrayIndex)
		}

		// Navigate deeper
		switch v := val.(type) {
		case map[string]interface{}:
			current = v
		case []interface{}:
			if arrayIndex >= 0 && arrayIndex < len(v) {
				if m, ok := v[arrayIndex].(map[string]interface{}); ok {
					current = m
				} else {
					return ""
				}
			} else if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					current = m
				} else {
					return ""
				}
			} else {
				return ""
			}
		default:
			return ""
		}
	}

	return ""
}

// findAlternativeKey tries to find an alternative key in the map that matches the given key.
// It handles snake_case to camelCase conversions and vice versa.
func (g *Generator) findAlternativeKey(data map[string]interface{}, key string) string {
	// Direct match
	if _, ok := data[key]; ok {
		return key
	}

	// Try camelCase
	camelKey := g.snakeToCamel(key)
	if _, ok := data[camelKey]; ok {
		return camelKey
	}

	// Try snake_case
	snakeKey := g.camelToSnake(key)
	if _, ok := data[snakeKey]; ok {
		return snakeKey
	}

	return ""
}

// valueToString converts a value to string, handling slices with optional index.
func (g *Generator) valueToString(val interface{}, arrayIndex int) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		if arrayIndex >= 0 && arrayIndex < len(v) {
			return fmt.Sprintf("%v", v[arrayIndex])
		}
		if len(v) > 0 {
			return fmt.Sprintf("%v", v[0])
		}
		return ""
	case []string:
		if arrayIndex >= 0 && arrayIndex < len(v) {
			return v[arrayIndex]
		}
		if len(v) > 0 {
			return v[0]
		}
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// snakeToCamel converts snake_case to camelCase.
func (g *Generator) snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// camelToSnake converts camelCase to snake_case.
func (g *Generator) camelToSnake(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// generateFingerprint generates an alert fingerprint for exact matching.
func (g *Generator) generateFingerprint(alert *Alert) string {
	// Include more details for exact matching
	key := fmt.Sprintf("%s:%s:%s:%d",
		alert.RuleID,
		alert.TenantID,
		alert.DedupKey,
		alert.EventCount)

	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// GenerateFromThreatIntel generates an alert from threat intelligence match.
func (g *Generator) GenerateFromThreatIntel(tenantID, iocType, iocValue, matchType string, confidence float64, events []map[string]interface{}, context map[string]interface{}) *Alert {
	now := time.Now()

	alert := &Alert{
		ID:            g.generateAlertID(),
		TenantID:      tenantID,
		Type:          AlertTypeThreatIntel,
		Title:         fmt.Sprintf("Threat Intel Match: %s", iocValue),
		Description:   fmt.Sprintf("Matched %s IOC (%s) with %s match type", iocType, iocValue, matchType),
		Severity:      g.severityFromConfidence(confidence),
		Status:        StatusNew,
		Confidence:    confidence,
		Priority:      g.calculatePriority(g.severityFromConfidence(confidence), confidence),
		SourceType:    "threat_intel",
		DetectionTime: now,
		EventCount:    len(events),
		Events:        events,
		Tags:          []string{"threat_intel", iocType},
		Context:       context,
		CreatedAt:     now,
		UpdatedAt:     now,
		TTL:           g.config.DefaultTTL,
	}

	// Add IOC as entity
	alert.Entities = []Entity{
		{
			Type:  iocType,
			Value: iocValue,
			Role:  "indicator",
		},
	}

	alert.DedupKey = g.generateDedupKey(alert)
	alert.Fingerprint = g.generateFingerprint(alert)

	return alert
}

// severityFromConfidence maps confidence to severity.
func (g *Generator) severityFromConfidence(confidence float64) AlertSeverity {
	switch {
	case confidence >= 0.9:
		return SeverityCritical
	case confidence >= 0.7:
		return SeverityHigh
	case confidence >= 0.5:
		return SeverityMedium
	case confidence >= 0.3:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
