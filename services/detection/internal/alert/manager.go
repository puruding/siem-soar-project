// Package alert provides alert management functionality.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/detection/internal/engine"
	"github.com/siem-soar-platform/services/detection/internal/mitre"
)

// Severity levels for alerts.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AlertStatus represents the status of an alert.
type AlertStatus string

const (
	StatusNew        AlertStatus = "new"
	StatusOpen       AlertStatus = "open"
	StatusInProgress AlertStatus = "in_progress"
	StatusResolved   AlertStatus = "resolved"
	StatusClosed     AlertStatus = "closed"
	StatusFalsePos   AlertStatus = "false_positive"
)

// Alert represents a security alert.
type Alert struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	RuleID        string                 `json:"rule_id"`
	RuleName      string                 `json:"rule_name"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Severity      Severity               `json:"severity"`
	Confidence    float64                `json:"confidence"`
	Status        AlertStatus            `json:"status"`
	Events        []*engine.Event        `json:"events"`
	MatchedFields map[string]interface{} `json:"matched_fields,omitempty"`
	ATTACKMapping *mitre.ATTACKMapping   `json:"attack_mapping,omitempty"`
	MLAnalysis    *MLAnalysis            `json:"ml_analysis,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Assignee      string                 `json:"assignee,omitempty"`
	Source        AlertSource            `json:"source"`
	TraceID       string                 `json:"trace_id,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
	TTL           time.Duration          `json:"ttl,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// MLAnalysis represents the ML Gateway analysis result.
// This is embedded in Alert for Kafka message enrichment.
type MLAnalysis struct {
	Classification     *Classification `json:"classification,omitempty"`
	RiskScore          float64         `json:"risk_score"`
	Priority           string          `json:"priority"` // critical, high, medium, low
	IsFalsePositive    bool            `json:"is_false_positive"`
	FPConfidence       float64         `json:"fp_confidence"`
	MITRETactics       []string        `json:"mitre_tactics,omitempty"`
	MITRETechniques    []string        `json:"mitre_techniques,omitempty"`
	RecommendedActions []string        `json:"recommended_actions,omitempty"`
	ProcessedAt        time.Time       `json:"processed_at"`
	TraceID            string          `json:"trace_id,omitempty"`
	ModelID            string          `json:"model_id,omitempty"`
	ModelVersion       string          `json:"model_version,omitempty"`
	CacheHit           bool            `json:"cache_hit"`
}

// Classification represents ML classification result.
type Classification struct {
	Category           string  `json:"category"`
	Severity           string  `json:"severity"`
	CategoryConfidence float64 `json:"category_confidence"`
	SeverityConfidence float64 `json:"severity_confidence"`
}

// AlertSource represents the source of an alert.
type AlertSource struct {
	Type     string   `json:"type"` // sigma, correlation, threshold, ml
	Engine   string   `json:"engine"`
	Hostname string   `json:"hostname,omitempty"`
	IPs      []string `json:"ips,omitempty"`
	Users    []string `json:"users,omitempty"`
}

// ManagerConfig holds alert manager configuration.
type ManagerConfig struct {
	// Deduplication
	DeduplicationEnabled  bool          `json:"deduplication_enabled"`
	DeduplicationWindow   time.Duration `json:"deduplication_window"`
	DeduplicationKey      []string      `json:"deduplication_key"` // Fields to use for dedup

	// Aggregation
	AggregationEnabled   bool          `json:"aggregation_enabled"`
	AggregationWindow    time.Duration `json:"aggregation_window"`
	MaxEventsPerAlert    int           `json:"max_events_per_alert"`

	// Alert settings
	DefaultTTL           time.Duration `json:"default_ttl"`
	MaxConcurrentAlerts  int           `json:"max_concurrent_alerts"`

	// Kafka producer settings
	KafkaBrokers         []string      `json:"kafka_brokers"`
	KafkaTopic           string        `json:"kafka_topic"`
	KafkaEnabled         bool          `json:"kafka_enabled"`
}

// DefaultManagerConfig returns default configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		DeduplicationEnabled: true,
		DeduplicationWindow:  5 * time.Minute,
		DeduplicationKey:     []string{"rule_id", "source.ip", "user.name"},
		AggregationEnabled:   true,
		AggregationWindow:    5 * time.Minute,
		MaxEventsPerAlert:    100,
		DefaultTTL:           24 * time.Hour,
		MaxConcurrentAlerts:  10000,
		KafkaTopic:           "alerts",
		KafkaEnabled:         false,
	}
}

// MLClient defines the interface for ML Gateway client.
type MLClient interface {
	TriageAlert(ctx context.Context, alertReq *MLAlertRequest) (*MLAnalysisResult, error)
	IsAvailable() bool
}

// MLAlertRequest is the request format for ML Gateway.
type MLAlertRequest struct {
	AlertID       string                 `json:"alert_id"`
	AlertType     string                 `json:"alert_type"`
	Severity      string                 `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	RuleID        string                 `json:"rule_id"`
	RuleName      string                 `json:"rule_name"`
	Events        []map[string]any       `json:"events"`
	MatchedFields map[string]interface{} `json:"matched_fields,omitempty"`
	TraceID       string                 `json:"trace_id"`
}

// MLAnalysisResult is the result from ML Gateway.
type MLAnalysisResult = MLAnalysis

// Manager manages alert creation and lifecycle.
type Manager struct {
	config      ManagerConfig
	mitreMapper *mitre.Mapper
	dedup       *DedupCache
	producer    AlertProducer
	mlClient    MLClient
	logger      *slog.Logger

	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	// Metrics
	alertsCreated    atomic.Uint64
	alertsDeduped    atomic.Uint64
	alertsPublished  atomic.Uint64
	alertsMLEnriched atomic.Uint64
	errors           atomic.Uint64
}

// AlertProducer defines the interface for publishing alerts.
type AlertProducer interface {
	Publish(ctx context.Context, alert *Alert) error
	Close() error
}

// NewManager creates a new alert manager.
func NewManager(cfg ManagerConfig, producer AlertProducer, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:      cfg,
		mitreMapper: mitre.NewMapper(),
		producer:    producer,
		logger:      logger.With("component", "alert-manager"),
		ctx:         ctx,
		cancel:      cancel,
	}

	if cfg.DeduplicationEnabled {
		m.dedup = NewDedupCache(cfg.DeduplicationWindow)
	}

	return m
}

// SetMLClient sets the ML Gateway client for alert enrichment.
func (m *Manager) SetMLClient(client MLClient) {
	m.mlClient = client
}

// Start starts the alert manager.
func (m *Manager) Start() error {
	m.logger.Info("starting alert manager")

	if m.dedup != nil {
		m.wg.Add(1)
		go m.dedupCleanupLoop()
	}

	return nil
}

// Stop stops the alert manager.
func (m *Manager) Stop() error {
	m.logger.Info("stopping alert manager")
	m.cancel()
	m.wg.Wait()

	if m.producer != nil {
		if err := m.producer.Close(); err != nil {
			m.logger.Error("failed to close producer", "error", err)
		}
	}

	return nil
}

// CreateAlert creates a new alert from a detection result.
func (m *Manager) CreateAlert(ctx context.Context, result *engine.DetectionResult, events []*engine.Event) (*Alert, error) {
	// Build deduplication key
	if m.config.DeduplicationEnabled && m.dedup != nil {
		dedupKey := m.buildDedupKey(result, events)
		if m.dedup.IsDuplicate(dedupKey) {
			m.alertsDeduped.Add(1)
			m.logger.Debug("alert deduplicated", "rule_id", result.RuleID)
			return nil, nil
		}
		m.dedup.Add(dedupKey)
	}

	// Create alert
	alert := &Alert{
		ID:            uuid.New().String(),
		RuleID:        result.RuleID,
		RuleName:      result.RuleName,
		Title:         m.generateTitle(result),
		Description:   m.generateDescription(result, events),
		Severity:      m.mapSeverity(result.Severity),
		Confidence:    m.calculateConfidence(result, events),
		Status:        StatusNew,
		Events:        m.limitEvents(events),
		MatchedFields: m.extractMatchedFields(result),
		Tags:          m.generateTags(result),
		Source:        m.extractSource(events),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		TTL:           m.config.DefaultTTL,
		Metadata:      result.Context,
	}

	// Add MITRE ATT&CK mapping
	if len(result.MITRETechniques) > 0 || len(result.MITRETactics) > 0 {
		alert.ATTACKMapping = m.mitreMapper.MapToATTACK(result.MITRETechniques, result.MITRETactics)
	}

	// Extract tenant ID from first event
	if len(events) > 0 {
		alert.TenantID = events[0].TenantID
	}

	m.alertsCreated.Add(1)

	// Publish alert (initial, without ML analysis)
	if m.producer != nil && m.config.KafkaEnabled {
		if err := m.producer.Publish(ctx, alert); err != nil {
			m.errors.Add(1)
			m.logger.Error("failed to publish alert", "error", err)
			return alert, fmt.Errorf("failed to publish alert: %w", err)
		}
		m.alertsPublished.Add(1)
	}

	// ML Enrichment (async, non-blocking)
	if m.mlClient != nil {
		go m.enrichWithML(alert)
	}

	return alert, nil
}

// enrichWithML asynchronously enriches an alert with ML analysis.
func (m *Manager) enrichWithML(alert *Alert) {
	mlCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build ML request
	req := &MLAlertRequest{
		AlertID:       alert.ID,
		AlertType:     string(alert.Source.Type),
		Severity:      string(alert.Severity),
		Title:         alert.Title,
		Description:   alert.Description,
		RuleID:        alert.RuleID,
		RuleName:      alert.RuleName,
		Events:        m.eventsToMaps(alert.Events),
		MatchedFields: alert.MatchedFields,
		TraceID:       alert.TraceID,
	}

	analysis, err := m.mlClient.TriageAlert(mlCtx, req)
	if err != nil {
		m.logger.Warn("ml_enrichment_failed", "alert_id", alert.ID, "error", err)
		return
	}

	if analysis == nil {
		// ML is disabled or circuit open - graceful degradation
		m.logger.Debug("ml_enrichment_skipped", "alert_id", alert.ID)
		return
	}

	// Update alert with ML analysis
	alert.MLAnalysis = analysis
	alert.UpdatedAt = time.Now()
	m.alertsMLEnriched.Add(1)

	// Update priority based on ML analysis
	if analysis.Priority != "" {
		m.updateAlertPriority(alert, analysis)
	}

	// Publish updated alert with ML analysis
	if m.producer != nil && m.config.KafkaEnabled {
		if err := m.producer.Publish(mlCtx, alert); err != nil {
			m.logger.Warn("failed to publish ml-enriched alert", "alert_id", alert.ID, "error", err)
		} else {
			m.logger.Debug("ml_enriched_alert_published", "alert_id", alert.ID, "risk_score", analysis.RiskScore)
		}
	}
}

// eventsToMaps converts engine events to map format for ML request.
func (m *Manager) eventsToMaps(events []*engine.Event) []map[string]any {
	result := make([]map[string]any, 0, len(events))
	for _, e := range events {
		eventMap := make(map[string]any)
		eventMap["event_id"] = e.EventID
		eventMap["timestamp"] = e.Timestamp
		eventMap["event_type"] = e.EventType

		// Include effective data
		for k, v := range e.GetEffectiveData() {
			eventMap[k] = v
		}

		result = append(result, eventMap)
	}
	return result
}

// updateAlertPriority updates alert severity based on ML priority.
func (m *Manager) updateAlertPriority(alert *Alert, analysis *MLAnalysis) {
	// If ML suggests different priority, consider upgrading (not downgrading for safety)
	mlSeverity := m.mapPriorityToSeverity(analysis.Priority)
	if severityRank(mlSeverity) > severityRank(alert.Severity) {
		alert.Severity = mlSeverity
		alert.AddTag("ml_upgraded")
	}

	// Mark as potential false positive
	if analysis.IsFalsePositive && analysis.FPConfidence > 0.8 {
		alert.AddTag("ml_likely_fp")
	}
}

// mapPriorityToSeverity maps ML priority to alert severity.
func (m *Manager) mapPriorityToSeverity(priority string) Severity {
	switch priority {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// severityRank returns numeric rank for severity comparison.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// CreateAlertFromMatch creates an alert from a Sigma rule match.
func (m *Manager) CreateAlertFromMatch(ctx context.Context, match interface{}, event *engine.Event) (*Alert, error) {
	// Type assert to get match details
	matchMap, ok := match.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid match type")
	}

	// Extract rule info
	ruleID, _ := matchMap["rule_id"].(string)
	ruleName, _ := matchMap["rule_name"].(string)
	severity, _ := matchMap["severity"].(string)

	alert := &Alert{
		ID:            uuid.New().String(),
		TenantID:      event.TenantID,
		RuleID:        ruleID,
		RuleName:      ruleName,
		Title:         fmt.Sprintf("Sigma Rule Match: %s", ruleName),
		Description:   fmt.Sprintf("Sigma rule %s matched event", ruleName),
		Severity:      m.mapSeverity(severity),
		Status:        StatusNew,
		Events:        []*engine.Event{event},
		MatchedFields: matchMap,
		Source: AlertSource{
			Type:   "sigma",
			Engine: "sigma-engine",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		TTL:       m.config.DefaultTTL,
	}

	// Add MITRE mapping if available
	if techniques, ok := matchMap["mitre_techniques"].([]string); ok {
		if tactics, ok := matchMap["mitre_tactics"].([]string); ok {
			alert.ATTACKMapping = m.mitreMapper.MapToATTACK(techniques, tactics)
		}
	}

	m.alertsCreated.Add(1)

	// Publish
	if m.producer != nil && m.config.KafkaEnabled {
		if err := m.producer.Publish(ctx, alert); err != nil {
			m.errors.Add(1)
			return alert, err
		}
		m.alertsPublished.Add(1)
	}

	return alert, nil
}

// AggregateAlerts aggregates similar alerts within a time window.
func (m *Manager) AggregateAlerts(alerts []*Alert) []*Alert {
	if !m.config.AggregationEnabled || len(alerts) < 2 {
		return alerts
	}

	// Group by rule ID
	groups := make(map[string][]*Alert)
	for _, alert := range alerts {
		groups[alert.RuleID] = append(groups[alert.RuleID], alert)
	}

	var aggregated []*Alert
	for ruleID, groupAlerts := range groups {
		if len(groupAlerts) == 1 {
			aggregated = append(aggregated, groupAlerts[0])
			continue
		}

		// Create aggregated alert
		primary := groupAlerts[0]
		primary.Title = fmt.Sprintf("[%d] %s", len(groupAlerts), primary.Title)
		primary.Description = fmt.Sprintf("Aggregated %d alerts for rule %s", len(groupAlerts), ruleID)

		// Combine events
		var allEvents []*engine.Event
		for _, a := range groupAlerts {
			allEvents = append(allEvents, a.Events...)
		}
		primary.Events = m.limitEvents(allEvents)

		// Update confidence
		var totalConfidence float64
		for _, a := range groupAlerts {
			totalConfidence += a.Confidence
		}
		primary.Confidence = totalConfidence / float64(len(groupAlerts))

		aggregated = append(aggregated, primary)
	}

	return aggregated
}

// Stats returns manager statistics.
func (m *Manager) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"alerts_created":     m.alertsCreated.Load(),
		"alerts_deduped":     m.alertsDeduped.Load(),
		"alerts_published":   m.alertsPublished.Load(),
		"alerts_ml_enriched": m.alertsMLEnriched.Load(),
		"errors":             m.errors.Load(),
		"ml_client_enabled":  m.mlClient != nil,
	}

	if m.dedup != nil {
		stats["dedup_cache_size"] = m.dedup.Size()
	}

	if m.mlClient != nil {
		stats["ml_client_available"] = m.mlClient.IsAvailable()
	}

	return stats
}

func (m *Manager) buildDedupKey(result *engine.DetectionResult, events []*engine.Event) string {
	// Build key from rule ID and source identifiers
	key := result.RuleID

	if len(events) > 0 {
		event := events[0]
		if ip, ok := event.Data["source.ip"].(string); ok {
			key += "|" + ip
		}
		if user, ok := event.Data["user.name"].(string); ok {
			key += "|" + user
		}
		if host, ok := event.Data["host.name"].(string); ok {
			key += "|" + host
		}
	}

	return key
}

func (m *Manager) generateTitle(result *engine.DetectionResult) string {
	if result.RuleName != "" {
		return fmt.Sprintf("Detection: %s", result.RuleName)
	}
	return fmt.Sprintf("Detection: Rule %s", result.RuleID)
}

func (m *Manager) generateDescription(result *engine.DetectionResult, events []*engine.Event) string {
	desc := fmt.Sprintf("Rule %s triggered", result.RuleID)

	if len(events) > 0 {
		desc += fmt.Sprintf(" with %d event(s)", len(events))
	}

	if len(result.MITRETechniques) > 0 {
		desc += fmt.Sprintf(". MITRE ATT&CK: %v", result.MITRETechniques)
	}

	return desc
}

func (m *Manager) mapSeverity(severity string) Severity {
	switch severity {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

func (m *Manager) calculateConfidence(result *engine.DetectionResult, events []*engine.Event) float64 {
	confidence := 0.5 // Base confidence

	// More matched events = higher confidence
	if len(events) > 5 {
		confidence += 0.2
	} else if len(events) > 2 {
		confidence += 0.1
	}

	// Has MITRE mapping = higher confidence
	if len(result.MITRETechniques) > 0 {
		confidence += 0.1
	}

	// Multiple tactics = higher confidence
	if len(result.MITRETactics) > 1 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (m *Manager) extractMatchedFields(result *engine.DetectionResult) map[string]interface{} {
	fields := make(map[string]interface{})

	for _, matched := range result.MatchedEvents {
		for k, v := range matched.MatchedFields {
			fields[k] = v
		}
	}

	return fields
}

func (m *Manager) generateTags(result *engine.DetectionResult) []string {
	var tags []string

	// Add severity tag
	tags = append(tags, "severity:"+result.Severity)

	// Add MITRE tactic tags
	for _, tactic := range result.MITRETactics {
		tags = append(tags, "attack."+tactic)
	}

	// Add MITRE technique tags
	for _, tech := range result.MITRETechniques {
		tags = append(tags, "attack."+tech)
	}

	return tags
}

func (m *Manager) extractSource(events []*engine.Event) AlertSource {
	source := AlertSource{
		Type:   "detection",
		Engine: "detection-engine",
	}

	ipSet := make(map[string]bool)
	userSet := make(map[string]bool)

	for _, event := range events {
		if ip, ok := event.Data["source.ip"].(string); ok {
			ipSet[ip] = true
		}
		if user, ok := event.Data["user.name"].(string); ok {
			userSet[user] = true
		}
		if host, ok := event.Data["host.name"].(string); ok && source.Hostname == "" {
			source.Hostname = host
		}
	}

	for ip := range ipSet {
		source.IPs = append(source.IPs, ip)
	}
	for user := range userSet {
		source.Users = append(source.Users, user)
	}

	return source
}

func (m *Manager) limitEvents(events []*engine.Event) []*engine.Event {
	if len(events) <= m.config.MaxEventsPerAlert {
		return events
	}
	return events[:m.config.MaxEventsPerAlert]
}

func (m *Manager) dedupCleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.dedup.Cleanup()
		}
	}
}

// AlertJSON returns the alert as JSON bytes.
func (a *Alert) AlertJSON() ([]byte, error) {
	return json.Marshal(a)
}

// UpdateStatus updates the alert status.
func (a *Alert) UpdateStatus(status AlertStatus) {
	a.Status = status
	a.UpdatedAt = time.Now()

	if status == StatusResolved || status == StatusClosed {
		now := time.Now()
		a.ResolvedAt = &now
	}
}

// AddTag adds a tag to the alert.
func (a *Alert) AddTag(tag string) {
	for _, t := range a.Tags {
		if t == tag {
			return
		}
	}
	a.Tags = append(a.Tags, tag)
}

// HasTechnique checks if the alert involves a specific MITRE technique.
func (a *Alert) HasTechnique(techniqueID string) bool {
	if a.ATTACKMapping == nil {
		return false
	}

	for _, tech := range a.ATTACKMapping.Techniques {
		if tech.ID == techniqueID {
			return true
		}
	}
	return false
}

// HasTactic checks if the alert involves a specific MITRE tactic.
func (a *Alert) HasTactic(tacticName string) bool {
	if a.ATTACKMapping == nil {
		return false
	}

	for _, tactic := range a.ATTACKMapping.Tactics {
		if tactic.ShortName == tacticName || tactic.Name == tacticName {
			return true
		}
	}
	return false
}
