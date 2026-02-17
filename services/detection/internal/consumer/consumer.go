// Package consumer provides Kafka consumer functionality for the detection service.
package consumer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kgo"
	"gopkg.in/yaml.v3"

	"github.com/siem-soar-platform/services/detection/internal/config"
	"github.com/siem-soar-platform/services/detection/internal/engine"
)

// Consumer consumes parsed events from Kafka and evaluates detection rules.
type Consumer struct {
	cfg           *config.Config
	client        *kgo.Client
	producer      *kgo.Client
	engine        *engine.Engine
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup

	// Simple rules for testing (when engine is nil)
	simpleRules []*SimpleRule

	// Sigma rules loaded from YAML files
	sigmaRules []*SigmaRule

	// HTTP client for gateway forwarding
	httpClient *http.Client

	// Metrics
	eventsConsumed   atomic.Uint64
	eventsProcessed  atomic.Uint64
	alertsGenerated  atomic.Uint64
	errors           atomic.Uint64
	parseErrors      atomic.Uint64
	processingTimeNs atomic.Uint64

	// Batch processing
	batchSize    int
	batchTimeout time.Duration
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(cfg *config.Config, detectionEngine *engine.Engine, logger *slog.Logger) (*Consumer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create HTTP client for gateway forwarding
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	c := &Consumer{
		cfg:          cfg,
		engine:       detectionEngine,
		logger:       logger.With("component", "kafka-consumer"),
		ctx:          ctx,
		cancel:       cancel,
		batchSize:    cfg.BatchSize,
		batchTimeout: cfg.BatchTimeout,
		simpleRules:  defaultSimpleRules(),
		httpClient:   httpClient,
	}

	// Load Sigma rules from filesystem
	rulesDir := "/app/rules" // Docker path
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		rulesDir = "./rules" // Local development path
	}

	if sigmaRules, err := c.loadSigmaRules(rulesDir); err != nil {
		logger.Warn("failed to load Sigma rules", "error", err, "path", rulesDir)
	} else {
		c.sigmaRules = sigmaRules
		logger.Info("loaded Sigma rules", "count", len(sigmaRules), "path", rulesDir)
	}

	return c, nil
}

// Start starts the consumer.
func (c *Consumer) Start() error {
	// Build consumer options
	consumerOpts, err := c.buildConsumerOptions()
	if err != nil {
		return fmt.Errorf("failed to build consumer options: %w", err)
	}

	// Create consumer client
	c.client, err = kgo.NewClient(consumerOpts...)
	if err != nil {
		return fmt.Errorf("failed to create consumer client: %w", err)
	}

	// Build producer options
	producerOpts, err := c.buildProducerOptions()
	if err != nil {
		c.client.Close()
		return fmt.Errorf("failed to build producer options: %w", err)
	}

	// Create producer client
	c.producer, err = kgo.NewClient(producerOpts...)
	if err != nil {
		c.client.Close()
		return fmt.Errorf("failed to create producer client: %w", err)
	}

	c.logger.Info("kafka consumer started",
		"brokers", c.cfg.Kafka.Brokers,
		"input_topic", c.cfg.Kafka.InputTopic,
		"output_topic", c.cfg.Kafka.OutputTopic,
		"consumer_group", c.cfg.Kafka.ConsumerGroup,
		"workers", c.cfg.Workers)

	// Start worker goroutines
	for i := 0; i < c.cfg.Workers; i++ {
		c.wg.Add(1)
		go c.worker(i)
	}

	return nil
}

// Stop stops the consumer.
func (c *Consumer) Stop() error {
	c.logger.Info("stopping kafka consumer")
	c.cancel()
	c.wg.Wait()

	if c.client != nil {
		c.client.Close()
	}
	if c.producer != nil {
		c.producer.Close()
	}

	c.logger.Info("kafka consumer stopped",
		"events_consumed", c.eventsConsumed.Load(),
		"events_processed", c.eventsProcessed.Load(),
		"alerts_generated", c.alertsGenerated.Load(),
		"errors", c.errors.Load())

	return nil
}

// Stats returns consumer statistics.
func (c *Consumer) Stats() ConsumerMetrics {
	return ConsumerMetrics{
		EventsConsumed:   c.eventsConsumed.Load(),
		EventsProcessed:  c.eventsProcessed.Load(),
		AlertsGenerated:  c.alertsGenerated.Load(),
		Errors:           c.errors.Load(),
		ParseErrors:      c.parseErrors.Load(),
		ProcessingTimeNs: c.processingTimeNs.Load(),
	}
}

func (c *Consumer) buildConsumerOptions() ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.cfg.Kafka.Brokers...),
		kgo.ConsumerGroup(c.cfg.Kafka.ConsumerGroup),
		kgo.ConsumeTopics(c.cfg.Kafka.InputTopic),
		kgo.FetchMaxBytes(10 * 1024 * 1024), // 10MB max fetch
		kgo.FetchMaxWait(500 * time.Millisecond),
	}

	// Offset reset
	if c.cfg.Kafka.OffsetReset == "earliest" {
		opts = append(opts, kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	} else {
		opts = append(opts, kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()))
	}

	// Auto-commit settings
	if c.cfg.Kafka.AutoCommit {
		opts = append(opts, kgo.DisableAutoCommit())
	}

	// TLS configuration
	if c.cfg.Kafka.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		opts = append(opts, kgo.DialTLSConfig(tlsConfig))
	}

	// SASL configuration (requires additional franz-go SASL packages)
	// To enable SASL, add github.com/twmb/franz-go/pkg/sasl dependencies
	if c.cfg.Kafka.SASLEnabled {
		c.logger.Warn("SASL is enabled but SASL packages are not included. Skipping SASL configuration.")
	}

	return opts, nil
}

func (c *Consumer) buildProducerOptions() ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.cfg.Kafka.Brokers...),
		kgo.DefaultProduceTopic(c.cfg.Kafka.OutputTopic),
		kgo.ProducerBatchMaxBytes(10 * 1024 * 1024), // 10MB max batch
		kgo.ProducerLinger(100 * time.Millisecond),
		kgo.RequiredAcks(kgo.AllISRAcks()),
	}

	// TLS configuration
	if c.cfg.Kafka.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		opts = append(opts, kgo.DialTLSConfig(tlsConfig))
	}

	// SASL configuration (requires additional franz-go SASL packages)
	// To enable SASL, add github.com/twmb/franz-go/pkg/sasl dependencies
	if c.cfg.Kafka.SASLEnabled {
		c.logger.Warn("SASL is enabled but SASL packages are not included. Skipping SASL configuration for producer.")
	}

	return opts, nil
}

func (c *Consumer) worker(id int) {
	defer c.wg.Done()

	logger := c.logger.With("worker_id", id)
	logger.Debug("worker started")

	batch := make([]*kgo.Record, 0, c.batchSize)
	timer := time.NewTimer(c.batchTimeout)
	defer timer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Process remaining batch
			if len(batch) > 0 {
				c.processBatch(batch)
			}
			logger.Debug("worker stopped")
			return
		default:
		}

		// Fetch records
		fetches := c.client.PollRecords(c.ctx, c.batchSize)
		if fetches.IsClientClosed() {
			return
		}

		if err := fetches.Err(); err != nil {
			if c.ctx.Err() == nil {
				logger.Error("fetch error", "error", err)
				c.errors.Add(1)
			}
			continue
		}

		// Process fetched records
		fetches.EachRecord(func(record *kgo.Record) {
			c.eventsConsumed.Add(1)
			batch = append(batch, record)
		})

		// Process batch if full or timeout
		if len(batch) >= c.batchSize {
			c.processBatch(batch)
			batch = batch[:0]
			timer.Reset(c.batchTimeout)
		}

		select {
		case <-timer.C:
			if len(batch) > 0 {
				c.processBatch(batch)
				batch = batch[:0]
			}
			timer.Reset(c.batchTimeout)
		default:
		}
	}
}

func (c *Consumer) processBatch(records []*kgo.Record) {
	if len(records) == 0 {
		return
	}

	startTime := time.Now()
	var alerts []*Alert

	for _, record := range records {
		// Parse event
		event, err := c.parseEvent(record.Value)
		if err != nil {
			c.parseErrors.Add(1)
			c.logger.Warn("failed to parse event",
				"error", err,
				"offset", record.Offset,
				"partition", record.Partition)
			continue
		}

		// Skip events that failed parsing
		if !event.ParseSuccess {
			continue
		}

		c.eventsProcessed.Add(1)

		// Evaluate rules against event
		eventAlerts := c.evaluateRules(event)
		alerts = append(alerts, eventAlerts...)
	}

	// Produce alerts
	if len(alerts) > 0 {
		c.produceAlerts(alerts)
	}

	// Commit offsets
	if err := c.client.CommitUncommittedOffsets(c.ctx); err != nil && c.ctx.Err() == nil {
		c.logger.Error("failed to commit offsets", "error", err)
		c.errors.Add(1)
	}

	processingTime := time.Since(startTime)
	c.processingTimeNs.Add(uint64(processingTime.Nanoseconds()))
}

func (c *Consumer) parseEvent(data []byte) (*ParsedEvent, error) {
	var event ParsedEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	return &event, nil
}

func (c *Consumer) evaluateRules(event *ParsedEvent) []*Alert {
	var alerts []*Alert

	// Use the engine if available
	if c.engine != nil {
		engineEvent := &engine.Event{
			EventID:   event.EventID,
			TenantID:  event.TenantID,
			Timestamp: event.Timestamp,
			EventType: event.SourceType,
			Raw:       event.Fields,        // Raw fields for backward compatibility
			Data:      event.Fields,        // Deprecated but kept for compatibility
			UDM:       event.UDM,           // UDM normalized data (may be nil)
		}

		if err := c.engine.ProcessEvent(engineEvent); err != nil {
			c.logger.Warn("failed to process event in engine", "event_id", event.EventID, "error", err)
		}

		// Collect results from engine (non-blocking)
		select {
		case result := <-c.engine.Results():
			if result != nil {
				alert := c.detectionResultToAlert(result, event)
				alerts = append(alerts, alert)
			}
		default:
		}
	}

	// Also evaluate simple rules for testing
	for _, rule := range c.simpleRules {
		if !rule.Enabled {
			continue
		}

		matched, matchedFields := c.evaluateSimpleRule(rule, event)
		if matched {
			alert := &Alert{
				AlertID:         uuid.New().String(),
				EventID:         event.EventID,
				TenantID:        event.TenantID,
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Severity:        rule.Severity,
				Timestamp:       time.Now(),
				SourceType:      event.SourceType,
				Fields:          event.Fields,
				MatchedFields:   matchedFields,
				RawLog:          event.RawLog,
				MITRETactics:    rule.MITRETactics,
				MITRETechniques: rule.MITRETechniques,
			}
			alerts = append(alerts, alert)
		}
	}

	// Evaluate Sigma rules
	for _, sigmaRule := range c.sigmaRules {
		matched, matchedFields := c.evaluateSigmaRule(sigmaRule, event)
		if matched {
			// Extract MITRE tactics and techniques from tags
			tactics, techniques := extractMITREFromTags(sigmaRule.Tags)

			alert := &Alert{
				AlertID:         uuid.New().String(),
				EventID:         event.EventID,
				TenantID:        event.TenantID,
				RuleID:          sigmaRule.ID,
				RuleName:        sigmaRule.Title,
				Severity:        normalizeSeverity(sigmaRule.Level),
				Timestamp:       time.Now(),
				SourceType:      event.SourceType,
				Fields:          event.Fields,
				MatchedFields:   matchedFields,
				RawLog:          event.RawLog,
				MITRETactics:    tactics,
				MITRETechniques: techniques,
			}
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

func (c *Consumer) evaluateSimpleRule(rule *SimpleRule, event *ParsedEvent) (bool, map[string]interface{}) {
	matchedFields := make(map[string]interface{})

	// Get field value
	value, found := getFieldValue(rule.Field, event.Fields)
	if !found {
		return false, nil
	}

	// Evaluate based on operator
	matched := false
	switch rule.Operator {
	case OpEquals:
		matched = equalValues(value, rule.Value)
	case OpContains:
		matched = containsValue(value, rule.Value)
	case OpStartsWith:
		matched = startsWithValue(value, rule.Value)
	case OpEndsWith:
		matched = endsWithValue(value, rule.Value)
	case OpIn:
		if list, ok := rule.Value.([]string); ok {
			for _, v := range list {
				if equalValues(value, v) {
					matched = true
					break
				}
			}
		}
	case OpExists:
		matched = found
	}

	if matched {
		matchedFields[rule.Field] = value
	}

	return matched, matchedFields
}

// evaluateSigmaRule evaluates a Sigma rule against an event.
func (c *Consumer) evaluateSigmaRule(rule *SigmaRule, event *ParsedEvent) (bool, map[string]interface{}) {
	matchedFields := make(map[string]interface{})

	// Only support simple "selection" condition for now
	if rule.Detection.Condition != "selection" {
		return false, nil
	}

	// Check all selection criteria
	for field, criteria := range rule.Detection.Selection {
		value, found := getFieldValue(field, event.Fields)

		// Handle special field modifiers (e.g., "command_line|contains")
		fieldName := field
		operator := OpEquals
		if strings.Contains(field, "|") {
			parts := strings.SplitN(field, "|", 2)
			fieldName = parts[0]
			modifier := parts[1]

			// Get value for actual field name
			value, found = getFieldValue(fieldName, event.Fields)

			switch modifier {
			case "contains":
				operator = OpContains
			case "startswith":
				operator = OpStartsWith
			case "endswith":
				operator = OpEndsWith
			default:
				operator = OpEquals
			}
		}

		if !found {
			return false, nil
		}

		// Evaluate criteria
		matched := false
		switch criteriaValue := criteria.(type) {
		case string:
			matched = evaluateFieldMatch(value, criteriaValue, operator)
		case []interface{}:
			// Multiple values (OR logic)
			for _, v := range criteriaValue {
				if strVal, ok := v.(string); ok {
					if evaluateFieldMatch(value, strVal, operator) {
						matched = true
						break
					}
				}
			}
		}

		if !matched {
			return false, nil
		}

		matchedFields[fieldName] = value
	}

	return true, matchedFields
}

// evaluateFieldMatch evaluates a field value against criteria using the specified operator.
func evaluateFieldMatch(value interface{}, criteria string, operator string) bool {
	switch operator {
	case OpEquals:
		return equalValues(value, criteria)
	case OpContains:
		return containsValue(value, criteria)
	case OpStartsWith:
		return startsWithValue(value, criteria)
	case OpEndsWith:
		return endsWithValue(value, criteria)
	default:
		return equalValues(value, criteria)
	}
}

// extractMITREFromTags extracts MITRE ATT&CK tactics and techniques from Sigma rule tags.
func extractMITREFromTags(tags []string) (tactics []string, techniques []string) {
	for _, tag := range tags {
		// Tags are in format "attack.tactic" or "attack.t1234.567"
		if !strings.HasPrefix(tag, "attack.") {
			continue
		}

		parts := strings.SplitN(tag, ".", 2)
		if len(parts) != 2 {
			continue
		}

		value := parts[1]

		// Check if it's a technique (starts with 't' followed by numbers)
		if strings.HasPrefix(strings.ToLower(value), "t") && len(value) > 1 {
			// Technique ID (e.g., t1059.001)
			techniques = append(techniques, strings.ToUpper(value))
		} else {
			// Map common tactic names to IDs
			tacticID := mapTacticNameToID(value)
			if tacticID != "" {
				tactics = append(tactics, tacticID)
			}
		}
	}

	return tactics, techniques
}

// mapTacticNameToID maps MITRE ATT&CK tactic names to IDs.
func mapTacticNameToID(tacticName string) string {
	tacticMap := map[string]string{
		"initial-access":       "TA0001",
		"execution":            "TA0002",
		"persistence":          "TA0003",
		"privilege-escalation": "TA0004",
		"privilege_escalation": "TA0004",
		"defense-evasion":      "TA0005",
		"defense_evasion":      "TA0005",
		"credential-access":    "TA0006",
		"credential_access":    "TA0006",
		"discovery":            "TA0007",
		"lateral-movement":     "TA0008",
		"lateral_movement":     "TA0008",
		"collection":           "TA0009",
		"exfiltration":         "TA0010",
		"command-and-control":  "TA0011",
		"command_and_control":  "TA0011",
		"impact":               "TA0040",
	}

	return tacticMap[strings.ToLower(tacticName)]
}

// normalizeSeverity converts Sigma severity levels to standard severity levels.
func normalizeSeverity(sigmaLevel string) string {
	switch strings.ToLower(sigmaLevel) {
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

func (c *Consumer) detectionResultToAlert(result *engine.DetectionResult, event *ParsedEvent) *Alert {
	var matchedFields map[string]interface{}
	if len(result.MatchedEvents) > 0 {
		matchedFields = result.MatchedEvents[0].MatchedFields
	}

	return &Alert{
		AlertID:         uuid.New().String(),
		EventID:         event.EventID,
		TenantID:        event.TenantID,
		RuleID:          result.RuleID,
		RuleName:        result.RuleName,
		Severity:        result.Severity,
		Timestamp:       time.Now(),
		SourceType:      event.SourceType,
		Fields:          event.Fields,
		MatchedFields:   matchedFields,
		RawLog:          event.RawLog,
		MITRETactics:    result.MITRETactics,
		MITRETechniques: result.MITRETechniques,
	}
}

func (c *Consumer) produceAlerts(alerts []*Alert) {
	var records []*kgo.Record

	for _, alert := range alerts {
		data, err := json.Marshal(alert)
		if err != nil {
			c.logger.Error("failed to marshal alert", "alert_id", alert.AlertID, "error", err)
			c.errors.Add(1)
			continue
		}

		record := &kgo.Record{
			Key:   []byte(alert.AlertID),
			Value: data,
			Headers: []kgo.RecordHeader{
				{Key: "tenant_id", Value: []byte(alert.TenantID)},
				{Key: "rule_id", Value: []byte(alert.RuleID)},
				{Key: "severity", Value: []byte(alert.Severity)},
			},
		}
		records = append(records, record)

		// Also forward to gateway HTTP API (fire and forget)
		go c.forwardAlertToGateway(alert)
	}

	if len(records) == 0 {
		return
	}

	// Produce records to Kafka
	results := c.producer.ProduceSync(c.ctx, records...)
	for _, result := range results {
		if result.Err != nil {
			c.logger.Error("failed to produce alert", "error", result.Err)
			c.errors.Add(1)
		} else {
			c.alertsGenerated.Add(1)
		}
	}
}

// forwardAlertToGateway forwards alert to gateway HTTP API
func (c *Consumer) forwardAlertToGateway(alert *Alert) {
	gatewayURL := "http://gateway:8080/api/v1/alerts"

	// Try localhost fallback for development
	if c.cfg.Kafka.Brokers[0] == "localhost:9092" {
		gatewayURL = "http://localhost:8080/api/v1/alerts"
	}

	data, err := json.Marshal(alert)
	if err != nil {
		c.logger.Warn("failed to marshal alert for gateway", "alert_id", alert.AlertID, "error", err)
		return
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", gatewayURL, bytes.NewReader(data))
	if err != nil {
		c.logger.Warn("failed to create gateway request", "alert_id", alert.AlertID, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Warn("failed to forward alert to gateway", "alert_id", alert.AlertID, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		c.logger.Warn("gateway returned non-success status",
			"alert_id", alert.AlertID,
			"status", resp.StatusCode)
		return
	}

	c.logger.Debug("alert forwarded to gateway", "alert_id", alert.AlertID)
}

// defaultSimpleRules returns default simple rules for testing.
func defaultSimpleRules() []*SimpleRule {
	return []*SimpleRule{
		{
			ID:          "rule-001",
			Name:        "Failed Login Detection",
			Description: "Detects failed login attempts",
			Severity:    SeverityMedium,
			Field:       "event_type",
			Operator:    OpEquals,
			Value:       "login_failure",
			MITRETactics:    []string{"TA0001"},
			MITRETechniques: []string{"T1078"},
			Enabled:     true,
		},
		{
			ID:          "rule-002",
			Name:        "Brute Force Detection",
			Description: "Detects potential brute force attacks",
			Severity:    SeverityHigh,
			Field:       "event_type",
			Operator:    OpIn,
			Value:       []string{"login_failure", "auth_failure", "authentication_failed"},
			MITRETactics:    []string{"TA0006"},
			MITRETechniques: []string{"T1110"},
			Enabled:     true,
		},
		{
			ID:          "rule-003",
			Name:        "Suspicious PowerShell",
			Description: "Detects suspicious PowerShell commands",
			Severity:    SeverityHigh,
			Field:       "process.command_line",
			Operator:    OpContains,
			Value:       "-encodedcommand",
			MITRETactics:    []string{"TA0002"},
			MITRETechniques: []string{"T1059.001"},
			Enabled:     true,
		},
		{
			ID:          "rule-004",
			Name:        "Critical System File Access",
			Description: "Detects access to critical system files",
			Severity:    SeverityCritical,
			Field:       "file.path",
			Operator:    OpContains,
			Value:       "/etc/passwd",
			MITRETactics:    []string{"TA0007"},
			MITRETechniques: []string{"T1003"},
			Enabled:     true,
		},
		{
			ID:          "rule-005",
			Name:        "Outbound Connection to Suspicious Port",
			Description: "Detects outbound connections to suspicious ports",
			Severity:    SeverityMedium,
			Field:       "destination.port",
			Operator:    OpIn,
			Value:       []string{"4444", "5555", "6666", "7777", "8888"},
			MITRETactics:    []string{"TA0011"},
			MITRETechniques: []string{"T1571"},
			Enabled:     true,
		},
	}
}

// loadSigmaRules loads Sigma rules from YAML files in the specified directory.
func (c *Consumer) loadSigmaRules(rulesDir string) ([]*SigmaRule, error) {
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("rules directory does not exist: %s", rulesDir)
	}

	var sigmaRules []*SigmaRule

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() || (!strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml")) {
			return nil
		}

		// Read YAML file
		data, err := os.ReadFile(path)
		if err != nil {
			c.logger.Warn("failed to read Sigma rule file", "path", path, "error", err)
			return nil // Continue with other files
		}

		// Parse YAML
		var rule SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			c.logger.Warn("failed to parse Sigma rule YAML", "path", path, "error", err)
			return nil // Continue with other files
		}

		sigmaRules = append(sigmaRules, &rule)
		c.logger.Debug("loaded Sigma rule", "id", rule.ID, "title", rule.Title, "path", path)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}

	return sigmaRules, nil
}

// Helper functions
func getFieldValue(field string, data map[string]interface{}) (interface{}, bool) {
	parts := strings.Split(field, ".")
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

func equalValues(value, expected interface{}) bool {
	if vs, ok := value.(string); ok {
		if es, ok := expected.(string); ok {
			return strings.EqualFold(vs, es)
		}
	}
	return value == expected
}

func containsValue(value, substr interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := substr.(string)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(vs), strings.ToLower(ss))
}

func startsWithValue(value, prefix interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ps, ok := prefix.(string)
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.ToLower(vs), strings.ToLower(ps))
}

func endsWithValue(value, suffix interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := suffix.(string)
	if !ok {
		return false
	}
	return strings.HasSuffix(strings.ToLower(vs), strings.ToLower(ss))
}
