// Package consumer provides Kafka consumer for ML-enriched alerts.
package consumer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/siem-soar-platform/services/soar/internal/engine"
	"github.com/siem-soar-platform/services/soar/internal/playbook"
)

// MLEnrichedAlert is the Kafka message format from Detection service.
type MLEnrichedAlert struct {
	AlertID       string                   `json:"id"`
	TenantID      string                   `json:"tenant_id"`
	RuleID        string                   `json:"rule_id"`
	RuleName      string                   `json:"rule_name"`
	Severity      string                   `json:"severity"`
	Title         string                   `json:"title"`
	Description   string                   `json:"description"`
	Events        []map[string]interface{} `json:"events"`
	MatchedFields map[string]interface{}   `json:"matched_fields"`
	ATTACKMapping *ATTACKMapping           `json:"attack_mapping,omitempty"`
	MLAnalysis    *MLAnalysis              `json:"ml_analysis,omitempty"`
	TraceID       string                   `json:"trace_id"`
	CreatedAt     time.Time                `json:"created_at"`
}

// ATTACKMapping contains MITRE ATT&CK mapping information.
type ATTACKMapping struct {
	Tactics    []string `json:"tactics,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

// MLAnalysis contains ML analysis results from the AI service.
type MLAnalysis struct {
	Classification  *Classification `json:"classification,omitempty"`
	RiskScore       float64         `json:"risk_score"`
	Priority        string          `json:"priority"`
	IsFalsePositive bool            `json:"is_false_positive"`
	FPConfidence    float64         `json:"fp_confidence"`
	MITRETactics    []string        `json:"mitre_tactics,omitempty"`
	MITRETechniques []string        `json:"mitre_techniques,omitempty"`
}

// Classification contains alert classification from ML model.
type Classification struct {
	Category   string  `json:"category"`
	SubType    string  `json:"sub_type,omitempty"`
	Confidence float64 `json:"confidence"`
}

// Handler processes ML-enriched alerts.
type Handler struct {
	engine      *engine.SOAREngine
	ruleStore   *PlaybookRuleStore
	idempotency *IdempotencyChecker
	logger      *slog.Logger
}

// NewHandler creates a new Handler instance.
func NewHandler(
	soarEngine *engine.SOAREngine,
	ruleStore *PlaybookRuleStore,
	idempotency *IdempotencyChecker,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return &Handler{
		engine:      soarEngine,
		ruleStore:   ruleStore,
		idempotency: idempotency,
		logger:      logger,
	}
}

// HandleAlert processes an ML-enriched alert.
// Returns error only for non-retryable failures.
func (h *Handler) HandleAlert(ctx context.Context, alert *MLEnrichedAlert) error {
	// Extract trace context from alert if available
	ctx = h.extractTraceContext(ctx, alert)

	h.logger.Info("Handling ML-enriched alert",
		"alert_id", alert.AlertID,
		"tenant_id", alert.TenantID,
		"rule_id", alert.RuleID,
		"severity", alert.Severity,
		"has_ml_analysis", alert.MLAnalysis != nil,
	)

	// 1. Check idempotency (skip if already processed)
	mlHash := h.computeMLHash(alert)
	if h.idempotency != nil {
		processed, err := h.idempotency.IsProcessed(ctx, alert.AlertID, mlHash)
		if err != nil {
			h.logger.Warn("Failed to check idempotency, continuing",
				"alert_id", alert.AlertID,
				"error", err,
			)
		} else if processed {
			h.logger.Info("Alert already processed, skipping",
				"alert_id", alert.AlertID,
			)
			return nil
		}
	}

	// 2. Check if ML analysis indicates false positive
	if alert.MLAnalysis != nil && alert.MLAnalysis.IsFalsePositive {
		h.logger.Info("Alert marked as false positive by ML, skipping playbook execution",
			"alert_id", alert.AlertID,
			"fp_confidence", alert.MLAnalysis.FPConfidence,
		)
		// Still mark as processed
		if h.idempotency != nil {
			h.idempotency.MarkProcessed(ctx, alert.AlertID, mlHash)
		}
		return nil
	}

	// 3. Find matching playbooks using ML analysis
	matchingRules, err := h.ruleStore.FindMatchingRules(ctx, alert)
	if err != nil {
		return fmt.Errorf("failed to find matching rules: %w", err)
	}

	if len(matchingRules) == 0 {
		h.logger.Info("No matching playbook rules for alert",
			"alert_id", alert.AlertID,
		)
		// Mark as processed even if no rules match
		if h.idempotency != nil {
			h.idempotency.MarkProcessed(ctx, alert.AlertID, mlHash)
		}
		return nil
	}

	h.logger.Info("Found matching playbook rules",
		"alert_id", alert.AlertID,
		"rule_count", len(matchingRules),
	)

	// 4. Execute matching playbooks
	var executionErrors []error
	for _, rule := range matchingRules {
		// Check if auto-execution or human approval required
		if rule.RequireApproval {
			h.logger.Info("Playbook requires approval, queueing for review",
				"alert_id", alert.AlertID,
				"rule_id", rule.ID,
				"playbook_id", rule.PlaybookID,
			)
			// Queue for approval (implementation depends on approval workflow)
			if err := h.queueForApproval(ctx, alert, rule); err != nil {
				h.logger.Error("Failed to queue for approval",
					"alert_id", alert.AlertID,
					"rule_id", rule.ID,
					"error", err,
				)
				executionErrors = append(executionErrors, err)
			}
			continue
		}

		// 5. Trigger playbook execution via Temporal
		execReq := h.buildExecuteRequest(alert, rule)
		result, err := h.engine.ExecutePlaybook(ctx, execReq)
		if err != nil {
			h.logger.Error("Failed to execute playbook",
				"alert_id", alert.AlertID,
				"playbook_id", rule.PlaybookID,
				"error", err,
			)
			executionErrors = append(executionErrors, err)
			continue
		}

		h.logger.Info("Triggered playbook execution",
			"alert_id", alert.AlertID,
			"playbook_id", rule.PlaybookID,
			"execution_id", result.ExecutionID,
			"workflow_id", result.WorkflowID,
		)
	}

	// 6. Mark as processed
	if h.idempotency != nil {
		if err := h.idempotency.MarkProcessed(ctx, alert.AlertID, mlHash); err != nil {
			h.logger.Warn("Failed to mark alert as processed",
				"alert_id", alert.AlertID,
				"error", err,
			)
		}
	}

	// Return error only if all executions failed
	if len(executionErrors) > 0 && len(executionErrors) == len(matchingRules) {
		return fmt.Errorf("all playbook executions failed: %v", executionErrors)
	}

	return nil
}

// extractTraceContext extracts OpenTelemetry trace context from the alert.
func (h *Handler) extractTraceContext(ctx context.Context, alert *MLEnrichedAlert) context.Context {
	if alert.TraceID == "" {
		return ctx
	}

	// Parse trace ID and create span context
	traceIDBytes, err := hex.DecodeString(alert.TraceID)
	if err != nil || len(traceIDBytes) != 16 {
		h.logger.Debug("Invalid trace ID format",
			"trace_id", alert.TraceID,
			"error", err,
		)
		return ctx
	}

	var traceID trace.TraceID
	copy(traceID[:], traceIDBytes)

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		Remote:  true,
	})

	return trace.ContextWithSpanContext(ctx, spanContext)
}

// computeMLHash computes a hash of the ML analysis for idempotency.
func (h *Handler) computeMLHash(alert *MLEnrichedAlert) string {
	if alert.MLAnalysis == nil {
		return "no-ml"
	}

	// Create a deterministic hash of ML analysis
	data := struct {
		RiskScore       float64  `json:"risk_score"`
		Priority        string   `json:"priority"`
		IsFalsePositive bool     `json:"is_false_positive"`
		FPConfidence    float64  `json:"fp_confidence"`
		Tactics         []string `json:"tactics,omitempty"`
		Techniques      []string `json:"techniques,omitempty"`
	}{
		RiskScore:       alert.MLAnalysis.RiskScore,
		Priority:        alert.MLAnalysis.Priority,
		IsFalsePositive: alert.MLAnalysis.IsFalsePositive,
		FPConfidence:    alert.MLAnalysis.FPConfidence,
		Tactics:         alert.MLAnalysis.MITRETactics,
		Techniques:      alert.MLAnalysis.MITRETechniques,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "hash-error"
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter hash
}

// buildExecuteRequest builds a playbook execution request from alert and rule.
func (h *Handler) buildExecuteRequest(alert *MLEnrichedAlert, rule *PlaybookRule) *engine.ExecutePlaybookRequest {
	// Build input data from alert
	inputs := make(map[string]interface{})

	// Basic alert info
	inputs["alert_id"] = alert.AlertID
	inputs["tenant_id"] = alert.TenantID
	inputs["rule_id"] = alert.RuleID
	inputs["rule_name"] = alert.RuleName
	inputs["severity"] = alert.Severity
	inputs["title"] = alert.Title
	inputs["description"] = alert.Description
	inputs["created_at"] = alert.CreatedAt

	// Events and matched fields
	inputs["events"] = alert.Events
	inputs["matched_fields"] = alert.MatchedFields

	// MITRE ATT&CK mapping
	if alert.ATTACKMapping != nil {
		inputs["attack_tactics"] = alert.ATTACKMapping.Tactics
		inputs["attack_techniques"] = alert.ATTACKMapping.Techniques
	}

	// ML analysis
	if alert.MLAnalysis != nil {
		mlData := map[string]interface{}{
			"risk_score":       alert.MLAnalysis.RiskScore,
			"priority":         alert.MLAnalysis.Priority,
			"is_false_positive": alert.MLAnalysis.IsFalsePositive,
			"fp_confidence":    alert.MLAnalysis.FPConfidence,
		}
		if alert.MLAnalysis.Classification != nil {
			mlData["classification"] = map[string]interface{}{
				"category":   alert.MLAnalysis.Classification.Category,
				"sub_type":   alert.MLAnalysis.Classification.SubType,
				"confidence": alert.MLAnalysis.Classification.Confidence,
			}
		}
		if len(alert.MLAnalysis.MITRETactics) > 0 {
			mlData["mitre_tactics"] = alert.MLAnalysis.MITRETactics
		}
		if len(alert.MLAnalysis.MITRETechniques) > 0 {
			mlData["mitre_techniques"] = alert.MLAnalysis.MITRETechniques
		}
		inputs["ml_analysis"] = mlData
	}

	// Build trigger info
	triggerInfo := map[string]interface{}{
		"source":    "kafka_consumer",
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}

	return &engine.ExecutePlaybookRequest{
		PlaybookID:  rule.PlaybookID,
		TriggerType: playbook.TriggerAlert,
		TriggerInfo: triggerInfo,
		AlertID:     alert.AlertID,
		TenantID:    alert.TenantID,
		Inputs:      inputs,
		Async:       true, // Always async for Kafka consumer
	}
}

// queueForApproval queues an alert for human approval before playbook execution.
func (h *Handler) queueForApproval(ctx context.Context, alert *MLEnrichedAlert, rule *PlaybookRule) error {
	// Build approval request
	approvalReq := &engine.ExecutePlaybookRequest{
		PlaybookID:  rule.PlaybookID,
		TriggerType: playbook.TriggerAlert,
		TriggerInfo: map[string]interface{}{
			"source":           "kafka_consumer",
			"rule_id":          rule.ID,
			"rule_name":        rule.Name,
			"requires_approval": true,
		},
		AlertID:  alert.AlertID,
		TenantID: alert.TenantID,
		Inputs: map[string]interface{}{
			"alert_id":    alert.AlertID,
			"rule_id":     alert.RuleID,
			"rule_name":   alert.RuleName,
			"severity":    alert.Severity,
			"title":       alert.Title,
			"description": alert.Description,
		},
		Async: true,
	}

	// Add ML analysis to approval context
	if alert.MLAnalysis != nil {
		approvalReq.Inputs["ml_risk_score"] = alert.MLAnalysis.RiskScore
		approvalReq.Inputs["ml_priority"] = alert.MLAnalysis.Priority
	}

	// For approval workflow, we still trigger the playbook but it will pause at approval step
	// The playbook should have an approval node at the beginning
	_, err := h.engine.ExecutePlaybook(ctx, approvalReq)
	return err
}
