// Package engine provides the core SOAR orchestration engine.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"

	"github.com/siem-soar-platform/services/soar/internal/connector"
	"github.com/siem-soar-platform/services/soar/internal/executor"
	"github.com/siem-soar-platform/services/soar/internal/integration"
	"github.com/siem-soar-platform/services/soar/internal/playbook"
)

// SOAREngine is the main orchestration engine for SOAR operations.
type SOAREngine struct {
	temporalClient  client.Client
	playbookRepo    playbook.Store
	executionStore  playbook.ExecutionStore
	integrationHub  *integration.Hub
	executor        *executor.Executor
	eventBus        EventBus
	caseClient      CaseClient
	alertClient     AlertClient
	metricsRecorder MetricsRecorder
	logger          *slog.Logger
	config          *EngineConfig

	mu               sync.RWMutex
	autoTriggers     map[string]*AutoTrigger
	scheduledJobs    map[string]*ScheduledJob
	rateLimiters     map[string]*RateLimiter
	circuitBreakers  map[string]*CircuitBreaker
}

// EngineConfig configures the SOAR engine.
type EngineConfig struct {
	Namespace           string
	TaskQueue           string
	DefaultTimeout      time.Duration
	MaxConcurrentExecs  int
	EnableAutoTrigger   bool
	EnableMetrics       bool
	EnableTracing       bool
	AlertPollingInterval time.Duration
	CasePollingInterval  time.Duration
	HealthCheckInterval  time.Duration
}

// DefaultEngineConfig returns default configuration.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		Namespace:            "siem-soar",
		TaskQueue:            "playbook-execution",
		DefaultTimeout:       24 * time.Hour,
		MaxConcurrentExecs:   1000,
		EnableAutoTrigger:    true,
		EnableMetrics:        true,
		EnableTracing:        true,
		AlertPollingInterval: 5 * time.Second,
		CasePollingInterval:  10 * time.Second,
		HealthCheckInterval:  30 * time.Second,
	}
}

// EventBus defines the interface for event publishing.
type EventBus interface {
	Publish(ctx context.Context, topic string, event interface{}) error
	Subscribe(topic string, handler func(event interface{})) error
}

// CaseClient defines the interface for case service integration.
type CaseClient interface {
	CreateCase(ctx context.Context, req *CreateCaseRequest) (*CaseResponse, error)
	UpdateCase(ctx context.Context, caseID string, req *UpdateCaseRequest) error
	AddTimeline(ctx context.Context, caseID string, entry *TimelineEntry) error
	AddEvidence(ctx context.Context, caseID string, evidence *Evidence) error
	GetCase(ctx context.Context, caseID string) (*CaseResponse, error)
}

// AlertClient defines the interface for alert service integration.
type AlertClient interface {
	GetAlert(ctx context.Context, alertID string) (*AlertResponse, error)
	UpdateAlertStatus(ctx context.Context, alertID string, status string) error
	GetPendingAlerts(ctx context.Context, filter *AlertFilter) ([]*AlertResponse, error)
}

// MetricsRecorder defines the interface for metrics recording.
type MetricsRecorder interface {
	RecordExecution(playbook string, duration time.Duration, success bool)
	RecordConnectorCall(connector, action string, duration time.Duration, success bool)
	RecordError(component, errorType string)
	IncrementCounter(name string, labels map[string]string)
}

// CreateCaseRequest represents a case creation request.
type CreateCaseRequest struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	AlertIDs    []string          `json:"alert_ids,omitempty"`
	Assignee    string            `json:"assignee,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// UpdateCaseRequest represents a case update request.
type UpdateCaseRequest struct {
	Status      string            `json:"status,omitempty"`
	Assignee    string            `json:"assignee,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Resolution  string            `json:"resolution,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CaseResponse represents a case from the case service.
type CaseResponse struct {
	ID          string    `json:"id"`
	Number      string    `json:"number"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Assignee    string    `json:"assignee"`
	CreatedAt   time.Time `json:"created_at"`
}

// TimelineEntry represents a case timeline entry.
type TimelineEntry struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Actor       string                 `json:"actor"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Evidence represents case evidence.
type Evidence struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Data        interface{}            `json:"data"`
	Source      string                 `json:"source"`
	CollectedAt time.Time              `json:"collected_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertResponse represents an alert from the alert service.
type AlertResponse struct {
	ID        string                 `json:"id"`
	RuleID    string                 `json:"rule_id"`
	RuleName  string                 `json:"rule_name"`
	Severity  string                 `json:"severity"`
	Status    string                 `json:"status"`
	Data      map[string]interface{} `json:"data"`
	CreatedAt time.Time              `json:"created_at"`
}

// AlertFilter defines filters for querying alerts.
type AlertFilter struct {
	Status    []string  `json:"status,omitempty"`
	Severity  []string  `json:"severity,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

// AutoTrigger represents an automatic playbook trigger.
type AutoTrigger struct {
	ID         string
	PlaybookID string
	Conditions []playbook.Condition
	Enabled    bool
	LastRun    time.Time
	RunCount   int64
}

// ScheduledJob represents a scheduled playbook execution.
type ScheduledJob struct {
	ID           string
	PlaybookID   string
	Schedule     string
	NextRun      time.Time
	LastRun      time.Time
	Enabled      bool
	WorkflowID   string
}

// RateLimiter controls execution rate for playbooks.
type RateLimiter struct {
	PlaybookID    string
	MaxExecutions int
	Window        time.Duration
	Tokens        int
	LastRefill    time.Time
	mu            sync.Mutex
}

// CircuitBreaker implements circuit breaker pattern for connectors.
type CircuitBreaker struct {
	Name          string
	State         CircuitState
	Failures      int
	Successes     int
	Threshold     int
	ResetTimeout  time.Duration
	LastStateChange time.Time
	mu            sync.Mutex
}

// CircuitState represents circuit breaker state.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// NewSOAREngine creates a new SOAR engine instance.
func NewSOAREngine(
	temporalClient client.Client,
	playbookRepo playbook.Store,
	executionStore playbook.ExecutionStore,
	integrationHub *integration.Hub,
	eventBus EventBus,
	caseClient CaseClient,
	alertClient AlertClient,
	config *EngineConfig,
	logger *slog.Logger,
) *SOAREngine {
	if config == nil {
		config = DefaultEngineConfig()
	}

	executorOpts := executor.ExecutorOptions{
		Namespace:          config.Namespace,
		TaskQueue:          config.TaskQueue,
		DefaultTimeout:     config.DefaultTimeout,
		MaxConcurrentExecs: config.MaxConcurrentExecs,
		EnableMetrics:      config.EnableMetrics,
		EnableTracing:      config.EnableTracing,
	}

	// Create adapter for executor
	hubAdapter := newConnectorRegistryAdapter(integrationHub)

	exec := executor.NewExecutor(
		temporalClient,
		playbookRepo,
		executionStore,
		hubAdapter,
		executorOpts,
		logger,
	)

	return &SOAREngine{
		temporalClient:   temporalClient,
		playbookRepo:     playbookRepo,
		executionStore:   executionStore,
		integrationHub:   integrationHub,
		executor:         exec,
		eventBus:         eventBus,
		caseClient:       caseClient,
		alertClient:      alertClient,
		logger:           logger,
		config:           config,
		autoTriggers:     make(map[string]*AutoTrigger),
		scheduledJobs:    make(map[string]*ScheduledJob),
		rateLimiters:     make(map[string]*RateLimiter),
		circuitBreakers:  make(map[string]*CircuitBreaker),
	}
}

// Start starts the SOAR engine background processes.
func (e *SOAREngine) Start(ctx context.Context) error {
	e.logger.Info("Starting SOAR engine",
		"namespace", e.config.Namespace,
		"task_queue", e.config.TaskQueue,
	)

	// Load auto triggers from playbooks
	if e.config.EnableAutoTrigger {
		if err := e.loadAutoTriggers(ctx); err != nil {
			return fmt.Errorf("failed to load auto triggers: %w", err)
		}

		// Start alert monitoring
		go e.alertMonitor(ctx)
	}

	// Start health check loop
	go e.healthCheckLoop(ctx)

	// Publish engine started event
	if e.eventBus != nil {
		e.eventBus.Publish(ctx, "soar.engine.started", map[string]interface{}{
			"timestamp": time.Now(),
			"namespace": e.config.Namespace,
		})
	}

	return nil
}

// Stop gracefully stops the SOAR engine.
func (e *SOAREngine) Stop() error {
	e.logger.Info("Stopping SOAR engine")
	return e.executor.Close()
}

// ExecutePlaybook executes a playbook with the given parameters.
func (e *SOAREngine) ExecutePlaybook(ctx context.Context, req *ExecutePlaybookRequest) (*ExecutionResponse, error) {
	// Check rate limit
	if err := e.checkRateLimit(req.PlaybookID); err != nil {
		return nil, err
	}

	// Build executor request
	execReq := &executor.ExecuteRequest{
		PlaybookID:   req.PlaybookID,
		PlaybookName: req.PlaybookName,
		Version:      req.Version,
		Inputs:       req.Inputs,
		TriggerType:  req.TriggerType,
		TriggerInfo:  req.TriggerInfo,
		AlertID:      req.AlertID,
		CaseID:       req.CaseID,
		TenantID:     req.TenantID,
		ExecutedBy:   req.ExecutedBy,
		Priority:     req.Priority,
		Async:        req.Async,
	}

	// Execute playbook
	startTime := time.Now()
	result, err := e.executor.Execute(ctx, execReq)
	duration := time.Since(startTime)

	// Record metrics
	if e.metricsRecorder != nil {
		e.metricsRecorder.RecordExecution(req.PlaybookID, duration, err == nil)
	}

	if err != nil {
		e.logger.Error("Playbook execution failed",
			"playbook_id", req.PlaybookID,
			"error", err,
			"duration_ms", duration.Milliseconds(),
		)
		return nil, err
	}

	// Publish execution event
	if e.eventBus != nil {
		e.eventBus.Publish(ctx, "soar.playbook.executed", map[string]interface{}{
			"execution_id": result.ExecutionID,
			"playbook_id":  req.PlaybookID,
			"status":       result.Status,
			"duration_ms":  duration.Milliseconds(),
		})
	}

	// Create case timeline entry if case is associated
	if req.CaseID != "" && e.caseClient != nil {
		entry := &TimelineEntry{
			Type:        "playbook_execution",
			Title:       fmt.Sprintf("Playbook executed: %s", req.PlaybookID),
			Description: fmt.Sprintf("Execution ID: %s, Status: %s", result.ExecutionID, result.Status),
			Timestamp:   time.Now(),
			Actor:       "SOAR Engine",
			Metadata: map[string]interface{}{
				"execution_id": result.ExecutionID,
				"playbook_id":  req.PlaybookID,
				"status":       string(result.Status),
			},
		}
		e.caseClient.AddTimeline(ctx, req.CaseID, entry)
	}

	return &ExecutionResponse{
		ExecutionID: result.ExecutionID,
		WorkflowID:  result.WorkflowID,
		RunID:       result.RunID,
		Status:      string(result.Status),
		Outputs:     result.Outputs,
		Error:       result.Error,
	}, nil
}

// ExecutePlaybookRequest represents a playbook execution request.
type ExecutePlaybookRequest struct {
	PlaybookID   string                 `json:"playbook_id"`
	PlaybookName string                 `json:"playbook_name,omitempty"`
	Version      int                    `json:"version,omitempty"`
	Inputs       map[string]interface{} `json:"inputs,omitempty"`
	TriggerType  playbook.TriggerType   `json:"trigger_type"`
	TriggerInfo  map[string]interface{} `json:"trigger_info,omitempty"`
	AlertID      string                 `json:"alert_id,omitempty"`
	CaseID       string                 `json:"case_id,omitempty"`
	TenantID     string                 `json:"tenant_id,omitempty"`
	ExecutedBy   string                 `json:"executed_by,omitempty"`
	Priority     int                    `json:"priority,omitempty"`
	Async        bool                   `json:"async,omitempty"`
}

// ExecutionResponse represents a playbook execution response.
type ExecutionResponse struct {
	ExecutionID string                 `json:"execution_id"`
	WorkflowID  string                 `json:"workflow_id"`
	RunID       string                 `json:"run_id"`
	Status      string                 `json:"status"`
	Outputs     map[string]interface{} `json:"outputs,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// GetExecutionStatus retrieves the status of an execution.
func (e *SOAREngine) GetExecutionStatus(ctx context.Context, executionID string) (*playbook.Execution, error) {
	return e.executor.GetStatus(ctx, executionID)
}

// ListExecutions lists executions with optional filters.
func (e *SOAREngine) ListExecutions(ctx context.Context, filter *playbook.ExecutionFilter) (*playbook.ExecutionListResult, error) {
	return e.executor.ListExecutions(ctx, filter)
}

// CancelExecution cancels a running execution.
func (e *SOAREngine) CancelExecution(ctx context.Context, executionID string) error {
	return e.executor.Cancel(ctx, executionID)
}

// PauseExecution pauses a running execution.
func (e *SOAREngine) PauseExecution(ctx context.Context, executionID string) error {
	return e.executor.Pause(ctx, executionID)
}

// ResumeExecution resumes a paused execution.
func (e *SOAREngine) ResumeExecution(ctx context.Context, executionID string) error {
	return e.executor.Resume(ctx, executionID)
}

// SendApproval sends an approval decision to a waiting execution.
func (e *SOAREngine) SendApproval(ctx context.Context, executionID string, approval *ApprovalDecision) error {
	signal := &executor.ApprovalSignal{
		StepID:   approval.StepID,
		Approved: approval.Approved,
		Approver: approval.Approver,
		Comment:  approval.Comment,
		Time:     time.Now(),
	}
	return e.executor.SendApproval(ctx, executionID, signal)
}

// ApprovalDecision represents an approval decision.
type ApprovalDecision struct {
	StepID   string `json:"step_id"`
	Approved bool   `json:"approved"`
	Approver string `json:"approver"`
	Comment  string `json:"comment,omitempty"`
}

// TriggerOnAlert triggers playbooks based on an alert.
func (e *SOAREngine) TriggerOnAlert(ctx context.Context, alert *AlertResponse) ([]*ExecutionResponse, error) {
	e.mu.RLock()
	triggers := make([]*AutoTrigger, 0)
	for _, t := range e.autoTriggers {
		if t.Enabled && e.matchesAlertConditions(alert, t.Conditions) {
			triggers = append(triggers, t)
		}
	}
	e.mu.RUnlock()

	var results []*ExecutionResponse
	for _, trigger := range triggers {
		req := &ExecutePlaybookRequest{
			PlaybookID:  trigger.PlaybookID,
			TriggerType: playbook.TriggerAlert,
			TriggerInfo: map[string]interface{}{
				"alert_id":   alert.ID,
				"rule_id":    alert.RuleID,
				"rule_name":  alert.RuleName,
				"severity":   alert.Severity,
				"trigger_id": trigger.ID,
			},
			AlertID: alert.ID,
			Inputs:  alert.Data,
			Async:   true,
		}

		result, err := e.ExecutePlaybook(ctx, req)
		if err != nil {
			e.logger.Error("Failed to trigger playbook for alert",
				"playbook_id", trigger.PlaybookID,
				"alert_id", alert.ID,
				"error", err,
			)
			continue
		}

		results = append(results, result)

		// Update trigger stats
		e.mu.Lock()
		trigger.LastRun = time.Now()
		trigger.RunCount++
		e.mu.Unlock()
	}

	return results, nil
}

// CreateIncidentFromAlert creates a case/incident from an alert and executes investigation playbook.
func (e *SOAREngine) CreateIncidentFromAlert(ctx context.Context, alertID string, playbookID string) (*IncidentResponse, error) {
	// Get alert details
	alert, err := e.alertClient.GetAlert(ctx, alertID)
	if err != nil {
		return nil, fmt.Errorf("failed to get alert: %w", err)
	}

	// Create case
	caseReq := &CreateCaseRequest{
		Title:       fmt.Sprintf("[%s] %s", alert.Severity, alert.RuleName),
		Description: fmt.Sprintf("Auto-created from alert %s", alertID),
		Severity:    alert.Severity,
		AlertIDs:    []string{alertID},
		Metadata: map[string]string{
			"source":    "soar_engine",
			"alert_id":  alertID,
			"rule_id":   alert.RuleID,
			"rule_name": alert.RuleName,
		},
	}

	caseResp, err := e.caseClient.CreateCase(ctx, caseReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create case: %w", err)
	}

	// Update alert status
	if err := e.alertClient.UpdateAlertStatus(ctx, alertID, "investigating"); err != nil {
		e.logger.Warn("Failed to update alert status", "alert_id", alertID, "error", err)
	}

	// Execute investigation playbook if specified
	var execResult *ExecutionResponse
	if playbookID != "" {
		req := &ExecutePlaybookRequest{
			PlaybookID:  playbookID,
			TriggerType: playbook.TriggerIncident,
			TriggerInfo: map[string]interface{}{
				"case_id":  caseResp.ID,
				"alert_id": alertID,
			},
			AlertID: alertID,
			CaseID:  caseResp.ID,
			Inputs:  alert.Data,
			Async:   true,
		}

		execResult, _ = e.ExecutePlaybook(ctx, req)
	}

	response := &IncidentResponse{
		CaseID:      caseResp.ID,
		CaseNumber:  caseResp.Number,
		AlertID:     alertID,
		Status:      "created",
		CreatedAt:   time.Now(),
	}

	if execResult != nil {
		response.ExecutionID = execResult.ExecutionID
	}

	return response, nil
}

// IncidentResponse represents the response from incident creation.
type IncidentResponse struct {
	CaseID      string    `json:"case_id"`
	CaseNumber  string    `json:"case_number"`
	AlertID     string    `json:"alert_id"`
	ExecutionID string    `json:"execution_id,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetMetrics returns current engine metrics.
func (e *SOAREngine) GetMetrics(ctx context.Context) (*EngineMetrics, error) {
	execMetrics, err := e.executor.Metrics(ctx)
	if err != nil {
		return nil, err
	}

	e.mu.RLock()
	autoTriggerCount := len(e.autoTriggers)
	scheduledJobCount := len(e.scheduledJobs)
	e.mu.RUnlock()

	connectorHealth := e.integrationHub.HealthCheck(ctx)

	return &EngineMetrics{
		RunningExecutions:   execMetrics.RunningExecutions,
		TotalExecutions:     execMetrics.TotalExecutions,
		SuccessRate:         execMetrics.SuccessRate,
		AverageDurationMs:   execMetrics.AverageDuration,
		ActiveTriggers:      autoTriggerCount,
		ScheduledJobs:       scheduledJobCount,
		ConnectorStatus:     connectorHealth,
		Timestamp:           time.Now(),
	}, nil
}

// EngineMetrics contains SOAR engine metrics.
type EngineMetrics struct {
	RunningExecutions   int                      `json:"running_executions"`
	TotalExecutions     int64                    `json:"total_executions"`
	SuccessRate         float64                  `json:"success_rate"`
	AverageDurationMs   float64                  `json:"average_duration_ms"`
	ActiveTriggers      int                      `json:"active_triggers"`
	ScheduledJobs       int                      `json:"scheduled_jobs"`
	ConnectorStatus     map[string]*integration.HealthStatus `json:"connector_status"`
	Timestamp           time.Time                `json:"timestamp"`
}

// loadAutoTriggers loads automatic triggers from playbooks.
func (e *SOAREngine) loadAutoTriggers(ctx context.Context) error {
	enabled := true
	filter := &playbook.ListFilter{
		Trigger: playbook.TriggerAutomatic,
		Enabled: &enabled,
	}

	result, err := e.playbookRepo.List(ctx, filter)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, pb := range result.Playbooks {
		trigger := &AutoTrigger{
			ID:         uuid.New().String(),
			PlaybookID: pb.ID,
			Conditions: pb.Trigger.Conditions,
			Enabled:    true,
		}
		e.autoTriggers[trigger.ID] = trigger
	}

	e.logger.Info("Loaded auto triggers", "count", len(e.autoTriggers))
	return nil
}

// alertMonitor monitors for new alerts and triggers playbooks.
func (e *SOAREngine) alertMonitor(ctx context.Context) {
	ticker := time.NewTicker(e.config.AlertPollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			filter := &AlertFilter{
				Status: []string{"new", "open"},
				Limit:  100,
			}

			alerts, err := e.alertClient.GetPendingAlerts(ctx, filter)
			if err != nil {
				e.logger.Error("Failed to fetch pending alerts", "error", err)
				continue
			}

			for _, alert := range alerts {
				e.TriggerOnAlert(ctx, alert)
			}
		}
	}
}

// healthCheckLoop performs periodic health checks.
func (e *SOAREngine) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(e.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check connector health
			healthStatus := e.integrationHub.HealthCheck(ctx)
			for name, status := range healthStatus {
				if status.Status != "healthy" {
					e.logger.Warn("Connector unhealthy",
						"connector", name,
						"status", status.Status,
						"error", status.Error,
					)
				}
			}
		}
	}
}

// matchesAlertConditions checks if an alert matches trigger conditions.
func (e *SOAREngine) matchesAlertConditions(alert *AlertResponse, conditions []playbook.Condition) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, cond := range conditions {
		if !e.evaluateCondition(alert.Data, cond) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition against data.
func (e *SOAREngine) evaluateCondition(data map[string]interface{}, cond playbook.Condition) bool {
	value, ok := data[cond.Field]
	if !ok {
		return cond.Operator == playbook.OpNotExists
	}

	switch cond.Operator {
	case playbook.OpEquals:
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	case playbook.OpNotEquals:
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", cond.Value)
	case playbook.OpExists:
		return true
	case playbook.OpNotExists:
		return false
	case playbook.OpContains:
		return containsString(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	default:
		return false
	}
}

// checkRateLimit checks if execution is within rate limits.
func (e *SOAREngine) checkRateLimit(playbookID string) error {
	e.mu.RLock()
	limiter, exists := e.rateLimiters[playbookID]
	e.mu.RUnlock()

	if !exists {
		return nil
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(limiter.LastRefill)
	if elapsed >= limiter.Window {
		limiter.Tokens = limiter.MaxExecutions
		limiter.LastRefill = now
	}

	// Check and consume token
	if limiter.Tokens <= 0 {
		return fmt.Errorf("rate limit exceeded for playbook %s", playbookID)
	}

	limiter.Tokens--
	return nil
}

// Helper functions

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0)
}

// connectorRegistryAdapter adapts integration.Hub to executor.ConnectorRegistry.
type connectorRegistryAdapter struct {
	hub *integration.Hub
}

// newConnectorRegistryAdapter creates a new registry adapter.
func newConnectorRegistryAdapter(hub *integration.Hub) *connectorRegistryAdapter {
	return &connectorRegistryAdapter{hub: hub}
}

// GetConnector retrieves a connector and wraps it to match executor.Connector interface.
func (a *connectorRegistryAdapter) GetConnector(name string) (executor.Connector, error) {
	conn, err := a.hub.GetConnector(name)
	if err != nil {
		return nil, err
	}
	return &executorConnectorWrapper{conn: conn}, nil
}

// ListConnectors lists all available connector names.
func (a *connectorRegistryAdapter) ListConnectors() []string {
	connInfos := a.hub.ListConnectors()
	names := make([]string, 0, len(connInfos))
	for _, info := range connInfos {
		names = append(names, info.Name)
	}
	return names
}

// executorConnectorWrapper wraps ActionConnector to implement executor.Connector.
type executorConnectorWrapper struct {
	conn connector.ActionConnector
}

// Execute executes an action.
func (w *executorConnectorWrapper) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	return w.conn.Execute(ctx, action, params)
}

// AvailableActions returns the list of action names.
func (w *executorConnectorWrapper) AvailableActions() []string {
	return w.conn.Actions()
}
