// Package executor provides the playbook execution engine.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"

	"github.com/siem-soar-platform/services/soar/internal/playbook"
)

// Executor is the main playbook execution engine.
type Executor struct {
	temporalClient client.Client
	playbookStore  playbook.Store
	executionStore playbook.ExecutionStore
	connectorRegistry ConnectorRegistry
	options        ExecutorOptions
	logger         *slog.Logger

	mu             sync.RWMutex
	runningExecs   map[string]*ExecutionContext
}

// ExecutorOptions configures the executor.
type ExecutorOptions struct {
	Namespace           string
	TaskQueue           string
	DefaultTimeout      time.Duration
	MaxConcurrentExecs  int
	EnableMetrics       bool
	EnableTracing       bool
}

// DefaultExecutorOptions returns default options.
func DefaultExecutorOptions() ExecutorOptions {
	return ExecutorOptions{
		Namespace:          "siem-soar",
		TaskQueue:          "playbook-execution",
		DefaultTimeout:     24 * time.Hour,
		MaxConcurrentExecs: 1000,
		EnableMetrics:      true,
		EnableTracing:      true,
	}
}

// ConnectorRegistry provides access to connectors.
type ConnectorRegistry interface {
	GetConnector(name string) (Connector, error)
	ListConnectors() []string
}

// Connector executes actions.
type Connector interface {
	Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
	AvailableActions() []string
}

// ExecutionContext holds the context for a running execution.
type ExecutionContext struct {
	Execution    *playbook.Execution
	Playbook     *playbook.Playbook
	Variables    map[string]interface{}
	StepOutputs  map[string]interface{}
	CancelFunc   context.CancelFunc
	StartTime    time.Time
}

// NewExecutor creates a new playbook executor.
func NewExecutor(
	temporalClient client.Client,
	playbookStore playbook.Store,
	executionStore playbook.ExecutionStore,
	connectorRegistry ConnectorRegistry,
	opts ExecutorOptions,
	logger *slog.Logger,
) *Executor {
	return &Executor{
		temporalClient:    temporalClient,
		playbookStore:     playbookStore,
		executionStore:    executionStore,
		connectorRegistry: connectorRegistry,
		options:           opts,
		logger:            logger,
		runningExecs:      make(map[string]*ExecutionContext),
	}
}

// ExecuteRequest represents a playbook execution request.
type ExecuteRequest struct {
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

// ExecuteResponse represents a playbook execution response.
type ExecuteResponse struct {
	ExecutionID string                  `json:"execution_id"`
	WorkflowID  string                  `json:"workflow_id"`
	RunID       string                  `json:"run_id"`
	Status      playbook.ExecutionStatus `json:"status"`
	Outputs     map[string]interface{}  `json:"outputs,omitempty"`
	Error       string                  `json:"error,omitempty"`
}

// Execute starts a playbook execution.
func (e *Executor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	// Get playbook
	var pb *playbook.Playbook
	var err error

	if req.PlaybookID != "" {
		if req.Version > 0 {
			pb, err = e.playbookStore.GetVersion(ctx, req.PlaybookID, req.Version)
		} else {
			pb, err = e.playbookStore.Get(ctx, req.PlaybookID)
		}
	} else if req.PlaybookName != "" {
		pb, err = e.playbookStore.GetByName(ctx, req.PlaybookName)
	} else {
		return nil, fmt.Errorf("playbook ID or name is required")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get playbook: %w", err)
	}

	if !pb.Enabled {
		return nil, fmt.Errorf("playbook %s is disabled", pb.ID)
	}

	// Validate inputs
	if err := e.validateInputs(pb, req.Inputs); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Create execution record
	execution := &playbook.Execution{
		ID:           uuid.New().String(),
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		Version:      pb.Version,
		Status:       playbook.StatusPending,
		Inputs:       req.Inputs,
		TriggerType:  req.TriggerType,
		TriggerInfo:  req.TriggerInfo,
		AlertID:      req.AlertID,
		CaseID:       req.CaseID,
		TenantID:     req.TenantID,
		ExecutedBy:   req.ExecutedBy,
		StartedAt:    time.Now(),
		StepResults:  make([]playbook.StepResult, 0),
	}

	// Start Temporal workflow
	workflowID := fmt.Sprintf("playbook-%s-%s", pb.ID, execution.ID)
	workflowOptions := client.StartWorkflowOptions{
		ID:                       workflowID,
		TaskQueue:                e.options.TaskQueue,
		WorkflowExecutionTimeout: time.Duration(pb.Timeout),
		SearchAttributes: map[string]interface{}{
			"PlaybookID":       pb.ID,
			"PlaybookName":     pb.Name,
			"PlaybookCategory": string(pb.Category),
			"ExecutionStatus":  string(playbook.StatusPending),
			"TenantID":         req.TenantID,
		},
	}

	if pb.Timeout == 0 {
		workflowOptions.WorkflowExecutionTimeout = e.options.DefaultTimeout
	}

	// Prepare workflow input
	workflowInput := PlaybookWorkflowInput{
		ExecutionID: execution.ID,
		Playbook:    pb,
		Inputs:      req.Inputs,
		TriggerInfo: req.TriggerInfo,
		TenantID:    req.TenantID,
	}

	// Start workflow
	workflowRun, err := e.temporalClient.ExecuteWorkflow(ctx, workflowOptions, PlaybookWorkflow, workflowInput)
	if err != nil {
		return nil, fmt.Errorf("failed to start workflow: %w", err)
	}

	execution.WorkflowID = workflowRun.GetID()
	execution.RunID = workflowRun.GetRunID()
	execution.Status = playbook.StatusRunning

	// Save execution
	if err := e.executionStore.Create(ctx, execution); err != nil {
		e.logger.Error("failed to save execution", "error", err, "execution_id", execution.ID)
	}

	response := &ExecuteResponse{
		ExecutionID: execution.ID,
		WorkflowID:  execution.WorkflowID,
		RunID:       execution.RunID,
		Status:      execution.Status,
	}

	// If synchronous, wait for completion
	if !req.Async {
		var result PlaybookWorkflowOutput
		err := workflowRun.Get(ctx, &result)
		if err != nil {
			response.Status = playbook.StatusFailed
			response.Error = err.Error()
		} else {
			response.Status = result.Status
			response.Outputs = result.Outputs
			if result.Error != "" {
				response.Error = result.Error
			}
		}
	}

	return response, nil
}

// validateInputs validates playbook inputs.
func (e *Executor) validateInputs(pb *playbook.Playbook, inputs map[string]interface{}) error {
	for _, input := range pb.Inputs {
		value, exists := inputs[input.Name]

		if input.Required && !exists {
			return fmt.Errorf("required input %s is missing", input.Name)
		}

		if exists && input.Validation != nil {
			if err := validateValue(value, input.Validation); err != nil {
				return fmt.Errorf("input %s validation failed: %w", input.Name, err)
			}
		}
	}

	return nil
}

// validateValue validates a value against validation rules.
func validateValue(value interface{}, validation *playbook.Validation) error {
	// Type-specific validation
	switch v := value.(type) {
	case string:
		if validation.MinLength > 0 && len(v) < validation.MinLength {
			return fmt.Errorf("string too short (min: %d)", validation.MinLength)
		}
		if validation.MaxLength > 0 && len(v) > validation.MaxLength {
			return fmt.Errorf("string too long (max: %d)", validation.MaxLength)
		}
		if len(validation.Enum) > 0 {
			found := false
			for _, e := range validation.Enum {
				if v == e {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("value not in allowed list")
			}
		}
	}

	return nil
}

// Cancel cancels a running execution.
func (e *Executor) Cancel(ctx context.Context, executionID string) error {
	execution, err := e.executionStore.Get(ctx, executionID)
	if err != nil {
		return err
	}

	if execution.Status != playbook.StatusRunning && execution.Status != playbook.StatusWaiting {
		return fmt.Errorf("execution %s is not running (status: %s)", executionID, execution.Status)
	}

	err = e.temporalClient.CancelWorkflow(ctx, execution.WorkflowID, execution.RunID)
	if err != nil {
		return fmt.Errorf("failed to cancel workflow: %w", err)
	}

	return e.executionStore.UpdateStatus(ctx, executionID, playbook.StatusCancelled, "Cancelled by user")
}

// Pause pauses a running execution (signals the workflow).
func (e *Executor) Pause(ctx context.Context, executionID string) error {
	execution, err := e.executionStore.Get(ctx, executionID)
	if err != nil {
		return err
	}

	err = e.temporalClient.SignalWorkflow(ctx, execution.WorkflowID, execution.RunID, SignalPause, nil)
	if err != nil {
		return fmt.Errorf("failed to pause workflow: %w", err)
	}

	return e.executionStore.UpdateStatus(ctx, executionID, playbook.StatusPaused, "")
}

// Resume resumes a paused execution.
func (e *Executor) Resume(ctx context.Context, executionID string) error {
	execution, err := e.executionStore.Get(ctx, executionID)
	if err != nil {
		return err
	}

	err = e.temporalClient.SignalWorkflow(ctx, execution.WorkflowID, execution.RunID, SignalResume, nil)
	if err != nil {
		return fmt.Errorf("failed to resume workflow: %w", err)
	}

	return e.executionStore.UpdateStatus(ctx, executionID, playbook.StatusRunning, "")
}

// GetStatus gets the current status of an execution.
func (e *Executor) GetStatus(ctx context.Context, executionID string) (*playbook.Execution, error) {
	return e.executionStore.Get(ctx, executionID)
}

// ListExecutions lists executions with filters.
func (e *Executor) ListExecutions(ctx context.Context, filter *playbook.ExecutionFilter) (*playbook.ExecutionListResult, error) {
	return e.executionStore.List(ctx, filter)
}

// RetryExecution retries a failed execution.
func (e *Executor) RetryExecution(ctx context.Context, executionID string) (*ExecuteResponse, error) {
	execution, err := e.executionStore.Get(ctx, executionID)
	if err != nil {
		return nil, err
	}

	if execution.Status != playbook.StatusFailed {
		return nil, fmt.Errorf("can only retry failed executions")
	}

	// Create new execution request from original
	req := &ExecuteRequest{
		PlaybookID:  execution.PlaybookID,
		Version:     execution.Version,
		Inputs:      execution.Inputs,
		TriggerType: execution.TriggerType,
		TriggerInfo: execution.TriggerInfo,
		AlertID:     execution.AlertID,
		CaseID:      execution.CaseID,
		TenantID:    execution.TenantID,
		ExecutedBy:  execution.ExecutedBy,
	}

	return e.Execute(ctx, req)
}

// Signal names for workflow control.
const (
	SignalPause    = "pause"
	SignalResume   = "resume"
	SignalApproval = "approval"
	SignalCancel   = "cancel"
)

// ApprovalSignal represents an approval signal payload.
type ApprovalSignal struct {
	StepID   string    `json:"step_id"`
	Approved bool      `json:"approved"`
	Approver string    `json:"approver"`
	Comment  string    `json:"comment,omitempty"`
	Time     time.Time `json:"time"`
}

// SendApproval sends an approval signal to a waiting execution.
func (e *Executor) SendApproval(ctx context.Context, executionID string, approval *ApprovalSignal) error {
	execution, err := e.executionStore.Get(ctx, executionID)
	if err != nil {
		return err
	}

	if execution.Status != playbook.StatusWaiting {
		return fmt.Errorf("execution %s is not waiting for approval", executionID)
	}

	approval.Time = time.Now()

	err = e.temporalClient.SignalWorkflow(ctx, execution.WorkflowID, execution.RunID, SignalApproval, approval)
	if err != nil {
		return fmt.Errorf("failed to send approval signal: %w", err)
	}

	return nil
}

// Metrics returns execution metrics.
func (e *Executor) Metrics(ctx context.Context) (*ExecutionMetrics, error) {
	e.mu.RLock()
	runningCount := len(e.runningExecs)
	e.mu.RUnlock()

	return &ExecutionMetrics{
		RunningExecutions: runningCount,
		Timestamp:         time.Now(),
	}, nil
}

// ExecutionMetrics contains execution metrics.
type ExecutionMetrics struct {
	RunningExecutions int       `json:"running_executions"`
	TotalExecutions   int64     `json:"total_executions"`
	SuccessRate       float64   `json:"success_rate"`
	AverageDuration   float64   `json:"average_duration_ms"`
	Timestamp         time.Time `json:"timestamp"`
}

// Close closes the executor.
func (e *Executor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Cancel all running contexts
	for _, ctx := range e.runningExecs {
		if ctx.CancelFunc != nil {
			ctx.CancelFunc()
		}
	}

	e.runningExecs = make(map[string]*ExecutionContext)
	return nil
}
