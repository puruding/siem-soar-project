// Package engine provides the orchestrator for complex multi-playbook scenarios.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/soar/internal/playbook"
)

// Orchestrator manages complex multi-playbook execution scenarios.
type Orchestrator struct {
	engine           *SOAREngine
	workflows        map[string]*OrchestratorWorkflow
	runningWorkflows map[string]*WorkflowExecution
	mu               sync.RWMutex
	logger           *slog.Logger
}

// OrchestratorWorkflow defines a multi-playbook orchestration workflow.
type OrchestratorWorkflow struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Stages      []WorkflowStage           `json:"stages"`
	Inputs      []playbook.InputParameter `json:"inputs,omitempty"`
	Outputs     []playbook.OutputField    `json:"outputs,omitempty"`
	ErrorPolicy ErrorPolicy               `json:"error_policy"`
	Timeout     time.Duration             `json:"timeout"`
	Enabled     bool                      `json:"enabled"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// WorkflowStage represents a stage in an orchestration workflow.
type WorkflowStage struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          StageType              `json:"type"`
	PlaybookIDs   []string               `json:"playbook_ids,omitempty"`
	Conditions    []playbook.Condition   `json:"conditions,omitempty"`
	InputMapping  map[string]string      `json:"input_mapping,omitempty"`
	OutputMapping map[string]string      `json:"output_mapping,omitempty"`
	OnSuccess     string                 `json:"on_success,omitempty"`
	OnFailure     string                 `json:"on_failure,omitempty"`
	Parallel      bool                   `json:"parallel"`
	MaxConcurrent int                    `json:"max_concurrent,omitempty"`
	Timeout       time.Duration          `json:"timeout,omitempty"`
	RetryPolicy   *playbook.RetryPolicy  `json:"retry_policy,omitempty"`
}

// StageType represents the type of workflow stage.
type StageType string

const (
	StageTypeSequential StageType = "sequential"
	StageTypeParallel   StageType = "parallel"
	StageTypeConditional StageType = "conditional"
	StageTypeLoop       StageType = "loop"
	StageTypeGate       StageType = "gate"
)

// ErrorPolicy defines how errors are handled in the workflow.
type ErrorPolicy string

const (
	ErrorPolicyAbort    ErrorPolicy = "abort"
	ErrorPolicyContinue ErrorPolicy = "continue"
	ErrorPolicyRetry    ErrorPolicy = "retry"
	ErrorPolicyFallback ErrorPolicy = "fallback"
)

// WorkflowExecution represents a running orchestration workflow.
type WorkflowExecution struct {
	ID            string                 `json:"id"`
	WorkflowID    string                 `json:"workflow_id"`
	WorkflowName  string                 `json:"workflow_name"`
	Status        WorkflowStatus         `json:"status"`
	CurrentStage  string                 `json:"current_stage"`
	StageResults  []StageResult          `json:"stage_results"`
	Inputs        map[string]interface{} `json:"inputs"`
	Outputs       map[string]interface{} `json:"outputs,omitempty"`
	Context       map[string]interface{} `json:"context"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
	Error         string                 `json:"error,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	ExecutedBy    string                 `json:"executed_by,omitempty"`
}

// WorkflowStatus represents the status of a workflow execution.
type WorkflowStatus string

const (
	WorkflowStatusPending   WorkflowStatus = "pending"
	WorkflowStatusRunning   WorkflowStatus = "running"
	WorkflowStatusCompleted WorkflowStatus = "completed"
	WorkflowStatusFailed    WorkflowStatus = "failed"
	WorkflowStatusCancelled WorkflowStatus = "cancelled"
	WorkflowStatusPaused    WorkflowStatus = "paused"
)

// StageResult represents the result of a workflow stage.
type StageResult struct {
	StageID      string                 `json:"stage_id"`
	StageName    string                 `json:"stage_name"`
	Status       WorkflowStatus         `json:"status"`
	Executions   []string               `json:"executions"` // Playbook execution IDs
	Outputs      map[string]interface{} `json:"outputs,omitempty"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Duration     time.Duration          `json:"duration_ms"`
	Error        string                 `json:"error,omitempty"`
	RetryCount   int                    `json:"retry_count"`
}

// NewOrchestrator creates a new orchestrator instance.
func NewOrchestrator(engine *SOAREngine, logger *slog.Logger) *Orchestrator {
	return &Orchestrator{
		engine:           engine,
		workflows:        make(map[string]*OrchestratorWorkflow),
		runningWorkflows: make(map[string]*WorkflowExecution),
		logger:           logger,
	}
}

// RegisterWorkflow registers an orchestration workflow.
func (o *Orchestrator) RegisterWorkflow(workflow *OrchestratorWorkflow) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if workflow.ID == "" {
		workflow.ID = uuid.New().String()
	}

	now := time.Now()
	workflow.CreatedAt = now
	workflow.UpdatedAt = now

	o.workflows[workflow.ID] = workflow
	o.logger.Info("Registered orchestration workflow",
		"workflow_id", workflow.ID,
		"name", workflow.Name,
		"stages", len(workflow.Stages),
	)

	return nil
}

// ExecuteWorkflow executes an orchestration workflow.
func (o *Orchestrator) ExecuteWorkflow(ctx context.Context, req *ExecuteWorkflowRequest) (*WorkflowExecution, error) {
	o.mu.RLock()
	workflow, exists := o.workflows[req.WorkflowID]
	o.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("workflow %s not found", req.WorkflowID)
	}

	if !workflow.Enabled {
		return nil, fmt.Errorf("workflow %s is disabled", req.WorkflowID)
	}

	// Create execution record
	execution := &WorkflowExecution{
		ID:           uuid.New().String(),
		WorkflowID:   workflow.ID,
		WorkflowName: workflow.Name,
		Status:       WorkflowStatusRunning,
		StageResults: make([]StageResult, 0),
		Inputs:       req.Inputs,
		Context:      make(map[string]interface{}),
		StartedAt:    time.Now(),
		TenantID:     req.TenantID,
		ExecutedBy:   req.ExecutedBy,
	}

	// Copy inputs to context
	for k, v := range req.Inputs {
		execution.Context[k] = v
	}

	o.mu.Lock()
	o.runningWorkflows[execution.ID] = execution
	o.mu.Unlock()

	// Execute workflow in goroutine if async
	if req.Async {
		go o.runWorkflow(ctx, workflow, execution)
		return execution, nil
	}

	// Execute synchronously
	if err := o.runWorkflow(ctx, workflow, execution); err != nil {
		return execution, err
	}

	return execution, nil
}

// ExecuteWorkflowRequest represents a workflow execution request.
type ExecuteWorkflowRequest struct {
	WorkflowID string                 `json:"workflow_id"`
	Inputs     map[string]interface{} `json:"inputs,omitempty"`
	TenantID   string                 `json:"tenant_id,omitempty"`
	ExecutedBy string                 `json:"executed_by,omitempty"`
	Async      bool                   `json:"async"`
}

// runWorkflow executes the workflow stages.
func (o *Orchestrator) runWorkflow(ctx context.Context, workflow *OrchestratorWorkflow, execution *WorkflowExecution) error {
	// Set up timeout
	if workflow.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, workflow.Timeout)
		defer cancel()
	}

	// Execute stages
	for _, stage := range workflow.Stages {
		select {
		case <-ctx.Done():
			o.completeExecution(execution, WorkflowStatusCancelled, "workflow cancelled or timed out")
			return ctx.Err()
		default:
		}

		// Check stage conditions
		if len(stage.Conditions) > 0 && !o.evaluateConditions(execution.Context, stage.Conditions) {
			o.logger.Info("Skipping stage due to conditions",
				"workflow_id", workflow.ID,
				"stage_id", stage.ID,
			)
			continue
		}

		// Execute stage
		execution.CurrentStage = stage.ID
		result, err := o.executeStage(ctx, &stage, execution)
		execution.StageResults = append(execution.StageResults, *result)

		if err != nil {
			switch workflow.ErrorPolicy {
			case ErrorPolicyAbort:
				o.completeExecution(execution, WorkflowStatusFailed, err.Error())
				return err
			case ErrorPolicyContinue:
				o.logger.Warn("Stage failed, continuing workflow",
					"workflow_id", workflow.ID,
					"stage_id", stage.ID,
					"error", err,
				)
			case ErrorPolicyRetry:
				// Retry logic would go here
				if result.RetryCount < 3 {
					// Retry
				}
			}
		}

		// Handle stage routing
		nextStage := stage.OnSuccess
		if result.Status == WorkflowStatusFailed && stage.OnFailure != "" {
			nextStage = stage.OnFailure
		}

		// Update context with stage outputs
		for k, v := range result.Outputs {
			execution.Context[fmt.Sprintf("%s.%s", stage.ID, k)] = v
		}

		// Apply output mapping
		for contextKey, outputKey := range stage.OutputMapping {
			if v, ok := result.Outputs[outputKey]; ok {
				execution.Context[contextKey] = v
			}
		}

		// If specific next stage, find and execute it
		if nextStage != "" && nextStage != "" {
			// Find and execute specific next stage
			// This would require stage graph traversal
		}
	}

	// Build outputs
	execution.Outputs = make(map[string]interface{})
	for _, output := range workflow.Outputs {
		if v, ok := execution.Context[output.Source]; ok {
			execution.Outputs[output.Name] = v
		}
	}

	o.completeExecution(execution, WorkflowStatusCompleted, "")
	return nil
}

// executeStage executes a single workflow stage.
func (o *Orchestrator) executeStage(ctx context.Context, stage *WorkflowStage, execution *WorkflowExecution) (*StageResult, error) {
	result := &StageResult{
		StageID:    stage.ID,
		StageName:  stage.Name,
		Status:     WorkflowStatusRunning,
		Executions: make([]string, 0),
		Outputs:    make(map[string]interface{}),
		StartedAt:  time.Now(),
	}

	o.logger.Info("Executing workflow stage",
		"workflow_id", execution.WorkflowID,
		"stage_id", stage.ID,
		"stage_name", stage.Name,
		"type", stage.Type,
	)

	var err error

	switch stage.Type {
	case StageTypeSequential:
		err = o.executeSequential(ctx, stage, execution, result)
	case StageTypeParallel:
		err = o.executeParallel(ctx, stage, execution, result)
	case StageTypeConditional:
		err = o.executeConditional(ctx, stage, execution, result)
	case StageTypeGate:
		err = o.executeGate(ctx, stage, execution, result)
	default:
		err = o.executeSequential(ctx, stage, execution, result)
	}

	now := time.Now()
	result.CompletedAt = &now
	result.Duration = now.Sub(result.StartedAt)

	if err != nil {
		result.Status = WorkflowStatusFailed
		result.Error = err.Error()
	} else {
		result.Status = WorkflowStatusCompleted
	}

	return result, err
}

// executeSequential executes playbooks sequentially.
func (o *Orchestrator) executeSequential(ctx context.Context, stage *WorkflowStage, execution *WorkflowExecution, result *StageResult) error {
	for _, playbookID := range stage.PlaybookIDs {
		// Build inputs from context using input mapping
		inputs := make(map[string]interface{})
		for inputKey, contextKey := range stage.InputMapping {
			if v, ok := execution.Context[contextKey]; ok {
				inputs[inputKey] = v
			}
		}

		req := &ExecutePlaybookRequest{
			PlaybookID:  playbookID,
			TriggerType: playbook.TriggerManual,
			TriggerInfo: map[string]interface{}{
				"workflow_id":   execution.WorkflowID,
				"execution_id":  execution.ID,
				"stage_id":      stage.ID,
			},
			Inputs:     inputs,
			TenantID:   execution.TenantID,
			ExecutedBy: execution.ExecutedBy,
			Async:      false,
		}

		resp, err := o.engine.ExecutePlaybook(ctx, req)
		if err != nil {
			return fmt.Errorf("playbook %s failed: %w", playbookID, err)
		}

		result.Executions = append(result.Executions, resp.ExecutionID)

		// Merge outputs
		for k, v := range resp.Outputs {
			result.Outputs[k] = v
		}
	}

	return nil
}

// executeParallel executes playbooks in parallel.
func (o *Orchestrator) executeParallel(ctx context.Context, stage *WorkflowStage, execution *WorkflowExecution, result *StageResult) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, len(stage.PlaybookIDs))

	// Semaphore for max concurrent
	maxConcurrent := stage.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = len(stage.PlaybookIDs)
	}
	sem := make(chan struct{}, maxConcurrent)

	for _, playbookID := range stage.PlaybookIDs {
		wg.Add(1)
		go func(pbID string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			inputs := make(map[string]interface{})
			for inputKey, contextKey := range stage.InputMapping {
				mu.Lock()
				if v, ok := execution.Context[contextKey]; ok {
					inputs[inputKey] = v
				}
				mu.Unlock()
			}

			req := &ExecutePlaybookRequest{
				PlaybookID:  pbID,
				TriggerType: playbook.TriggerManual,
				TriggerInfo: map[string]interface{}{
					"workflow_id":  execution.WorkflowID,
					"execution_id": execution.ID,
					"stage_id":     stage.ID,
				},
				Inputs:     inputs,
				TenantID:   execution.TenantID,
				ExecutedBy: execution.ExecutedBy,
				Async:      false,
			}

			resp, err := o.engine.ExecutePlaybook(ctx, req)
			if err != nil {
				errChan <- fmt.Errorf("playbook %s failed: %w", pbID, err)
				return
			}

			mu.Lock()
			result.Executions = append(result.Executions, resp.ExecutionID)
			for k, v := range resp.Outputs {
				result.Outputs[k] = v
			}
			mu.Unlock()
		}(playbookID)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("parallel execution had %d errors: %v", len(errs), errs[0])
	}

	return nil
}

// executeConditional executes based on conditions.
func (o *Orchestrator) executeConditional(ctx context.Context, stage *WorkflowStage, execution *WorkflowExecution, result *StageResult) error {
	// Evaluate conditions and execute appropriate playbook
	for i, cond := range stage.Conditions {
		if o.evaluateCondition(execution.Context, cond) && i < len(stage.PlaybookIDs) {
			req := &ExecutePlaybookRequest{
				PlaybookID:  stage.PlaybookIDs[i],
				TriggerType: playbook.TriggerManual,
				Inputs:      execution.Context,
				TenantID:    execution.TenantID,
				ExecutedBy:  execution.ExecutedBy,
				Async:       false,
			}

			resp, err := o.engine.ExecutePlaybook(ctx, req)
			if err != nil {
				return err
			}

			result.Executions = append(result.Executions, resp.ExecutionID)
			for k, v := range resp.Outputs {
				result.Outputs[k] = v
			}
			return nil
		}
	}

	return nil
}

// executeGate waits for an approval or external signal.
func (o *Orchestrator) executeGate(ctx context.Context, stage *WorkflowStage, execution *WorkflowExecution, result *StageResult) error {
	// Gate stages would wait for approval or external signal
	// For now, just pass through
	o.logger.Info("Gate stage reached",
		"workflow_id", execution.WorkflowID,
		"stage_id", stage.ID,
	)
	return nil
}

// evaluateConditions evaluates multiple conditions.
func (o *Orchestrator) evaluateConditions(data map[string]interface{}, conditions []playbook.Condition) bool {
	for _, cond := range conditions {
		if !o.evaluateCondition(data, cond) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition.
func (o *Orchestrator) evaluateCondition(data map[string]interface{}, cond playbook.Condition) bool {
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
	default:
		return false
	}
}

// completeExecution marks the workflow execution as complete.
func (o *Orchestrator) completeExecution(execution *WorkflowExecution, status WorkflowStatus, errMsg string) {
	now := time.Now()
	execution.Status = status
	execution.CompletedAt = &now
	execution.Error = errMsg
	execution.CurrentStage = ""

	o.logger.Info("Workflow execution completed",
		"execution_id", execution.ID,
		"workflow_id", execution.WorkflowID,
		"status", status,
		"duration_ms", now.Sub(execution.StartedAt).Milliseconds(),
	)
}

// GetWorkflowExecution retrieves a workflow execution by ID.
func (o *Orchestrator) GetWorkflowExecution(executionID string) (*WorkflowExecution, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	execution, exists := o.runningWorkflows[executionID]
	if !exists {
		return nil, fmt.Errorf("workflow execution %s not found", executionID)
	}

	return execution, nil
}

// ListWorkflowExecutions lists all workflow executions.
func (o *Orchestrator) ListWorkflowExecutions() []*WorkflowExecution {
	o.mu.RLock()
	defer o.mu.RUnlock()

	executions := make([]*WorkflowExecution, 0, len(o.runningWorkflows))
	for _, exec := range o.runningWorkflows {
		executions = append(executions, exec)
	}

	return executions
}

// CancelWorkflowExecution cancels a running workflow execution.
func (o *Orchestrator) CancelWorkflowExecution(executionID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	execution, exists := o.runningWorkflows[executionID]
	if !exists {
		return fmt.Errorf("workflow execution %s not found", executionID)
	}

	if execution.Status != WorkflowStatusRunning {
		return fmt.Errorf("workflow execution %s is not running", executionID)
	}

	now := time.Now()
	execution.Status = WorkflowStatusCancelled
	execution.CompletedAt = &now
	execution.Error = "cancelled by user"

	return nil
}

// ListWorkflows lists all registered workflows.
func (o *Orchestrator) ListWorkflows() []*OrchestratorWorkflow {
	o.mu.RLock()
	defer o.mu.RUnlock()

	workflows := make([]*OrchestratorWorkflow, 0, len(o.workflows))
	for _, wf := range o.workflows {
		workflows = append(workflows, wf)
	}

	return workflows
}

// GetWorkflow retrieves a workflow by ID.
func (o *Orchestrator) GetWorkflow(workflowID string) (*OrchestratorWorkflow, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	workflow, exists := o.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}

	return workflow, nil
}

// DeleteWorkflow removes a workflow.
func (o *Orchestrator) DeleteWorkflow(workflowID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, exists := o.workflows[workflowID]; !exists {
		return fmt.Errorf("workflow %s not found", workflowID)
	}

	delete(o.workflows, workflowID)
	return nil
}
