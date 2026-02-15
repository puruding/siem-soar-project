package unit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SOAR Engine Unit Tests
// =============================================================================

// PlaybookDefinition represents a playbook configuration
type PlaybookDefinition struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"`
	Description string                 `json:"description" yaml:"description"`
	Version     string                 `json:"version" yaml:"version"`
	Author      string                 `json:"author" yaml:"author"`
	Category    string                 `json:"category" yaml:"category"`
	Triggers    []Trigger              `json:"triggers" yaml:"triggers"`
	Inputs      []InputParameter       `json:"inputs" yaml:"inputs"`
	Steps       []PlaybookStep         `json:"steps" yaml:"steps"`
	Outputs     []OutputParameter      `json:"outputs" yaml:"outputs"`
	Metadata    map[string]interface{} `json:"metadata" yaml:"metadata"`
}

type Trigger struct {
	Type       string                 `json:"type" yaml:"type"`
	Conditions map[string]interface{} `json:"conditions" yaml:"conditions"`
}

type InputParameter struct {
	Name        string      `json:"name" yaml:"name"`
	Type        string      `json:"type" yaml:"type"`
	Description string      `json:"description" yaml:"description"`
	Required    bool        `json:"required" yaml:"required"`
	Default     interface{} `json:"default" yaml:"default"`
}

type OutputParameter struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description" yaml:"description"`
}

type PlaybookStep struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"`
	Type        string                 `json:"type" yaml:"type"`
	Action      string                 `json:"action" yaml:"action"`
	Parameters  map[string]interface{} `json:"parameters" yaml:"parameters"`
	OnSuccess   string                 `json:"on_success" yaml:"on_success"`
	OnFailure   string                 `json:"on_failure" yaml:"on_failure"`
	Timeout     time.Duration          `json:"timeout" yaml:"timeout"`
	Retries     int                    `json:"retries" yaml:"retries"`
	Condition   string                 `json:"condition" yaml:"condition"`
}

// PlaybookExecution represents an execution instance
type PlaybookExecution struct {
	ID           string                 `json:"id"`
	PlaybookID   string                 `json:"playbook_id"`
	PlaybookName string                 `json:"playbook_name"`
	Status       string                 `json:"status"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time"`
	Inputs       map[string]interface{} `json:"inputs"`
	Outputs      map[string]interface{} `json:"outputs"`
	CurrentStep  string                 `json:"current_step"`
	StepResults  map[string]StepResult  `json:"step_results"`
	Error        string                 `json:"error"`
	TriggeredBy  string                 `json:"triggered_by"`
}

type StepResult struct {
	StepID    string                 `json:"step_id"`
	Status    string                 `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Output    map[string]interface{} `json:"output"`
	Error     string                 `json:"error"`
}

// PlaybookValidator validates playbook definitions
type PlaybookValidator struct{}

func (v *PlaybookValidator) Validate(pb *PlaybookDefinition) []string {
	var errors []string

	if pb.ID == "" {
		errors = append(errors, "playbook ID is required")
	}

	if pb.Name == "" {
		errors = append(errors, "playbook name is required")
	}

	if len(pb.Steps) == 0 {
		errors = append(errors, "at least one step is required")
	}

	// Validate steps
	stepIDs := make(map[string]bool)
	for i, step := range pb.Steps {
		if step.ID == "" {
			errors = append(errors, fmt.Sprintf("step %d: ID is required", i))
		} else if stepIDs[step.ID] {
			errors = append(errors, fmt.Sprintf("duplicate step ID: %s", step.ID))
		}
		stepIDs[step.ID] = true

		if step.Action == "" {
			errors = append(errors, fmt.Sprintf("step %s: action is required", step.ID))
		}

		// Validate step references
		if step.OnSuccess != "" && step.OnSuccess != "end" && !stepIDs[step.OnSuccess] {
			// Check if target step exists (might be defined later)
			found := false
			for _, s := range pb.Steps {
				if s.ID == step.OnSuccess {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, fmt.Sprintf("step %s: invalid on_success reference: %s", step.ID, step.OnSuccess))
			}
		}
	}

	// Validate inputs
	for _, input := range pb.Inputs {
		if input.Name == "" {
			errors = append(errors, "input parameter name is required")
		}
		if input.Type == "" {
			errors = append(errors, fmt.Sprintf("input %s: type is required", input.Name))
		}
	}

	return errors
}

func TestPlaybookValidator_Validate(t *testing.T) {
	validator := &PlaybookValidator{}

	t.Run("valid playbook", func(t *testing.T) {
		pb := &PlaybookDefinition{
			ID:   "enrichment-basic",
			Name: "Basic Enrichment",
			Steps: []PlaybookStep{
				{
					ID:     "enrich-ip",
					Name:   "Enrich IP",
					Action: "ti.lookup_ip",
				},
			},
		}

		errors := validator.Validate(pb)
		assert.Empty(t, errors)
	})

	t.Run("missing required fields", func(t *testing.T) {
		pb := &PlaybookDefinition{}

		errors := validator.Validate(pb)
		assert.Contains(t, errors, "playbook ID is required")
		assert.Contains(t, errors, "playbook name is required")
		assert.Contains(t, errors, "at least one step is required")
	})

	t.Run("duplicate step IDs", func(t *testing.T) {
		pb := &PlaybookDefinition{
			ID:   "test",
			Name: "Test",
			Steps: []PlaybookStep{
				{ID: "step1", Action: "action1"},
				{ID: "step1", Action: "action2"},
			},
		}

		errors := validator.Validate(pb)
		assert.Contains(t, errors, "duplicate step ID: step1")
	})

	t.Run("missing step action", func(t *testing.T) {
		pb := &PlaybookDefinition{
			ID:   "test",
			Name: "Test",
			Steps: []PlaybookStep{
				{ID: "step1"},
			},
		}

		errors := validator.Validate(pb)
		assert.Contains(t, errors, "step step1: action is required")
	})
}

// PlaybookEngine executes playbooks
type PlaybookEngine struct {
	mu         sync.RWMutex
	playbooks  map[string]*PlaybookDefinition
	executions map[string]*PlaybookExecution
	actions    map[string]ActionHandler
}

type ActionHandler func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error)

func NewPlaybookEngine() *PlaybookEngine {
	engine := &PlaybookEngine{
		playbooks:  make(map[string]*PlaybookDefinition),
		executions: make(map[string]*PlaybookExecution),
		actions:    make(map[string]ActionHandler),
	}

	// Register built-in actions
	engine.RegisterAction("log", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		return map[string]interface{}{"logged": true}, nil
	})

	engine.RegisterAction("delay", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		if duration, ok := params["duration"].(time.Duration); ok {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(duration):
				return map[string]interface{}{"delayed": true}, nil
			}
		}
		return map[string]interface{}{"delayed": false}, nil
	})

	return engine
}

func (e *PlaybookEngine) RegisterAction(name string, handler ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions[name] = handler
}

func (e *PlaybookEngine) LoadPlaybook(pb *PlaybookDefinition) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	validator := &PlaybookValidator{}
	if errors := validator.Validate(pb); len(errors) > 0 {
		return fmt.Errorf("invalid playbook: %v", errors)
	}

	e.playbooks[pb.ID] = pb
	return nil
}

func (e *PlaybookEngine) GetPlaybook(id string) (*PlaybookDefinition, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if pb, ok := e.playbooks[id]; ok {
		return pb, nil
	}
	return nil, fmt.Errorf("playbook not found: %s", id)
}

func (e *PlaybookEngine) StartExecution(ctx context.Context, playbookID string, inputs map[string]interface{}, triggeredBy string) (*PlaybookExecution, error) {
	pb, err := e.GetPlaybook(playbookID)
	if err != nil {
		return nil, err
	}

	// Validate inputs
	if err := e.validateInputs(pb, inputs); err != nil {
		return nil, err
	}

	execution := &PlaybookExecution{
		ID:           fmt.Sprintf("exec-%d", time.Now().UnixNano()),
		PlaybookID:   pb.ID,
		PlaybookName: pb.Name,
		Status:       "running",
		StartTime:    time.Now(),
		Inputs:       inputs,
		Outputs:      make(map[string]interface{}),
		StepResults:  make(map[string]StepResult),
		TriggeredBy:  triggeredBy,
	}

	e.mu.Lock()
	e.executions[execution.ID] = execution
	e.mu.Unlock()

	// Execute asynchronously
	go e.executePlaybook(ctx, execution, pb)

	return execution, nil
}

func (e *PlaybookEngine) validateInputs(pb *PlaybookDefinition, inputs map[string]interface{}) error {
	for _, param := range pb.Inputs {
		if param.Required {
			if _, ok := inputs[param.Name]; !ok {
				if param.Default == nil {
					return fmt.Errorf("required input missing: %s", param.Name)
				}
			}
		}
	}
	return nil
}

func (e *PlaybookEngine) executePlaybook(ctx context.Context, execution *PlaybookExecution, pb *PlaybookDefinition) {
	defer func() {
		now := time.Now()
		execution.EndTime = &now
	}()

	stepIndex := 0
	for stepIndex < len(pb.Steps) {
		select {
		case <-ctx.Done():
			execution.Status = "cancelled"
			execution.Error = ctx.Err().Error()
			return
		default:
		}

		step := &pb.Steps[stepIndex]
		execution.CurrentStep = step.ID

		result := e.executeStep(ctx, step, execution.Inputs)
		execution.StepResults[step.ID] = result

		if result.Status == "failed" {
			if step.OnFailure == "" || step.OnFailure == "end" {
				execution.Status = "failed"
				execution.Error = result.Error
				return
			}
			// Find next step
			stepIndex = e.findStepIndex(pb, step.OnFailure)
		} else {
			if step.OnSuccess == "" || step.OnSuccess == "end" {
				stepIndex++
				if stepIndex >= len(pb.Steps) {
					break
				}
			} else {
				stepIndex = e.findStepIndex(pb, step.OnSuccess)
			}
		}
	}

	execution.Status = "completed"
}

func (e *PlaybookEngine) executeStep(ctx context.Context, step *PlaybookStep, inputs map[string]interface{}) StepResult {
	result := StepResult{
		StepID:    step.ID,
		StartTime: time.Now(),
	}

	e.mu.RLock()
	handler, exists := e.actions[step.Action]
	e.mu.RUnlock()

	if !exists {
		result.Status = "failed"
		result.Error = fmt.Sprintf("unknown action: %s", step.Action)
		result.EndTime = time.Now()
		return result
	}

	// Apply timeout
	stepCtx := ctx
	if step.Timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
		defer cancel()
	}

	// Execute with retries
	var output map[string]interface{}
	var err error

	retries := step.Retries
	if retries <= 0 {
		retries = 1
	}

	for attempt := 0; attempt < retries; attempt++ {
		output, err = handler(stepCtx, step.Parameters)
		if err == nil {
			break
		}
	}

	result.EndTime = time.Now()
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "completed"
		result.Output = output
	}

	return result
}

func (e *PlaybookEngine) findStepIndex(pb *PlaybookDefinition, stepID string) int {
	for i, step := range pb.Steps {
		if step.ID == stepID {
			return i
		}
	}
	return len(pb.Steps)
}

func (e *PlaybookEngine) GetExecution(id string) (*PlaybookExecution, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if exec, ok := e.executions[id]; ok {
		return exec, nil
	}
	return nil, fmt.Errorf("execution not found: %s", id)
}

func TestPlaybookEngine_LoadPlaybook(t *testing.T) {
	engine := NewPlaybookEngine()

	t.Run("valid playbook", func(t *testing.T) {
		pb := &PlaybookDefinition{
			ID:   "test-pb",
			Name: "Test Playbook",
			Steps: []PlaybookStep{
				{ID: "step1", Action: "log"},
			},
		}

		err := engine.LoadPlaybook(pb)
		assert.NoError(t, err)

		loaded, err := engine.GetPlaybook("test-pb")
		assert.NoError(t, err)
		assert.Equal(t, "Test Playbook", loaded.Name)
	})

	t.Run("invalid playbook", func(t *testing.T) {
		pb := &PlaybookDefinition{
			ID: "invalid",
		}

		err := engine.LoadPlaybook(pb)
		assert.Error(t, err)
	})
}

func TestPlaybookEngine_ExecutePlaybook(t *testing.T) {
	engine := NewPlaybookEngine()

	// Register test action
	actionCalled := false
	engine.RegisterAction("test.action", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		actionCalled = true
		return map[string]interface{}{"result": "success"}, nil
	})

	pb := &PlaybookDefinition{
		ID:   "test-execution",
		Name: "Test Execution",
		Steps: []PlaybookStep{
			{
				ID:     "step1",
				Action: "test.action",
			},
		},
	}
	engine.LoadPlaybook(pb)

	ctx := context.Background()
	execution, err := engine.StartExecution(ctx, "test-execution", nil, "test")
	require.NoError(t, err)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	exec, _ := engine.GetExecution(execution.ID)
	assert.Equal(t, "completed", exec.Status)
	assert.True(t, actionCalled)
}

func TestPlaybookEngine_ExecutionWithInputs(t *testing.T) {
	engine := NewPlaybookEngine()

	receivedParams := make(map[string]interface{})
	engine.RegisterAction("check.input", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		receivedParams = params
		return map[string]interface{}{"checked": true}, nil
	})

	pb := &PlaybookDefinition{
		ID:   "input-test",
		Name: "Input Test",
		Inputs: []InputParameter{
			{Name: "alert_id", Type: "string", Required: true},
		},
		Steps: []PlaybookStep{
			{
				ID:     "check",
				Action: "check.input",
				Parameters: map[string]interface{}{
					"id": "{{ alert_id }}",
				},
			},
		},
	}
	engine.LoadPlaybook(pb)

	ctx := context.Background()
	inputs := map[string]interface{}{"alert_id": "alert-123"}

	_, err := engine.StartExecution(ctx, "input-test", inputs, "test")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
}

func TestPlaybookEngine_ExecutionFailure(t *testing.T) {
	engine := NewPlaybookEngine()

	engine.RegisterAction("fail.action", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		return nil, fmt.Errorf("intentional failure")
	})

	pb := &PlaybookDefinition{
		ID:   "fail-test",
		Name: "Fail Test",
		Steps: []PlaybookStep{
			{
				ID:     "fail",
				Action: "fail.action",
			},
		},
	}
	engine.LoadPlaybook(pb)

	ctx := context.Background()
	execution, err := engine.StartExecution(ctx, "fail-test", nil, "test")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	exec, _ := engine.GetExecution(execution.ID)
	assert.Equal(t, "failed", exec.Status)
	assert.Contains(t, exec.Error, "intentional failure")
}

func TestPlaybookEngine_ExecutionCancellation(t *testing.T) {
	engine := NewPlaybookEngine()

	engine.RegisterAction("slow.action", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	})

	pb := &PlaybookDefinition{
		ID:   "cancel-test",
		Name: "Cancel Test",
		Steps: []PlaybookStep{
			{ID: "slow", Action: "slow.action"},
		},
	}
	engine.LoadPlaybook(pb)

	ctx, cancel := context.WithCancel(context.Background())
	execution, err := engine.StartExecution(ctx, "cancel-test", nil, "test")
	require.NoError(t, err)

	// Cancel after short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	time.Sleep(100 * time.Millisecond)

	exec, _ := engine.GetExecution(execution.ID)
	assert.Equal(t, "cancelled", exec.Status)
}

// ActionRegistry manages available actions
type ActionRegistry struct {
	mu      sync.RWMutex
	actions map[string]ActionInfo
}

type ActionInfo struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Category    string           `json:"category"`
	Parameters  []ParameterInfo  `json:"parameters"`
	Handler     ActionHandler    `json:"-"`
}

type ParameterInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

func NewActionRegistry() *ActionRegistry {
	return &ActionRegistry{
		actions: make(map[string]ActionInfo),
	}
}

func (r *ActionRegistry) Register(info ActionInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info.Name == "" {
		return fmt.Errorf("action name is required")
	}

	if info.Handler == nil {
		return fmt.Errorf("action handler is required")
	}

	r.actions[info.Name] = info
	return nil
}

func (r *ActionRegistry) Get(name string) (*ActionInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if info, ok := r.actions[name]; ok {
		return &info, nil
	}
	return nil, fmt.Errorf("action not found: %s", name)
}

func (r *ActionRegistry) ListByCategory(category string) []ActionInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ActionInfo
	for _, info := range r.actions {
		if category == "" || info.Category == category {
			result = append(result, info)
		}
	}
	return result
}

func TestActionRegistry(t *testing.T) {
	registry := NewActionRegistry()

	t.Run("register action", func(t *testing.T) {
		err := registry.Register(ActionInfo{
			Name:        "email.send",
			Description: "Send email",
			Category:    "notification",
			Parameters: []ParameterInfo{
				{Name: "to", Type: "string", Required: true},
				{Name: "subject", Type: "string", Required: true},
			},
			Handler: func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
				return map[string]interface{}{"sent": true}, nil
			},
		})
		assert.NoError(t, err)
	})

	t.Run("get action", func(t *testing.T) {
		info, err := registry.Get("email.send")
		assert.NoError(t, err)
		assert.Equal(t, "Send email", info.Description)
	})

	t.Run("list by category", func(t *testing.T) {
		registry.Register(ActionInfo{
			Name:     "slack.send",
			Category: "notification",
			Handler:  func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) { return nil, nil },
		})
		registry.Register(ActionInfo{
			Name:     "firewall.block",
			Category: "containment",
			Handler:  func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) { return nil, nil },
		})

		notifications := registry.ListByCategory("notification")
		assert.Len(t, notifications, 2)

		containments := registry.ListByCategory("containment")
		assert.Len(t, containments, 1)
	})
}

// ApprovalGate represents a manual approval step
type ApprovalGate struct {
	mu        sync.RWMutex
	approvals map[string]*ApprovalRequest
}

type ApprovalRequest struct {
	ID          string                 `json:"id"`
	ExecutionID string                 `json:"execution_id"`
	StepID      string                 `json:"step_id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Requestor   string                 `json:"requestor"`
	Approvers   []string               `json:"approvers"`
	Status      string                 `json:"status"` // pending, approved, rejected
	CreatedAt   time.Time              `json:"created_at"`
	ResolvedAt  *time.Time             `json:"resolved_at"`
	ResolvedBy  string                 `json:"resolved_by"`
	Context     map[string]interface{} `json:"context"`
}

func NewApprovalGate() *ApprovalGate {
	return &ApprovalGate{
		approvals: make(map[string]*ApprovalRequest),
	}
}

func (g *ApprovalGate) CreateRequest(req *ApprovalRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	req.ID = fmt.Sprintf("approval-%d", time.Now().UnixNano())
	req.Status = "pending"
	req.CreatedAt = time.Now()

	g.approvals[req.ID] = req
	return nil
}

func (g *ApprovalGate) Approve(id, approver string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	req, ok := g.approvals[id]
	if !ok {
		return fmt.Errorf("approval request not found: %s", id)
	}

	if req.Status != "pending" {
		return fmt.Errorf("approval already resolved")
	}

	// Check if approver is authorized
	authorized := false
	for _, a := range req.Approvers {
		if a == approver || a == "*" {
			authorized = true
			break
		}
	}

	if !authorized {
		return fmt.Errorf("user not authorized to approve")
	}

	now := time.Now()
	req.Status = "approved"
	req.ResolvedAt = &now
	req.ResolvedBy = approver

	return nil
}

func (g *ApprovalGate) Reject(id, approver, reason string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	req, ok := g.approvals[id]
	if !ok {
		return fmt.Errorf("approval request not found: %s", id)
	}

	if req.Status != "pending" {
		return fmt.Errorf("approval already resolved")
	}

	now := time.Now()
	req.Status = "rejected"
	req.ResolvedAt = &now
	req.ResolvedBy = approver
	req.Context["rejection_reason"] = reason

	return nil
}

func (g *ApprovalGate) GetPending() []*ApprovalRequest {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var pending []*ApprovalRequest
	for _, req := range g.approvals {
		if req.Status == "pending" {
			pending = append(pending, req)
		}
	}
	return pending
}

func TestApprovalGate(t *testing.T) {
	gate := NewApprovalGate()

	req := &ApprovalRequest{
		ExecutionID: "exec-123",
		StepID:      "approval-step",
		Title:       "Approve Containment",
		Description: "Block IP 192.168.1.100",
		Requestor:   "analyst@example.com",
		Approvers:   []string{"manager@example.com", "admin@example.com"},
		Context:     map[string]interface{}{"ip": "192.168.1.100"},
	}

	t.Run("create request", func(t *testing.T) {
		err := gate.CreateRequest(req)
		assert.NoError(t, err)
		assert.NotEmpty(t, req.ID)
		assert.Equal(t, "pending", req.Status)
	})

	t.Run("list pending", func(t *testing.T) {
		pending := gate.GetPending()
		assert.Len(t, pending, 1)
	})

	t.Run("approve by authorized user", func(t *testing.T) {
		err := gate.Approve(req.ID, "manager@example.com")
		assert.NoError(t, err)

		pending := gate.GetPending()
		assert.Len(t, pending, 0)
	})

	t.Run("approve unauthorized", func(t *testing.T) {
		req2 := &ApprovalRequest{
			Title:     "Another Approval",
			Approvers: []string{"specific@example.com"},
			Context:   make(map[string]interface{}),
		}
		gate.CreateRequest(req2)

		err := gate.Approve(req2.ID, "unauthorized@example.com")
		assert.Error(t, err)
	})
}

// WorkflowMetrics tracks workflow execution metrics
type WorkflowMetrics struct {
	mu               sync.RWMutex
	totalExecutions  int64
	completedCount   int64
	failedCount      int64
	cancelledCount   int64
	avgDuration      time.Duration
	actionCounts     map[string]int64
	stepDurations    map[string]time.Duration
}

func NewWorkflowMetrics() *WorkflowMetrics {
	return &WorkflowMetrics{
		actionCounts:  make(map[string]int64),
		stepDurations: make(map[string]time.Duration),
	}
}

func (m *WorkflowMetrics) RecordExecution(execution *PlaybookExecution) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalExecutions++

	switch execution.Status {
	case "completed":
		m.completedCount++
	case "failed":
		m.failedCount++
	case "cancelled":
		m.cancelledCount++
	}

	// Update average duration
	if execution.EndTime != nil {
		duration := execution.EndTime.Sub(execution.StartTime)
		m.avgDuration = (m.avgDuration*time.Duration(m.totalExecutions-1) + duration) / time.Duration(m.totalExecutions)
	}

	// Record step metrics
	for _, result := range execution.StepResults {
		stepDuration := result.EndTime.Sub(result.StartTime)
		if existing, ok := m.stepDurations[result.StepID]; ok {
			m.stepDurations[result.StepID] = (existing + stepDuration) / 2
		} else {
			m.stepDurations[result.StepID] = stepDuration
		}
	}
}

func (m *WorkflowMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var successRate float64
	if m.totalExecutions > 0 {
		successRate = float64(m.completedCount) / float64(m.totalExecutions) * 100
	}

	return map[string]interface{}{
		"total_executions": m.totalExecutions,
		"completed":        m.completedCount,
		"failed":           m.failedCount,
		"cancelled":        m.cancelledCount,
		"success_rate":     successRate,
		"avg_duration_ms":  m.avgDuration.Milliseconds(),
	}
}

func TestWorkflowMetrics(t *testing.T) {
	metrics := NewWorkflowMetrics()

	now := time.Now()
	endTime := now.Add(100 * time.Millisecond)

	// Record some executions
	metrics.RecordExecution(&PlaybookExecution{
		Status:    "completed",
		StartTime: now,
		EndTime:   &endTime,
		StepResults: map[string]StepResult{
			"step1": {StepID: "step1", StartTime: now, EndTime: endTime},
		},
	})

	metrics.RecordExecution(&PlaybookExecution{
		Status:    "failed",
		StartTime: now,
		EndTime:   &endTime,
	})

	stats := metrics.GetStats()
	assert.Equal(t, int64(2), stats["total_executions"])
	assert.Equal(t, int64(1), stats["completed"])
	assert.Equal(t, int64(1), stats["failed"])
	assert.Equal(t, 50.0, stats["success_rate"])
}

// Benchmark tests
func BenchmarkPlaybookEngine_Execute(b *testing.B) {
	engine := NewPlaybookEngine()

	engine.RegisterAction("noop", func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
		return nil, nil
	})

	pb := &PlaybookDefinition{
		ID:   "bench",
		Name: "Benchmark",
		Steps: []PlaybookStep{
			{ID: "s1", Action: "noop"},
			{ID: "s2", Action: "noop"},
			{ID: "s3", Action: "noop"},
		},
	}
	engine.LoadPlaybook(pb)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.StartExecution(ctx, "bench", nil, "bench")
	}
}
