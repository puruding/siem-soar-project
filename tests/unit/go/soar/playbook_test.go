// Package soar_test provides unit tests for the SOAR engine.
package soar_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Category represents playbook category types.
type Category string

const (
	CategoryEnrichment    Category = "enrichment"
	CategoryContainment   Category = "containment"
	CategoryRemediation   Category = "remediation"
	CategoryNotification  Category = "notification"
	CategoryInvestigation Category = "investigation"
)

// TriggerType represents how a playbook can be triggered.
type TriggerType string

const (
	TriggerManual    TriggerType = "manual"
	TriggerAutomatic TriggerType = "automatic"
	TriggerAlert     TriggerType = "alert"
)

// StepType represents the type of step in a playbook.
type StepType string

const (
	StepTypeAction    StepType = "action"
	StepTypeCondition StepType = "condition"
	StepTypeParallel  StepType = "parallel"
	StepTypeApproval  StepType = "approval"
	StepTypeLoop      StepType = "loop"
)

// Playbook represents a SOAR playbook definition.
type Playbook struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    Category          `json:"category"`
	Version     int               `json:"version"`
	Enabled     bool              `json:"enabled"`
	Trigger     Trigger           `json:"trigger"`
	Steps       []Step            `json:"steps"`
	Inputs      []InputParameter  `json:"inputs"`
	Outputs     []OutputField     `json:"outputs"`
	Timeout     time.Duration     `json:"timeout"`
	Tags        []string          `json:"tags"`
}

// Trigger defines how a playbook is triggered.
type Trigger struct {
	Type       TriggerType          `json:"type"`
	Conditions []TriggerCondition   `json:"conditions,omitempty"`
}

// TriggerCondition defines a condition for automatic triggering.
type TriggerCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// Step represents a single step in the playbook.
type Step struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        StepType               `json:"type"`
	Action      *ActionConfig          `json:"action,omitempty"`
	Condition   *ConditionConfig       `json:"condition,omitempty"`
	Parallel    *ParallelConfig        `json:"parallel,omitempty"`
	Approval    *ApprovalConfig        `json:"approval,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	ContinueOnError bool               `json:"continue_on_error,omitempty"`
}

// ActionConfig defines an action step configuration.
type ActionConfig struct {
	Connector  string                 `json:"connector"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// ConditionConfig defines a conditional branching step.
type ConditionConfig struct {
	Conditions []TriggerCondition `json:"conditions"`
	ThenSteps  []Step             `json:"then"`
	ElseSteps  []Step             `json:"else,omitempty"`
}

// ParallelConfig defines parallel execution of steps.
type ParallelConfig struct {
	Branches []ParallelBranch `json:"branches"`
	FailFast bool             `json:"fail_fast,omitempty"`
}

// ParallelBranch defines a branch in parallel execution.
type ParallelBranch struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Steps []Step `json:"steps"`
}

// ApprovalConfig defines an approval step configuration.
type ApprovalConfig struct {
	Approvers []string      `json:"approvers"`
	Timeout   time.Duration `json:"timeout"`
	Message   string        `json:"message"`
}

// InputParameter defines an input parameter for a playbook.
type InputParameter struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Required bool        `json:"required"`
	Default  interface{} `json:"default,omitempty"`
}

// OutputField defines an output field from a playbook.
type OutputField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Source string `json:"source"`
}

// ExecutionStatus represents the status of a playbook execution.
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusWaiting   ExecutionStatus = "waiting_approval"
)

// Execution represents a playbook execution instance.
type Execution struct {
	ID           string                 `json:"id"`
	PlaybookID   string                 `json:"playbook_id"`
	Status       ExecutionStatus        `json:"status"`
	Inputs       map[string]interface{} `json:"inputs"`
	Outputs      map[string]interface{} `json:"outputs,omitempty"`
	CurrentStep  string                 `json:"current_step,omitempty"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Error        string                 `json:"error,omitempty"`
}

// Validator validates playbook definitions.
type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Validate(p *Playbook) error {
	if p.ID == "" {
		return &ValidationError{Field: "id", Message: "ID is required"}
	}
	if p.Name == "" {
		return &ValidationError{Field: "name", Message: "Name is required"}
	}
	if len(p.Steps) == 0 {
		return &ValidationError{Field: "steps", Message: "At least one step is required"}
	}
	return nil
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

// TestPlaybookCreation tests playbook creation.
func TestPlaybookCreation(t *testing.T) {
	playbook := &Playbook{
		ID:          "pb-001",
		Name:        "IP Enrichment",
		Description: "Enriches alert with IP intelligence",
		Category:    CategoryEnrichment,
		Version:     1,
		Enabled:     true,
		Trigger: Trigger{
			Type: TriggerAlert,
			Conditions: []TriggerCondition{
				{Field: "alert.type", Operator: "equals", Value: "suspicious_ip"},
			},
		},
		Steps: []Step{
			{
				ID:   "step-1",
				Name: "Get IP Reputation",
				Type: StepTypeAction,
				Action: &ActionConfig{
					Connector:  "virustotal",
					Action:     "ip_lookup",
					Parameters: map[string]interface{}{"ip": "{{alert.source_ip}}"},
				},
			},
		},
		Timeout: 5 * time.Minute,
	}

	assert.Equal(t, "pb-001", playbook.ID)
	assert.Equal(t, "IP Enrichment", playbook.Name)
	assert.Equal(t, CategoryEnrichment, playbook.Category)
	assert.True(t, playbook.Enabled)
	assert.Len(t, playbook.Steps, 1)
}

// TestPlaybookValidation tests playbook validation.
func TestPlaybookValidation(t *testing.T) {
	validator := NewValidator()

	t.Run("valid playbook", func(t *testing.T) {
		playbook := &Playbook{
			ID:   "pb-001",
			Name: "Test Playbook",
			Steps: []Step{
				{ID: "step-1", Name: "Test Step", Type: StepTypeAction},
			},
		}
		err := validator.Validate(playbook)
		assert.NoError(t, err)
	})

	t.Run("missing ID", func(t *testing.T) {
		playbook := &Playbook{
			Name: "Test Playbook",
			Steps: []Step{
				{ID: "step-1", Name: "Test Step", Type: StepTypeAction},
			},
		}
		err := validator.Validate(playbook)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID")
	})

	t.Run("missing name", func(t *testing.T) {
		playbook := &Playbook{
			ID: "pb-001",
			Steps: []Step{
				{ID: "step-1", Name: "Test Step", Type: StepTypeAction},
			},
		}
		err := validator.Validate(playbook)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Name")
	})

	t.Run("no steps", func(t *testing.T) {
		playbook := &Playbook{
			ID:    "pb-001",
			Name:  "Test Playbook",
			Steps: []Step{},
		}
		err := validator.Validate(playbook)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "step")
	})
}

// TestPlaybookSerialization tests JSON serialization.
func TestPlaybookSerialization(t *testing.T) {
	playbook := &Playbook{
		ID:       "pb-001",
		Name:     "Test Playbook",
		Category: CategoryContainment,
		Version:  1,
		Enabled:  true,
		Steps: []Step{
			{
				ID:   "step-1",
				Name: "Block IP",
				Type: StepTypeAction,
				Action: &ActionConfig{
					Connector: "firewall",
					Action:    "block_ip",
					Parameters: map[string]interface{}{
						"ip": "{{alert.source_ip}}",
					},
				},
			},
		},
	}

	// Serialize
	data, err := json.Marshal(playbook)
	require.NoError(t, err)

	// Deserialize
	var decoded Playbook
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, playbook.ID, decoded.ID)
	assert.Equal(t, playbook.Name, decoded.Name)
	assert.Equal(t, playbook.Category, decoded.Category)
	assert.Len(t, decoded.Steps, 1)
}

// TestConditionalStep tests conditional branching.
func TestConditionalStep(t *testing.T) {
	step := Step{
		ID:   "step-condition",
		Name: "Check Severity",
		Type: StepTypeCondition,
		Condition: &ConditionConfig{
			Conditions: []TriggerCondition{
				{Field: "alert.severity", Operator: "equals", Value: "critical"},
			},
			ThenSteps: []Step{
				{ID: "block", Name: "Block IP", Type: StepTypeAction},
			},
			ElseSteps: []Step{
				{ID: "notify", Name: "Notify SOC", Type: StepTypeAction},
			},
		},
	}

	assert.Equal(t, StepTypeCondition, step.Type)
	assert.NotNil(t, step.Condition)
	assert.Len(t, step.Condition.ThenSteps, 1)
	assert.Len(t, step.Condition.ElseSteps, 1)
}

// TestParallelStep tests parallel execution.
func TestParallelStep(t *testing.T) {
	step := Step{
		ID:   "step-parallel",
		Name: "Enrich Alert",
		Type: StepTypeParallel,
		Parallel: &ParallelConfig{
			FailFast: true,
			Branches: []ParallelBranch{
				{
					ID:   "branch-vt",
					Name: "VirusTotal",
					Steps: []Step{
						{ID: "vt-lookup", Name: "VT IP Lookup", Type: StepTypeAction},
					},
				},
				{
					ID:   "branch-geo",
					Name: "GeoIP",
					Steps: []Step{
						{ID: "geo-lookup", Name: "GeoIP Lookup", Type: StepTypeAction},
					},
				},
			},
		},
	}

	assert.Equal(t, StepTypeParallel, step.Type)
	assert.NotNil(t, step.Parallel)
	assert.True(t, step.Parallel.FailFast)
	assert.Len(t, step.Parallel.Branches, 2)
}

// TestApprovalStep tests approval gate.
func TestApprovalStep(t *testing.T) {
	step := Step{
		ID:   "step-approval",
		Name: "Approve Containment",
		Type: StepTypeApproval,
		Approval: &ApprovalConfig{
			Approvers: []string{"soc-analyst", "security-team"},
			Timeout:   30 * time.Minute,
			Message:   "Please approve IP block action",
		},
	}

	assert.Equal(t, StepTypeApproval, step.Type)
	assert.NotNil(t, step.Approval)
	assert.Len(t, step.Approval.Approvers, 2)
	assert.Equal(t, 30*time.Minute, step.Approval.Timeout)
}

// TestExecutionLifecycle tests execution status transitions.
func TestExecutionLifecycle(t *testing.T) {
	execution := &Execution{
		ID:         "exec-001",
		PlaybookID: "pb-001",
		Status:     StatusPending,
		Inputs:     map[string]interface{}{"alert_id": "alert-123"},
		StartedAt:  time.Now(),
	}

	// Start execution
	execution.Status = StatusRunning
	assert.Equal(t, StatusRunning, execution.Status)

	// Wait for approval
	execution.Status = StatusWaiting
	execution.CurrentStep = "step-approval"
	assert.Equal(t, StatusWaiting, execution.Status)

	// Complete
	now := time.Now()
	execution.Status = StatusCompleted
	execution.CompletedAt = &now
	execution.Outputs = map[string]interface{}{"result": "success"}
	assert.Equal(t, StatusCompleted, execution.Status)
	assert.NotNil(t, execution.CompletedAt)
}

// TestPlaybookCategories tests category types.
func TestPlaybookCategories(t *testing.T) {
	categories := []Category{
		CategoryEnrichment,
		CategoryContainment,
		CategoryRemediation,
		CategoryNotification,
		CategoryInvestigation,
	}

	for _, cat := range categories {
		assert.NotEmpty(t, string(cat))
	}
}

// TestTriggerTypes tests trigger types.
func TestTriggerTypes(t *testing.T) {
	triggers := []TriggerType{
		TriggerManual,
		TriggerAutomatic,
		TriggerAlert,
	}

	for _, trig := range triggers {
		assert.NotEmpty(t, string(trig))
	}
}

// TestInputParameters tests input parameter handling.
func TestInputParameters(t *testing.T) {
	inputs := []InputParameter{
		{Name: "alert_id", Type: "string", Required: true},
		{Name: "source_ip", Type: "ip", Required: true},
		{Name: "block_duration", Type: "duration", Required: false, Default: "1h"},
	}

	assert.Len(t, inputs, 3)
	assert.True(t, inputs[0].Required)
	assert.False(t, inputs[2].Required)
	assert.Equal(t, "1h", inputs[2].Default)
}

// TestOutputFields tests output field handling.
func TestOutputFields(t *testing.T) {
	outputs := []OutputField{
		{Name: "reputation_score", Type: "number", Source: "step-1.result.score"},
		{Name: "blocked", Type: "boolean", Source: "step-2.result.success"},
	}

	assert.Len(t, outputs, 2)
	assert.Equal(t, "step-1.result.score", outputs[0].Source)
}

// TestPlaybookWithComplexWorkflow tests a complete playbook workflow.
func TestPlaybookWithComplexWorkflow(t *testing.T) {
	playbook := &Playbook{
		ID:       "pb-suspicious-login",
		Name:     "Suspicious Login Response",
		Category: CategoryInvestigation,
		Version:  1,
		Enabled:  true,
		Trigger: Trigger{
			Type: TriggerAlert,
			Conditions: []TriggerCondition{
				{Field: "alert.type", Operator: "equals", Value: "suspicious_login"},
			},
		},
		Inputs: []InputParameter{
			{Name: "alert_id", Type: "string", Required: true},
		},
		Steps: []Step{
			// Step 1: Parallel enrichment
			{
				ID:   "enrich",
				Name: "Enrich Alert",
				Type: StepTypeParallel,
				Parallel: &ParallelConfig{
					Branches: []ParallelBranch{
						{ID: "geo", Name: "GeoIP", Steps: []Step{{ID: "geo-1"}}},
						{ID: "vt", Name: "VirusTotal", Steps: []Step{{ID: "vt-1"}}},
					},
				},
			},
			// Step 2: Check severity
			{
				ID:   "check-severity",
				Name: "Check Severity",
				Type: StepTypeCondition,
				Condition: &ConditionConfig{
					Conditions: []TriggerCondition{
						{Field: "enrich.vt.score", Operator: "greater_than", Value: 70},
					},
					ThenSteps: []Step{
						// Step 3a: Request approval
						{
							ID:   "approval",
							Type: StepTypeApproval,
							Approval: &ApprovalConfig{
								Approvers: []string{"soc-lead"},
								Timeout:   15 * time.Minute,
							},
						},
						// Step 3b: Block
						{ID: "block", Name: "Block IP", Type: StepTypeAction},
					},
					ElseSteps: []Step{
						{ID: "notify", Name: "Notify", Type: StepTypeAction},
					},
				},
			},
		},
		Timeout: 30 * time.Minute,
	}

	assert.Equal(t, "pb-suspicious-login", playbook.ID)
	assert.Len(t, playbook.Steps, 2)
	assert.Equal(t, StepTypeParallel, playbook.Steps[0].Type)
	assert.Equal(t, StepTypeCondition, playbook.Steps[1].Type)
}

// Benchmark tests
func BenchmarkPlaybookSerialization(b *testing.B) {
	playbook := &Playbook{
		ID:       "pb-001",
		Name:     "Test Playbook",
		Category: CategoryEnrichment,
		Steps: []Step{
			{ID: "step-1", Name: "Step 1", Type: StepTypeAction},
			{ID: "step-2", Name: "Step 2", Type: StepTypeAction},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(playbook)
	}
}

func BenchmarkPlaybookValidation(b *testing.B) {
	validator := NewValidator()
	playbook := &Playbook{
		ID:   "pb-001",
		Name: "Test Playbook",
		Steps: []Step{
			{ID: "step-1", Name: "Step 1", Type: StepTypeAction},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(playbook)
	}
}
