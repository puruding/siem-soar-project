// Package playbook provides playbook model definitions and management.
package playbook

import (
	"encoding/json"
	"time"
)

// Category represents playbook category types.
type Category string

const (
	CategoryEnrichment   Category = "enrichment"
	CategoryContainment  Category = "containment"
	CategoryRemediation  Category = "remediation"
	CategoryNotification Category = "notification"
	CategoryInvestigation Category = "investigation"
	CategoryResponse     Category = "response"
	CategoryCustom       Category = "custom"
)

// TriggerType represents how a playbook can be triggered.
type TriggerType string

const (
	TriggerManual    TriggerType = "manual"
	TriggerAutomatic TriggerType = "automatic"
	TriggerScheduled TriggerType = "scheduled"
	TriggerWebhook   TriggerType = "webhook"
	TriggerAlert     TriggerType = "alert"
	TriggerIncident  TriggerType = "incident"
)

// ConditionOperator represents comparison operators for conditions.
type ConditionOperator string

const (
	OpEquals         ConditionOperator = "equals"
	OpNotEquals      ConditionOperator = "not_equals"
	OpContains       ConditionOperator = "contains"
	OpNotContains    ConditionOperator = "not_contains"
	OpStartsWith     ConditionOperator = "starts_with"
	OpEndsWith       ConditionOperator = "ends_with"
	OpGreaterThan    ConditionOperator = "greater_than"
	OpLessThan       ConditionOperator = "less_than"
	OpGreaterOrEqual ConditionOperator = "greater_or_equal"
	OpLessOrEqual    ConditionOperator = "less_or_equal"
	OpIn             ConditionOperator = "in"
	OpNotIn          ConditionOperator = "not_in"
	OpMatches        ConditionOperator = "matches"  // regex
	OpExists         ConditionOperator = "exists"
	OpNotExists      ConditionOperator = "not_exists"
)

// StepType represents the type of step in a playbook.
type StepType string

const (
	StepTypeAction      StepType = "action"
	StepTypeCondition   StepType = "condition"
	StepTypeParallel    StepType = "parallel"
	StepTypeLoop        StepType = "loop"
	StepTypeWait        StepType = "wait"
	StepTypeApproval    StepType = "approval"
	StepTypeSubPlaybook StepType = "sub_playbook"
	StepTypeScript      StepType = "script"
	StepTypeTransform   StepType = "transform"
)

// Playbook represents a SOAR playbook definition.
type Playbook struct {
	// Metadata
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	DisplayName string            `json:"display_name" yaml:"display_name"`
	Description string            `json:"description" yaml:"description"`
	Version     int               `json:"version" yaml:"version"`
	Category    Category          `json:"category" yaml:"category"`
	Tags        []string          `json:"tags" yaml:"tags"`
	Author      string            `json:"author" yaml:"author"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Lifecycle
	Enabled   bool      `json:"enabled" yaml:"enabled"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`

	// Configuration
	Trigger     Trigger          `json:"trigger" yaml:"trigger"`
	Inputs      []InputParameter `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Outputs     []OutputField    `json:"outputs,omitempty" yaml:"outputs,omitempty"`
	Variables   []Variable       `json:"variables,omitempty" yaml:"variables,omitempty"`
	Secrets     []SecretRef      `json:"secrets,omitempty" yaml:"secrets,omitempty"`

	// Execution
	Steps       []Step             `json:"steps" yaml:"steps"`
	ErrorHandler *ErrorHandler     `json:"error_handler,omitempty" yaml:"error_handler,omitempty"`
	Timeout     Duration           `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	RetryPolicy *RetryPolicy       `json:"retry_policy,omitempty" yaml:"retry_policy,omitempty"`
	RateLimit   *RateLimit         `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`

	// Access Control
	TenantID    string   `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

// Duration is a wrapper for time.Duration that supports YAML marshaling.
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
	}
	return nil
}

// Trigger defines how a playbook is triggered.
type Trigger struct {
	Type       TriggerType            `json:"type" yaml:"type"`
	Conditions []Condition            `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Schedule   *ScheduleConfig        `json:"schedule,omitempty" yaml:"schedule,omitempty"`
	Webhook    *WebhookConfig         `json:"webhook,omitempty" yaml:"webhook,omitempty"`
	Filters    map[string]interface{} `json:"filters,omitempty" yaml:"filters,omitempty"`
}

// ScheduleConfig defines scheduled trigger configuration.
type ScheduleConfig struct {
	Cron     string `json:"cron,omitempty" yaml:"cron,omitempty"`
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
	Timezone string `json:"timezone,omitempty" yaml:"timezone,omitempty"`
}

// WebhookConfig defines webhook trigger configuration.
type WebhookConfig struct {
	Path       string            `json:"path" yaml:"path"`
	Method     string            `json:"method" yaml:"method"`
	Headers    map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	AuthType   string            `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
	SecretName string            `json:"secret_name,omitempty" yaml:"secret_name,omitempty"`
}

// Condition defines a condition for triggering or branching.
type Condition struct {
	Field    string            `json:"field" yaml:"field"`
	Operator ConditionOperator `json:"operator" yaml:"operator"`
	Value    interface{}       `json:"value" yaml:"value"`
	And      []Condition       `json:"and,omitempty" yaml:"and,omitempty"`
	Or       []Condition       `json:"or,omitempty" yaml:"or,omitempty"`
}

// InputParameter defines an input parameter for a playbook.
type InputParameter struct {
	Name        string      `json:"name" yaml:"name"`
	Type        string      `json:"type" yaml:"type"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool        `json:"required" yaml:"required"`
	Default     interface{} `json:"default,omitempty" yaml:"default,omitempty"`
	Validation  *Validation `json:"validation,omitempty" yaml:"validation,omitempty"`
}

// OutputField defines an output field from a playbook.
type OutputField struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Source      string `json:"source" yaml:"source"` // Reference to step output
}

// Variable defines a variable used within the playbook.
type Variable struct {
	Name    string      `json:"name" yaml:"name"`
	Type    string      `json:"type" yaml:"type"`
	Value   interface{} `json:"value,omitempty" yaml:"value,omitempty"`
	Dynamic bool        `json:"dynamic,omitempty" yaml:"dynamic,omitempty"`
	Source  string      `json:"source,omitempty" yaml:"source,omitempty"`
}

// SecretRef references an external secret.
type SecretRef struct {
	Name     string `json:"name" yaml:"name"`
	Provider string `json:"provider" yaml:"provider"` // vault, aws, azure, k8s
	Path     string `json:"path" yaml:"path"`
	Key      string `json:"key" yaml:"key"`
}

// Validation defines validation rules for parameters.
type Validation struct {
	Pattern   string      `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	MinLength int         `json:"min_length,omitempty" yaml:"min_length,omitempty"`
	MaxLength int         `json:"max_length,omitempty" yaml:"max_length,omitempty"`
	Min       interface{} `json:"min,omitempty" yaml:"min,omitempty"`
	Max       interface{} `json:"max,omitempty" yaml:"max,omitempty"`
	Enum      []string    `json:"enum,omitempty" yaml:"enum,omitempty"`
}

// Step represents a single step in the playbook.
type Step struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"`
	Type        StepType               `json:"type" yaml:"type"`
	Description string                 `json:"description,omitempty" yaml:"description,omitempty"`

	// Action configuration (when type is "action")
	Action *ActionConfig `json:"action,omitempty" yaml:"action,omitempty"`

	// Condition configuration (when type is "condition")
	Condition   *ConditionConfig `json:"condition,omitempty" yaml:"condition,omitempty"`

	// Parallel configuration (when type is "parallel")
	Parallel *ParallelConfig `json:"parallel,omitempty" yaml:"parallel,omitempty"`

	// Loop configuration (when type is "loop")
	Loop *LoopConfig `json:"loop,omitempty" yaml:"loop,omitempty"`

	// Wait configuration (when type is "wait")
	Wait *WaitConfig `json:"wait,omitempty" yaml:"wait,omitempty"`

	// Approval configuration (when type is "approval")
	Approval *ApprovalConfig `json:"approval,omitempty" yaml:"approval,omitempty"`

	// SubPlaybook configuration (when type is "sub_playbook")
	SubPlaybook *SubPlaybookConfig `json:"sub_playbook,omitempty" yaml:"sub_playbook,omitempty"`

	// Script configuration (when type is "script")
	Script *ScriptConfig `json:"script,omitempty" yaml:"script,omitempty"`

	// Transform configuration (when type is "transform")
	Transform *TransformConfig `json:"transform,omitempty" yaml:"transform,omitempty"`

	// Common step options
	ContinueOnError bool         `json:"continue_on_error,omitempty" yaml:"continue_on_error,omitempty"`
	Timeout         Duration     `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	RetryPolicy     *RetryPolicy `json:"retry_policy,omitempty" yaml:"retry_policy,omitempty"`
	SkipCondition   *Condition   `json:"skip_condition,omitempty" yaml:"skip_condition,omitempty"`

	// Output mapping
	OutputMapping map[string]string `json:"output_mapping,omitempty" yaml:"output_mapping,omitempty"`
}

// ActionConfig defines an action step configuration.
type ActionConfig struct {
	Connector  string                 `json:"connector" yaml:"connector"`
	Action     string                 `json:"action" yaml:"action"`
	Parameters map[string]interface{} `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// ConditionConfig defines a conditional branching step.
type ConditionConfig struct {
	Conditions []Condition `json:"conditions" yaml:"conditions"`
	ThenSteps  []Step      `json:"then" yaml:"then"`
	ElseSteps  []Step      `json:"else,omitempty" yaml:"else,omitempty"`
}

// ParallelConfig defines parallel execution of steps.
type ParallelConfig struct {
	Branches      []ParallelBranch `json:"branches" yaml:"branches"`
	FailFast      bool             `json:"fail_fast,omitempty" yaml:"fail_fast,omitempty"`
	MaxConcurrent int              `json:"max_concurrent,omitempty" yaml:"max_concurrent,omitempty"`
}

// ParallelBranch defines a branch in parallel execution.
type ParallelBranch struct {
	ID    string `json:"id" yaml:"id"`
	Name  string `json:"name" yaml:"name"`
	Steps []Step `json:"steps" yaml:"steps"`
}

// LoopConfig defines loop iteration configuration.
type LoopConfig struct {
	Items      string `json:"items" yaml:"items"`           // Expression to iterate over
	ItemVar    string `json:"item_var" yaml:"item_var"`     // Variable name for current item
	IndexVar   string `json:"index_var,omitempty" yaml:"index_var,omitempty"` // Variable name for index
	MaxIterations int  `json:"max_iterations,omitempty" yaml:"max_iterations,omitempty"`
	Steps      []Step `json:"steps" yaml:"steps"`
	Parallel   bool   `json:"parallel,omitempty" yaml:"parallel,omitempty"`
}

// WaitConfig defines a wait step configuration.
type WaitConfig struct {
	Duration   Duration    `json:"duration,omitempty" yaml:"duration,omitempty"`
	Until      *Condition  `json:"until,omitempty" yaml:"until,omitempty"`
	Signal     string      `json:"signal,omitempty" yaml:"signal,omitempty"`
	MaxWait    Duration    `json:"max_wait,omitempty" yaml:"max_wait,omitempty"`
}

// ApprovalConfig defines an approval step configuration.
type ApprovalConfig struct {
	Approvers      []string          `json:"approvers" yaml:"approvers"`
	ApproverGroups []string          `json:"approver_groups,omitempty" yaml:"approver_groups,omitempty"`
	RequiredCount  int               `json:"required_count,omitempty" yaml:"required_count,omitempty"`
	Timeout        Duration          `json:"timeout" yaml:"timeout"`
	Escalation     *EscalationConfig `json:"escalation,omitempty" yaml:"escalation,omitempty"`
	Message        string            `json:"message" yaml:"message"`
	Actions        []ApprovalAction  `json:"actions,omitempty" yaml:"actions,omitempty"`
}

// ApprovalAction defines possible approval actions.
type ApprovalAction struct {
	Name        string `json:"name" yaml:"name"`
	Label       string `json:"label" yaml:"label"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Style       string `json:"style,omitempty" yaml:"style,omitempty"` // primary, danger, warning
}

// EscalationConfig defines escalation rules.
type EscalationConfig struct {
	Timeout    Duration `json:"timeout" yaml:"timeout"`
	Escalators []string `json:"escalators" yaml:"escalators"`
	MaxLevels  int      `json:"max_levels,omitempty" yaml:"max_levels,omitempty"`
}

// SubPlaybookConfig defines a sub-playbook invocation.
type SubPlaybookConfig struct {
	PlaybookID   string                 `json:"playbook_id" yaml:"playbook_id"`
	Version      int                    `json:"version,omitempty" yaml:"version,omitempty"`
	Inputs       map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	Synchronous  bool                   `json:"synchronous" yaml:"synchronous"`
}

// ScriptConfig defines a script execution step.
type ScriptConfig struct {
	Language string                 `json:"language" yaml:"language"` // python, javascript, go
	Code     string                 `json:"code" yaml:"code"`
	Timeout  Duration               `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Inputs   map[string]interface{} `json:"inputs,omitempty" yaml:"inputs,omitempty"`
}

// TransformConfig defines data transformation.
type TransformConfig struct {
	Type       string                 `json:"type" yaml:"type"` // jq, jsonpath, template
	Expression string                 `json:"expression" yaml:"expression"`
	Source     string                 `json:"source" yaml:"source"`
	Target     string                 `json:"target" yaml:"target"`
}

// ErrorHandler defines error handling configuration.
type ErrorHandler struct {
	Type       string `json:"type" yaml:"type"` // retry, fallback, ignore, abort
	Steps      []Step `json:"steps,omitempty" yaml:"steps,omitempty"`
	MaxRetries int    `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
}

// RetryPolicy defines retry behavior.
type RetryPolicy struct {
	MaxAttempts        int      `json:"max_attempts" yaml:"max_attempts"`
	InitialInterval    Duration `json:"initial_interval" yaml:"initial_interval"`
	MaxInterval        Duration `json:"max_interval" yaml:"max_interval"`
	BackoffCoefficient float64  `json:"backoff_coefficient" yaml:"backoff_coefficient"`
	RetryableErrors    []string `json:"retryable_errors,omitempty" yaml:"retryable_errors,omitempty"`
}

// RateLimit defines rate limiting for playbook execution.
type RateLimit struct {
	MaxExecutions int      `json:"max_executions" yaml:"max_executions"`
	Window        Duration `json:"window" yaml:"window"`
	BurstSize     int      `json:"burst_size,omitempty" yaml:"burst_size,omitempty"`
}

// ExecutionStatus represents the status of a playbook execution.
type ExecutionStatus string

const (
	StatusPending    ExecutionStatus = "pending"
	StatusRunning    ExecutionStatus = "running"
	StatusCompleted  ExecutionStatus = "completed"
	StatusFailed     ExecutionStatus = "failed"
	StatusCancelled  ExecutionStatus = "cancelled"
	StatusTimedOut   ExecutionStatus = "timed_out"
	StatusWaiting    ExecutionStatus = "waiting_approval"
	StatusPaused     ExecutionStatus = "paused"
)

// Execution represents a playbook execution instance.
type Execution struct {
	ID           string                 `json:"id"`
	PlaybookID   string                 `json:"playbook_id"`
	PlaybookName string                 `json:"playbook_name"`
	Version      int                    `json:"version"`
	Status       ExecutionStatus        `json:"status"`
	WorkflowID   string                 `json:"workflow_id"` // Temporal workflow ID
	RunID        string                 `json:"run_id"`      // Temporal run ID
	Inputs       map[string]interface{} `json:"inputs"`
	Outputs      map[string]interface{} `json:"outputs,omitempty"`
	TriggerType  TriggerType            `json:"trigger_type"`
	TriggerInfo  map[string]interface{} `json:"trigger_info,omitempty"`
	AlertID      string                 `json:"alert_id,omitempty"`
	CaseID       string                 `json:"case_id,omitempty"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Error        string                 `json:"error,omitempty"`
	CurrentStep  string                 `json:"current_step,omitempty"`
	StepResults  []StepResult           `json:"step_results,omitempty"`
	TenantID     string                 `json:"tenant_id,omitempty"`
	ExecutedBy   string                 `json:"executed_by,omitempty"`
}

// StepResult represents the result of a step execution.
type StepResult struct {
	StepID      string                 `json:"step_id"`
	StepName    string                 `json:"step_name"`
	StepType    StepType               `json:"step_type"`
	Status      ExecutionStatus        `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    time.Duration          `json:"duration_ms"`
	Inputs      map[string]interface{} `json:"inputs,omitempty"`
	Outputs     map[string]interface{} `json:"outputs,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Retries     int                    `json:"retries,omitempty"`
}
