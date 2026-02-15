// Package playbook provides validation for playbook definitions.
package playbook

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a validation error with context.
type ValidationError struct {
	Field   string
	Message string
	Path    string
}

func (e *ValidationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (at %s)", e.Field, e.Message, e.Path)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult contains all validation errors.
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// AddError adds an error to the result.
func (r *ValidationResult) AddError(field, message, path string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Path:    path,
	})
}

// Error returns a combined error message.
func (r *ValidationResult) Error() string {
	if r.Valid {
		return ""
	}

	var msgs []string
	for _, err := range r.Errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// Validator validates playbook definitions.
type Validator struct {
	registeredConnectors map[string]bool
	registeredActions    map[string][]string
	customValidators     []CustomValidator
}

// CustomValidator is a custom validation function.
type CustomValidator func(*Playbook, *ValidationResult)

// ValidatorOption configures the validator.
type ValidatorOption func(*Validator)

// WithConnectors sets the registered connectors.
func WithConnectors(connectors []string) ValidatorOption {
	return func(v *Validator) {
		for _, c := range connectors {
			v.registeredConnectors[c] = true
		}
	}
}

// WithActions sets the registered actions per connector.
func WithActions(connector string, actions []string) ValidatorOption {
	return func(v *Validator) {
		v.registeredActions[connector] = actions
	}
}

// WithCustomValidator adds a custom validator.
func WithCustomValidator(cv CustomValidator) ValidatorOption {
	return func(v *Validator) {
		v.customValidators = append(v.customValidators, cv)
	}
}

// NewValidator creates a new playbook validator.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		registeredConnectors: make(map[string]bool),
		registeredActions:    make(map[string][]string),
		customValidators:     make([]CustomValidator, 0),
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

// Validate validates a playbook definition.
func (v *Validator) Validate(pb *Playbook) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Validate metadata
	v.validateMetadata(pb, result)

	// Validate trigger
	v.validateTrigger(pb, result)

	// Validate inputs
	v.validateInputs(pb, result)

	// Validate outputs
	v.validateOutputs(pb, result)

	// Validate steps
	v.validateSteps(pb.Steps, result, "steps")

	// Validate error handler
	if pb.ErrorHandler != nil {
		v.validateErrorHandler(pb.ErrorHandler, result)
	}

	// Validate retry policy
	if pb.RetryPolicy != nil {
		v.validateRetryPolicy(pb.RetryPolicy, result, "retryPolicy")
	}

	// Run custom validators
	for _, cv := range v.customValidators {
		cv(pb, result)
	}

	return result
}

// validateMetadata validates playbook metadata.
func (v *Validator) validateMetadata(pb *Playbook, result *ValidationResult) {
	if pb.Name == "" {
		result.AddError("name", "playbook name is required", "")
	} else if !isValidIdentifier(pb.Name) {
		result.AddError("name", "playbook name must be alphanumeric with underscores/dashes", "")
	}

	if pb.ID != "" && !isValidIdentifier(pb.ID) {
		result.AddError("id", "playbook ID must be alphanumeric with underscores/dashes", "")
	}

	if pb.Version < 1 {
		result.AddError("version", "version must be at least 1", "")
	}

	if !isValidCategory(pb.Category) {
		result.AddError("category", fmt.Sprintf("invalid category: %s", pb.Category), "")
	}
}

// validateTrigger validates the trigger configuration.
func (v *Validator) validateTrigger(pb *Playbook, result *ValidationResult) {
	if !isValidTriggerType(pb.Trigger.Type) {
		result.AddError("trigger.type", fmt.Sprintf("invalid trigger type: %s", pb.Trigger.Type), "trigger")
	}

	switch pb.Trigger.Type {
	case TriggerScheduled:
		if pb.Trigger.Schedule == nil {
			result.AddError("trigger.schedule", "schedule configuration required for scheduled trigger", "trigger")
		} else {
			v.validateSchedule(pb.Trigger.Schedule, result)
		}

	case TriggerWebhook:
		if pb.Trigger.Webhook == nil {
			result.AddError("trigger.webhook", "webhook configuration required for webhook trigger", "trigger")
		} else {
			v.validateWebhook(pb.Trigger.Webhook, result)
		}

	case TriggerAlert, TriggerIncident:
		if len(pb.Trigger.Conditions) == 0 {
			result.AddError("trigger.conditions", "conditions required for alert/incident trigger", "trigger")
		}
	}

	// Validate conditions
	for i, cond := range pb.Trigger.Conditions {
		v.validateCondition(&cond, result, fmt.Sprintf("trigger.conditions[%d]", i))
	}
}

// validateSchedule validates schedule configuration.
func (v *Validator) validateSchedule(schedule *ScheduleConfig, result *ValidationResult) {
	if schedule.Cron == "" && schedule.Interval == "" {
		result.AddError("schedule", "either cron or interval must be specified", "trigger.schedule")
	}

	if schedule.Cron != "" && !isValidCron(schedule.Cron) {
		result.AddError("schedule.cron", "invalid cron expression", "trigger.schedule")
	}

	if schedule.Interval != "" {
		_, err := time.ParseDuration(schedule.Interval)
		if err != nil {
			result.AddError("schedule.interval", "invalid interval duration", "trigger.schedule")
		}
	}

	if schedule.Timezone != "" {
		_, err := time.LoadLocation(schedule.Timezone)
		if err != nil {
			result.AddError("schedule.timezone", "invalid timezone", "trigger.schedule")
		}
	}
}

// validateWebhook validates webhook configuration.
func (v *Validator) validateWebhook(webhook *WebhookConfig, result *ValidationResult) {
	if webhook.Path == "" {
		result.AddError("webhook.path", "webhook path is required", "trigger.webhook")
	} else if !strings.HasPrefix(webhook.Path, "/") {
		result.AddError("webhook.path", "webhook path must start with /", "trigger.webhook")
	}

	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true}
	if webhook.Method != "" && !validMethods[webhook.Method] {
		result.AddError("webhook.method", "invalid HTTP method", "trigger.webhook")
	}

	validAuthTypes := map[string]bool{"none": true, "basic": true, "bearer": true, "api_key": true, "hmac": true}
	if webhook.AuthType != "" && !validAuthTypes[webhook.AuthType] {
		result.AddError("webhook.auth_type", "invalid auth type", "trigger.webhook")
	}
}

// validateInputs validates input parameters.
func (v *Validator) validateInputs(pb *Playbook, result *ValidationResult) {
	names := make(map[string]bool)

	for i, input := range pb.Inputs {
		path := fmt.Sprintf("inputs[%d]", i)

		if input.Name == "" {
			result.AddError("name", "input name is required", path)
		} else if names[input.Name] {
			result.AddError("name", fmt.Sprintf("duplicate input name: %s", input.Name), path)
		} else {
			names[input.Name] = true
		}

		if !isValidType(input.Type) {
			result.AddError("type", fmt.Sprintf("invalid type: %s", input.Type), path)
		}

		if input.Validation != nil {
			v.validateInputValidation(input.Validation, result, path)
		}
	}
}

// validateInputValidation validates input validation rules.
func (v *Validator) validateInputValidation(val *Validation, result *ValidationResult, path string) {
	if val.Pattern != "" {
		_, err := regexp.Compile(val.Pattern)
		if err != nil {
			result.AddError("validation.pattern", "invalid regex pattern", path)
		}
	}

	if val.MinLength < 0 {
		result.AddError("validation.min_length", "min_length must be non-negative", path)
	}

	if val.MaxLength > 0 && val.MinLength > val.MaxLength {
		result.AddError("validation", "min_length cannot exceed max_length", path)
	}
}

// validateOutputs validates output fields.
func (v *Validator) validateOutputs(pb *Playbook, result *ValidationResult) {
	names := make(map[string]bool)

	for i, output := range pb.Outputs {
		path := fmt.Sprintf("outputs[%d]", i)

		if output.Name == "" {
			result.AddError("name", "output name is required", path)
		} else if names[output.Name] {
			result.AddError("name", fmt.Sprintf("duplicate output name: %s", output.Name), path)
		} else {
			names[output.Name] = true
		}

		if output.Source == "" {
			result.AddError("source", "output source is required", path)
		}
	}
}

// validateSteps validates steps recursively.
func (v *Validator) validateSteps(steps []Step, result *ValidationResult, basePath string) {
	stepIDs := make(map[string]bool)

	for i, step := range steps {
		path := fmt.Sprintf("%s[%d]", basePath, i)

		// Validate step ID uniqueness
		if step.ID != "" {
			if stepIDs[step.ID] {
				result.AddError("id", fmt.Sprintf("duplicate step ID: %s", step.ID), path)
			} else {
				stepIDs[step.ID] = true
			}
		}

		// Validate step type
		if !isValidStepType(step.Type) {
			result.AddError("type", fmt.Sprintf("invalid step type: %s", step.Type), path)
			continue
		}

		// Validate type-specific configuration
		switch step.Type {
		case StepTypeAction:
			v.validateActionStep(&step, result, path)
		case StepTypeCondition:
			v.validateConditionStep(&step, result, path)
		case StepTypeParallel:
			v.validateParallelStep(&step, result, path)
		case StepTypeLoop:
			v.validateLoopStep(&step, result, path)
		case StepTypeWait:
			v.validateWaitStep(&step, result, path)
		case StepTypeApproval:
			v.validateApprovalStep(&step, result, path)
		case StepTypeSubPlaybook:
			v.validateSubPlaybookStep(&step, result, path)
		case StepTypeScript:
			v.validateScriptStep(&step, result, path)
		case StepTypeTransform:
			v.validateTransformStep(&step, result, path)
		}

		// Validate retry policy if present
		if step.RetryPolicy != nil {
			v.validateRetryPolicy(step.RetryPolicy, result, path+".retry_policy")
		}

		// Validate skip condition if present
		if step.SkipCondition != nil {
			v.validateCondition(step.SkipCondition, result, path+".skip_condition")
		}
	}
}

// validateActionStep validates an action step.
func (v *Validator) validateActionStep(step *Step, result *ValidationResult, path string) {
	if step.Action == nil {
		result.AddError("action", "action configuration required", path)
		return
	}

	if step.Action.Connector == "" {
		result.AddError("action.connector", "connector is required", path)
	} else if len(v.registeredConnectors) > 0 && !v.registeredConnectors[step.Action.Connector] {
		result.AddError("action.connector", fmt.Sprintf("unknown connector: %s", step.Action.Connector), path)
	}

	if step.Action.Action == "" {
		result.AddError("action.action", "action name is required", path)
	}
}

// validateConditionStep validates a condition step.
func (v *Validator) validateConditionStep(step *Step, result *ValidationResult, path string) {
	if step.Condition == nil {
		result.AddError("condition", "condition configuration required", path)
		return
	}

	if len(step.Condition.Conditions) == 0 {
		result.AddError("condition.conditions", "at least one condition is required", path)
	}

	for i, cond := range step.Condition.Conditions {
		v.validateCondition(&cond, result, fmt.Sprintf("%s.conditions[%d]", path, i))
	}

	if len(step.Condition.ThenSteps) == 0 {
		result.AddError("condition.then", "then steps are required", path)
	}

	v.validateSteps(step.Condition.ThenSteps, result, path+".then")
	v.validateSteps(step.Condition.ElseSteps, result, path+".else")
}

// validateParallelStep validates a parallel step.
func (v *Validator) validateParallelStep(step *Step, result *ValidationResult, path string) {
	if step.Parallel == nil {
		result.AddError("parallel", "parallel configuration required", path)
		return
	}

	if len(step.Parallel.Branches) < 2 {
		result.AddError("parallel.branches", "at least two branches required for parallel execution", path)
	}

	branchIDs := make(map[string]bool)
	for i, branch := range step.Parallel.Branches {
		branchPath := fmt.Sprintf("%s.branches[%d]", path, i)

		if branch.ID != "" && branchIDs[branch.ID] {
			result.AddError("id", fmt.Sprintf("duplicate branch ID: %s", branch.ID), branchPath)
		} else if branch.ID != "" {
			branchIDs[branch.ID] = true
		}

		if len(branch.Steps) == 0 {
			result.AddError("steps", "branch must have at least one step", branchPath)
		}

		v.validateSteps(branch.Steps, result, branchPath+".steps")
	}
}

// validateLoopStep validates a loop step.
func (v *Validator) validateLoopStep(step *Step, result *ValidationResult, path string) {
	if step.Loop == nil {
		result.AddError("loop", "loop configuration required", path)
		return
	}

	if step.Loop.Items == "" {
		result.AddError("loop.items", "items expression is required", path)
	}

	if step.Loop.ItemVar == "" {
		result.AddError("loop.item_var", "item variable name is required", path)
	}

	if len(step.Loop.Steps) == 0 {
		result.AddError("loop.steps", "loop must have at least one step", path)
	}

	v.validateSteps(step.Loop.Steps, result, path+".steps")
}

// validateWaitStep validates a wait step.
func (v *Validator) validateWaitStep(step *Step, result *ValidationResult, path string) {
	if step.Wait == nil {
		result.AddError("wait", "wait configuration required", path)
		return
	}

	hasConfig := step.Wait.Duration > 0 || step.Wait.Until != nil || step.Wait.Signal != ""
	if !hasConfig {
		result.AddError("wait", "duration, until condition, or signal is required", path)
	}

	if step.Wait.Until != nil {
		v.validateCondition(step.Wait.Until, result, path+".until")
	}
}

// validateApprovalStep validates an approval step.
func (v *Validator) validateApprovalStep(step *Step, result *ValidationResult, path string) {
	if step.Approval == nil {
		result.AddError("approval", "approval configuration required", path)
		return
	}

	if len(step.Approval.Approvers) == 0 && len(step.Approval.ApproverGroups) == 0 {
		result.AddError("approval", "at least one approver or approver group is required", path)
	}

	if step.Approval.Timeout == 0 {
		result.AddError("approval.timeout", "timeout is required for approval steps", path)
	}

	if step.Approval.Message == "" {
		result.AddError("approval.message", "message is required for approval steps", path)
	}

	if step.Approval.RequiredCount > len(step.Approval.Approvers) {
		result.AddError("approval.required_count", "required count cannot exceed number of approvers", path)
	}
}

// validateSubPlaybookStep validates a sub-playbook step.
func (v *Validator) validateSubPlaybookStep(step *Step, result *ValidationResult, path string) {
	if step.SubPlaybook == nil {
		result.AddError("sub_playbook", "sub_playbook configuration required", path)
		return
	}

	if step.SubPlaybook.PlaybookID == "" {
		result.AddError("sub_playbook.playbook_id", "playbook ID is required", path)
	}
}

// validateScriptStep validates a script step.
func (v *Validator) validateScriptStep(step *Step, result *ValidationResult, path string) {
	if step.Script == nil {
		result.AddError("script", "script configuration required", path)
		return
	}

	validLanguages := map[string]bool{"python": true, "javascript": true, "go": true}
	if !validLanguages[step.Script.Language] {
		result.AddError("script.language", fmt.Sprintf("unsupported language: %s", step.Script.Language), path)
	}

	if step.Script.Code == "" {
		result.AddError("script.code", "code is required", path)
	}
}

// validateTransformStep validates a transform step.
func (v *Validator) validateTransformStep(step *Step, result *ValidationResult, path string) {
	if step.Transform == nil {
		result.AddError("transform", "transform configuration required", path)
		return
	}

	validTypes := map[string]bool{"jq": true, "jsonpath": true, "template": true}
	if !validTypes[step.Transform.Type] {
		result.AddError("transform.type", fmt.Sprintf("unsupported transform type: %s", step.Transform.Type), path)
	}

	if step.Transform.Expression == "" {
		result.AddError("transform.expression", "expression is required", path)
	}

	if step.Transform.Source == "" {
		result.AddError("transform.source", "source is required", path)
	}

	if step.Transform.Target == "" {
		result.AddError("transform.target", "target is required", path)
	}
}

// validateCondition validates a condition.
func (v *Validator) validateCondition(cond *Condition, result *ValidationResult, path string) {
	if cond.Field == "" && len(cond.And) == 0 && len(cond.Or) == 0 {
		result.AddError("field", "condition field is required unless using and/or", path)
	}

	if cond.Field != "" && !isValidOperator(cond.Operator) {
		result.AddError("operator", fmt.Sprintf("invalid operator: %s", cond.Operator), path)
	}

	for i, sub := range cond.And {
		v.validateCondition(&sub, result, fmt.Sprintf("%s.and[%d]", path, i))
	}

	for i, sub := range cond.Or {
		v.validateCondition(&sub, result, fmt.Sprintf("%s.or[%d]", path, i))
	}
}

// validateErrorHandler validates error handler configuration.
func (v *Validator) validateErrorHandler(handler *ErrorHandler, result *ValidationResult) {
	validTypes := map[string]bool{"retry": true, "fallback": true, "ignore": true, "abort": true}
	if !validTypes[handler.Type] {
		result.AddError("error_handler.type", fmt.Sprintf("invalid error handler type: %s", handler.Type), "")
	}

	if handler.Type == "fallback" && len(handler.Steps) == 0 {
		result.AddError("error_handler.steps", "fallback steps are required for fallback handler", "")
	}

	if handler.Type == "retry" && handler.MaxRetries <= 0 {
		result.AddError("error_handler.max_retries", "max_retries must be positive for retry handler", "")
	}
}

// validateRetryPolicy validates retry policy configuration.
func (v *Validator) validateRetryPolicy(policy *RetryPolicy, result *ValidationResult, path string) {
	if policy.MaxAttempts < 1 {
		result.AddError("max_attempts", "max_attempts must be at least 1", path)
	}

	if policy.BackoffCoefficient < 1.0 {
		result.AddError("backoff_coefficient", "backoff_coefficient must be at least 1.0", path)
	}

	if policy.MaxInterval > 0 && policy.InitialInterval > policy.MaxInterval {
		result.AddError("initial_interval", "initial_interval cannot exceed max_interval", path)
	}
}

// Helper functions

func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_-]*$`, s)
	return matched
}

func isValidCategory(c Category) bool {
	validCategories := map[Category]bool{
		CategoryEnrichment:   true,
		CategoryContainment:  true,
		CategoryRemediation:  true,
		CategoryNotification: true,
		CategoryInvestigation: true,
		CategoryResponse:     true,
		CategoryCustom:       true,
	}
	return validCategories[c]
}

func isValidTriggerType(t TriggerType) bool {
	validTypes := map[TriggerType]bool{
		TriggerManual:    true,
		TriggerAutomatic: true,
		TriggerScheduled: true,
		TriggerWebhook:   true,
		TriggerAlert:     true,
		TriggerIncident:  true,
	}
	return validTypes[t]
}

func isValidStepType(t StepType) bool {
	validTypes := map[StepType]bool{
		StepTypeAction:      true,
		StepTypeCondition:   true,
		StepTypeParallel:    true,
		StepTypeLoop:        true,
		StepTypeWait:        true,
		StepTypeApproval:    true,
		StepTypeSubPlaybook: true,
		StepTypeScript:      true,
		StepTypeTransform:   true,
	}
	return validTypes[t]
}

func isValidOperator(op ConditionOperator) bool {
	validOps := map[ConditionOperator]bool{
		OpEquals:         true,
		OpNotEquals:      true,
		OpContains:       true,
		OpNotContains:    true,
		OpStartsWith:     true,
		OpEndsWith:       true,
		OpGreaterThan:    true,
		OpLessThan:       true,
		OpGreaterOrEqual: true,
		OpLessOrEqual:    true,
		OpIn:             true,
		OpNotIn:          true,
		OpMatches:        true,
		OpExists:         true,
		OpNotExists:      true,
	}
	return validOps[op]
}

func isValidType(t string) bool {
	validTypes := map[string]bool{
		"string":   true,
		"int":      true,
		"float":    true,
		"bool":     true,
		"array":    true,
		"object":   true,
		"datetime": true,
		"duration": true,
		"ip":       true,
		"url":      true,
		"email":    true,
		"any":      true,
	}
	return validTypes[t]
}

func isValidCron(cron string) bool {
	// Basic cron validation (5 or 6 fields)
	parts := strings.Fields(cron)
	return len(parts) >= 5 && len(parts) <= 6
}
