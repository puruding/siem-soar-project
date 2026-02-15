// Package executor provides Temporal workflow definitions for playbook execution.
package executor

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/siem-soar-platform/services/soar/internal/playbook"
)

// PlaybookWorkflowInput is the input for the playbook workflow.
type PlaybookWorkflowInput struct {
	ExecutionID string                 `json:"execution_id"`
	Playbook    *playbook.Playbook     `json:"playbook"`
	Inputs      map[string]interface{} `json:"inputs"`
	TriggerInfo map[string]interface{} `json:"trigger_info,omitempty"`
	TenantID    string                 `json:"tenant_id,omitempty"`
}

// PlaybookWorkflowOutput is the output from the playbook workflow.
type PlaybookWorkflowOutput struct {
	ExecutionID string                   `json:"execution_id"`
	Status      playbook.ExecutionStatus `json:"status"`
	Outputs     map[string]interface{}   `json:"outputs,omitempty"`
	Error       string                   `json:"error,omitempty"`
	StepResults []StepResultOutput       `json:"step_results,omitempty"`
}

// StepResultOutput represents a step result in the workflow output.
type StepResultOutput struct {
	StepID    string                 `json:"step_id"`
	StepName  string                 `json:"step_name"`
	Status    string                 `json:"status"`
	Outputs   map[string]interface{} `json:"outputs,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Duration  int64                  `json:"duration_ms"`
}

// WorkflowState maintains the state of the workflow execution.
type WorkflowState struct {
	Inputs      map[string]interface{}
	Variables   map[string]interface{}
	StepOutputs map[string]interface{}
	Paused      bool
	Cancelled   bool
}

// PlaybookWorkflow is the main Temporal workflow for playbook execution.
func PlaybookWorkflow(ctx workflow.Context, input PlaybookWorkflowInput) (*PlaybookWorkflowOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting playbook execution",
		"execution_id", input.ExecutionID,
		"playbook_id", input.Playbook.ID,
		"playbook_name", input.Playbook.Name,
	)

	// Update search attributes
	_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
		"ExecutionStatus": string(playbook.StatusRunning),
	})

	// Initialize workflow state
	state := &WorkflowState{
		Inputs:      input.Inputs,
		Variables:   make(map[string]interface{}),
		StepOutputs: make(map[string]interface{}),
	}

	// Initialize variables from playbook definition
	for _, v := range input.Playbook.Variables {
		if v.Value != nil {
			state.Variables[v.Name] = v.Value
		}
	}

	// Copy inputs to variables
	for k, v := range input.Inputs {
		state.Variables[k] = v
	}

	// Add trigger info to variables
	if input.TriggerInfo != nil {
		state.Variables["trigger"] = input.TriggerInfo
	}

	// Set up signal channels
	pauseCh := workflow.GetSignalChannel(ctx, SignalPause)
	resumeCh := workflow.GetSignalChannel(ctx, SignalResume)
	cancelCh := workflow.GetSignalChannel(ctx, SignalCancel)

	// Create a selector for signal handling
	selector := workflow.NewSelector(ctx)

	// Handle pause signal
	selector.AddReceive(pauseCh, func(c workflow.ReceiveChannel, more bool) {
		c.Receive(ctx, nil)
		state.Paused = true
		logger.Info("Workflow paused")
	})

	// Handle cancel signal
	selector.AddReceive(cancelCh, func(c workflow.ReceiveChannel, more bool) {
		c.Receive(ctx, nil)
		state.Cancelled = true
		logger.Info("Workflow cancelled")
	})

	// Execute steps
	output := &PlaybookWorkflowOutput{
		ExecutionID: input.ExecutionID,
		StepResults: make([]StepResultOutput, 0),
	}

	err := executeSteps(ctx, input.Playbook.Steps, state, output, selector, pauseCh, resumeCh)
	if err != nil {
		output.Status = playbook.StatusFailed
		output.Error = err.Error()
		_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
			"ExecutionStatus": string(playbook.StatusFailed),
		})
		return output, nil
	}

	if state.Cancelled {
		output.Status = playbook.StatusCancelled
		_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
			"ExecutionStatus": string(playbook.StatusCancelled),
		})
		return output, nil
	}

	// Collect outputs
	output.Status = playbook.StatusCompleted
	output.Outputs = collectOutputs(input.Playbook.Outputs, state)
	_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
		"ExecutionStatus": string(playbook.StatusCompleted),
	})

	logger.Info("Playbook execution completed",
		"execution_id", input.ExecutionID,
		"status", output.Status,
	)

	return output, nil
}

// executeSteps executes a list of steps sequentially.
func executeSteps(
	ctx workflow.Context,
	steps []playbook.Step,
	state *WorkflowState,
	output *PlaybookWorkflowOutput,
	selector workflow.Selector,
	pauseCh, resumeCh workflow.ReceiveChannel,
) error {
	for _, step := range steps {
		// Check for cancellation
		if state.Cancelled {
			return nil
		}

		// Handle pause
		for state.Paused {
			// Wait for resume signal
			resumeCh.Receive(ctx, nil)
			state.Paused = false
		}

		// Check skip condition
		if step.SkipCondition != nil {
			shouldSkip, err := evaluateCondition(step.SkipCondition, state)
			if err != nil {
				return fmt.Errorf("failed to evaluate skip condition for step %s: %w", step.ID, err)
			}
			if shouldSkip {
				continue
			}
		}

		// Execute step
		result, err := executeStep(ctx, &step, state, pauseCh, resumeCh)
		if err != nil && !step.ContinueOnError {
			return fmt.Errorf("step %s failed: %w", step.ID, err)
		}

		// Record result
		output.StepResults = append(output.StepResults, *result)

		// Store step output
		if result.Outputs != nil {
			state.StepOutputs[step.ID] = result.Outputs

			// Apply output mapping
			if step.OutputMapping != nil {
				for varName, outputPath := range step.OutputMapping {
					value := getValueFromPath(result.Outputs, outputPath)
					state.Variables[varName] = value
				}
			}
		}
	}

	return nil
}

// executeStep executes a single step based on its type.
func executeStep(
	ctx workflow.Context,
	step *playbook.Step,
	state *WorkflowState,
	pauseCh, resumeCh workflow.ReceiveChannel,
) (*StepResultOutput, error) {
	startTime := workflow.Now(ctx)
	result := &StepResultOutput{
		StepID:   step.ID,
		StepName: step.Name,
	}

	var err error
	var outputs map[string]interface{}

	// Create activity options
	activityOptions := workflow.ActivityOptions{
		TaskQueue:              "playbook-execution",
		StartToCloseTimeout:    time.Duration(step.Timeout),
		HeartbeatTimeout:       time.Minute,
		RetryPolicy:            buildRetryPolicy(step.RetryPolicy),
	}

	if step.Timeout == 0 {
		activityOptions.StartToCloseTimeout = 5 * time.Minute
	}

	activityCtx := workflow.WithActivityOptions(ctx, activityOptions)

	switch step.Type {
	case playbook.StepTypeAction:
		outputs, err = executeActionStep(activityCtx, step, state)

	case playbook.StepTypeCondition:
		outputs, err = executeConditionStep(ctx, step, state, pauseCh, resumeCh)

	case playbook.StepTypeParallel:
		outputs, err = executeParallelStep(ctx, step, state)

	case playbook.StepTypeLoop:
		outputs, err = executeLoopStep(ctx, step, state, pauseCh, resumeCh)

	case playbook.StepTypeWait:
		outputs, err = executeWaitStep(ctx, step, state)

	case playbook.StepTypeApproval:
		outputs, err = executeApprovalStep(ctx, step, state)

	case playbook.StepTypeSubPlaybook:
		outputs, err = executeSubPlaybookStep(activityCtx, step, state)

	case playbook.StepTypeScript:
		outputs, err = executeScriptStep(activityCtx, step, state)

	case playbook.StepTypeTransform:
		outputs, err = executeTransformStep(activityCtx, step, state)

	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	endTime := workflow.Now(ctx)
	result.Duration = endTime.Sub(startTime).Milliseconds()

	if err != nil {
		result.Status = string(playbook.StatusFailed)
		result.Error = err.Error()
	} else {
		result.Status = string(playbook.StatusCompleted)
		result.Outputs = outputs
	}

	return result, err
}

// executeActionStep executes an action step.
func executeActionStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Action == nil {
		return nil, fmt.Errorf("action configuration is missing")
	}

	// Resolve parameters
	params := resolveParameters(step.Action.Parameters, state)

	input := ActionActivityInput{
		Connector:  step.Action.Connector,
		Action:     step.Action.Action,
		Parameters: params,
	}

	var output ActionActivityOutput
	err := workflow.ExecuteActivity(ctx, ExecuteActionActivity, input).Get(ctx, &output)
	if err != nil {
		return nil, err
	}

	return output.Result, nil
}

// executeConditionStep executes a condition step.
func executeConditionStep(
	ctx workflow.Context,
	step *playbook.Step,
	state *WorkflowState,
	pauseCh, resumeCh workflow.ReceiveChannel,
) (map[string]interface{}, error) {
	if step.Condition == nil {
		return nil, fmt.Errorf("condition configuration is missing")
	}

	// Evaluate condition
	conditionMet := true
	for _, cond := range step.Condition.Conditions {
		met, err := evaluateCondition(&cond, state)
		if err != nil {
			return nil, err
		}
		if !met {
			conditionMet = false
			break
		}
	}

	// Execute appropriate branch
	var stepsToExecute []playbook.Step
	if conditionMet {
		stepsToExecute = step.Condition.ThenSteps
	} else {
		stepsToExecute = step.Condition.ElseSteps
	}

	if len(stepsToExecute) > 0 {
		output := &PlaybookWorkflowOutput{StepResults: make([]StepResultOutput, 0)}
		selector := workflow.NewSelector(ctx)
		err := executeSteps(ctx, stepsToExecute, state, output, selector, pauseCh, resumeCh)
		if err != nil {
			return nil, err
		}
	}

	return map[string]interface{}{
		"condition_met": conditionMet,
	}, nil
}

// executeParallelStep executes steps in parallel.
func executeParallelStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Parallel == nil {
		return nil, fmt.Errorf("parallel configuration is missing")
	}

	// Create child workflows for each branch
	futures := make([]workflow.Future, len(step.Parallel.Branches))

	for i, branch := range step.Parallel.Branches {
		// Create a child workflow context
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID: fmt.Sprintf("%s-%s", workflow.GetInfo(ctx).WorkflowExecution.ID, branch.ID),
		})

		futures[i] = workflow.ExecuteChildWorkflow(childCtx, ParallelBranchWorkflow, ParallelBranchInput{
			BranchID: branch.ID,
			Steps:    branch.Steps,
			State:    state,
		})
	}

	// Wait for all branches to complete
	results := make(map[string]interface{})
	var lastErr error

	for i, future := range futures {
		var output ParallelBranchOutput
		err := future.Get(ctx, &output)
		if err != nil {
			if step.Parallel.FailFast {
				return nil, fmt.Errorf("branch %s failed: %w", step.Parallel.Branches[i].ID, err)
			}
			lastErr = err
		}
		results[step.Parallel.Branches[i].ID] = output.Results
	}

	if lastErr != nil && step.Parallel.FailFast {
		return nil, lastErr
	}

	return results, nil
}

// executeLoopStep executes steps in a loop.
func executeLoopStep(
	ctx workflow.Context,
	step *playbook.Step,
	state *WorkflowState,
	pauseCh, resumeCh workflow.ReceiveChannel,
) (map[string]interface{}, error) {
	if step.Loop == nil {
		return nil, fmt.Errorf("loop configuration is missing")
	}

	// Get items to iterate over
	items, ok := getValueFromState(step.Loop.Items, state).([]interface{})
	if !ok {
		return nil, fmt.Errorf("loop items must be an array")
	}

	results := make([]interface{}, 0)
	maxIter := step.Loop.MaxIterations
	if maxIter <= 0 {
		maxIter = len(items)
	}

	for i, item := range items {
		if i >= maxIter {
			break
		}

		// Set loop variables
		state.Variables[step.Loop.ItemVar] = item
		if step.Loop.IndexVar != "" {
			state.Variables[step.Loop.IndexVar] = i
		}

		// Execute loop steps
		output := &PlaybookWorkflowOutput{StepResults: make([]StepResultOutput, 0)}
		selector := workflow.NewSelector(ctx)
		err := executeSteps(ctx, step.Loop.Steps, state, output, selector, pauseCh, resumeCh)
		if err != nil {
			return nil, fmt.Errorf("loop iteration %d failed: %w", i, err)
		}

		results = append(results, state.StepOutputs)
	}

	// Clean up loop variables
	delete(state.Variables, step.Loop.ItemVar)
	if step.Loop.IndexVar != "" {
		delete(state.Variables, step.Loop.IndexVar)
	}

	return map[string]interface{}{
		"iterations": len(results),
		"results":    results,
	}, nil
}

// executeWaitStep executes a wait step.
func executeWaitStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Wait == nil {
		return nil, fmt.Errorf("wait configuration is missing")
	}

	// Wait for duration
	if step.Wait.Duration > 0 {
		err := workflow.Sleep(ctx, time.Duration(step.Wait.Duration))
		if err != nil {
			return nil, err
		}
	}

	// Wait for condition
	if step.Wait.Until != nil {
		maxWait := time.Duration(step.Wait.MaxWait)
		if maxWait <= 0 {
			maxWait = 24 * time.Hour
		}

		deadline := workflow.Now(ctx).Add(maxWait)
		for workflow.Now(ctx).Before(deadline) {
			met, err := evaluateCondition(step.Wait.Until, state)
			if err != nil {
				return nil, err
			}
			if met {
				break
			}
			workflow.Sleep(ctx, time.Minute)
		}
	}

	// Wait for signal
	if step.Wait.Signal != "" {
		signalCh := workflow.GetSignalChannel(ctx, step.Wait.Signal)
		var signalValue interface{}
		signalCh.Receive(ctx, &signalValue)
		return map[string]interface{}{
			"signal":       step.Wait.Signal,
			"signal_value": signalValue,
		}, nil
	}

	return map[string]interface{}{
		"waited": true,
	}, nil
}

// executeApprovalStep executes an approval step.
func executeApprovalStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Approval == nil {
		return nil, fmt.Errorf("approval configuration is missing")
	}

	// Update search attributes
	_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
		"ExecutionStatus":  string(playbook.StatusWaiting),
		"RequiresApproval": true,
	})

	// Request approval activity
	activityOptions := workflow.ActivityOptions{
		TaskQueue:           "playbook-execution",
		StartToCloseTimeout: time.Minute,
	}
	activityCtx := workflow.WithActivityOptions(ctx, activityOptions)

	requestInput := RequestApprovalInput{
		StepID:         step.ID,
		Message:        resolveString(step.Approval.Message, state),
		Approvers:      step.Approval.Approvers,
		ApproverGroups: step.Approval.ApproverGroups,
		RequiredCount:  step.Approval.RequiredCount,
		Timeout:        time.Duration(step.Approval.Timeout),
	}

	err := workflow.ExecuteActivity(activityCtx, RequestApprovalActivity, requestInput).Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request approval: %w", err)
	}

	// Wait for approval signals
	approvalCh := workflow.GetSignalChannel(ctx, SignalApproval)
	approvals := make([]ApprovalSignal, 0)
	requiredCount := step.Approval.RequiredCount
	if requiredCount <= 0 {
		requiredCount = 1
	}

	timeout := time.Duration(step.Approval.Timeout)
	ctx, cancel := workflow.WithCancel(ctx)
	defer cancel()

	selector := workflow.NewSelector(ctx)
	timedOut := false

	selector.AddReceive(approvalCh, func(c workflow.ReceiveChannel, more bool) {
		var signal ApprovalSignal
		c.Receive(ctx, &signal)
		approvals = append(approvals, signal)
	})

	timerFuture := workflow.NewTimer(ctx, timeout)
	selector.AddFuture(timerFuture, func(f workflow.Future) {
		timedOut = true
	})

	approvedCount := 0
	rejectedCount := 0

	for {
		selector.Select(ctx)

		if timedOut {
			// Handle escalation if configured
			if step.Approval.Escalation != nil {
				return nil, fmt.Errorf("approval timed out, escalation not implemented")
			}
			return nil, fmt.Errorf("approval timed out")
		}

		// Count approvals
		for _, a := range approvals {
			if a.Approved {
				approvedCount++
			} else {
				rejectedCount++
			}
		}

		if approvedCount >= requiredCount {
			break
		}

		// Check if rejection makes approval impossible
		remainingApprovers := len(step.Approval.Approvers) - len(approvals)
		if approvedCount+remainingApprovers < requiredCount {
			return nil, fmt.Errorf("approval rejected: not enough remaining approvers")
		}

		approvals = approvals[:0] // Reset for next iteration
	}

	_ = workflow.UpsertSearchAttributes(ctx, map[string]interface{}{
		"ExecutionStatus":  string(playbook.StatusRunning),
		"RequiresApproval": false,
		"ApprovalStatus":   "approved",
	})

	return map[string]interface{}{
		"approved":       true,
		"approved_count": approvedCount,
		"rejected_count": rejectedCount,
		"approvals":      approvals,
	}, nil
}

// executeSubPlaybookStep executes a sub-playbook.
func executeSubPlaybookStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.SubPlaybook == nil {
		return nil, fmt.Errorf("sub_playbook configuration is missing")
	}

	input := SubPlaybookActivityInput{
		PlaybookID: step.SubPlaybook.PlaybookID,
		Version:    step.SubPlaybook.Version,
		Inputs:     resolveParameters(step.SubPlaybook.Inputs, state),
	}

	var output SubPlaybookActivityOutput
	err := workflow.ExecuteActivity(ctx, ExecuteSubPlaybookActivity, input).Get(ctx, &output)
	if err != nil {
		return nil, err
	}

	return output.Outputs, nil
}

// executeScriptStep executes a script.
func executeScriptStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Script == nil {
		return nil, fmt.Errorf("script configuration is missing")
	}

	input := ScriptActivityInput{
		Language: step.Script.Language,
		Code:     step.Script.Code,
		Inputs:   resolveParameters(step.Script.Inputs, state),
		Timeout:  time.Duration(step.Script.Timeout),
	}

	var output ScriptActivityOutput
	err := workflow.ExecuteActivity(ctx, ExecuteScriptActivity, input).Get(ctx, &output)
	if err != nil {
		return nil, err
	}

	return output.Result, nil
}

// executeTransformStep executes a data transformation.
func executeTransformStep(ctx workflow.Context, step *playbook.Step, state *WorkflowState) (map[string]interface{}, error) {
	if step.Transform == nil {
		return nil, fmt.Errorf("transform configuration is missing")
	}

	sourceValue := getValueFromState(step.Transform.Source, state)

	input := TransformActivityInput{
		Type:       step.Transform.Type,
		Expression: step.Transform.Expression,
		Source:     sourceValue,
	}

	var output TransformActivityOutput
	err := workflow.ExecuteActivity(ctx, ExecuteTransformActivity, input).Get(ctx, &output)
	if err != nil {
		return nil, err
	}

	// Store result in target variable
	state.Variables[step.Transform.Target] = output.Result

	return map[string]interface{}{
		step.Transform.Target: output.Result,
	}, nil
}

// ParallelBranchInput is the input for a parallel branch workflow.
type ParallelBranchInput struct {
	BranchID string
	Steps    []playbook.Step
	State    *WorkflowState
}

// ParallelBranchOutput is the output from a parallel branch workflow.
type ParallelBranchOutput struct {
	BranchID string
	Results  map[string]interface{}
}

// ParallelBranchWorkflow executes a parallel branch.
func ParallelBranchWorkflow(ctx workflow.Context, input ParallelBranchInput) (*ParallelBranchOutput, error) {
	output := &PlaybookWorkflowOutput{StepResults: make([]StepResultOutput, 0)}
	pauseCh := workflow.GetSignalChannel(ctx, SignalPause)
	resumeCh := workflow.GetSignalChannel(ctx, SignalResume)
	selector := workflow.NewSelector(ctx)

	err := executeSteps(ctx, input.Steps, input.State, output, selector, pauseCh, resumeCh)
	if err != nil {
		return nil, err
	}

	return &ParallelBranchOutput{
		BranchID: input.BranchID,
		Results:  input.State.StepOutputs,
	}, nil
}

// Helper functions

func buildRetryPolicy(policy *playbook.RetryPolicy) *temporal.RetryPolicy {
	if policy == nil {
		return &temporal.RetryPolicy{
			MaximumAttempts: 3,
		}
	}

	return &temporal.RetryPolicy{
		MaximumAttempts:        int32(policy.MaxAttempts),
		InitialInterval:        time.Duration(policy.InitialInterval),
		MaximumInterval:        time.Duration(policy.MaxInterval),
		BackoffCoefficient:     policy.BackoffCoefficient,
		NonRetryableErrorTypes: policy.RetryableErrors,
	}
}

func evaluateCondition(cond *playbook.Condition, state *WorkflowState) (bool, error) {
	// Handle AND conditions
	if len(cond.And) > 0 {
		for _, subCond := range cond.And {
			met, err := evaluateCondition(&subCond, state)
			if err != nil {
				return false, err
			}
			if !met {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle OR conditions
	if len(cond.Or) > 0 {
		for _, subCond := range cond.Or {
			met, err := evaluateCondition(&subCond, state)
			if err != nil {
				return false, err
			}
			if met {
				return true, nil
			}
		}
		return false, nil
	}

	// Evaluate single condition
	fieldValue := getValueFromState(cond.Field, state)
	return compareValues(fieldValue, cond.Value, cond.Operator)
}

func compareValues(actual, expected interface{}, op playbook.ConditionOperator) (bool, error) {
	switch op {
	case playbook.OpEquals:
		return actual == expected, nil
	case playbook.OpNotEquals:
		return actual != expected, nil
	case playbook.OpExists:
		return actual != nil, nil
	case playbook.OpNotExists:
		return actual == nil, nil
	case playbook.OpContains:
		if s, ok := actual.(string); ok {
			if e, ok := expected.(string); ok {
				return containsString(s, e), nil
			}
		}
		return false, nil
	// Add more operators as needed
	default:
		return false, fmt.Errorf("unsupported operator: %s", op)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0)
}

func getValueFromState(path string, state *WorkflowState) interface{} {
	// Check variables first
	if val, ok := state.Variables[path]; ok {
		return val
	}

	// Check inputs
	if val, ok := state.Inputs[path]; ok {
		return val
	}

	// Check step outputs (format: steps.stepId.field)
	if val, ok := state.StepOutputs[path]; ok {
		return val
	}

	return nil
}

func getValueFromPath(data map[string]interface{}, path string) interface{} {
	return data[path]
}

func resolveParameters(params map[string]interface{}, state *WorkflowState) map[string]interface{} {
	if params == nil {
		return nil
	}

	resolved := make(map[string]interface{})
	for k, v := range params {
		resolved[k] = resolveValue(v, state)
	}
	return resolved
}

func resolveValue(value interface{}, state *WorkflowState) interface{} {
	switch v := value.(type) {
	case string:
		return resolveString(v, state)
	case map[string]interface{}:
		return resolveParameters(v, state)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = resolveValue(item, state)
		}
		return result
	default:
		return value
	}
}

func resolveString(s string, state *WorkflowState) string {
	// Simple variable substitution
	if playbook.IsExpression(s) {
		// Extract and resolve expressions
		if val := getValueFromState(s, state); val != nil {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return s
}

func collectOutputs(outputs []playbook.OutputField, state *WorkflowState) map[string]interface{} {
	result := make(map[string]interface{})
	for _, output := range outputs {
		value := getValueFromState(output.Source, state)
		result[output.Name] = value
	}
	return result
}
