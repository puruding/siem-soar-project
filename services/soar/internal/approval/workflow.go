// Package approval provides Temporal workflow for approval management.
package approval

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// WorkflowInput defines input for the approval workflow.
type WorkflowInput struct {
	StepID           string                 `json:"step_id"`
	ExecutionID      string                 `json:"execution_id"`
	Type             ApprovalType           `json:"type"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Approvers        []string               `json:"approvers"`
	ApproverGroups   []string               `json:"approver_groups,omitempty"`
	RequiredCount    int                    `json:"required_count,omitempty"`
	Context          map[string]interface{} `json:"context,omitempty"`
	AlertID          string                 `json:"alert_id,omitempty"`
	CaseID           string                 `json:"case_id,omitempty"`
	PlaybookName     string                 `json:"playbook_name,omitempty"`
	Timeout          time.Duration          `json:"timeout"`
	Actions          []Action               `json:"actions,omitempty"`
	Priority         string                 `json:"priority,omitempty"`
	EscalationConfig *EscalationConfig      `json:"escalation_config,omitempty"`
}

// WorkflowResult contains the approval workflow result.
type WorkflowResult struct {
	Approved    bool      `json:"approved"`
	Status      string    `json:"status"`
	Response    *Response `json:"response,omitempty"`
	Responses   []Response `json:"responses"`
	CompletedAt time.Time `json:"completed_at"`
}

// ApprovalWorkflow implements the Temporal workflow for approvals.
func ApprovalWorkflow(ctx workflow.Context, input WorkflowInput) (*WorkflowResult, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting approval workflow", "step_id", input.StepID, "type", input.Type)

	// Workflow options
	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		HeartbeatTimeout:    30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	// Create approval request
	workflowInfo := workflow.GetInfo(ctx)
	createInput := &CreateRequestInput{
		WorkflowID:       workflowInfo.WorkflowExecution.ID,
		RunID:            workflowInfo.WorkflowExecution.RunID,
		StepID:           input.StepID,
		ExecutionID:      input.ExecutionID,
		Type:             input.Type,
		Title:            input.Title,
		Description:      input.Description,
		Approvers:        input.Approvers,
		ApproverGroups:   input.ApproverGroups,
		RequiredCount:    input.RequiredCount,
		Context:          input.Context,
		AlertID:          input.AlertID,
		CaseID:           input.CaseID,
		PlaybookName:     input.PlaybookName,
		Timeout:          input.Timeout,
		Actions:          input.Actions,
		Priority:         input.Priority,
		EscalationConfig: input.EscalationConfig,
	}

	var request *Request
	err := workflow.ExecuteActivity(ctx, "CreateApprovalRequest", createInput).Get(ctx, &request)
	if err != nil {
		logger.Error("Failed to create approval request", "error", err)
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	logger.Info("Approval request created", "request_id", request.ID)

	// Wait for approval signal or timeout
	signalCh := workflow.GetSignalChannel(ctx, "approval-response")
	timeoutTimer := workflow.NewTimer(ctx, input.Timeout)

	// Setup escalation if configured
	var escalationTimer workflow.Future
	if input.EscalationConfig != nil && input.EscalationConfig.Enabled {
		escalationTimer = workflow.NewTimer(ctx, input.EscalationConfig.Timeout)
	}

	// Setup reminder timer (send reminder halfway through timeout)
	reminderTimer := workflow.NewTimer(ctx, input.Timeout/2)

	var response Response
	approved := false
	completed := false

	for !completed {
		selector := workflow.NewSelector(ctx)

		// Handle approval response signal
		selector.AddReceive(signalCh, func(c workflow.ReceiveChannel, more bool) {
			c.Receive(ctx, &response)
			logger.Info("Received approval response", "approver", response.Approver, "action", response.Action)

			// Check if approval is complete
			var currentRequest *Request
			err := workflow.ExecuteActivity(ctx, "GetApprovalRequest", request.ID).Get(ctx, &currentRequest)
			if err != nil {
				logger.Error("Failed to get approval request status", "error", err)
				return
			}

			if currentRequest.Status == StatusApproved {
				approved = true
				completed = true
			} else if currentRequest.Status == StatusRejected || currentRequest.Status == StatusCancelled {
				approved = false
				completed = true
			}
		})

		// Handle timeout
		selector.AddFuture(timeoutTimer, func(f workflow.Future) {
			logger.Warn("Approval request timed out")

			// Mark as expired
			var expiredRequest *Request
			err := workflow.ExecuteActivity(ctx, "ExpireApprovalRequest", request.ID).Get(ctx, &expiredRequest)
			if err != nil {
				logger.Error("Failed to expire approval request", "error", err)
			}

			approved = false
			completed = true
		})

		// Handle reminder
		if reminderTimer != nil {
			selector.AddFuture(reminderTimer, func(f workflow.Future) {
				logger.Info("Sending approval reminder")

				err := workflow.ExecuteActivity(ctx, "SendApprovalReminders", request.ID).Get(ctx, nil)
				if err != nil {
					logger.Error("Failed to send reminders", "error", err)
				}

				reminderTimer = nil // Don't send multiple reminders
			})
		}

		// Handle escalation
		if escalationTimer != nil {
			selector.AddFuture(escalationTimer, func(f workflow.Future) {
				logger.Info("Escalating approval request")

				err := workflow.ExecuteActivity(ctx, "EscalateApprovalRequest", request.ID, input.EscalationConfig).Get(ctx, nil)
				if err != nil {
					logger.Error("Failed to escalate request", "error", err)
				}

				// Schedule next escalation if max levels not reached
				if input.EscalationConfig.MaxLevels == 0 || request.EscalationLevel < input.EscalationConfig.MaxLevels {
					escalationTimer = workflow.NewTimer(ctx, input.EscalationConfig.Timeout)
				} else {
					escalationTimer = nil
				}
			})
		}

		selector.Select(ctx)
	}

	// Get final request state
	var finalRequest *Request
	err = workflow.ExecuteActivity(ctx, "GetApprovalRequest", request.ID).Get(ctx, &finalRequest)
	if err != nil {
		logger.Error("Failed to get final request state", "error", err)
		return nil, fmt.Errorf("failed to get final request state: %w", err)
	}

	result := &WorkflowResult{
		Approved:    approved,
		Status:      string(finalRequest.Status),
		Response:    &response,
		Responses:   finalRequest.Responses,
		CompletedAt: time.Now(),
	}

	logger.Info("Approval workflow completed", "approved", approved, "status", result.Status)

	return result, nil
}

// Activities for approval workflow

// CreateApprovalRequestActivity creates an approval request.
func CreateApprovalRequestActivity(ctx workflow.Context, input *CreateRequestInput) (*Request, error) {
	// This should call the approval service
	// Implementation will be injected via dependency injection
	return nil, fmt.Errorf("not implemented")
}

// GetApprovalRequestActivity retrieves an approval request.
func GetApprovalRequestActivity(ctx workflow.Context, requestID string) (*Request, error) {
	return nil, fmt.Errorf("not implemented")
}

// ExpireApprovalRequestActivity marks a request as expired.
func ExpireApprovalRequestActivity(ctx workflow.Context, requestID string) (*Request, error) {
	return nil, fmt.Errorf("not implemented")
}

// SendApprovalRemindersActivity sends reminder notifications.
func SendApprovalRemindersActivity(ctx workflow.Context, requestID string) error {
	return fmt.Errorf("not implemented")
}

// EscalateApprovalRequestActivity escalates an approval request.
func EscalateApprovalRequestActivity(ctx workflow.Context, requestID string, config *EscalationConfig) error {
	return fmt.Errorf("not implemented")
}

// Helper function to wait for approval with timeout
func WaitForApproval(
	ctx workflow.Context,
	stepID string,
	title string,
	description string,
	approvers []string,
	timeout time.Duration,
) (bool, error) {
	input := WorkflowInput{
		StepID:      stepID,
		Type:        TypeAnyApprover,
		Title:       title,
		Description: description,
		Approvers:   approvers,
		Timeout:     timeout,
	}

	result, err := ApprovalWorkflow(ctx, input)
	if err != nil {
		return false, err
	}

	return result.Approved, nil
}
