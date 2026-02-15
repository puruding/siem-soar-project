// Package executor provides Temporal worker configuration.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Worker manages Temporal workers for playbook execution.
type Worker struct {
	client            client.Client
	worker            worker.Worker
	connectorRegistry ConnectorRegistry
	executor          *Executor
	notificationSvc   NotificationService
	scriptExecutor    ScriptExecutor
	enrichmentSvc     EnrichmentService
	options           WorkerOptions
	logger            *slog.Logger
}

// WorkerOptions configures the worker.
type WorkerOptions struct {
	TaskQueue                    string
	MaxConcurrentActivities      int
	MaxConcurrentWorkflows       int
	MaxConcurrentLocalActivities int
	WorkerStopTimeout            time.Duration
	EnableSessionWorker          bool
	EnableLogging                bool
}

// DefaultWorkerOptions returns default worker options.
func DefaultWorkerOptions() WorkerOptions {
	return WorkerOptions{
		TaskQueue:                    "playbook-execution",
		MaxConcurrentActivities:      100,
		MaxConcurrentWorkflows:       1000,
		MaxConcurrentLocalActivities: 100,
		WorkerStopTimeout:            30 * time.Second,
		EnableSessionWorker:          false,
		EnableLogging:                true,
	}
}

// NewWorker creates a new Temporal worker.
func NewWorker(
	temporalClient client.Client,
	connectorRegistry ConnectorRegistry,
	executor *Executor,
	notificationSvc NotificationService,
	scriptExecutor ScriptExecutor,
	enrichmentSvc EnrichmentService,
	opts WorkerOptions,
	logger *slog.Logger,
) *Worker {
	return &Worker{
		client:            temporalClient,
		connectorRegistry: connectorRegistry,
		executor:          executor,
		notificationSvc:   notificationSvc,
		scriptExecutor:    scriptExecutor,
		enrichmentSvc:     enrichmentSvc,
		options:           opts,
		logger:            logger,
	}
}

// Start starts the worker.
func (w *Worker) Start() error {
	workerOptions := worker.Options{
		MaxConcurrentActivityExecutionSize:     w.options.MaxConcurrentActivities,
		MaxConcurrentWorkflowTaskExecutionSize: w.options.MaxConcurrentWorkflows,
		MaxConcurrentLocalActivityExecutionSize: w.options.MaxConcurrentLocalActivities,
		EnableSessionWorker:                    w.options.EnableSessionWorker,
		BackgroundActivityContext:              w.createActivityContext(),
	}

	w.worker = worker.New(w.client, w.options.TaskQueue, workerOptions)

	// Register workflows
	w.registerWorkflows()

	// Register activities
	w.registerActivities()

	w.logger.Info("Starting Temporal worker",
		"task_queue", w.options.TaskQueue,
		"max_concurrent_activities", w.options.MaxConcurrentActivities,
		"max_concurrent_workflows", w.options.MaxConcurrentWorkflows,
	)

	return w.worker.Start()
}

// Stop stops the worker gracefully.
func (w *Worker) Stop() {
	w.logger.Info("Stopping Temporal worker")
	w.worker.Stop()
}

// registerWorkflows registers all workflow types.
func (w *Worker) registerWorkflows() {
	// Main playbook workflow
	w.worker.RegisterWorkflowWithOptions(PlaybookWorkflow, workflow.RegisterOptions{
		Name: "PlaybookWorkflow",
	})

	// Parallel branch workflow
	w.worker.RegisterWorkflowWithOptions(ParallelBranchWorkflow, workflow.RegisterOptions{
		Name: "ParallelBranchWorkflow",
	})

	// Approval workflow
	w.worker.RegisterWorkflowWithOptions(ApprovalWorkflow, workflow.RegisterOptions{
		Name: "ApprovalWorkflow",
	})

	// Scheduled playbook workflow
	w.worker.RegisterWorkflowWithOptions(ScheduledPlaybookWorkflow, workflow.RegisterOptions{
		Name: "ScheduledPlaybookWorkflow",
	})
}

// registerActivities registers all activity types.
func (w *Worker) registerActivities() {
	// Action execution
	w.worker.RegisterActivityWithOptions(ExecuteActionActivity, activity.RegisterOptions{
		Name: "ExecuteActionActivity",
	})

	// Approval
	w.worker.RegisterActivityWithOptions(RequestApprovalActivity, activity.RegisterOptions{
		Name: "RequestApprovalActivity",
	})

	// Sub-playbook
	w.worker.RegisterActivityWithOptions(ExecuteSubPlaybookActivity, activity.RegisterOptions{
		Name: "ExecuteSubPlaybookActivity",
	})

	// Script execution
	w.worker.RegisterActivityWithOptions(ExecuteScriptActivity, activity.RegisterOptions{
		Name: "ExecuteScriptActivity",
	})

	// Data transformation
	w.worker.RegisterActivityWithOptions(ExecuteTransformActivity, activity.RegisterOptions{
		Name: "ExecuteTransformActivity",
	})

	// Enrichment
	w.worker.RegisterActivityWithOptions(ExecuteEnrichmentActivity, activity.RegisterOptions{
		Name: "ExecuteEnrichmentActivity",
	})

	// Notification
	w.worker.RegisterActivityWithOptions(ExecuteNotificationActivity, activity.RegisterOptions{
		Name: "ExecuteNotificationActivity",
	})

	// Ticket creation
	w.worker.RegisterActivityWithOptions(ExecuteTicketActivity, activity.RegisterOptions{
		Name: "ExecuteTicketActivity",
	})

	// Connector-specific activities
	w.registerConnectorActivities()
}

// registerConnectorActivities registers connector-specific activities.
func (w *Worker) registerConnectorActivities() {
	// Email connector
	w.worker.RegisterActivityWithOptions(SendEmailActivity, activity.RegisterOptions{
		Name: "SendEmailActivity",
	})

	// Slack connector
	w.worker.RegisterActivityWithOptions(SendSlackMessageActivity, activity.RegisterOptions{
		Name: "SendSlackMessageActivity",
	})

	// Firewall connector
	w.worker.RegisterActivityWithOptions(BlockIPActivity, activity.RegisterOptions{
		Name: "BlockIPActivity",
	})
	w.worker.RegisterActivityWithOptions(UnblockIPActivity, activity.RegisterOptions{
		Name: "UnblockIPActivity",
	})

	// EDR connector
	w.worker.RegisterActivityWithOptions(IsolateHostActivity, activity.RegisterOptions{
		Name: "IsolateHostActivity",
	})
	w.worker.RegisterActivityWithOptions(UnisolateHostActivity, activity.RegisterOptions{
		Name: "UnisolateHostActivity",
	})

	// AD connector
	w.worker.RegisterActivityWithOptions(DisableUserActivity, activity.RegisterOptions{
		Name: "DisableUserActivity",
	})
	w.worker.RegisterActivityWithOptions(EnableUserActivity, activity.RegisterOptions{
		Name: "EnableUserActivity",
	})
	w.worker.RegisterActivityWithOptions(ResetPasswordActivity, activity.RegisterOptions{
		Name: "ResetPasswordActivity",
	})

	// Threat Intel connector
	w.worker.RegisterActivityWithOptions(LookupIOCActivity, activity.RegisterOptions{
		Name: "LookupIOCActivity",
	})

	// SIEM connector
	w.worker.RegisterActivityWithOptions(RunQueryActivity, activity.RegisterOptions{
		Name: "RunQueryActivity",
	})
}

// createActivityContext creates a context with dependencies for activities.
func (w *Worker) createActivityContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, connectorRegistryKey, w.connectorRegistry)
	ctx = context.WithValue(ctx, executorKey, w.executor)
	ctx = context.WithValue(ctx, notificationKey, w.notificationSvc)
	ctx = context.WithValue(ctx, scriptExecutorKey, w.scriptExecutor)
	ctx = context.WithValue(ctx, enrichmentKey, w.enrichmentSvc)
	return ctx
}

// ApprovalWorkflowInput is the input for the approval workflow.
type ApprovalWorkflowInput struct {
	ExecutionID    string        `json:"execution_id"`
	StepID         string        `json:"step_id"`
	Message        string        `json:"message"`
	Approvers      []string      `json:"approvers"`
	ApproverGroups []string      `json:"approver_groups,omitempty"`
	RequiredCount  int           `json:"required_count"`
	Timeout        time.Duration `json:"timeout"`
	Escalation     *EscalationConfig `json:"escalation,omitempty"`
}

// ApprovalWorkflowOutput is the output from the approval workflow.
type ApprovalWorkflowOutput struct {
	Approved bool              `json:"approved"`
	Approvals []ApprovalRecord `json:"approvals"`
	TimedOut  bool             `json:"timed_out"`
}

// ApprovalRecord records an approval decision.
type ApprovalRecord struct {
	Approver  string    `json:"approver"`
	Approved  bool      `json:"approved"`
	Comment   string    `json:"comment,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// EscalationConfig defines escalation settings.
type EscalationConfig struct {
	Timeout    time.Duration `json:"timeout"`
	Escalators []string      `json:"escalators"`
	MaxLevels  int           `json:"max_levels"`
}

// ApprovalWorkflow handles approval logic as a separate workflow.
func ApprovalWorkflow(ctx workflow.Context, input ApprovalWorkflowInput) (*ApprovalWorkflowOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting approval workflow",
		"execution_id", input.ExecutionID,
		"step_id", input.StepID,
	)

	output := &ApprovalWorkflowOutput{
		Approvals: make([]ApprovalRecord, 0),
	}

	// Send approval request
	activityOptions := workflow.ActivityOptions{
		TaskQueue:           "playbook-execution",
		StartToCloseTimeout: time.Minute,
	}
	activityCtx := workflow.WithActivityOptions(ctx, activityOptions)

	requestInput := RequestApprovalInput{
		StepID:         input.StepID,
		Message:        input.Message,
		Approvers:      input.Approvers,
		ApproverGroups: input.ApproverGroups,
		RequiredCount:  input.RequiredCount,
		Timeout:        input.Timeout,
	}

	err := workflow.ExecuteActivity(activityCtx, RequestApprovalActivity, requestInput).Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request approval: %w", err)
	}

	// Wait for approvals
	approvalCh := workflow.GetSignalChannel(ctx, SignalApproval)
	requiredCount := input.RequiredCount
	if requiredCount <= 0 {
		requiredCount = 1
	}

	approvedCount := 0
	rejectedCount := 0
	escalationLevel := 0

	timerCtx, cancel := workflow.WithCancel(ctx)
	defer cancel()

	for {
		selector := workflow.NewSelector(timerCtx)

		// Set up approval signal handler
		selector.AddReceive(approvalCh, func(c workflow.ReceiveChannel, more bool) {
			var signal ApprovalSignal
			c.Receive(ctx, &signal)

			record := ApprovalRecord{
				Approver:  signal.Approver,
				Approved:  signal.Approved,
				Comment:   signal.Comment,
				Timestamp: signal.Time,
			}
			output.Approvals = append(output.Approvals, record)

			if signal.Approved {
				approvedCount++
			} else {
				rejectedCount++
			}
		})

		// Set up timeout
		timeout := input.Timeout
		if input.Escalation != nil && escalationLevel > 0 {
			timeout = input.Escalation.Timeout
		}

		timerFuture := workflow.NewTimer(timerCtx, timeout)
		timedOut := false
		selector.AddFuture(timerFuture, func(f workflow.Future) {
			timedOut = true
		})

		selector.Select(ctx)

		// Check if approved
		if approvedCount >= requiredCount {
			output.Approved = true
			break
		}

		// Check if rejection makes approval impossible
		remainingApprovers := len(input.Approvers) - (approvedCount + rejectedCount)
		if approvedCount+remainingApprovers < requiredCount {
			output.Approved = false
			break
		}

		// Handle timeout with escalation
		if timedOut {
			if input.Escalation != nil && escalationLevel < input.Escalation.MaxLevels {
				escalationLevel++
				// Send escalation notification
				escalateInput := RequestApprovalInput{
					StepID:    input.StepID,
					Message:   fmt.Sprintf("[ESCALATION Level %d] %s", escalationLevel, input.Message),
					Approvers: input.Escalation.Escalators,
					Timeout:   input.Escalation.Timeout,
				}
				_ = workflow.ExecuteActivity(activityCtx, RequestApprovalActivity, escalateInput).Get(ctx, nil)
				continue
			}

			output.TimedOut = true
			break
		}
	}

	return output, nil
}

// ScheduledPlaybookWorkflowInput is the input for scheduled playbook workflow.
type ScheduledPlaybookWorkflowInput struct {
	PlaybookID string `json:"playbook_id"`
	Schedule   string `json:"schedule"` // cron expression
	TenantID   string `json:"tenant_id,omitempty"`
}

// ScheduledPlaybookWorkflow executes playbooks on a schedule.
func ScheduledPlaybookWorkflow(ctx workflow.Context, input ScheduledPlaybookWorkflowInput) error {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting scheduled playbook workflow",
		"playbook_id", input.PlaybookID,
		"schedule", input.Schedule,
	)

	// This workflow runs indefinitely, executing the playbook on schedule
	for {
		// Calculate next execution time based on cron
		// In production, use a proper cron parser
		nextRun := time.Minute // Simplified

		// Wait until next scheduled time
		err := workflow.Sleep(ctx, nextRun)
		if err != nil {
			return err
		}

		// Execute the playbook as a child workflow
		childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowID: fmt.Sprintf("scheduled-%s-%d", input.PlaybookID, workflow.Now(ctx).Unix()),
		})

		// Get playbook and execute
		activityOptions := workflow.ActivityOptions{
			TaskQueue:           "playbook-execution",
			StartToCloseTimeout: time.Minute,
		}
		activityCtx := workflow.WithActivityOptions(ctx, activityOptions)

		var playbookData interface{}
		err = workflow.ExecuteActivity(activityCtx, GetPlaybookActivity, input.PlaybookID).Get(ctx, &playbookData)
		if err != nil {
			logger.Error("Failed to get playbook", "error", err)
			continue
		}

		// Execute playbook
		workflowInput := PlaybookWorkflowInput{
			ExecutionID: fmt.Sprintf("scheduled-%d", workflow.Now(ctx).Unix()),
			TenantID:    input.TenantID,
		}

		future := workflow.ExecuteChildWorkflow(childCtx, PlaybookWorkflow, workflowInput)
		var result PlaybookWorkflowOutput
		if err := future.Get(ctx, &result); err != nil {
			logger.Error("Scheduled playbook execution failed", "error", err)
		}
	}
}

// GetPlaybookActivity retrieves a playbook.
func GetPlaybookActivity(ctx context.Context, playbookID string) (interface{}, error) {
	// Get playbook from store
	// This is a placeholder - implement actual retrieval
	return nil, nil
}

// Connector-specific activities

// SendEmailActivity sends an email.
func SendEmailActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("email")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "send_email", input)
}

// SendSlackMessageActivity sends a Slack message.
func SendSlackMessageActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("slack")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "send_message", input)
}

// BlockIPActivity blocks an IP address.
func BlockIPActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("firewall")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "block_ip", input)
}

// UnblockIPActivity unblocks an IP address.
func UnblockIPActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("firewall")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "unblock_ip", input)
}

// IsolateHostActivity isolates a host.
func IsolateHostActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("edr")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "isolate_host", input)
}

// UnisolateHostActivity removes host isolation.
func UnisolateHostActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("edr")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "unisolate_host", input)
}

// DisableUserActivity disables a user account.
func DisableUserActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("active_directory")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "disable_user", input)
}

// EnableUserActivity enables a user account.
func EnableUserActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("active_directory")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "enable_user", input)
}

// ResetPasswordActivity resets a user's password.
func ResetPasswordActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("active_directory")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "reset_password", input)
}

// LookupIOCActivity looks up an IOC in threat intelligence.
func LookupIOCActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector("threat_intel")
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "lookup_ioc", input)
}

// RunQueryActivity runs a SIEM query.
func RunQueryActivity(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	registry := getConnectorRegistry(ctx)
	siemType := input["siem"].(string)
	connector, err := registry.GetConnector(siemType)
	if err != nil {
		return nil, err
	}
	return connector.Execute(ctx, "run_query", input)
}
