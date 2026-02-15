// Package executor provides Temporal activities for playbook execution.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.temporal.io/sdk/activity"
)

// ActionActivityInput is the input for the action activity.
type ActionActivityInput struct {
	Connector  string                 `json:"connector"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ActionActivityOutput is the output from the action activity.
type ActionActivityOutput struct {
	Result  map[string]interface{} `json:"result"`
	Metrics ActionMetrics          `json:"metrics"`
}

// ActionMetrics contains metrics for an action execution.
type ActionMetrics struct {
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration_ms"`
	Retries     int           `json:"retries"`
	ConnectorID string        `json:"connector_id"`
}

// ExecuteActionActivity executes a connector action.
func ExecuteActionActivity(ctx context.Context, input ActionActivityInput) (*ActionActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Executing action",
		"connector", input.Connector,
		"action", input.Action,
	)

	startTime := time.Now()

	// Get connector from registry
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector(input.Connector)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector %s: %w", input.Connector, err)
	}

	// Execute action
	result, err := connector.Execute(ctx, input.Action, input.Parameters)
	if err != nil {
		return nil, fmt.Errorf("action %s failed: %w", input.Action, err)
	}

	endTime := time.Now()

	return &ActionActivityOutput{
		Result: result,
		Metrics: ActionMetrics{
			StartTime:   startTime,
			EndTime:     endTime,
			Duration:    endTime.Sub(startTime),
			ConnectorID: input.Connector,
		},
	}, nil
}

// RequestApprovalInput is the input for the approval request activity.
type RequestApprovalInput struct {
	StepID         string        `json:"step_id"`
	Message        string        `json:"message"`
	Approvers      []string      `json:"approvers"`
	ApproverGroups []string      `json:"approver_groups,omitempty"`
	RequiredCount  int           `json:"required_count"`
	Timeout        time.Duration `json:"timeout"`
	Actions        []string      `json:"actions,omitempty"`
}

// RequestApprovalOutput is the output from the approval request activity.
type RequestApprovalOutput struct {
	RequestID   string    `json:"request_id"`
	RequestedAt time.Time `json:"requested_at"`
}

// RequestApprovalActivity sends approval notifications.
func RequestApprovalActivity(ctx context.Context, input RequestApprovalInput) (*RequestApprovalOutput, error) {
	logger := activity.GetLogger(ctx)
	info := activity.GetInfo(ctx)

	logger.Info("Requesting approval",
		"step_id", input.StepID,
		"approvers", input.Approvers,
		"workflow_id", info.WorkflowExecution.ID,
	)

	// Get notification service
	notifier := getNotificationService(ctx)

	// Build approval request notification
	notification := ApprovalNotification{
		WorkflowID:  info.WorkflowExecution.ID,
		RunID:       info.WorkflowExecution.RunID,
		StepID:      input.StepID,
		Message:     input.Message,
		Approvers:   input.Approvers,
		Timeout:     input.Timeout,
		RequestedAt: time.Now(),
		ApprovalURL: fmt.Sprintf("/api/v1/executions/%s/approve", info.WorkflowExecution.ID),
		RejectURL:   fmt.Sprintf("/api/v1/executions/%s/reject", info.WorkflowExecution.ID),
	}

	// Send notifications to all approvers
	for _, approver := range input.Approvers {
		if err := notifier.SendApprovalRequest(ctx, approver, &notification); err != nil {
			logger.Warn("Failed to send approval notification",
				"approver", approver,
				"error", err,
			)
		}
	}

	// Send to approver groups
	for _, group := range input.ApproverGroups {
		if err := notifier.SendApprovalRequestToGroup(ctx, group, &notification); err != nil {
			logger.Warn("Failed to send approval notification to group",
				"group", group,
				"error", err,
			)
		}
	}

	return &RequestApprovalOutput{
		RequestID:   fmt.Sprintf("%s-%s", info.WorkflowExecution.ID, input.StepID),
		RequestedAt: notification.RequestedAt,
	}, nil
}

// ApprovalNotification represents an approval request notification.
type ApprovalNotification struct {
	WorkflowID  string        `json:"workflow_id"`
	RunID       string        `json:"run_id"`
	StepID      string        `json:"step_id"`
	Message     string        `json:"message"`
	Approvers   []string      `json:"approvers"`
	Timeout     time.Duration `json:"timeout"`
	RequestedAt time.Time     `json:"requested_at"`
	ApprovalURL string        `json:"approval_url"`
	RejectURL   string        `json:"reject_url"`
}

// SubPlaybookActivityInput is the input for the sub-playbook activity.
type SubPlaybookActivityInput struct {
	PlaybookID string                 `json:"playbook_id"`
	Version    int                    `json:"version,omitempty"`
	Inputs     map[string]interface{} `json:"inputs"`
}

// SubPlaybookActivityOutput is the output from the sub-playbook activity.
type SubPlaybookActivityOutput struct {
	ExecutionID string                 `json:"execution_id"`
	Status      string                 `json:"status"`
	Outputs     map[string]interface{} `json:"outputs"`
}

// ExecuteSubPlaybookActivity executes a sub-playbook.
func ExecuteSubPlaybookActivity(ctx context.Context, input SubPlaybookActivityInput) (*SubPlaybookActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Executing sub-playbook",
		"playbook_id", input.PlaybookID,
		"version", input.Version,
	)

	// Get executor from context
	executor := getExecutor(ctx)

	// Execute sub-playbook synchronously
	req := &ExecuteRequest{
		PlaybookID: input.PlaybookID,
		Version:    input.Version,
		Inputs:     input.Inputs,
		Async:      false,
	}

	resp, err := executor.Execute(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sub-playbook execution failed: %w", err)
	}

	return &SubPlaybookActivityOutput{
		ExecutionID: resp.ExecutionID,
		Status:      string(resp.Status),
		Outputs:     resp.Outputs,
	}, nil
}

// ScriptActivityInput is the input for the script activity.
type ScriptActivityInput struct {
	Language string                 `json:"language"`
	Code     string                 `json:"code"`
	Inputs   map[string]interface{} `json:"inputs"`
	Timeout  time.Duration          `json:"timeout"`
}

// ScriptActivityOutput is the output from the script activity.
type ScriptActivityOutput struct {
	Result   map[string]interface{} `json:"result"`
	Stdout   string                 `json:"stdout,omitempty"`
	Stderr   string                 `json:"stderr,omitempty"`
	ExitCode int                    `json:"exit_code"`
}

// ExecuteScriptActivity executes a script.
func ExecuteScriptActivity(ctx context.Context, input ScriptActivityInput) (*ScriptActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Executing script",
		"language", input.Language,
	)

	// Get script executor
	scriptExecutor := getScriptExecutor(ctx)

	// Execute script
	result, stdout, stderr, exitCode, err := scriptExecutor.Execute(ctx, input.Language, input.Code, input.Inputs, input.Timeout)
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	return &ScriptActivityOutput{
		Result:   result,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}, nil
}

// TransformActivityInput is the input for the transform activity.
type TransformActivityInput struct {
	Type       string      `json:"type"`
	Expression string      `json:"expression"`
	Source     interface{} `json:"source"`
}

// TransformActivityOutput is the output from the transform activity.
type TransformActivityOutput struct {
	Result interface{} `json:"result"`
}

// ExecuteTransformActivity executes a data transformation.
func ExecuteTransformActivity(ctx context.Context, input TransformActivityInput) (*TransformActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Executing transform",
		"type", input.Type,
	)

	var result interface{}
	var err error

	switch input.Type {
	case "jq":
		result, err = executeJQTransform(input.Source, input.Expression)
	case "jsonpath":
		result, err = executeJSONPathTransform(input.Source, input.Expression)
	case "template":
		result, err = executeTemplateTransform(input.Source, input.Expression)
	default:
		err = fmt.Errorf("unsupported transform type: %s", input.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("transform failed: %w", err)
	}

	return &TransformActivityOutput{
		Result: result,
	}, nil
}

// EnrichmentActivityInput is the input for enrichment activities.
type EnrichmentActivityInput struct {
	Type       string                 `json:"type"` // ip, domain, hash, user, etc.
	Value      string                 `json:"value"`
	Sources    []string               `json:"sources,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// EnrichmentActivityOutput is the output from enrichment activities.
type EnrichmentActivityOutput struct {
	Enrichments map[string]interface{} `json:"enrichments"`
	Sources     []string               `json:"sources"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ExecuteEnrichmentActivity enriches an entity.
func ExecuteEnrichmentActivity(ctx context.Context, input EnrichmentActivityInput) (*EnrichmentActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Executing enrichment",
		"type", input.Type,
		"value", input.Value,
	)

	// Get enrichment service
	enricher := getEnrichmentService(ctx)

	enrichments, usedSources, err := enricher.Enrich(ctx, input.Type, input.Value, input.Sources)
	if err != nil {
		return nil, fmt.Errorf("enrichment failed: %w", err)
	}

	return &EnrichmentActivityOutput{
		Enrichments: enrichments,
		Sources:     usedSources,
		Timestamp:   time.Now(),
	}, nil
}

// NotificationActivityInput is the input for notification activities.
type NotificationActivityInput struct {
	Channel    string                 `json:"channel"` // email, slack, teams, pagerduty, etc.
	Recipients []string               `json:"recipients"`
	Subject    string                 `json:"subject"`
	Message    string                 `json:"message"`
	Template   string                 `json:"template,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Priority   string                 `json:"priority,omitempty"`
}

// NotificationActivityOutput is the output from notification activities.
type NotificationActivityOutput struct {
	Sent      bool      `json:"sent"`
	MessageID string    `json:"message_id,omitempty"`
	SentAt    time.Time `json:"sent_at"`
	Errors    []string  `json:"errors,omitempty"`
}

// ExecuteNotificationActivity sends a notification.
func ExecuteNotificationActivity(ctx context.Context, input NotificationActivityInput) (*NotificationActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Sending notification",
		"channel", input.Channel,
		"recipients", input.Recipients,
	)

	// Get notification service
	notifier := getNotificationService(ctx)

	notification := &Notification{
		Channel:    input.Channel,
		Recipients: input.Recipients,
		Subject:    input.Subject,
		Message:    input.Message,
		Template:   input.Template,
		Data:       input.Data,
		Priority:   input.Priority,
	}

	messageID, err := notifier.Send(ctx, notification)
	if err != nil {
		return &NotificationActivityOutput{
			Sent:   false,
			Errors: []string{err.Error()},
		}, nil
	}

	return &NotificationActivityOutput{
		Sent:      true,
		MessageID: messageID,
		SentAt:    time.Now(),
	}, nil
}

// TicketActivityInput is the input for ticket creation activities.
type TicketActivityInput struct {
	System      string                 `json:"system"` // jira, servicenow, etc.
	Project     string                 `json:"project"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority,omitempty"`
	Assignee    string                 `json:"assignee,omitempty"`
	Labels      []string               `json:"labels,omitempty"`
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// TicketActivityOutput is the output from ticket creation activities.
type TicketActivityOutput struct {
	TicketID  string    `json:"ticket_id"`
	TicketKey string    `json:"ticket_key"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

// ExecuteTicketActivity creates a ticket.
func ExecuteTicketActivity(ctx context.Context, input TicketActivityInput) (*TicketActivityOutput, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Creating ticket",
		"system", input.System,
		"project", input.Project,
	)

	// Get connector
	registry := getConnectorRegistry(ctx)
	connector, err := registry.GetConnector(input.System)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector %s: %w", input.System, err)
	}

	params := map[string]interface{}{
		"project":       input.Project,
		"type":          input.Type,
		"title":         input.Title,
		"description":   input.Description,
		"priority":      input.Priority,
		"assignee":      input.Assignee,
		"labels":        input.Labels,
		"custom_fields": input.CustomFields,
	}

	result, err := connector.Execute(ctx, "create_ticket", params)
	if err != nil {
		return nil, fmt.Errorf("ticket creation failed: %w", err)
	}

	return &TicketActivityOutput{
		TicketID:  result["ticket_id"].(string),
		TicketKey: result["ticket_key"].(string),
		URL:       result["url"].(string),
		CreatedAt: time.Now(),
	}, nil
}

// Transform helper functions

func executeJQTransform(source interface{}, expression string) (interface{}, error) {
	// In production, use a proper jq library
	// This is a simplified placeholder
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal(sourceJSON, &result); err != nil {
		return nil, err
	}

	// For now, return source as-is (implement actual jq processing)
	return result, nil
}

func executeJSONPathTransform(source interface{}, expression string) (interface{}, error) {
	// In production, use a proper JSONPath library
	// This is a simplified placeholder
	return source, nil
}

func executeTemplateTransform(source interface{}, templateStr string) (interface{}, error) {
	// In production, use text/template or html/template
	// This is a simplified placeholder
	return source, nil
}

// Context helpers - these would be set up by the worker

type contextKey string

const (
	connectorRegistryKey contextKey = "connector_registry"
	executorKey          contextKey = "executor"
	notificationKey      contextKey = "notification_service"
	scriptExecutorKey    contextKey = "script_executor"
	enrichmentKey        contextKey = "enrichment_service"
)

func getConnectorRegistry(ctx context.Context) ConnectorRegistry {
	return ctx.Value(connectorRegistryKey).(ConnectorRegistry)
}

func getExecutor(ctx context.Context) *Executor {
	return ctx.Value(executorKey).(*Executor)
}

func getNotificationService(ctx context.Context) NotificationService {
	return ctx.Value(notificationKey).(NotificationService)
}

func getScriptExecutor(ctx context.Context) ScriptExecutor {
	return ctx.Value(scriptExecutorKey).(ScriptExecutor)
}

func getEnrichmentService(ctx context.Context) EnrichmentService {
	return ctx.Value(enrichmentKey).(EnrichmentService)
}

// Service interfaces

// NotificationService sends notifications.
type NotificationService interface {
	Send(ctx context.Context, notification *Notification) (string, error)
	SendApprovalRequest(ctx context.Context, approver string, request *ApprovalNotification) error
	SendApprovalRequestToGroup(ctx context.Context, group string, request *ApprovalNotification) error
}

// Notification represents a notification to be sent.
type Notification struct {
	Channel    string
	Recipients []string
	Subject    string
	Message    string
	Template   string
	Data       map[string]interface{}
	Priority   string
}

// ScriptExecutor executes scripts.
type ScriptExecutor interface {
	Execute(ctx context.Context, language, code string, inputs map[string]interface{}, timeout time.Duration) (map[string]interface{}, string, string, int, error)
}

// EnrichmentService enriches entities.
type EnrichmentService interface {
	Enrich(ctx context.Context, entityType, value string, sources []string) (map[string]interface{}, []string, error)
}
