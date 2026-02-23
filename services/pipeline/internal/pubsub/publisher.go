package pubsub

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

// MessageType represents the type of pub/sub message.
type MessageType string

const (
	MessageTypeEvent          MessageType = "event"
	MessageTypeClassification MessageType = "classification"
	MessageTypeApproval       MessageType = "approval"
	MessageTypeExecution      MessageType = "execution"
	MessageTypeAudit          MessageType = "audit"
)

// MessageAction represents the action performed on a message.
type MessageAction string

const (
	MessageActionCreate MessageAction = "create"
	MessageActionUpdate MessageAction = "update"
	MessageActionDelete MessageAction = "delete"
)

// PubSubMessage is the standard message format for pub/sub.
type PubSubMessage struct {
	Type      MessageType   `json:"type"`
	Action    MessageAction `json:"action"`
	Payload   interface{}   `json:"payload"`
	Timestamp time.Time     `json:"timestamp"`
	TraceID   string        `json:"trace_id,omitempty"`
	TenantID  string        `json:"tenant_id,omitempty"`
}

// NewMessage creates a new PubSubMessage.
func NewMessage(msgType MessageType, action MessageAction, payload interface{}) *PubSubMessage {
	return &PubSubMessage{
		Type:      msgType,
		Action:    action,
		Payload:   payload,
		Timestamp: time.Now().UTC(),
	}
}

// WithTraceID sets the trace ID on the message.
func (m *PubSubMessage) WithTraceID(traceID string) *PubSubMessage {
	m.TraceID = traceID
	return m
}

// WithTenantID sets the tenant ID on the message.
func (m *PubSubMessage) WithTenantID(tenantID string) *PubSubMessage {
	m.TenantID = tenantID
	return m
}

// EventPublisher publishes pipeline events.
type EventPublisher struct {
	pubsub *PubSub
	logger *slog.Logger
}

// NewEventPublisher creates a new EventPublisher.
func NewEventPublisher(pubsub *PubSub) *EventPublisher {
	return &EventPublisher{
		pubsub: pubsub,
		logger: slog.Default().With("component", "event_publisher"),
	}
}

// PublishEvent publishes a new event to the pipeline.
func (p *EventPublisher) PublishEvent(ctx context.Context, event *model.PipelineEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	msg := NewMessage(MessageTypeEvent, MessageActionCreate, event).
		WithTenantID(event.TenantID)

	if err := p.pubsub.Publish(ctx, ChannelEvents, msg); err != nil {
		p.logger.Error("failed to publish event",
			"event_id", event.ID,
			"error", err,
		)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.logger.Debug("event published",
		"event_id", event.ID,
		"stage", event.Stage,
		"channel", ChannelEvents,
	)

	return nil
}

// PublishEventBatch publishes multiple events in a batch.
func (p *EventPublisher) PublishEventBatch(ctx context.Context, events []*model.PipelineEvent) error {
	if len(events) == 0 {
		return nil
	}

	var errs []error
	for _, event := range events {
		if err := p.PublishEvent(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to publish %d/%d events: %v", len(errs), len(events), errs[0])
	}

	return nil
}

// ClassificationMessage wraps a classification with metadata for pub/sub.
type ClassificationMessage struct {
	EventID        string                `json:"event_id"`
	TenantID       string                `json:"tenant_id"`
	Classification *model.Classification `json:"classification"`
}

// PublishClassification publishes a classification result.
func (p *EventPublisher) PublishClassification(ctx context.Context, classification *model.Classification) error {
	if classification == nil {
		return fmt.Errorf("classification cannot be nil")
	}

	// Wrap classification with context since model.Classification doesn't have tenant/event IDs
	msg := NewMessage(MessageTypeClassification, MessageActionCreate, classification)

	if err := p.pubsub.Publish(ctx, ChannelClassifications, msg); err != nil {
		p.logger.Error("failed to publish classification",
			"label", classification.Label,
			"method", classification.Method,
			"error", err,
		)
		return fmt.Errorf("failed to publish classification: %w", err)
	}

	p.logger.Debug("classification published",
		"label", classification.Label,
		"method", classification.Method,
		"confidence", classification.Confidence,
		"channel", ChannelClassifications,
	)

	return nil
}

// PublishClassificationWithContext publishes a classification result with event context.
func (p *EventPublisher) PublishClassificationWithContext(ctx context.Context, eventID, tenantID string, classification *model.Classification) error {
	if classification == nil {
		return fmt.Errorf("classification cannot be nil")
	}

	wrapped := &ClassificationMessage{
		EventID:        eventID,
		TenantID:       tenantID,
		Classification: classification,
	}

	msg := NewMessage(MessageTypeClassification, MessageActionCreate, wrapped).
		WithTenantID(tenantID)

	if err := p.pubsub.Publish(ctx, ChannelClassifications, msg); err != nil {
		p.logger.Error("failed to publish classification",
			"event_id", eventID,
			"label", classification.Label,
			"error", err,
		)
		return fmt.Errorf("failed to publish classification: %w", err)
	}

	p.logger.Debug("classification published",
		"event_id", eventID,
		"label", classification.Label,
		"method", classification.Method,
		"channel", ChannelClassifications,
	)

	return nil
}

// PublishApproval publishes an approval request/response.
func (p *EventPublisher) PublishApproval(ctx context.Context, approval *model.ApprovalInfo) error {
	if approval == nil {
		return fmt.Errorf("approval cannot be nil")
	}

	action := MessageActionCreate
	if approval.Status != model.ApprovalPending {
		action = MessageActionUpdate
	}

	msg := NewMessage(MessageTypeApproval, action, approval)

	if err := p.pubsub.Publish(ctx, ChannelApprovals, msg); err != nil {
		p.logger.Error("failed to publish approval",
			"approval_id", approval.ApprovalID,
			"status", approval.Status,
			"error", err,
		)
		return fmt.Errorf("failed to publish approval: %w", err)
	}

	p.logger.Debug("approval published",
		"approval_id", approval.ApprovalID,
		"status", approval.Status,
		"step_name", approval.StepName,
		"channel", ChannelApprovals,
	)

	return nil
}

// ApprovalMessage wraps approval info with additional context.
type ApprovalMessage struct {
	TenantID     string             `json:"tenant_id"`
	EventID      string             `json:"event_id,omitempty"`
	ExecutionID  string             `json:"execution_id,omitempty"`
	ApprovalInfo *model.ApprovalInfo `json:"approval_info"`
}

// PublishApprovalWithContext publishes an approval request/response with context.
func (p *EventPublisher) PublishApprovalWithContext(ctx context.Context, tenantID, eventID, executionID string, approval *model.ApprovalInfo) error {
	if approval == nil {
		return fmt.Errorf("approval cannot be nil")
	}

	action := MessageActionCreate
	if approval.Status != model.ApprovalPending {
		action = MessageActionUpdate
	}

	wrapped := &ApprovalMessage{
		TenantID:     tenantID,
		EventID:      eventID,
		ExecutionID:  executionID,
		ApprovalInfo: approval,
	}

	msg := NewMessage(MessageTypeApproval, action, wrapped).
		WithTenantID(tenantID)

	if err := p.pubsub.Publish(ctx, ChannelApprovals, msg); err != nil {
		p.logger.Error("failed to publish approval",
			"approval_id", approval.ApprovalID,
			"status", approval.Status,
			"error", err,
		)
		return fmt.Errorf("failed to publish approval: %w", err)
	}

	p.logger.Debug("approval published",
		"approval_id", approval.ApprovalID,
		"status", approval.Status,
		"execution_id", executionID,
		"channel", ChannelApprovals,
	)

	return nil
}

// PublishApprovalRequest is a convenience method for publishing a new approval request.
func (p *EventPublisher) PublishApprovalRequest(ctx context.Context, approval *model.ApprovalInfo) error {
	approval.Status = model.ApprovalPending
	approval.RequestedAt = time.Now().UTC()
	return p.PublishApproval(ctx, approval)
}

// PublishApprovalResponse is a convenience method for publishing an approval response.
func (p *EventPublisher) PublishApprovalResponse(ctx context.Context, approval *model.ApprovalInfo) error {
	return p.PublishApproval(ctx, approval)
}

// PublishAuditLog publishes an audit log entry.
func (p *EventPublisher) PublishAuditLog(ctx context.Context, log *model.AuditLog) error {
	if log == nil {
		return fmt.Errorf("audit log cannot be nil")
	}

	// Ensure timestamp is set
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}

	msg := NewMessage(MessageTypeAudit, MessageActionCreate, log).
		WithTenantID(log.TenantID)

	if err := p.pubsub.Publish(ctx, ChannelAuditLogs, msg); err != nil {
		p.logger.Error("failed to publish audit log",
			"audit_id", log.ID,
			"event_type", log.EventType,
			"error", err,
		)
		return fmt.Errorf("failed to publish audit log: %w", err)
	}

	p.logger.Debug("audit log published",
		"audit_id", log.ID,
		"event_type", log.EventType,
		"actor_type", log.ActorType,
		"channel", ChannelAuditLogs,
	)

	return nil
}

// ExecutionEvent represents a pipeline execution event.
type ExecutionEvent struct {
	ID           string                 `json:"id"`
	PipelineID   string                 `json:"pipeline_id"`
	StageID      string                 `json:"stage_id,omitempty"`
	Status       string                 `json:"status"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Duration     time.Duration          `json:"duration,omitempty"`
	EventsCount  int64                  `json:"events_count,omitempty"`
	ErrorCount   int64                  `json:"error_count,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	TenantID     string                 `json:"tenant_id"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PublishExecution publishes a pipeline execution event.
func (p *EventPublisher) PublishExecution(ctx context.Context, execution *ExecutionEvent) error {
	if execution == nil {
		return fmt.Errorf("execution event cannot be nil")
	}

	action := MessageActionCreate
	if execution.CompletedAt != nil {
		action = MessageActionUpdate
	}

	msg := NewMessage(MessageTypeExecution, action, execution).
		WithTenantID(execution.TenantID)

	if err := p.pubsub.Publish(ctx, ChannelExecutions, msg); err != nil {
		p.logger.Error("failed to publish execution event",
			"execution_id", execution.ID,
			"pipeline_id", execution.PipelineID,
			"error", err,
		)
		return fmt.Errorf("failed to publish execution event: %w", err)
	}

	p.logger.Debug("execution event published",
		"execution_id", execution.ID,
		"pipeline_id", execution.PipelineID,
		"status", execution.Status,
		"channel", ChannelExecutions,
	)

	return nil
}

// PublishExecutionStarted publishes a pipeline execution started event.
func (p *EventPublisher) PublishExecutionStarted(ctx context.Context, pipelineID, executionID, tenantID string) error {
	return p.PublishExecution(ctx, &ExecutionEvent{
		ID:         executionID,
		PipelineID: pipelineID,
		Status:     "started",
		StartedAt:  time.Now().UTC(),
		TenantID:   tenantID,
	})
}

// PublishExecutionCompleted publishes a pipeline execution completed event.
func (p *EventPublisher) PublishExecutionCompleted(ctx context.Context, pipelineID, executionID, tenantID string, eventsCount int64) error {
	now := time.Now().UTC()
	return p.PublishExecution(ctx, &ExecutionEvent{
		ID:          executionID,
		PipelineID:  pipelineID,
		Status:      "completed",
		CompletedAt: &now,
		EventsCount: eventsCount,
		TenantID:    tenantID,
	})
}

// PublishExecutionFailed publishes a pipeline execution failed event.
func (p *EventPublisher) PublishExecutionFailed(ctx context.Context, pipelineID, executionID, tenantID, errorMsg string) error {
	now := time.Now().UTC()
	return p.PublishExecution(ctx, &ExecutionEvent{
		ID:           executionID,
		PipelineID:   pipelineID,
		Status:       "failed",
		CompletedAt:  &now,
		ErrorMessage: errorMsg,
		TenantID:     tenantID,
	})
}

// Close closes the event publisher.
func (p *EventPublisher) Close() error {
	return p.pubsub.Close()
}
