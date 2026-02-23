// Package websocket provides WebSocket hub and client management for real-time
// communication in the pipeline service.
package websocket

import "time"

// MessageType defines WebSocket message types.
type MessageType string

const (
	// TypeEvent is sent when a new pipeline event is received.
	TypeEvent MessageType = "event"
	// TypeClassification is sent when an event is classified.
	TypeClassification MessageType = "classification"
	// TypePlaybook is sent when a playbook is matched.
	TypePlaybook MessageType = "playbook"
	// TypeExecution is sent when execution status changes.
	TypeExecution MessageType = "execution"
	// TypeApproval is sent when approval is requested or resolved.
	TypeApproval MessageType = "approval"
	// TypeAudit is sent when an audit log entry is created.
	TypeAudit MessageType = "audit"
	// TypeStats is sent for periodic statistics updates.
	TypeStats MessageType = "stats"
	// TypeHeartbeat is used for connection keep-alive.
	TypeHeartbeat MessageType = "heartbeat"
)

// String returns the string representation of the message type.
func (t MessageType) String() string {
	return string(t)
}

// IsValid checks if the message type is valid.
func (t MessageType) IsValid() bool {
	switch t {
	case TypeEvent, TypeClassification, TypePlaybook, TypeExecution,
		TypeApproval, TypeAudit, TypeStats, TypeHeartbeat:
		return true
	}
	return false
}

// AllMessageTypes returns all available message types (excluding heartbeat).
func AllMessageTypes() []MessageType {
	return []MessageType{
		TypeEvent,
		TypeClassification,
		TypePlaybook,
		TypeExecution,
		TypeApproval,
		TypeAudit,
		TypeStats,
	}
}

// MessageAction defines the action for a message.
type MessageAction string

const (
	// ActionCreate indicates a new resource was created.
	ActionCreate MessageAction = "create"
	// ActionUpdate indicates an existing resource was updated.
	ActionUpdate MessageAction = "update"
	// ActionDelete indicates a resource was deleted.
	ActionDelete MessageAction = "delete"
)

// String returns the string representation of the action.
func (a MessageAction) String() string {
	return string(a)
}

// WSMessage is the standard WebSocket message format.
type WSMessage struct {
	// Type is the message type (e.g., "event", "classification").
	Type MessageType `json:"type"`
	// Action is the action performed (e.g., "create", "update").
	Action MessageAction `json:"action"`
	// Payload contains the message data.
	Payload interface{} `json:"payload"`
	// Timestamp is when the message was created.
	Timestamp time.Time `json:"timestamp"`
	// TraceID is the distributed tracing ID for correlation.
	TraceID string `json:"trace_id,omitempty"`
	// TenantID is the tenant this message belongs to.
	TenantID string `json:"tenant_id,omitempty"`
}

// NewWSMessage creates a new WSMessage with the current timestamp.
func NewWSMessage(msgType MessageType, action MessageAction, payload interface{}) *WSMessage {
	return &WSMessage{
		Type:      msgType,
		Action:    action,
		Payload:   payload,
		Timestamp: time.Now().UTC(),
	}
}

// WithTraceID sets the trace ID on the message.
func (m *WSMessage) WithTraceID(traceID string) *WSMessage {
	m.TraceID = traceID
	return m
}

// WithTenantID sets the tenant ID on the message.
func (m *WSMessage) WithTenantID(tenantID string) *WSMessage {
	m.TenantID = tenantID
	return m
}

// SubscribeMessage is sent by client to subscribe to specific types.
type SubscribeMessage struct {
	// Types is the list of message types to subscribe to.
	Types []MessageType `json:"types"`
	// TenantID filters messages to a specific tenant.
	TenantID string `json:"tenant_id"`
}

// UnsubscribeMessage is sent by client to unsubscribe from specific types.
type UnsubscribeMessage struct {
	// Types is the list of message types to unsubscribe from.
	Types []MessageType `json:"types"`
}

// HeartbeatMessage is used for connection keep-alive.
type HeartbeatMessage struct {
	// Ping is true if this is a ping request.
	Ping bool `json:"ping"`
	// Pong is true if this is a pong response.
	Pong bool `json:"pong"`
	// Timestamp is when the heartbeat was sent.
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// NewPingMessage creates a new ping heartbeat message.
func NewPingMessage() *HeartbeatMessage {
	return &HeartbeatMessage{
		Ping:      true,
		Timestamp: time.Now().UTC(),
	}
}

// NewPongMessage creates a new pong heartbeat message.
func NewPongMessage() *HeartbeatMessage {
	return &HeartbeatMessage{
		Pong:      true,
		Timestamp: time.Now().UTC(),
	}
}

// ClientMessage represents a message sent by the client.
type ClientMessage struct {
	// Type is the message type.
	Type string `json:"type"`
	// Data contains the message payload.
	Data interface{} `json:"data,omitempty"`
}

// ClientMessageType constants for client-to-server messages.
const (
	ClientMsgSubscribe   = "subscribe"
	ClientMsgUnsubscribe = "unsubscribe"
	ClientMsgPing        = "ping"
)

// ErrorMessage is sent to clients when an error occurs.
type ErrorMessage struct {
	// Code is the error code.
	Code string `json:"code"`
	// Message is the human-readable error message.
	Message string `json:"message"`
	// Timestamp is when the error occurred.
	Timestamp time.Time `json:"timestamp"`
}

// NewErrorMessage creates a new error message.
func NewErrorMessage(code, message string) *ErrorMessage {
	return &ErrorMessage{
		Code:      code,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
}

// Common error codes.
const (
	ErrCodeInvalidMessage   = "INVALID_MESSAGE"
	ErrCodeInvalidType      = "INVALID_TYPE"
	ErrCodeUnauthorized     = "UNAUTHORIZED"
	ErrCodeInternalError    = "INTERNAL_ERROR"
	ErrCodeRateLimited      = "RATE_LIMITED"
	ErrCodeSubscriptionFail = "SUBSCRIPTION_FAILED"
)
