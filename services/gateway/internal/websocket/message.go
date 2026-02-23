// Package websocket provides WebSocket hub and client management for real-time
// communication in the gateway service.
package websocket

import "time"

// MessageType defines WebSocket message types.
type MessageType string

const (
	// TypeAlert is sent when an alert is created or updated.
	TypeAlert MessageType = "alert"
	// TypeEvent is sent when a new event is received.
	TypeEvent MessageType = "event"
	// TypePipeline is sent for pipeline status updates.
	TypePipeline MessageType = "pipeline"
	// TypeMetric is sent for metric updates.
	TypeMetric MessageType = "metric"
	// TypeCase is sent for case updates.
	TypeCase MessageType = "case"
	// TypePlaybook is sent for playbook execution updates.
	TypePlaybook MessageType = "playbook"
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
	case TypeAlert, TypeEvent, TypePipeline, TypeMetric,
		TypeCase, TypePlaybook, TypeHeartbeat:
		return true
	}
	return false
}

// AllMessageTypes returns all available message types (excluding heartbeat).
func AllMessageTypes() []MessageType {
	return []MessageType{
		TypeAlert,
		TypeEvent,
		TypePipeline,
		TypeMetric,
		TypeCase,
		TypePlaybook,
	}
}

// MessageAction defines the action for a message.
type MessageAction string

const (
	// ActionCreated indicates a new resource was created.
	ActionCreated MessageAction = "created"
	// ActionUpdated indicates an existing resource was updated.
	ActionUpdated MessageAction = "updated"
	// ActionDeleted indicates a resource was deleted.
	ActionDeleted MessageAction = "deleted"
)

// String returns the string representation of the action.
func (a MessageAction) String() string {
	return string(a)
}

// Message is the standard WebSocket message format.
type Message struct {
	// Type is the message type (e.g., "alert", "event").
	Type MessageType `json:"type"`
	// Action is the action performed (e.g., "created", "updated").
	Action MessageAction `json:"action"`
	// Payload contains the message data.
	Payload interface{} `json:"payload"`
	// Timestamp is when the message was created.
	Timestamp time.Time `json:"timestamp"`
	// TenantID is the tenant this message belongs to (optional).
	TenantID string `json:"tenant_id,omitempty"`
}

// NewMessage creates a new Message with the current timestamp.
func NewMessage(msgType MessageType, action MessageAction, payload interface{}) *Message {
	return &Message{
		Type:      msgType,
		Action:    action,
		Payload:   payload,
		Timestamp: time.Now().UTC(),
	}
}

// WithTenantID sets the tenant ID on the message.
func (m *Message) WithTenantID(tenantID string) *Message {
	m.TenantID = tenantID
	return m
}

// SubscribeRequest is sent by client to subscribe to specific types.
type SubscribeRequest struct {
	// Action must be "subscribe".
	Action string `json:"action"`
	// Types is the list of message types to subscribe to.
	Types []string `json:"types"`
}

// UnsubscribeRequest is sent by client to unsubscribe from specific types.
type UnsubscribeRequest struct {
	// Action must be "unsubscribe".
	Action string `json:"action"`
	// Types is the list of message types to unsubscribe from.
	Types []string `json:"types"`
}

// ClientMessage represents a message sent by the client.
type ClientMessage struct {
	// Action is the action type (subscribe, unsubscribe, ping).
	Action string `json:"action"`
	// Types is the list of message types (for subscribe/unsubscribe).
	Types []string `json:"types,omitempty"`
}

// Common client action types.
const (
	ClientActionSubscribe   = "subscribe"
	ClientActionUnsubscribe = "unsubscribe"
	ClientActionPing        = "ping"
)

// ErrorMessage is sent to clients when an error occurs.
type ErrorMessage struct {
	// Type is always "error".
	Type string `json:"type"`
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
		Type:      "error",
		Code:      code,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
}

// Common error codes.
const (
	ErrCodeInvalidMessage = "INVALID_MESSAGE"
	ErrCodeInvalidType    = "INVALID_TYPE"
	ErrCodeUnauthorized   = "UNAUTHORIZED"
	ErrCodeInternalError  = "INTERNAL_ERROR"
)

// SubscriptionConfirmation is sent when subscription changes.
type SubscriptionConfirmation struct {
	// Type is "subscribed" or "unsubscribed".
	Type string `json:"type"`
	// Types is the list of types affected.
	Types []string `json:"types"`
	// Timestamp is when the change occurred.
	Timestamp time.Time `json:"timestamp"`
}

// PongMessage is sent in response to a ping.
type PongMessage struct {
	// Type is "pong".
	Type string `json:"type"`
	// Timestamp is when the pong was sent.
	Timestamp time.Time `json:"timestamp"`
}
