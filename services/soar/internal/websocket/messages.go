// Package websocket provides WebSocket functionality for real-time SOAR status updates.
package websocket

import "time"

// Message type constants for WebSocket communication.
const (
	MsgTypeExecutionStarted   = "execution:started"
	MsgTypeExecutionProgress  = "execution:progress"
	MsgTypeExecutionCompleted = "execution:completed"
	MsgTypeExecutionFailed    = "execution:failed"
	MsgTypeExecutionPaused    = "execution:paused"
	MsgTypeExecutionResumed   = "execution:resumed"
	MsgTypeExecutionCancelled = "execution:cancelled"
	MsgTypeNodeStarted        = "node:started"
	MsgTypeNodeCompleted      = "node:completed"
	MsgTypeNodeFailed         = "node:failed"
	MsgTypeApprovalRequired   = "approval:required"
	MsgTypeApprovalReceived   = "approval:received"
	MsgTypeApprovalRejected   = "approval:rejected"
	MsgTypeHeartbeat          = "heartbeat"
	MsgTypeSubscribe          = "subscribe"
	MsgTypeUnsubscribe        = "unsubscribe"
	MsgTypeError              = "error"
)

// ExecutionStatusMessage is the WebSocket message for execution status updates.
type ExecutionStatusMessage struct {
	Type         string                 `json:"type"`
	ExecutionID  string                 `json:"execution_id"`
	AlertID      string                 `json:"alert_id,omitempty"`
	CaseID       string                 `json:"case_id,omitempty"`
	PlaybookID   string                 `json:"playbook_id"`
	PlaybookName string                 `json:"playbook_name"`
	Status       string                 `json:"status"`
	Progress     float64                `json:"progress"` // 0-100
	CurrentStep  string                 `json:"current_step,omitempty"`
	TotalSteps   int                    `json:"total_steps,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// NodeStatusMessage represents individual node/step status updates.
type NodeStatusMessage struct {
	Type        string                 `json:"type"`
	ExecutionID string                 `json:"execution_id"`
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	NodeType    string                 `json:"node_type"`
	Status      string                 `json:"status"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	DurationMs  int64                  `json:"duration_ms,omitempty"`
	Output      interface{}            `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ApprovalMessage represents approval workflow messages.
type ApprovalMessage struct {
	Type         string                 `json:"type"`
	ExecutionID  string                 `json:"execution_id"`
	NodeID       string                 `json:"node_id"`
	NodeName     string                 `json:"node_name"`
	ApprovalType string                 `json:"approval_type"` // required, approved, rejected
	ApprovedBy   string                 `json:"approved_by,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Timeout      int64                  `json:"timeout,omitempty"` // seconds until expiry
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// HeartbeatMessage is sent periodically to keep connections alive.
type HeartbeatMessage struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	ServerID  string    `json:"server_id,omitempty"`
}

// SubscribeMessage is sent by clients to subscribe to topics.
type SubscribeMessage struct {
	Type   string   `json:"type"`
	Topics []string `json:"topics"`
}

// UnsubscribeMessage is sent by clients to unsubscribe from topics.
type UnsubscribeMessage struct {
	Type   string   `json:"type"`
	Topics []string `json:"topics"`
}

// ErrorMessage represents an error sent to clients.
type ErrorMessage struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ClientMessage is a generic incoming message from clients.
type ClientMessage struct {
	Type   string   `json:"type"`
	Topics []string `json:"topics,omitempty"`
}

// NewExecutionStatusMessage creates a new ExecutionStatusMessage.
func NewExecutionStatusMessage(
	msgType string,
	executionID string,
	playbookID string,
	playbookName string,
	status string,
	progress float64,
) *ExecutionStatusMessage {
	return &ExecutionStatusMessage{
		Type:         msgType,
		ExecutionID:  executionID,
		PlaybookID:   playbookID,
		PlaybookName: playbookName,
		Status:       status,
		Progress:     progress,
		Timestamp:    time.Now(),
	}
}

// NewNodeStatusMessage creates a new NodeStatusMessage.
func NewNodeStatusMessage(
	msgType string,
	executionID string,
	nodeID string,
	nodeName string,
	nodeType string,
	status string,
) *NodeStatusMessage {
	return &NodeStatusMessage{
		Type:        msgType,
		ExecutionID: executionID,
		NodeID:      nodeID,
		NodeName:    nodeName,
		NodeType:    nodeType,
		Status:      status,
		Timestamp:   time.Now(),
	}
}

// NewApprovalMessage creates a new ApprovalMessage.
func NewApprovalMessage(
	msgType string,
	executionID string,
	nodeID string,
	nodeName string,
	approvalType string,
) *ApprovalMessage {
	return &ApprovalMessage{
		Type:         msgType,
		ExecutionID:  executionID,
		NodeID:       nodeID,
		NodeName:     nodeName,
		ApprovalType: approvalType,
		Timestamp:    time.Now(),
	}
}

// NewHeartbeatMessage creates a new HeartbeatMessage.
func NewHeartbeatMessage(serverID string) *HeartbeatMessage {
	return &HeartbeatMessage{
		Type:      MsgTypeHeartbeat,
		Timestamp: time.Now(),
		ServerID:  serverID,
	}
}

// NewErrorMessage creates a new ErrorMessage.
func NewErrorMessage(code, message string) *ErrorMessage {
	return &ErrorMessage{
		Type:    MsgTypeError,
		Code:    code,
		Message: message,
	}
}
