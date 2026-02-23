package handler

import (
	"github.com/siem-soar-platform/services/gateway/internal/websocket"
)

// wsHub is the global WebSocket hub reference.
var wsHub *websocket.Hub

// SetWebSocketHub sets the global WebSocket hub for broadcasting.
func SetWebSocketHub(hub *websocket.Hub) {
	wsHub = hub
}

// GetWebSocketHub returns the global WebSocket hub.
func GetWebSocketHub() *websocket.Hub {
	return wsHub
}

// BroadcastAlertCreated broadcasts an alert creation to connected clients.
func BroadcastAlertCreated(alert Alert) {
	if wsHub != nil {
		wsHub.BroadcastAlert(websocket.ActionCreated, alert)
	}
}

// BroadcastAlertUpdated broadcasts an alert update to connected clients.
func BroadcastAlertUpdated(alert Alert) {
	if wsHub != nil {
		wsHub.BroadcastAlert(websocket.ActionUpdated, alert)
	}
}

// BroadcastCaseCreated broadcasts a case creation to connected clients.
func BroadcastCaseCreated(caseData Case) {
	if wsHub != nil {
		wsHub.BroadcastCase(websocket.ActionCreated, caseData)
	}
}

// BroadcastCaseUpdated broadcasts a case update to connected clients.
func BroadcastCaseUpdated(caseData Case) {
	if wsHub != nil {
		wsHub.BroadcastCase(websocket.ActionUpdated, caseData)
	}
}

// BroadcastPlaybookExecution broadcasts a playbook execution to connected clients.
func BroadcastPlaybookExecution(execution PlaybookExecution) {
	if wsHub != nil {
		wsHub.BroadcastPlaybook(websocket.ActionCreated, execution)
	}
}
