package websocket

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Handler handles WebSocket connections.
type Handler struct {
	hub      *Hub
	upgrader websocket.Upgrader
	logger   *slog.Logger
}

// NewHandler creates a new WebSocket handler.
func NewHandler(hub *Hub, logger *slog.Logger) *Handler {
	return &Handler{
		hub: hub,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// TODO: In production, implement proper origin checking
				// For now, allow all origins for development
				return true
			},
		},
		logger: logger,
	}
}

// ServeWS upgrades HTTP connection to WebSocket.
// Query params:
//   - topics: comma-separated list of topics to subscribe to
//     e.g., /ws/soar?topics=execution:123,alert:456
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket connection", "error", err)
		return
	}

	// Generate client ID
	clientID := uuid.New().String()

	// Parse initial topics from query params
	topicsParam := r.URL.Query().Get("topics")
	var topics []string
	if topicsParam != "" {
		topics = strings.Split(topicsParam, ",")
		// Trim whitespace from topics
		for i, topic := range topics {
			topics[i] = strings.TrimSpace(topic)
		}
	}

	// Create client
	client := NewClient(clientID, conn, h.hub, h.logger)

	// Register with hub
	h.hub.RegisterClient(client, topics)

	h.logger.Info("WebSocket client connected",
		"client_id", clientID,
		"remote_addr", r.RemoteAddr,
		"topics", topics,
	)

	// Start read and write pumps
	go client.WritePump()
	go client.ReadPump()
}

// ServeHTTP implements http.Handler interface for compatibility.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.ServeWS(w, r)
}

// GetHub returns the underlying hub for direct access if needed.
func (h *Handler) GetHub() *Hub {
	return h.hub
}
