package websocket

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WebSocket connection configuration constants.
const (
	// WriteWait is the time allowed to write a message to the peer.
	WriteWait = 10 * time.Second

	// PongWait is the time allowed to read the next pong message from the peer.
	PongWait = 60 * time.Second

	// PingPeriod is the period for sending pings to peer (must be less than PongWait).
	PingPeriod = (PongWait * 9) / 10

	// MaxMessageSize is the maximum message size allowed from peer.
	MaxMessageSize = 512 * 1024 // 512KB
)

// Client represents a WebSocket client connection.
type Client struct {
	// ID is the unique identifier for this client.
	ID string

	// TenantID is the tenant this client belongs to.
	TenantID string

	// Conn is the underlying WebSocket connection.
	Conn *websocket.Conn

	// Send is the channel for outbound messages.
	Send chan []byte

	// Hub is the hub this client is registered with.
	Hub *Hub

	// Subscribed tracks which message types the client is subscribed to.
	Subscribed map[MessageType]bool

	// mu protects the Subscribed map.
	mu sync.RWMutex

	// logger for client-specific logging.
	logger *slog.Logger

	// connectedAt is when the client connected.
	connectedAt time.Time

	// lastActivity is the last time the client sent or received a message.
	lastActivity time.Time

	// activityMu protects lastActivity.
	activityMu sync.RWMutex
}

// NewClient creates a new WebSocket client.
func NewClient(hub *Hub, conn *websocket.Conn, tenantID string) *Client {
	clientID := uuid.New().String()
	now := time.Now().UTC()

	return &Client{
		ID:           clientID,
		TenantID:     tenantID,
		Conn:         conn,
		Send:         make(chan []byte, 256),
		Hub:          hub,
		Subscribed:   make(map[MessageType]bool),
		logger:       slog.Default().With("component", "ws_client", "client_id", clientID),
		connectedAt:  now,
		lastActivity: now,
	}
}

// ReadPump pumps messages from the WebSocket connection to the hub.
// The application runs ReadPump in a per-connection goroutine.
func (c *Client) ReadPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
		c.logger.Info("client disconnected",
			"tenant_id", c.TenantID,
			"connected_duration", time.Since(c.connectedAt).String(),
		)
	}()

	c.Conn.SetReadLimit(MaxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(PongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(PongWait))
		c.updateActivity()
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.logger.Warn("unexpected close error", "error", err)
			}
			break
		}

		c.updateActivity()
		c.handleMessage(message)
	}
}

// WritePump pumps messages from the hub to the WebSocket connection.
// The application runs WritePump in a per-connection goroutine.
func (c *Client) WritePump() {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				// The hub closed the channel.
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current WebSocket message.
			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming messages from the client.
func (c *Client) handleMessage(message []byte) {
	var clientMsg ClientMessage
	if err := json.Unmarshal(message, &clientMsg); err != nil {
		c.sendError(ErrCodeInvalidMessage, "failed to parse message")
		return
	}

	switch clientMsg.Type {
	case ClientMsgSubscribe:
		c.handleSubscribe(clientMsg.Data)
	case ClientMsgUnsubscribe:
		c.handleUnsubscribe(clientMsg.Data)
	case ClientMsgPing:
		c.sendPong()
	default:
		c.sendError(ErrCodeInvalidType, "unknown message type: "+clientMsg.Type)
	}
}

// handleSubscribe processes subscription requests.
func (c *Client) handleSubscribe(data interface{}) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		c.sendError(ErrCodeInvalidMessage, "invalid subscription data")
		return
	}

	var subMsg SubscribeMessage
	if err := json.Unmarshal(dataBytes, &subMsg); err != nil {
		c.sendError(ErrCodeInvalidMessage, "invalid subscription format")
		return
	}

	// Validate message types
	for _, t := range subMsg.Types {
		if !t.IsValid() {
			c.sendError(ErrCodeInvalidType, "invalid message type: "+string(t))
			return
		}
	}

	// Update tenant ID if provided
	if subMsg.TenantID != "" && c.TenantID == "" {
		c.TenantID = subMsg.TenantID
	}

	c.Subscribe(subMsg.Types)

	c.logger.Debug("client subscribed",
		"types", subMsg.Types,
		"tenant_id", c.TenantID,
	)

	// Send confirmation
	c.sendJSON(map[string]interface{}{
		"type":        "subscribed",
		"types":       subMsg.Types,
		"tenant_id":   c.TenantID,
		"timestamp":   time.Now().UTC(),
	})
}

// handleUnsubscribe processes unsubscription requests.
func (c *Client) handleUnsubscribe(data interface{}) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		c.sendError(ErrCodeInvalidMessage, "invalid unsubscription data")
		return
	}

	var unsubMsg UnsubscribeMessage
	if err := json.Unmarshal(dataBytes, &unsubMsg); err != nil {
		c.sendError(ErrCodeInvalidMessage, "invalid unsubscription format")
		return
	}

	c.Unsubscribe(unsubMsg.Types)

	c.logger.Debug("client unsubscribed",
		"types", unsubMsg.Types,
	)

	// Send confirmation
	c.sendJSON(map[string]interface{}{
		"type":      "unsubscribed",
		"types":     unsubMsg.Types,
		"timestamp": time.Now().UTC(),
	})
}

// sendPong sends a pong response to the client.
func (c *Client) sendPong() {
	c.sendJSON(map[string]interface{}{
		"type": "pong",
		"pong": true,
		"timestamp": time.Now().UTC(),
	})
}

// sendError sends an error message to the client.
func (c *Client) sendError(code, message string) {
	errMsg := NewErrorMessage(code, message)
	c.sendJSON(map[string]interface{}{
		"type":      "error",
		"code":      errMsg.Code,
		"message":   errMsg.Message,
		"timestamp": errMsg.Timestamp,
	})
}

// sendJSON sends a JSON message to the client.
func (c *Client) sendJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		c.logger.Error("failed to marshal JSON", "error", err)
		return
	}

	select {
	case c.Send <- data:
	default:
		// Channel is full, client is slow
		c.logger.Warn("client send buffer full, message dropped")
	}
}

// Subscribe subscribes the client to specific message types.
func (c *Client) Subscribe(types []MessageType) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, t := range types {
		c.Subscribed[t] = true
	}
}

// SubscribeAll subscribes the client to all message types.
func (c *Client) SubscribeAll() {
	c.Subscribe(AllMessageTypes())
}

// Unsubscribe unsubscribes the client from specific message types.
func (c *Client) Unsubscribe(types []MessageType) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, t := range types {
		delete(c.Subscribed, t)
	}
}

// UnsubscribeAll unsubscribes the client from all message types.
func (c *Client) UnsubscribeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Subscribed = make(map[MessageType]bool)
}

// IsSubscribed checks if client is subscribed to a message type.
func (c *Client) IsSubscribed(msgType MessageType) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Subscribed[msgType]
}

// GetSubscriptions returns a copy of the subscribed message types.
func (c *Client) GetSubscriptions() []MessageType {
	c.mu.RLock()
	defer c.mu.RUnlock()

	types := make([]MessageType, 0, len(c.Subscribed))
	for t := range c.Subscribed {
		types = append(types, t)
	}
	return types
}

// updateActivity updates the last activity timestamp.
func (c *Client) updateActivity() {
	c.activityMu.Lock()
	c.lastActivity = time.Now().UTC()
	c.activityMu.Unlock()
}

// LastActivity returns the last activity timestamp.
func (c *Client) LastActivity() time.Time {
	c.activityMu.RLock()
	defer c.activityMu.RUnlock()
	return c.lastActivity
}

// ConnectedAt returns the connection start time.
func (c *Client) ConnectedAt() time.Time {
	return c.connectedAt
}

// Close closes the client connection and cleans up resources.
func (c *Client) Close() error {
	close(c.Send)
	return c.Conn.Close()
}
