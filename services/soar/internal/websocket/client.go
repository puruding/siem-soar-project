package websocket

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 8192
)

// Client represents a single WebSocket client connection.
type Client struct {
	ID     string
	Conn   *websocket.Conn
	Hub    *Hub
	Send   chan []byte
	Topics map[string]bool
	Logger *slog.Logger

	mu sync.RWMutex
}

// NewClient creates a new WebSocket client.
func NewClient(id string, conn *websocket.Conn, hub *Hub, logger *slog.Logger) *Client {
	return &Client{
		ID:     id,
		Conn:   conn,
		Hub:    hub,
		Send:   make(chan []byte, 256),
		Topics: make(map[string]bool),
		Logger: logger,
	}
}

// ReadPump pumps messages from the WebSocket connection to the hub.
//
// The application runs ReadPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) ReadPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.Logger.Warn("WebSocket unexpected close", "client_id", c.ID, "error", err)
			}
			break
		}

		c.handleMessage(message)
	}
}

// WritePump pumps messages from the hub to the WebSocket connection.
//
// A goroutine running WritePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
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

			// Add queued messages to the current websocket message.
			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming messages from the client.
func (c *Client) handleMessage(message []byte) {
	var msg ClientMessage
	if err := json.Unmarshal(message, &msg); err != nil {
		c.Logger.Warn("Failed to parse client message", "client_id", c.ID, "error", err)
		c.sendError("PARSE_ERROR", "Invalid message format")
		return
	}

	switch msg.Type {
	case MsgTypeSubscribe:
		c.handleSubscribe(msg.Topics)
	case MsgTypeUnsubscribe:
		c.handleUnsubscribe(msg.Topics)
	default:
		c.Logger.Debug("Unknown message type", "client_id", c.ID, "type", msg.Type)
	}
}

// handleSubscribe subscribes the client to the specified topics.
func (c *Client) handleSubscribe(topics []string) {
	if len(topics) == 0 {
		return
	}

	c.mu.Lock()
	for _, topic := range topics {
		c.Topics[topic] = true
	}
	c.mu.Unlock()

	c.Hub.subscribe <- &ClientSubscription{
		Client: c,
		Topics: topics,
	}

	c.Logger.Debug("Client subscribed to topics", "client_id", c.ID, "topics", topics)
}

// handleUnsubscribe unsubscribes the client from the specified topics.
func (c *Client) handleUnsubscribe(topics []string) {
	if len(topics) == 0 {
		return
	}

	c.mu.Lock()
	for _, topic := range topics {
		delete(c.Topics, topic)
	}
	c.mu.Unlock()

	c.Hub.unsubscribe <- &ClientSubscription{
		Client: c,
		Topics: topics,
	}

	c.Logger.Debug("Client unsubscribed from topics", "client_id", c.ID, "topics", topics)
}

// sendError sends an error message to the client.
func (c *Client) sendError(code, message string) {
	errMsg := NewErrorMessage(code, message)
	data, _ := json.Marshal(errMsg)
	select {
	case c.Send <- data:
	default:
		// Channel full, drop message
	}
}

// GetTopics returns the current list of subscribed topics.
func (c *Client) GetTopics() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	topics := make([]string, 0, len(c.Topics))
	for topic := range c.Topics {
		topics = append(topics, topic)
	}
	return topics
}

// IsSubscribed checks if the client is subscribed to a topic.
func (c *Client) IsSubscribed(topic string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Topics[topic]
}
