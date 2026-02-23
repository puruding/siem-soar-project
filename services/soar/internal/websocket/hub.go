package websocket

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// Hub manages WebSocket connections and message broadcasting.
type Hub struct {
	// Registered clients by topic (e.g., "execution:{id}", "alert:{id}")
	clients map[string]map[*Client]bool

	// All connected clients for global broadcasts
	allClients map[*Client]bool

	// Channel for registering clients
	register chan *Client

	// Channel for unregistering clients
	unregister chan *Client

	// Channel for subscribing clients to topics
	subscribe chan *ClientSubscription

	// Channel for unsubscribing clients from topics
	unsubscribe chan *ClientSubscription

	// Channel for broadcasting messages
	broadcast chan *BroadcastMessage

	// Logger
	logger *slog.Logger

	// Mutex for thread-safe operations
	mu sync.RWMutex

	// Server ID for heartbeat messages
	serverID string

	// Done channel for shutdown
	done chan struct{}
}

// ClientSubscription represents a client subscription request.
type ClientSubscription struct {
	Client *Client
	Topics []string
}

// BroadcastMessage represents a message to be broadcast.
type BroadcastMessage struct {
	Topic   string
	Message []byte
}

// NewHub creates a new Hub instance.
func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients:     make(map[string]map[*Client]bool),
		allClients:  make(map[*Client]bool),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		subscribe:   make(chan *ClientSubscription),
		unsubscribe: make(chan *ClientSubscription),
		broadcast:   make(chan *BroadcastMessage, 256),
		logger:      logger,
		serverID:    generateServerID(),
		done:        make(chan struct{}),
	}
}

// Run starts the hub's main event loop.
func (h *Hub) Run() {
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-h.done:
			h.cleanup()
			return

		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case sub := <-h.subscribe:
			h.subscribeClient(sub)

		case sub := <-h.unsubscribe:
			h.unsubscribeClient(sub)

		case msg := <-h.broadcast:
			h.broadcastMessage(msg)

		case <-heartbeatTicker.C:
			h.sendHeartbeat()
		}
	}
}

// Stop gracefully stops the hub.
func (h *Hub) Stop() {
	close(h.done)
}

// registerClient registers a new client.
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.allClients[client] = true
	h.logger.Info("Client registered", "client_id", client.ID)
}

// unregisterClient unregisters a client and cleans up subscriptions.
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.allClients[client]; !ok {
		return
	}

	// Remove from all topic subscriptions
	for topic := range client.Topics {
		if clients, ok := h.clients[topic]; ok {
			delete(clients, client)
			if len(clients) == 0 {
				delete(h.clients, topic)
			}
		}
	}

	delete(h.allClients, client)
	close(client.Send)
	h.logger.Info("Client unregistered", "client_id", client.ID)
}

// subscribeClient subscribes a client to topics.
func (h *Hub) subscribeClient(sub *ClientSubscription) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, topic := range sub.Topics {
		if h.clients[topic] == nil {
			h.clients[topic] = make(map[*Client]bool)
		}
		h.clients[topic][sub.Client] = true
	}

	h.logger.Debug("Client subscribed",
		"client_id", sub.Client.ID,
		"topics", sub.Topics,
	)
}

// unsubscribeClient unsubscribes a client from topics.
func (h *Hub) unsubscribeClient(sub *ClientSubscription) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, topic := range sub.Topics {
		if clients, ok := h.clients[topic]; ok {
			delete(clients, sub.Client)
			if len(clients) == 0 {
				delete(h.clients, topic)
			}
		}
	}
}

// broadcastMessage broadcasts a message to all clients subscribed to the topic.
func (h *Hub) broadcastMessage(msg *BroadcastMessage) {
	h.mu.RLock()
	clients := h.clients[msg.Topic]
	h.mu.RUnlock()

	for client := range clients {
		select {
		case client.Send <- msg.Message:
		default:
			// Client's send buffer is full, skip
			h.logger.Warn("Client send buffer full, dropping message",
				"client_id", client.ID,
				"topic", msg.Topic,
			)
		}
	}
}

// sendHeartbeat sends a heartbeat to all connected clients.
func (h *Hub) sendHeartbeat() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	heartbeat := NewHeartbeatMessage(h.serverID)
	data, _ := json.Marshal(heartbeat)

	for client := range h.allClients {
		select {
		case client.Send <- data:
		default:
			// Skip if buffer is full
		}
	}
}

// cleanup closes all client connections.
func (h *Hub) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.allClients {
		close(client.Send)
	}

	h.clients = make(map[string]map[*Client]bool)
	h.allClients = make(map[*Client]bool)
}

// Broadcast sends a message to all clients subscribed to the topic.
// This is the public API for broadcasting messages.
func (h *Hub) Broadcast(topic string, message []byte) {
	select {
	case h.broadcast <- &BroadcastMessage{
		Topic:   topic,
		Message: message,
	}:
	default:
		h.logger.Warn("Broadcast channel full, dropping message", "topic", topic)
	}
}

// BroadcastToAll sends a message to all connected clients.
func (h *Hub) BroadcastToAll(message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.allClients {
		select {
		case client.Send <- message:
		default:
			// Skip if buffer is full
		}
	}
}

// RegisterClient adds a new client to the hub with initial topics.
func (h *Hub) RegisterClient(client *Client, topics []string) {
	h.register <- client

	if len(topics) > 0 {
		h.subscribe <- &ClientSubscription{
			Client: client,
			Topics: topics,
		}
		client.mu.Lock()
		for _, topic := range topics {
			client.Topics[topic] = true
		}
		client.mu.Unlock()
	}
}

// UnregisterClient removes a client from the hub.
func (h *Hub) UnregisterClient(client *Client) {
	h.unregister <- client
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.allClients)
}

// TopicClientCount returns the number of clients subscribed to a topic.
func (h *Hub) TopicClientCount(topic string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients[topic])
}

// GetTopics returns all active topics.
func (h *Hub) GetTopics() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	topics := make([]string, 0, len(h.clients))
	for topic := range h.clients {
		topics = append(topics, topic)
	}
	return topics
}

// generateServerID creates a unique server identifier.
func generateServerID() string {
	return time.Now().Format("20060102150405")
}
