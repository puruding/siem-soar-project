package websocket

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Hub maintains the set of active clients and broadcasts messages to them.
// This is a simple in-memory hub without Redis for demo/dev purposes.
type Hub struct {
	// clients is the set of registered clients.
	clients map[*Client]bool

	// clientsByTenant indexes clients by tenant ID for efficient tenant-specific broadcasts.
	clientsByTenant map[string]map[*Client]bool

	// register is the channel for client registration requests.
	register chan *Client

	// unregister is the channel for client unregistration requests.
	unregister chan *Client

	// broadcast is the channel for messages to be broadcast to all clients.
	broadcast chan *Message

	// mu protects the clients maps.
	mu sync.RWMutex

	// logger for hub logging.
	logger *slog.Logger

	// stats tracks hub statistics.
	stats *hubStats

	// done signals shutdown.
	done chan struct{}
}

// hubStats tracks hub statistics.
type hubStats struct {
	totalClients    atomic.Int64
	messagesIn      atomic.Int64
	messagesOut     atomic.Int64
	lastMessageTime atomic.Int64
}

// NewHub creates a new Hub.
func NewHub(logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}

	return &Hub{
		clients:         make(map[*Client]bool),
		clientsByTenant: make(map[string]map[*Client]bool),
		register:        make(chan *Client),
		unregister:      make(chan *Client),
		broadcast:       make(chan *Message, 256),
		logger:          logger.With("component", "ws_hub"),
		stats:           &hubStats{},
		done:            make(chan struct{}),
	}
}

// Run starts the hub's main loop.
func (h *Hub) Run(ctx context.Context) {
	h.logger.Info("starting WebSocket hub")

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("shutting down WebSocket hub (context cancelled)")
			h.shutdown()
			return

		case <-h.done:
			h.logger.Info("hub shutdown requested")
			h.shutdown()
			return

		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case message := <-h.broadcast:
			h.broadcastMessage(message)
		}
	}
}

// registerClient registers a new client.
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client] = true

	// Add to tenant index
	if client.TenantID != "" {
		if h.clientsByTenant[client.TenantID] == nil {
			h.clientsByTenant[client.TenantID] = make(map[*Client]bool)
		}
		h.clientsByTenant[client.TenantID][client] = true
	}

	h.stats.totalClients.Add(1)

	h.logger.Info("client registered",
		"client_id", client.ID,
		"tenant_id", client.TenantID,
		"total_clients", h.stats.totalClients.Load(),
	)
}

// unregisterClient unregisters a client.
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; !ok {
		return
	}

	delete(h.clients, client)

	// Remove from tenant index
	if client.TenantID != "" {
		if tenantClients, ok := h.clientsByTenant[client.TenantID]; ok {
			delete(tenantClients, client)
			if len(tenantClients) == 0 {
				delete(h.clientsByTenant, client.TenantID)
			}
		}
	}

	// Close the send channel to signal the write pump to exit
	close(client.Send)

	h.stats.totalClients.Add(-1)

	h.logger.Info("client unregistered",
		"client_id", client.ID,
		"tenant_id", client.TenantID,
		"total_clients", h.stats.totalClients.Load(),
	)
}

// broadcastMessage sends a message to all subscribed clients.
func (h *Hub) broadcastMessage(msg *Message) {
	h.stats.messagesIn.Add(1)
	h.stats.lastMessageTime.Store(time.Now().UnixNano())

	data, err := json.Marshal(msg)
	if err != nil {
		h.logger.Error("failed to marshal broadcast message", "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	var sentCount int64
	for client := range h.clients {
		if h.shouldSendToClient(client, msg) {
			select {
			case client.Send <- data:
				sentCount++
			default:
				// Client's send buffer is full
				h.logger.Warn("client send buffer full",
					"client_id", client.ID,
					"tenant_id", client.TenantID,
				)
			}
		}
	}

	h.stats.messagesOut.Add(sentCount)

	h.logger.Debug("message broadcast",
		"type", msg.Type,
		"action", msg.Action,
		"sent_to", sentCount,
	)
}

// shouldSendToClient determines if a message should be sent to a client.
func (h *Hub) shouldSendToClient(client *Client, msg *Message) bool {
	// Check if client is subscribed to this message type
	if !client.IsSubscribed(msg.Type) {
		return false
	}

	// If message has a tenant ID, only send to clients of that tenant
	if msg.TenantID != "" && client.TenantID != "" && msg.TenantID != client.TenantID {
		return false
	}

	return true
}

// RegisterClient registers a new client (called from handler).
func (h *Hub) RegisterClient(client *Client) {
	h.register <- client
}

// UnregisterClient unregisters a client (called from handler).
func (h *Hub) UnregisterClient(client *Client) {
	h.unregister <- client
}

// Broadcast sends a message to all subscribed clients.
func (h *Hub) Broadcast(msg *Message) {
	select {
	case h.broadcast <- msg:
	default:
		h.logger.Warn("broadcast channel full, message dropped",
			"type", msg.Type,
			"action", msg.Action,
		)
	}
}

// BroadcastToTenant sends a message to clients of a specific tenant.
func (h *Hub) BroadcastToTenant(tenantID string, msg *Message) {
	if tenantID == "" {
		h.Broadcast(msg)
		return
	}

	// Set tenant ID on message for filtering
	msg.TenantID = tenantID
	h.Broadcast(msg)
}

// BroadcastAlert is a convenience method for broadcasting alert updates.
func (h *Hub) BroadcastAlert(action MessageAction, payload interface{}) {
	h.Broadcast(NewMessage(TypeAlert, action, payload))
}

// BroadcastEvent is a convenience method for broadcasting event updates.
func (h *Hub) BroadcastEvent(action MessageAction, payload interface{}) {
	h.Broadcast(NewMessage(TypeEvent, action, payload))
}

// BroadcastPipeline is a convenience method for broadcasting pipeline updates.
func (h *Hub) BroadcastPipeline(action MessageAction, payload interface{}) {
	h.Broadcast(NewMessage(TypePipeline, action, payload))
}

// BroadcastCase is a convenience method for broadcasting case updates.
func (h *Hub) BroadcastCase(action MessageAction, payload interface{}) {
	h.Broadcast(NewMessage(TypeCase, action, payload))
}

// BroadcastPlaybook is a convenience method for broadcasting playbook updates.
func (h *Hub) BroadcastPlaybook(action MessageAction, payload interface{}) {
	h.Broadcast(NewMessage(TypePlaybook, action, payload))
}

// Stats returns current hub statistics.
func (h *Hub) Stats() HubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clientsByTenant := make(map[string]int)
	for tenantID, clients := range h.clientsByTenant {
		clientsByTenant[tenantID] = len(clients)
	}

	lastMsgNano := h.stats.lastMessageTime.Load()
	var messagesPerSec float64
	if lastMsgNano > 0 {
		elapsed := time.Since(time.Unix(0, lastMsgNano)).Seconds()
		if elapsed > 0 && elapsed < 60 {
			messagesPerSec = float64(h.stats.messagesIn.Load()) / elapsed
		}
	}

	return HubStats{
		TotalClients:    int(h.stats.totalClients.Load()),
		ClientsByTenant: clientsByTenant,
		MessagesPerSec:  messagesPerSec,
		MessagesIn:      h.stats.messagesIn.Load(),
		MessagesOut:     h.stats.messagesOut.Load(),
	}
}

// ClientCount returns the total number of connected clients.
func (h *Hub) ClientCount() int {
	return int(h.stats.totalClients.Load())
}

// TenantClientCount returns the number of clients for a specific tenant.
func (h *Hub) TenantClientCount(tenantID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if clients, ok := h.clientsByTenant[tenantID]; ok {
		return len(clients)
	}
	return 0
}

// shutdown gracefully shuts down the hub.
func (h *Hub) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Close all client connections
	for client := range h.clients {
		close(client.Send)
		delete(h.clients, client)
	}

	// Clear tenant index
	h.clientsByTenant = make(map[string]map[*Client]bool)

	h.logger.Info("hub shutdown complete")
}

// Stop signals the hub to stop.
func (h *Hub) Stop() {
	close(h.done)
}

// HubStats contains hub statistics.
type HubStats struct {
	// TotalClients is the total number of connected clients.
	TotalClients int `json:"total_clients"`
	// ClientsByTenant is a map of tenant ID to client count.
	ClientsByTenant map[string]int `json:"clients_by_tenant"`
	// MessagesPerSec is the current message rate.
	MessagesPerSec float64 `json:"messages_per_sec"`
	// MessagesIn is the total number of messages received.
	MessagesIn int64 `json:"messages_in"`
	// MessagesOut is the total number of messages sent.
	MessagesOut int64 `json:"messages_out"`
}
