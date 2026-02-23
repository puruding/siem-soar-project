package websocket

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/siem-soar-platform/services/gateway/internal/auth"
)

// Upgrader configuration for WebSocket connections.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// CheckOrigin allows connections from any origin in development.
	// In production, this should be more restrictive.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// SetAllowedOrigins configures the allowed origins for WebSocket connections.
func SetAllowedOrigins(origins []string) {
	if len(origins) == 0 {
		return
	}

	allowedOrigins := make(map[string]bool)
	for _, origin := range origins {
		allowedOrigins[strings.ToLower(origin)] = true
	}

	upgrader.CheckOrigin = func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Allow connections without Origin header (non-browser clients)
		}
		return allowedOrigins[strings.ToLower(origin)]
	}
}

// HandlerConfig configures the WebSocket handler.
type HandlerConfig struct {
	// Hub is the WebSocket hub.
	Hub *Hub
	// JWTAuthenticator validates JWT tokens.
	JWTAuthenticator *auth.JWTAuthenticator
	// AuthEnabled determines if authentication is required.
	AuthEnabled bool
	// Logger for handler logging.
	Logger *slog.Logger
	// DefaultSubscriptions are the message types clients subscribe to by default.
	DefaultSubscriptions []MessageType
}

// NewHandler creates a WebSocket handler with the given configuration.
func NewHandler(cfg HandlerConfig) http.HandlerFunc {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default().With("component", "ws_handler")
	}

	// Default to subscribing to all types
	if len(cfg.DefaultSubscriptions) == 0 {
		cfg.DefaultSubscriptions = AllMessageTypes()
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for WebSocket preflight
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 1. Authentication
		var tenantID, userID string

		if cfg.AuthEnabled {
			token := extractToken(r)
			if token == "" {
				cfg.Logger.Warn("WebSocket: missing authentication token",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "unauthorized: missing authentication token", http.StatusUnauthorized)
				return
			}

			if cfg.JWTAuthenticator == nil {
				cfg.Logger.Error("WebSocket: JWT authenticator not configured")
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			claims, err := cfg.JWTAuthenticator.Authenticate(token)
			if err != nil {
				cfg.Logger.Warn("WebSocket: invalid authentication token",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				http.Error(w, "unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			tenantID = claims.TenantID
			userID = claims.UserID
		} else {
			// Dev mode: try to get tenant ID from header or use default
			tenantID = r.Header.Get("X-Tenant-ID")
			if tenantID == "" {
				tenantID = "dev-tenant"
			}
			userID = r.Header.Get("X-User-ID")
			if userID == "" {
				userID = "dev-user"
			}
		}

		// 2. WebSocket Upgrade
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			cfg.Logger.Error("failed to upgrade WebSocket connection",
				"remote_addr", r.RemoteAddr,
				"error", err,
			)
			return
		}

		// 3. Create client and register with hub
		client := NewClient(cfg.Hub, conn, tenantID, userID)

		// Subscribe to default types
		client.Subscribe(cfg.DefaultSubscriptions)

		cfg.Hub.RegisterClient(client)

		cfg.Logger.Info("WebSocket client connected",
			"client_id", client.ID,
			"tenant_id", tenantID,
			"user_id", userID,
			"remote_addr", r.RemoteAddr,
			"subscriptions", cfg.DefaultSubscriptions,
		)

		// 4. Start goroutines for reading and writing
		go client.WritePump()
		go client.ReadPump()
	}
}

// NewAlertHandler creates a WebSocket handler that only subscribes to alert messages.
func NewAlertHandler(cfg HandlerConfig) http.HandlerFunc {
	cfg.DefaultSubscriptions = []MessageType{TypeAlert}
	return NewHandler(cfg)
}

// NewPipelineHandler creates a WebSocket handler that only subscribes to pipeline messages.
func NewPipelineHandler(cfg HandlerConfig) http.HandlerFunc {
	cfg.DefaultSubscriptions = []MessageType{TypePipeline, TypeEvent}
	return NewHandler(cfg)
}

// ServeWS handles WebSocket upgrade and creates client.
// This is a convenience function that creates a handler with default settings.
func ServeWS(hub *Hub) http.HandlerFunc {
	authEnabled := isAuthEnabled()

	return NewHandler(HandlerConfig{
		Hub:         hub,
		AuthEnabled: authEnabled,
		Logger:      slog.Default().With("component", "ws_handler"),
	})
}

// ServeWSWithAuth handles WebSocket upgrade with JWT authentication.
func ServeWSWithAuth(hub *Hub, jwtAuth *auth.JWTAuthenticator) http.HandlerFunc {
	return NewHandler(HandlerConfig{
		Hub:              hub,
		JWTAuthenticator: jwtAuth,
		AuthEnabled:      true,
		Logger:           slog.Default().With("component", "ws_handler"),
	})
}

// isAuthEnabled checks if AUTH_ENABLED environment variable is set.
func isAuthEnabled() bool {
	val := os.Getenv("AUTH_ENABLED")
	if val == "" {
		return true // Default to enabled
	}
	val = strings.ToLower(val)
	return val == "true" || val == "1" || val == "yes"
}

// extractToken extracts the JWT token from the request.
// It checks the Authorization header (Bearer token) and query parameter (token).
func extractToken(r *http.Request) string {
	// Check Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Check query parameter (useful for WebSocket connections)
	token := r.URL.Query().Get("token")
	if token != "" {
		return token
	}

	// Check Sec-WebSocket-Protocol header (can be used to pass token)
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if protocol != "" {
		// Protocol format: "access_token, <token>"
		parts := strings.SplitN(protocol, ",", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}

	return ""
}

// StatsHandler returns hub statistics as JSON.
func StatsHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := hub.Stats()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(stats)
	}
}

// HealthHandler returns the health status of the WebSocket hub.
func HealthHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "healthy",
			"total_clients": hub.ClientCount(),
		})
	}
}
