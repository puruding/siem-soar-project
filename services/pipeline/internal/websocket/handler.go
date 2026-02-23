package websocket

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
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

// JWTValidator is a function that validates JWT tokens.
// It should return the tenant ID if valid, or an error if invalid.
type JWTValidator func(token string) (tenantID string, err error)

// HandlerConfig configures the WebSocket handler.
type HandlerConfig struct {
	// Hub is the WebSocket hub.
	Hub *Hub
	// JWTValidator validates JWT tokens and returns tenant ID.
	JWTValidator JWTValidator
	// RequireAuth determines if authentication is required.
	RequireAuth bool
	// Logger for handler logging.
	Logger *slog.Logger
}

// NewHandler creates a WebSocket handler with the given configuration.
func NewHandler(cfg HandlerConfig) http.HandlerFunc {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default().With("component", "ws_handler")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// 1. JWT Authentication
		var tenantID string
		if cfg.RequireAuth {
			token := extractToken(r)
			if token == "" {
				cfg.Logger.Warn("missing authentication token",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "unauthorized: missing authentication token", http.StatusUnauthorized)
				return
			}

			if cfg.JWTValidator == nil {
				cfg.Logger.Error("JWT validator not configured")
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			var err error
			tenantID, err = cfg.JWTValidator(token)
			if err != nil {
				cfg.Logger.Warn("invalid authentication token",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				http.Error(w, "unauthorized: invalid token", http.StatusUnauthorized)
				return
			}
		} else {
			// Try to get tenant ID from header if auth is not required
			tenantID = r.Header.Get("X-Tenant-ID")
		}

		// 2. WebSocket Upgrade
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			cfg.Logger.Error("failed to upgrade connection",
				"remote_addr", r.RemoteAddr,
				"error", err,
			)
			return
		}

		// 3. Create client and register with hub
		client := NewClient(cfg.Hub, conn, tenantID)

		// Subscribe to all types by default
		client.SubscribeAll()

		cfg.Hub.RegisterClient(client)

		cfg.Logger.Info("WebSocket client connected",
			"client_id", client.ID,
			"tenant_id", tenantID,
			"remote_addr", r.RemoteAddr,
		)

		// 4. Start goroutines for reading and writing
		go client.WritePump()
		go client.ReadPump()
	}
}

// ServeWS handles WebSocket upgrade and creates client.
// This is a convenience function that creates a handler with default settings.
func ServeWS(hub *Hub) http.HandlerFunc {
	return NewHandler(HandlerConfig{
		Hub:         hub,
		RequireAuth: false,
		Logger:      slog.Default().With("component", "ws_handler"),
	})
}

// ServeWSWithAuth handles WebSocket upgrade with JWT authentication.
func ServeWSWithAuth(hub *Hub, validator JWTValidator) http.HandlerFunc {
	return NewHandler(HandlerConfig{
		Hub:          hub,
		JWTValidator: validator,
		RequireAuth:  true,
		Logger:       slog.Default().With("component", "ws_handler"),
	})
}

// extractToken extracts the JWT token from the request.
// It checks the Authorization header (Bearer token) and query parameter (token).
func extractToken(r *http.Request) string {
	// Check Authorization header first
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
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
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(stats)
	}
}

// HealthHandler returns the health status of the WebSocket hub.
func HealthHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "healthy",
			"total_clients": hub.ClientCount(),
		})
	}
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, statusCode int, errResp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errResp)
}

// Common JWT validation errors.
var (
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenInvalid     = errors.New("token invalid")
	ErrTokenMissing     = errors.New("token missing")
	ErrTenantIDMissing  = errors.New("tenant ID missing from token")
)
