package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/siem-soar-platform/services/ml-gateway/internal/client"
	"github.com/siem-soar-platform/services/ml-gateway/internal/config"
)

// ModelClients holds HTTP clients for ML services.
type ModelClients struct {
	ClassifyClient *client.HTTPClient
	DGAClient      *client.HTTPClient
	PriorityClient *client.HTTPClient
}

// PredictHandler handles prediction requests.
type PredictHandler struct {
	clients     *ModelClients
	redisClient *client.RedisClient
	config      *config.Config
}

// NewPredictHandler creates a new prediction handler.
func NewPredictHandler(clients *ModelClients, redisClient *client.RedisClient, cfg *config.Config) *PredictHandler {
	return &PredictHandler{
		clients:     clients,
		redisClient: redisClient,
		config:      cfg,
	}
}

// ServeHTTP handles prediction requests.
func (h *PredictHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ModelHandler handles model management requests.
type ModelHandler struct {
	clients *ModelClients
	config  *config.Config
}

// NewModelHandler creates a new model handler.
func NewModelHandler(clients *ModelClients, cfg *config.Config) *ModelHandler {
	return &ModelHandler{
		clients: clients,
		config:  cfg,
	}
}

// ServeHTTP handles model management requests.
func (h *ModelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HealthHandler handles health check requests.
type HealthHandler struct {
	clients *ModelClients
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(clients *ModelClients) *HealthHandler {
	return &HealthHandler{
		clients: clients,
	}
}

// ServeHTTP handles health check requests.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "ml-gateway",
		"timestamp": time.Now().Unix(),
	})
}
