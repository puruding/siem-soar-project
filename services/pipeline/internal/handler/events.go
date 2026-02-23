// Package handler provides HTTP handlers for the pipeline service.
package handler

import (
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
	"github.com/siem-soar-platform/services/pipeline/internal/repository"
	"github.com/siem-soar-platform/services/pipeline/internal/websocket"
)

// EventHandler handles HTTP requests for event stream operations.
type EventHandler struct {
	repo   *repository.EventRepository
	hub    *websocket.Hub
	logger *slog.Logger
}

// NewEventHandler creates a new event handler.
func NewEventHandler(repo *repository.EventRepository, hub *websocket.Hub, logger *slog.Logger) *EventHandler {
	return &EventHandler{
		repo:   repo,
		hub:    hub,
		logger: logger,
	}
}

// RegisterRoutes registers all event stream routes on the given mux.
func (h *EventHandler) RegisterRoutes(mux *http.ServeMux) {
	// Event stream routes
	mux.HandleFunc("GET /api/v1/pipeline/events", h.corsMiddleware(h.ListEventsEnhanced))
	mux.HandleFunc("GET /api/v1/pipeline/events/{id}", h.corsMiddleware(h.GetEventDetail))
	mux.HandleFunc("GET /api/v1/pipeline/events/stream", h.HandleWebSocket)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/stream", h.corsPreflightHandler)
}

// corsMiddleware wraps a handler with CORS headers.
func (h *EventHandler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// corsPreflightHandler handles CORS preflight requests.
func (h *EventHandler) corsPreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// EventListResponse represents the response for GET /api/v1/pipeline/events.
type EventListResponse struct {
	Events     []model.PipelineEvent `json:"events"`
	Pagination Pagination            `json:"pagination"`
}

// EventDetailResponse represents the response for GET /api/v1/pipeline/events/:id.
type EventDetailResponse struct {
	Event          *model.PipelineEvent     `json:"event"`
	RawLog         string                   `json:"raw_log"`
	ParsedFields   map[string]interface{}   `json:"parsed_fields"`
	Classification *model.Classification    `json:"classification,omitempty"`
	PlaybookMatch  *model.PlaybookMatch     `json:"playbook_match,omitempty"`
	Execution      *model.ExecutionStatus   `json:"execution,omitempty"`
	Timeline       []repository.TimelineEntry `json:"timeline"`
}

// ListEventsEnhanced handles GET /api/v1/pipeline/events with enhanced filtering and pagination.
func (h *EventHandler) ListEventsEnhanced(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	filter := h.parseEventFilter(r)

	// Get tenant ID from header if not in query
	if filter.TenantID == "" {
		filter.TenantID = r.Header.Get("X-Tenant-ID")
	}

	// Validate pagination
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Limit < 1 || filter.Limit > 1000 {
		filter.Limit = 100
	}

	// Fetch events from repository
	events, total, err := h.repo.ListEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list events", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to list events: "+err.Error())
		return
	}

	// Calculate pagination
	totalPages := int(math.Ceil(float64(total) / float64(filter.Limit)))
	if totalPages < 1 {
		totalPages = 1
	}

	response := EventListResponse{
		Events: events,
		Pagination: Pagination{
			Page:       filter.Page,
			Limit:      filter.Limit,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// parseEventFilter parses query parameters into an EventFilter.
func (h *EventHandler) parseEventFilter(r *http.Request) repository.EventFilter {
	query := r.URL.Query()

	filter := repository.EventFilter{
		Page:  1,
		Limit: 100,
	}

	// Parse tenant_id
	if tenantID := query.Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}

	// Parse severity (can be comma-separated)
	if severity := query.Get("severity"); severity != "" {
		filter.Severity = strings.Split(severity, ",")
	}

	// Parse source (can be comma-separated)
	if source := query.Get("source"); source != "" {
		filter.Source = strings.Split(source, ",")
	}

	// Parse stage
	if stage := query.Get("stage"); stage != "" {
		filter.Stage = stage
	}

	// Parse time range
	if from := query.Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			filter.From = t
		}
	}
	if to := query.Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			filter.To = t
		}
	}

	// Parse pagination
	if page := query.Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filter.Page = p
		}
	}
	if limit := query.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			filter.Limit = l
		}
	}

	return filter
}

// GetEventDetail handles GET /api/v1/pipeline/events/:id with full details.
func (h *EventHandler) GetEventDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	// Get tenant ID from header
	tenantID := r.Header.Get("X-Tenant-ID")

	// Fetch event from repository
	event, err := h.repo.GetEventByID(r.Context(), tenantID, id)
	if err != nil {
		h.logger.Warn("event not found", "event_id", id, "error", err)
		h.writeError(w, http.StatusNotFound, "event not found: "+id)
		return
	}

	// Fetch timeline entries
	timeline, err := h.repo.GetEventTimeline(r.Context(), id)
	if err != nil {
		h.logger.Warn("failed to fetch timeline", "event_id", id, "error", err)
		timeline = []repository.TimelineEntry{}
	}

	// Parse fields from raw log (placeholder - would be more sophisticated in production)
	parsedFields := h.parseRawLog(event.RawLog)

	response := EventDetailResponse{
		Event:          event,
		RawLog:         event.RawLog,
		ParsedFields:   parsedFields,
		Classification: event.Classification,
		PlaybookMatch:  event.PlaybookMatch,
		Execution:      event.Execution,
		Timeline:       timeline,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// parseRawLog parses a raw log string into structured fields.
// This is a simple implementation - a production system would use proper parsers.
func (h *EventHandler) parseRawLog(rawLog string) map[string]interface{} {
	fields := make(map[string]interface{})

	// Try to parse as JSON first
	var jsonFields map[string]interface{}
	if err := json.Unmarshal([]byte(rawLog), &jsonFields); err == nil {
		return jsonFields
	}

	// Simple key=value parsing
	parts := strings.Fields(rawLog)
	for _, part := range parts {
		if idx := strings.Index(part, "="); idx > 0 {
			key := part[:idx]
			value := strings.Trim(part[idx+1:], "\"'")
			fields[key] = value
		}
	}

	// If no fields parsed, store the raw log as a message field
	if len(fields) == 0 {
		fields["message"] = rawLog
	}

	return fields
}

// HandleWebSocket handles GET /api/v1/pipeline/events/stream (WebSocket).
func (h *EventHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	if h.hub == nil {
		h.writeError(w, http.StatusServiceUnavailable, "WebSocket hub not available")
		return
	}

	// Use the existing WebSocket handler from the websocket package
	handler := websocket.ServeWS(h.hub)
	handler(w, r)
}

// writeError writes an error response.
func (h *EventHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
