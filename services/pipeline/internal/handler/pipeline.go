// Package handler provides HTTP handlers for the pipeline service.
package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
	"github.com/siem-soar-platform/services/pipeline/internal/service"
)

// PipelineHandler handles HTTP requests for pipeline operations.
type PipelineHandler struct {
	service *service.PipelineService
	logger  *slog.Logger
}

// NewPipelineHandler creates a new pipeline handler.
func NewPipelineHandler(svc *service.PipelineService, logger *slog.Logger) *PipelineHandler {
	return &PipelineHandler{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers all pipeline routes on the given mux.
func (h *PipelineHandler) RegisterRoutes(mux *http.ServeMux) {
	// Event routes
	mux.HandleFunc("GET /api/v1/pipeline/events", h.corsMiddleware(h.ListEvents))
	mux.HandleFunc("POST /api/v1/pipeline/events", h.corsMiddleware(h.ProcessEvent))
	mux.HandleFunc("GET /api/v1/pipeline/events/{id}", h.corsMiddleware(h.GetEvent))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/{id}", h.corsPreflightHandler)

	// Classification routes
	mux.HandleFunc("PUT /api/v1/pipeline/events/{id}/classification", h.corsMiddleware(h.UpdateClassification))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/{id}/classification", h.corsPreflightHandler)

	// Execution routes
	mux.HandleFunc("GET /api/v1/pipeline/events/{id}/execution", h.corsMiddleware(h.GetExecution))
	mux.HandleFunc("POST /api/v1/pipeline/events/{id}/approve", h.corsMiddleware(h.ApproveExecution))
	mux.HandleFunc("POST /api/v1/pipeline/events/{id}/reject", h.corsMiddleware(h.RejectExecution))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/{id}/execution", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/{id}/approve", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/events/{id}/reject", h.corsPreflightHandler)

	// Stats and status routes
	mux.HandleFunc("GET /api/v1/pipeline/stats", h.corsMiddleware(h.GetStatsWithTimeRange))
	mux.HandleFunc("GET /api/v1/pipeline/status", h.corsMiddleware(h.GetStatus))
	mux.HandleFunc("GET /api/v1/pipeline/stages", h.corsMiddleware(h.GetStageDetails))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/stats", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/status", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/stages", h.corsPreflightHandler)
}

// corsMiddleware wraps a handler with CORS headers.
func (h *PipelineHandler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
func (h *PipelineHandler) corsPreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// ProcessEventRequest represents the request body for processing an event.
type ProcessEventRequest struct {
	TenantID string `json:"tenant_id"`
	RawLog   string `json:"raw_log"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

// ProcessEvent handles POST /api/v1/pipeline/events
func (h *PipelineHandler) ProcessEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req ProcessEventRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Get tenant ID from header if not in body
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	event := &model.PipelineEvent{
		TenantID:  tenantID,
		RawLog:    req.RawLog,
		Source:    req.Source,
		Severity:  req.Severity,
		CreatedAt: time.Now(),
	}

	if err := h.service.ProcessEvent(r.Context(), event); err != nil {
		h.logger.Error("failed to process event", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to process event: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      event.ID,
		"stage":   event.Stage,
		"message": "event processing started",
	})
}

// GetEvent handles GET /api/v1/pipeline/events/{id}
func (h *PipelineHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	event, err := h.service.GetEvent(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "event not found: "+id)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(event)
}

// ListEvents handles GET /api/v1/pipeline/events
func (h *PipelineHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	filter := model.DefaultFilter()

	// Parse query parameters
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}
	if source := r.URL.Query().Get("source"); source != "" {
		filter.Source = source
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = severity
	}
	if stage := r.URL.Query().Get("stage"); stage != "" {
		filter.Stage = model.PipelineStage(stage)
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	events, total, err := h.service.ListEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list events", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to list events")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// UpdateClassificationRequest represents the request body for updating classification.
type UpdateClassificationRequest struct {
	Label           string   `json:"label"`
	Confidence      float32  `json:"confidence"`
	Method          string   `json:"method"`
	MatchedRules    []string `json:"matched_rules"`
	MatchedIOCs     []string `json:"matched_iocs"`
	MITRETactics    []string `json:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques"`
}

// UpdateClassification handles PUT /api/v1/pipeline/events/{id}/classification
func (h *PipelineHandler) UpdateClassification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req UpdateClassificationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	classification := &model.Classification{
		Label:           req.Label,
		Confidence:      req.Confidence,
		Method:          req.Method,
		MatchedRules:    req.MatchedRules,
		MatchedIOCs:     req.MatchedIOCs,
		MITRETactics:    req.MITRETactics,
		MITRETechniques: req.MITRETechniques,
	}

	if err := h.service.UpdateEventClassification(r.Context(), id, classification); err != nil {
		h.logger.Error("failed to update classification", "event_id", id, "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to update classification")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "classification updated",
	})
}

// GetExecution handles GET /api/v1/pipeline/events/{id}/execution
func (h *PipelineHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	event, err := h.service.GetEvent(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "event not found: "+id)
		return
	}

	if event.Execution == nil {
		h.writeError(w, http.StatusNotFound, "no execution for event: "+id)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(event.Execution)
}

// ApprovalRequest represents the request body for approval operations.
type ApprovalRequest struct {
	Approver string `json:"approver"`
	Reason   string `json:"reason,omitempty"`
}

// ApproveExecution handles POST /api/v1/pipeline/events/{id}/approve
func (h *PipelineHandler) ApproveExecution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req ApprovalRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Approver == "" {
		h.writeError(w, http.StatusBadRequest, "approver is required")
		return
	}

	if err := h.service.ApproveExecution(r.Context(), id, req.Approver); err != nil {
		h.logger.Error("failed to approve execution", "event_id", id, "error", err)
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "execution approved",
	})
}

// RejectExecution handles POST /api/v1/pipeline/events/{id}/reject
func (h *PipelineHandler) RejectExecution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "event ID required")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req ApprovalRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Approver == "" {
		h.writeError(w, http.StatusBadRequest, "approver is required")
		return
	}

	if err := h.service.RejectExecution(r.Context(), id, req.Approver, req.Reason); err != nil {
		h.logger.Error("failed to reject execution", "event_id", id, "error", err)
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "execution rejected",
	})
}

// GetStats handles GET /api/v1/pipeline/stats (legacy, no time range)
func (h *PipelineHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	stats, err := h.service.GetStats(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get stats", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// GetStatsWithTimeRange handles GET /api/v1/pipeline/stats with time range support.
// Query params: from, to (RFC3339), interval (1m, 5m, 1h, 1d)
func (h *PipelineHandler) GetStatsWithTimeRange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	// Parse time range parameters
	from, to := h.parseTimeRange(r)

	stats, err := h.service.GetStatsWithTimeRange(r.Context(), tenantID, from, to)
	if err != nil {
		h.logger.Error("failed to get stats with time range", "error", err, "from", from, "to", to)
		h.writeError(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// GetStatus handles GET /api/v1/pipeline/status
func (h *PipelineHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	status, err := h.service.GetStatus(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get pipeline status", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to get pipeline status")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// GetStageDetails handles GET /api/v1/pipeline/stages
func (h *PipelineHandler) GetStageDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	details, err := h.service.GetStageDetails(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get stage details", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to get stage details")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stages": details,
	})
}

// parseTimeRange parses from/to query parameters or applies defaults based on interval.
func (h *PipelineHandler) parseTimeRange(r *http.Request) (from, to time.Time) {
	now := time.Now()
	to = now

	// Parse 'to' parameter
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if parsed, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = parsed
		}
	}

	// Parse 'from' parameter
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if parsed, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = parsed
			return from, to
		}
	}

	// Default based on interval
	interval := r.URL.Query().Get("interval")
	switch interval {
	case "1m":
		from = to.Add(-1 * time.Minute)
	case "5m":
		from = to.Add(-5 * time.Minute)
	case "1h":
		from = to.Add(-1 * time.Hour)
	case "1d":
		from = to.Add(-24 * time.Hour)
	default:
		// Default to last hour
		from = to.Add(-1 * time.Hour)
	}

	return from, to
}

// writeError writes an error response.
func (h *PipelineHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
