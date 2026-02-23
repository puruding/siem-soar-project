// Package handler provides HTTP handlers for the pipeline service.
package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
	"github.com/siem-soar-platform/services/pipeline/internal/pubsub"
	"github.com/siem-soar-platform/services/pipeline/internal/service"
)

// ApprovalHandler handles HTTP requests for approval operations.
type ApprovalHandler struct {
	service *service.PipelineService
	pubsub  *pubsub.PubSub
	logger  *slog.Logger
}

// NewApprovalHandler creates a new approval handler.
func NewApprovalHandler(svc *service.PipelineService, ps *pubsub.PubSub, logger *slog.Logger) *ApprovalHandler {
	return &ApprovalHandler{
		service: svc,
		pubsub:  ps,
		logger:  logger,
	}
}

// RegisterRoutes registers all approval routes on the given mux.
func (h *ApprovalHandler) RegisterRoutes(mux *http.ServeMux) {
	// Approval routes
	mux.HandleFunc("GET /api/v1/pipeline/approvals", h.corsMiddleware(h.ListApprovals))
	mux.HandleFunc("GET /api/v1/pipeline/approvals/{id}", h.corsMiddleware(h.GetApproval))
	mux.HandleFunc("POST /api/v1/pipeline/approvals/{id}/approve", h.corsMiddleware(h.ApproveRequest))
	mux.HandleFunc("POST /api/v1/pipeline/approvals/{id}/reject", h.corsMiddleware(h.RejectRequest))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/approvals", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/approvals/{id}", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/approvals/{id}/approve", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/approvals/{id}/reject", h.corsPreflightHandler)
}

// ApprovalPagination represents pagination information for approval responses.
type ApprovalPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// ApprovalListResponse represents the response for approval list.
type ApprovalListResponse struct {
	Approvals  []ApprovalSummary  `json:"approvals"`
	Pagination ApprovalPagination `json:"pagination"`
}

// ApprovalSummary represents a summary of an approval request.
type ApprovalSummary struct {
	ID           string    `json:"id"`
	ExecutionID  string    `json:"execution_id"`
	PlaybookName string    `json:"playbook_name"`
	StepName     string    `json:"step_name"`
	RequiredRole string    `json:"required_role"`
	Status       string    `json:"status"`
	RequestedAt  time.Time `json:"requested_at"`
	EventSummary string    `json:"event_summary"`
}

// ApprovalDetailResponse represents the detailed response for an approval.
type ApprovalDetailResponse struct {
	ID            string             `json:"id"`
	ExecutionID   string             `json:"execution_id"`
	EventID       string             `json:"event_id"`
	PlaybookID    string             `json:"playbook_id"`
	PlaybookName  string             `json:"playbook_name"`
	StepName      string             `json:"step_name"`
	StepIndex     int                `json:"step_index"`
	TotalSteps    int                `json:"total_steps"`
	RequiredRole  string             `json:"required_role"`
	Status        string             `json:"status"`
	RequestedAt   time.Time          `json:"requested_at"`
	ResolvedAt    *time.Time         `json:"resolved_at,omitempty"`
	Approver      string             `json:"approver,omitempty"`
	EventSummary  model.EventSummary `json:"event_summary"`
	Classification *model.Classification `json:"classification,omitempty"`
}

// ApproveRequest represents the request body for approval.
type ApproveRequest struct {
	Comment string `json:"comment,omitempty"`
}

// ApproveResponse represents the response for approval.
type ApproveResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	ExecutionID string `json:"execution_id"`
	NextStep    string `json:"next_step,omitempty"`
}

// RejectRequest represents the request body for rejection.
type RejectRequest struct {
	Reason string `json:"reason"`
}

// RejectResponse represents the response for rejection.
type RejectResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	ExecutionID string `json:"execution_id"`
}

// ApprovalStatusUpdate represents an approval status change for pub/sub.
type ApprovalStatusUpdate struct {
	ApprovalID  string    `json:"approval_id"`
	ExecutionID string    `json:"execution_id"`
	EventID     string    `json:"event_id"`
	Status      string    `json:"status"`
	Approver    string    `json:"approver,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// corsMiddleware wraps a handler with CORS headers.
func (h *ApprovalHandler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
func (h *ApprovalHandler) corsPreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// ListApprovals handles GET /api/v1/pipeline/approvals
func (h *ApprovalHandler) ListApprovals(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	page := 1
	pageSize := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	statusFilter := r.URL.Query().Get("status")
	if statusFilter == "" {
		statusFilter = model.ApprovalPending // Default to pending approvals
	}

	filter := model.PipelineEventFilter{
		Limit:  pageSize * 10, // Fetch more to filter
		Offset: 0,
	}

	// Apply tenant filter
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" && filter.TenantID == "" {
		filter.TenantID = tenantID
	}

	// Filter by execution stage
	filter.Stage = model.StageFlowExecution

	events, total, err := h.service.ListEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list events", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to list approvals")
		return
	}

	// Build approval summaries from events with pending approvals
	summaries := make([]ApprovalSummary, 0)
	for _, event := range events {
		if event.Execution == nil || event.Execution.ApprovalInfo == nil {
			continue
		}

		approval := event.Execution.ApprovalInfo

		// Filter by status
		if statusFilter != "" && statusFilter != "all" && approval.Status != statusFilter {
			continue
		}

		playbookName := "Unknown Playbook"
		if event.PlaybookMatch != nil {
			playbookName = event.PlaybookMatch.PlaybookName
		}

		eventSummary := event.Source
		if event.Classification != nil {
			eventSummary = event.Classification.Label + " - " + event.Source
		}

		summary := ApprovalSummary{
			ID:           approval.ApprovalID,
			ExecutionID:  event.Execution.ExecutionID,
			PlaybookName: playbookName,
			StepName:     approval.StepName,
			RequiredRole: approval.RequiredRole,
			Status:       approval.Status,
			RequestedAt:  approval.RequestedAt,
			EventSummary: eventSummary,
		}
		summaries = append(summaries, summary)
	}

	// Apply pagination to filtered results
	totalFiltered := len(summaries)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > totalFiltered {
		start = totalFiltered
	}
	if end > totalFiltered {
		end = totalFiltered
	}
	paginatedSummaries := summaries[start:end]

	totalPages := (totalFiltered + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	response := ApprovalListResponse{
		Approvals: paginatedSummaries,
		Pagination: ApprovalPagination{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetApproval handles GET /api/v1/pipeline/approvals/:id
func (h *ApprovalHandler) GetApproval(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "approval ID required")
		return
	}

	// Find the event with this approval ID
	event, err := h.findEventByApprovalID(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "approval not found: "+id)
		return
	}

	if event.Execution == nil || event.Execution.ApprovalInfo == nil {
		h.writeError(w, http.StatusNotFound, "no approval info for event")
		return
	}

	approval := event.Execution.ApprovalInfo

	playbookID := ""
	playbookName := "Unknown Playbook"
	if event.PlaybookMatch != nil {
		playbookID = event.PlaybookMatch.PlaybookID
		playbookName = event.PlaybookMatch.PlaybookName
	}

	eventLabel := ""
	if event.Classification != nil {
		eventLabel = event.Classification.Label
	}

	response := ApprovalDetailResponse{
		ID:           approval.ApprovalID,
		ExecutionID:  event.Execution.ExecutionID,
		EventID:      event.ID,
		PlaybookID:   playbookID,
		PlaybookName: playbookName,
		StepName:     approval.StepName,
		StepIndex:    event.Execution.CurrentStep,
		TotalSteps:   event.Execution.TotalSteps,
		RequiredRole: approval.RequiredRole,
		Status:       approval.Status,
		RequestedAt:  approval.RequestedAt,
		EventSummary: model.EventSummary{
			ID:        event.ID,
			Source:    event.Source,
			Severity:  event.Severity,
			Label:     eventLabel,
			Timestamp: event.CreatedAt,
		},
		Classification: event.Classification,
	}

	if !approval.ResolvedAt.IsZero() {
		response.ResolvedAt = &approval.ResolvedAt
		response.Approver = approval.Approver
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ApproveRequest handles POST /api/v1/pipeline/approvals/:id/approve
func (h *ApprovalHandler) ApproveRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "approval ID required")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req ApproveRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}

	// Get approver from request or header
	approver := r.Header.Get("X-User-ID")
	if approver == "" {
		approver = "system"
	}

	// Find the event with this approval ID
	event, err := h.findEventByApprovalID(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "approval not found: "+id)
		return
	}

	// Approve the execution
	if err := h.service.ApproveExecution(r.Context(), event.ID, approver); err != nil {
		h.logger.Error("failed to approve execution", "approval_id", id, "error", err)
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Publish approval status update
	h.publishApprovalUpdate(r.Context(), ApprovalStatusUpdate{
		ApprovalID:  id,
		ExecutionID: event.Execution.ExecutionID,
		EventID:     event.ID,
		Status:      model.ApprovalApproved,
		Approver:    approver,
		Timestamp:   time.Now(),
	})

	// Determine next step
	nextStep := ""
	if event.Execution != nil && event.Execution.CurrentStep < event.Execution.TotalSteps {
		nextStep = "Step " + strconv.Itoa(event.Execution.CurrentStep+1) + " of " + strconv.Itoa(event.Execution.TotalSteps)
	}

	response := ApproveResponse{
		Success:     true,
		Message:     "Approval granted successfully",
		ExecutionID: event.Execution.ExecutionID,
		NextStep:    nextStep,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RejectRequest handles POST /api/v1/pipeline/approvals/:id/reject
func (h *ApprovalHandler) RejectRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "approval ID required")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req RejectRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Reason == "" {
		h.writeError(w, http.StatusBadRequest, "reason is required for rejection")
		return
	}

	// Get approver from request or header
	approver := r.Header.Get("X-User-ID")
	if approver == "" {
		approver = "system"
	}

	// Find the event with this approval ID
	event, err := h.findEventByApprovalID(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "approval not found: "+id)
		return
	}

	// Reject the execution
	if err := h.service.RejectExecution(r.Context(), event.ID, approver, req.Reason); err != nil {
		h.logger.Error("failed to reject execution", "approval_id", id, "error", err)
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Publish approval status update
	h.publishApprovalUpdate(r.Context(), ApprovalStatusUpdate{
		ApprovalID:  id,
		ExecutionID: event.Execution.ExecutionID,
		EventID:     event.ID,
		Status:      model.ApprovalRejected,
		Approver:    approver,
		Reason:      req.Reason,
		Timestamp:   time.Now(),
	})

	response := RejectResponse{
		Success:     true,
		Message:     "Approval rejected",
		ExecutionID: event.Execution.ExecutionID,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// findEventByApprovalID finds an event by its approval ID.
func (h *ApprovalHandler) findEventByApprovalID(ctx context.Context, approvalID string) (*model.PipelineEvent, error) {
	// In a production system, we would have a separate index/table for approvals
	// For now, we search through events
	filter := model.PipelineEventFilter{
		Stage: model.StageFlowExecution,
		Limit: 1000,
	}

	events, _, err := h.service.ListEvents(ctx, filter)
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		if event.Execution != nil && event.Execution.ApprovalInfo != nil {
			if event.Execution.ApprovalInfo.ApprovalID == approvalID {
				return event, nil
			}
		}
	}

	return nil, ErrApprovalNotFound
}

// publishApprovalUpdate publishes an approval status update via Redis pub/sub.
func (h *ApprovalHandler) publishApprovalUpdate(ctx context.Context, update ApprovalStatusUpdate) {
	if h.pubsub == nil {
		h.logger.Warn("pubsub not available, skipping approval update broadcast")
		return
	}

	if err := h.pubsub.Publish(ctx, pubsub.ChannelApprovals, update); err != nil {
		h.logger.Error("failed to publish approval update",
			"approval_id", update.ApprovalID,
			"error", err,
		)
	} else {
		h.logger.Debug("approval update published",
			"approval_id", update.ApprovalID,
			"status", update.Status,
		)
	}
}

// writeError writes an error response.
func (h *ApprovalHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// ErrApprovalNotFound is returned when an approval is not found.
var ErrApprovalNotFound = &ApprovalError{Message: "approval not found"}

// ApprovalError represents an approval-related error.
type ApprovalError struct {
	Message string
}

func (e *ApprovalError) Error() string {
	return e.Message
}
