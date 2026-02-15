// Package handler provides HTTP handlers for case management.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/siem-soar-platform/services/case/internal/model"
	"github.com/siem-soar-platform/services/case/internal/service"
)

// CaseHandler handles HTTP requests for case management.
type CaseHandler struct {
	service *service.CaseService
}

// NewCaseHandler creates a new case handler.
func NewCaseHandler(service *service.CaseService) *CaseHandler {
	return &CaseHandler{service: service}
}

// RegisterRoutes registers case management routes.
func (h *CaseHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/cases", h.CreateCase).Methods("POST")
	r.HandleFunc("/cases", h.ListCases).Methods("GET")
	r.HandleFunc("/cases/{id}", h.GetCase).Methods("GET")
	r.HandleFunc("/cases/{id}", h.UpdateCase).Methods("PUT", "PATCH")
	r.HandleFunc("/cases/{id}", h.DeleteCase).Methods("DELETE")
	r.HandleFunc("/cases/{id}/assign", h.AssignCase).Methods("POST")
	r.HandleFunc("/cases/{id}/escalate", h.EscalateCase).Methods("POST")
	r.HandleFunc("/cases/{id}/history", h.GetHistory).Methods("GET")
	r.HandleFunc("/cases/{id}/timeline", h.GetTimeline).Methods("GET")
	r.HandleFunc("/cases/summary", h.GetSummary).Methods("GET")
}

// CreateCase creates a new case.
func (h *CaseHandler) CreateCase(w http.ResponseWriter, r *http.Request) {
	var req model.CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get user from context (in production, from auth middleware)
	createdBy := r.Header.Get("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	caseObj, err := h.service.CreateCase(r.Context(), &req, createdBy)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, caseObj)
}

// GetCase retrieves a case by ID.
func (h *CaseHandler) GetCase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	caseObj, err := h.service.GetCase(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, caseObj)
}

// UpdateCase updates an existing case.
func (h *CaseHandler) UpdateCase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req model.UpdateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updatedBy := r.Header.Get("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	caseObj, err := h.service.UpdateCase(r.Context(), id, &req, updatedBy)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, caseObj)
}

// DeleteCase deletes a case.
func (h *CaseHandler) DeleteCase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	err := h.service.DeleteCase(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListCases retrieves cases based on filter criteria.
func (h *CaseHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	filter := &model.CaseFilter{}

	// Parse query parameters
	query := r.URL.Query()

	// Status filter
	if statuses := query["status"]; len(statuses) > 0 {
		filter.Status = make([]model.CaseStatus, len(statuses))
		for i, s := range statuses {
			filter.Status[i] = model.CaseStatus(s)
		}
	}

	// Severity filter
	if severities := query["severity"]; len(severities) > 0 {
		filter.Severity = make([]model.CaseSeverity, len(severities))
		for i, s := range severities {
			filter.Severity[i] = model.CaseSeverity(s)
		}
	}

	// Priority filter
	if priorities := query["priority"]; len(priorities) > 0 {
		filter.Priority = make([]model.CasePriority, len(priorities))
		for i, p := range priorities {
			filter.Priority[i] = model.CasePriority(p)
		}
	}

	// Type filter
	if types := query["type"]; len(types) > 0 {
		filter.Type = make([]model.CaseType, len(types))
		for i, t := range types {
			filter.Type[i] = model.CaseType(t)
		}
	}

	// String filters
	filter.Assignee = query.Get("assignee")
	filter.Team = query.Get("team")
	filter.Search = query.Get("search")
	filter.TenantID = query.Get("tenant_id")

	// Pagination
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	// Sorting
	filter.SortBy = query.Get("sort_by")
	filter.SortOrder = query.Get("sort_order")

	// SLA filter
	if slaBreachedStr := query.Get("sla_breached"); slaBreachedStr != "" {
		if slaBreached, err := strconv.ParseBool(slaBreachedStr); err == nil {
			filter.SLABreached = &slaBreached
		}
	}

	result, err := h.service.ListCases(r.Context(), filter)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// GetSummary retrieves case statistics.
func (h *CaseHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")

	summary, err := h.service.GetSummary(r.Context(), tenantID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, summary)
}

// AssignCase assigns a case to a user.
func (h *CaseHandler) AssignCase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	assignedBy := r.Header.Get("X-User-ID")
	if assignedBy == "" {
		assignedBy = "system"
	}

	err := h.service.AssignCase(r.Context(), id, req.Assignee, assignedBy)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"message": "case assigned successfully",
	})
}

// EscalateCase escalates a case severity.
func (h *CaseHandler) EscalateCase(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	escalatedBy := r.Header.Get("X-User-ID")
	if escalatedBy == "" {
		escalatedBy = "system"
	}

	err := h.service.EscalateCase(r.Context(), id, req.Reason, escalatedBy)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"message": "case escalated successfully",
	})
}

// GetHistory retrieves case history.
func (h *CaseHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	history, err := h.service.GetHistory(r.Context(), id, limit)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, history)
}

// GetTimeline builds and returns a case timeline.
func (h *CaseHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	timeline, err := h.service.BuildTimeline(r.Context(), id)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, timeline)
}

// Helper methods

func (h *CaseHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *CaseHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"error": message,
	})
}
