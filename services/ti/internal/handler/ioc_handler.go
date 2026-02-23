// Package handler provides HTTP handlers for the TI service.
package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
	"github.com/siem-soar-platform/services/ti/internal/service"
)

// IOCHandler handles IOC-related HTTP requests.
type IOCHandler struct {
	service *service.IOCService
	logger  *slog.Logger
}

// NewIOCHandler creates a new IOC handler.
func NewIOCHandler(svc *service.IOCService, logger *slog.Logger) *IOCHandler {
	return &IOCHandler{
		service: svc,
		logger:  logger.With("component", "ioc-handler"),
	}
}

// APIError represents an API error response.
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, err string) {
	writeJSON(w, status, APIError{Error: err})
}

// ListIOCs handles GET /api/v1/iocs
func (h *IOCHandler) ListIOCs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	req := &service.ListRequest{
		Search: r.URL.Query().Get("search"),
	}

	// Parse types
	if types := r.URL.Query().Get("types"); types != "" {
		req.Types = strings.Split(types, ",")
	}

	// Parse threat_types
	if threatTypes := r.URL.Query().Get("threat_types"); threatTypes != "" {
		req.ThreatTypes = strings.Split(threatTypes, ",")
	}

	// Parse severities
	if severities := r.URL.Query().Get("severities"); severities != "" {
		req.Severities = strings.Split(severities, ",")
	}

	// Parse sources
	if sources := r.URL.Query().Get("sources"); sources != "" {
		req.Sources = strings.Split(sources, ",")
	}

	// Parse tags
	if tags := r.URL.Query().Get("tags"); tags != "" {
		req.Tags = strings.Split(tags, ",")
	}

	// Parse min_confidence
	if minConfStr := r.URL.Query().Get("min_confidence"); minConfStr != "" {
		if minConf, err := strconv.Atoi(minConfStr); err == nil {
			req.MinConfidence = minConf
		}
	}

	// Parse is_active
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		active := activeStr == "true"
		req.IsActive = &active
	}

	// Parse pagination
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			req.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			req.Offset = offset
		}
	}

	// List IOCs
	resp, err := h.service.List(ctx, req)
	if err != nil {
		h.logger.Error("failed to list IOCs", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// CreateIOC handles POST /api/v1/iocs
func (h *IOCHandler) CreateIOC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.CreateIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ioc, err := h.service.Create(ctx, &req)
	if err != nil {
		h.logger.Error("failed to create IOC", "error", err)
		if strings.Contains(err.Error(), "required") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "IOC created",
		"ioc":     ioc,
	})
}

// GetIOC handles GET /api/v1/iocs/{id}
func (h *IOCHandler) GetIOC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	ioc, err := h.service.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get IOC", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if ioc == nil {
		writeError(w, http.StatusNotFound, "IOC not found")
		return
	}

	writeJSON(w, http.StatusOK, ioc)
}

// UpdateIOC handles PUT /api/v1/iocs/{id}
func (h *IOCHandler) UpdateIOC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req service.UpdateIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ioc, err := h.service.Update(ctx, id, &req)
	if err != nil {
		h.logger.Error("failed to update IOC", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "IOC updated",
		"ioc":     ioc,
	})
}

// DeleteIOC handles DELETE /api/v1/iocs/{id}
func (h *IOCHandler) DeleteIOC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	err := h.service.Delete(ctx, id)
	if err != nil {
		h.logger.Error("failed to delete IOC", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "IOC deleted",
	})
}

// LookupIOC handles GET /api/v1/iocs/lookup
func (h *IOCHandler) LookupIOC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	value := r.URL.Query().Get("value")
	if value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	req := &service.LookupRequest{
		Type:  r.URL.Query().Get("type"),
		Value: value,
	}

	resp, err := h.service.Lookup(ctx, req)
	if err != nil {
		h.logger.Error("failed to lookup IOC", "value", value, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// BatchLookup handles POST /api/v1/iocs/batch-lookup
func (h *IOCHandler) BatchLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.BatchLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Indicators) == 0 {
		writeError(w, http.StatusBadRequest, "at least one indicator is required")
		return
	}

	resp, err := h.service.BatchLookup(ctx, &req)
	if err != nil {
		h.logger.Error("failed to batch lookup IOCs", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetStats handles GET /api/v1/iocs/stats
func (h *IOCHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := r.URL.Query().Get("tenant_id")

	stats, err := h.service.GetStats(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get IOC stats", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// CreateIOCBatchRequest represents a batch create request.
type CreateIOCBatchRequest struct {
	IOCs []service.CreateIOCRequest `json:"iocs"`
}

// CreateIOCBatch handles POST /api/v1/iocs/batch
func (h *IOCHandler) CreateIOCBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateIOCBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.IOCs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one IOC is required")
		return
	}

	if len(req.IOCs) > 1000 {
		writeError(w, http.StatusBadRequest, "maximum 1000 IOCs per batch")
		return
	}

	created := 0
	failed := 0
	var errors []string

	for _, iocReq := range req.IOCs {
		_, err := h.service.Create(ctx, &iocReq)
		if err != nil {
			failed++
			errors = append(errors, iocReq.Value+": "+err.Error())
		} else {
			created++
		}
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "batch create completed",
		"created": created,
		"failed":  failed,
		"errors":  errors,
	})
}

// ExportIOCs handles GET /api/v1/iocs/export
func (h *IOCHandler) ExportIOCs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Parse filters
	req := &service.ListRequest{
		Search: r.URL.Query().Get("search"),
		Limit:  10000, // Max export size
	}

	if types := r.URL.Query().Get("types"); types != "" {
		req.Types = strings.Split(types, ",")
	}

	resp, err := h.service.List(ctx, req)
	if err != nil {
		h.logger.Error("failed to export IOCs", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=iocs.json")
		json.NewEncoder(w).Encode(resp.IOCs)

	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=iocs.csv")
		w.Write([]byte("type,value,threat_type,severity,confidence,source,first_seen,last_seen\n"))
		for _, ioc := range resp.IOCs {
			line := strings.Join([]string{
				string(ioc.Type),
				ioc.Value,
				string(ioc.ThreatType),
				string(ioc.Severity),
				strconv.Itoa(ioc.Confidence),
				ioc.Source,
				ioc.FirstSeen.Format(time.RFC3339),
				ioc.LastSeen.Format(time.RFC3339),
			}, ",") + "\n"
			w.Write([]byte(line))
		}

	case "stix":
		// STIX 2.1 format - simplified
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=iocs.stix.json")
		stixBundle := map[string]interface{}{
			"type":        "bundle",
			"id":          "bundle--" + time.Now().Format("20060102150405"),
			"spec_version": "2.1",
			"objects":     convertToSTIX(resp.IOCs),
		}
		json.NewEncoder(w).Encode(stixBundle)

	default:
		writeError(w, http.StatusBadRequest, "unsupported format")
	}
}

// convertToSTIX converts IOCs to STIX 2.1 format.
func convertToSTIX(iocs []*ioc.IOC) []map[string]interface{} {
	objects := make([]map[string]interface{}, 0, len(iocs))
	for _, i := range iocs {
		obj := map[string]interface{}{
			"type":       "indicator",
			"id":         "indicator--" + i.ID,
			"created":    i.CreatedAt.Format(time.RFC3339),
			"modified":   i.UpdatedAt.Format(time.RFC3339),
			"name":       i.Name,
			"pattern":    buildSTIXPattern(i),
			"valid_from": i.ValidFrom.Format(time.RFC3339),
		}
		if !i.ValidUntil.IsZero() {
			obj["valid_until"] = i.ValidUntil.Format(time.RFC3339)
		}
		if i.Description != "" {
			obj["description"] = i.Description
		}
		if len(i.Labels) > 0 {
			obj["labels"] = i.Labels
		}
		objects = append(objects, obj)
	}
	return objects
}

// buildSTIXPattern builds a STIX pattern from an IOC.
func buildSTIXPattern(i *ioc.IOC) string {
	switch i.Type {
	case ioc.TypeIP:
		return fmt.Sprintf("[ipv4-addr:value = '%s']", i.Value)
	case ioc.TypeDomain:
		return fmt.Sprintf("[domain-name:value = '%s']", i.Value)
	case ioc.TypeURL:
		return fmt.Sprintf("[url:value = '%s']", i.Value)
	case ioc.TypeMD5:
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", i.Value)
	case ioc.TypeSHA1:
		return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", i.Value)
	case ioc.TypeSHA256:
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", i.Value)
	case ioc.TypeEmail:
		return fmt.Sprintf("[email-addr:value = '%s']", i.Value)
	default:
		return fmt.Sprintf("[x-custom:value = '%s']", i.Value)
	}
}
