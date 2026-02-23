// Package handler provides HTTP handlers for the TI service.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/siem-soar-platform/services/ti/internal/service"
)

// FeedHandler handles feed-related HTTP requests.
type FeedHandler struct {
	service *service.FeedService
	logger  *slog.Logger
}

// NewFeedHandler creates a new feed handler.
func NewFeedHandler(svc *service.FeedService, logger *slog.Logger) *FeedHandler {
	return &FeedHandler{
		service: svc,
		logger:  logger.With("component", "feed-handler"),
	}
}

// ListFeeds handles GET /api/v1/feeds
func (h *FeedHandler) ListFeeds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	feeds, err := h.service.ListFeeds(ctx)
	if err != nil {
		h.logger.Error("failed to list feeds", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Mask sensitive fields
	for _, f := range feeds {
		if f.APIKey != "" {
			f.APIKey = "***"
		}
		if f.Password != "" {
			f.Password = "***"
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"feeds": feeds,
		"total": len(feeds),
	})
}

// CreateFeed handles POST /api/v1/feeds
func (h *FeedHandler) CreateFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.CreateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	feed, err := h.service.CreateFeed(ctx, &req)
	if err != nil {
		h.logger.Error("failed to create feed", "error", err)
		if strings.Contains(err.Error(), "required") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Mask sensitive fields
	if feed.APIKey != "" {
		feed.APIKey = "***"
	}
	if feed.Password != "" {
		feed.Password = "***"
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "feed created",
		"feed":    feed,
	})
}

// GetFeed handles GET /api/v1/feeds/{id}
func (h *FeedHandler) GetFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	feed, err := h.service.GetFeed(ctx, id)
	if err != nil {
		h.logger.Error("failed to get feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Mask sensitive fields
	if feed.APIKey != "" {
		feed.APIKey = "***"
	}
	if feed.Password != "" {
		feed.Password = "***"
	}

	writeJSON(w, http.StatusOK, feed)
}

// UpdateFeed handles PUT /api/v1/feeds/{id}
func (h *FeedHandler) UpdateFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	var req service.UpdateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	feed, err := h.service.UpdateFeed(ctx, id, &req)
	if err != nil {
		h.logger.Error("failed to update feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Mask sensitive fields
	if feed.APIKey != "" {
		feed.APIKey = "***"
	}
	if feed.Password != "" {
		feed.Password = "***"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "feed updated",
		"feed":    feed,
	})
}

// DeleteFeed handles DELETE /api/v1/feeds/{id}
func (h *FeedHandler) DeleteFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	err := h.service.DeleteFeed(ctx, id)
	if err != nil {
		h.logger.Error("failed to delete feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "feed deleted",
	})
}

// SyncFeed handles POST /api/v1/feeds/{id}/sync
func (h *FeedHandler) SyncFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	result, err := h.service.SyncFeed(ctx, id)
	if err != nil {
		h.logger.Error("failed to sync feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"message": "feed sync started",
		"result":  result,
	})
}

// SyncAllFeeds handles POST /api/v1/feeds/sync
func (h *FeedHandler) SyncAllFeeds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	results, err := h.service.SyncAllFeeds(ctx)
	if err != nil {
		h.logger.Error("failed to sync all feeds", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"message": "all feeds sync started",
		"results": results,
	})
}

// TestFeed handles POST /api/v1/feeds/test
func (h *FeedHandler) TestFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req service.CreateFeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err := h.service.TestFeed(ctx, &req)
	if err != nil {
		h.logger.Error("feed test failed", "error", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "feed connection test successful",
	})
}

// GetFeedStats handles GET /api/v1/feeds/stats
func (h *FeedHandler) GetFeedStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = ctx // Not used but kept for consistency

	stats := h.service.FeedStats(ctx)
	writeJSON(w, http.StatusOK, stats)
}

// EnableFeed handles POST /api/v1/feeds/{id}/enable
func (h *FeedHandler) EnableFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	enabled := true
	_, err := h.service.UpdateFeed(ctx, id, &service.UpdateFeedRequest{
		Enabled: &enabled,
	})
	if err != nil {
		h.logger.Error("failed to enable feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "feed enabled",
	})
}

// DisableFeed handles POST /api/v1/feeds/{id}/disable
func (h *FeedHandler) DisableFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	enabled := false
	_, err := h.service.UpdateFeed(ctx, id, &service.UpdateFeedRequest{
		Enabled: &enabled,
	})
	if err != nil {
		h.logger.Error("failed to disable feed", "id", id, "error", err)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "feed disabled",
	})
}
