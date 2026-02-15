// Package handler provides HTTP handlers for asset management.
package handler

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/siem-soar-platform/services/asset-registry/internal/model"
	"github.com/siem-soar-platform/services/asset-registry/internal/service"
)

// AssetHandler handles HTTP requests for asset management.
type AssetHandler struct {
	service *service.AssetService
	logger  *slog.Logger
}

// NewAssetHandler creates a new asset handler.
func NewAssetHandler(svc *service.AssetService, logger *slog.Logger) *AssetHandler {
	return &AssetHandler{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers asset routes on a Gin router group.
func (h *AssetHandler) RegisterRoutes(rg *gin.RouterGroup) {
	// Asset CRUD
	rg.POST("/assets", h.CreateAsset)
	rg.GET("/assets", h.ListAssets)
	rg.GET("/assets/:id", h.GetAsset)
	rg.PUT("/assets/:id", h.UpdateAsset)
	rg.DELETE("/assets/:id", h.DeleteAsset)

	// Asset identification and search
	rg.POST("/assets/identify", h.IdentifyAsset)
	rg.GET("/assets/search", h.SearchAssets)

	// Asset Groups
	rg.POST("/asset-groups", h.CreateAssetGroup)
	rg.GET("/asset-groups", h.ListAssetGroups)
	rg.GET("/asset-groups/:id", h.GetAssetGroup)
	rg.PUT("/asset-groups/:id", h.UpdateAssetGroup)
	rg.DELETE("/asset-groups/:id", h.DeleteAssetGroup)
	rg.POST("/asset-groups/:id/members", h.AddGroupMembers)
	rg.DELETE("/asset-groups/:id/members", h.RemoveGroupMembers)
	rg.GET("/asset-groups/:id/members", h.GetGroupMembers)

	// Identifiers
	rg.POST("/assets/:id/identifiers", h.AddIdentifier)

	// Lookup
	rg.GET("/assets/lookup", h.LookupAsset)

	// Unknown IP Registration
	rg.POST("/assets/unknown", h.RegisterUnknownIP)

	// History
	rg.GET("/assets/:id/history", h.GetAssetHistory)
}

// CreateAsset handles asset creation.
// POST /api/v1/assets
func (h *AssetHandler) CreateAsset(c *gin.Context) {
	var req model.CreateAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	asset, err := h.service.CreateAsset(c.Request.Context(), &req, createdBy)
	if err != nil {
		h.logger.Error("failed to create asset", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, asset)
}

// GetAsset handles asset retrieval.
// GET /api/v1/assets/:id
func (h *AssetHandler) GetAsset(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset id is required"})
		return
	}

	asset, err := h.service.GetAsset(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		h.logger.Error("failed to get asset", "error", err, "asset_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// UpdateAsset handles asset update.
// PUT /api/v1/assets/:id
func (h *AssetHandler) UpdateAsset(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset id is required"})
		return
	}

	var req model.UpdateAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	asset, err := h.service.UpdateAsset(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		h.logger.Error("failed to update asset", "error", err, "asset_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// DeleteAsset handles asset deletion.
// DELETE /api/v1/assets/:id
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset id is required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeleteAsset(c.Request.Context(), id, deletedBy)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		h.logger.Error("failed to delete asset", "error", err, "asset_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// ListAssets handles asset listing with filters.
// GET /api/v1/assets
func (h *AssetHandler) ListAssets(c *gin.Context) {
	filter := &model.AssetFilter{}

	// Parse query parameters
	if types := c.QueryArray("type"); len(types) > 0 {
		filter.Types = make([]model.AssetType, len(types))
		for i, t := range types {
			filter.Types[i] = model.AssetType(t)
		}
	}

	if statuses := c.QueryArray("status"); len(statuses) > 0 {
		filter.Statuses = make([]model.AssetStatus, len(statuses))
		for i, s := range statuses {
			filter.Statuses[i] = model.AssetStatus(s)
		}
	}

	if criticalities := c.QueryArray("criticality"); len(criticalities) > 0 {
		filter.Criticalities = make([]model.Criticality, len(criticalities))
		for i, cr := range criticalities {
			filter.Criticalities[i] = model.Criticality(cr)
		}
	}

	filter.IPAddress = c.Query("ip_address")
	filter.Hostname = c.Query("hostname")
	filter.OS = c.Query("os")
	filter.Location = c.Query("location")
	filter.Environment = c.Query("environment")
	filter.Owner = c.Query("owner")
	filter.Team = c.Query("team")
	filter.GroupID = c.Query("group_id")
	filter.Search = c.Query("search")
	filter.TenantID = c.Query("tenant_id")

	if tags := c.QueryArray("tag"); len(tags) > 0 {
		filter.Tags = tags
	}

	// Pagination
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	// Sorting
	filter.SortBy = c.DefaultQuery("sort_by", "created_at")
	filter.SortOrder = c.DefaultQuery("sort_order", "desc")

	result, err := h.service.ListAssets(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list assets", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// CreateAssetGroup handles asset group creation.
// POST /api/v1/asset-groups
func (h *AssetHandler) CreateAssetGroup(c *gin.Context) {
	var req model.CreateAssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	group, err := h.service.CreateAssetGroup(c.Request.Context(), &req, createdBy)
	if err != nil {
		h.logger.Error("failed to create asset group", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// ListAssetGroups handles asset group listing.
// GET /api/v1/asset-groups
func (h *AssetHandler) ListAssetGroups(c *gin.Context) {
	tenantID := c.Query("tenant_id")

	limit := 20
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	groups, total, err := h.service.ListAssetGroups(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.Error("failed to list asset groups", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"groups":   groups,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// AddIdentifier handles adding an identifier to an asset.
// POST /api/v1/assets/:id/identifiers
func (h *AssetHandler) AddIdentifier(c *gin.Context) {
	assetID := c.Param("id")
	if assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset id is required"})
		return
	}

	var req model.AddIdentifierRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	addedBy := c.GetHeader("X-User-ID")
	if addedBy == "" {
		addedBy = "system"
	}

	identifier, err := h.service.AddIdentifier(c.Request.Context(), assetID, &req, addedBy)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		h.logger.Error("failed to add identifier", "error", err, "asset_id", assetID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, identifier)
}

// LookupAsset handles asset lookup by identifier.
// GET /api/v1/assets/lookup?type=ip&value=192.168.1.1
func (h *AssetHandler) LookupAsset(c *gin.Context) {
	identType := c.Query("type")
	value := c.Query("value")

	if identType == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type and value query parameters are required"})
		return
	}

	asset, err := h.service.LookupAsset(c.Request.Context(), identType, value)
	if err != nil {
		h.logger.Error("failed to lookup asset", "error", err, "type", identType, "value", value)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if asset == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no asset found for identifier"})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// RegisterUnknownIP handles registration of unknown IPs.
// POST /api/v1/assets/unknown
func (h *AssetHandler) RegisterUnknownIP(c *gin.Context) {
	var req model.UnknownIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	asset, err := h.service.RegisterUnknownIP(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("failed to register unknown IP", "error", err, "ip", req.IPAddress)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, asset)
}

// GetAssetHistory handles asset history retrieval.
// GET /api/v1/assets/:id/history
func (h *AssetHandler) GetAssetHistory(c *gin.Context) {
	assetID := c.Param("id")
	if assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset id is required"})
		return
	}

	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	history, err := h.service.GetAssetHistory(c.Request.Context(), assetID, limit)
	if err != nil {
		if err.Error() == "asset not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		h.logger.Error("failed to get asset history", "error", err, "asset_id", assetID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
		"total":   len(history),
	})
}

// IdentifyAsset handles asset identification.
// POST /api/v1/assets/identify
func (h *AssetHandler) IdentifyAsset(c *gin.Context) {
	var req model.IdentifyAssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	// Validate at least one identifier provided
	if req.IP == "" && req.Hostname == "" && req.MAC == "" && req.FQDN == "" && req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one identifier is required"})
		return
	}

	response, err := h.service.IdentifyAsset(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("failed to identify asset", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// SearchAssets handles asset search.
// GET /api/v1/assets/search
func (h *AssetHandler) SearchAssets(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search query 'q' is required"})
		return
	}

	req := &model.AssetSearchRequest{
		Query:    query,
		Types:    c.QueryArray("type"),
		Statuses: c.QueryArray("status"),
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			req.Limit = l
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			req.Offset = o
		}
	}

	result, err := h.service.SearchAssets(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("failed to search assets", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetAssetGroup handles asset group retrieval.
// GET /api/v1/asset-groups/:id
func (h *AssetHandler) GetAssetGroup(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	group, err := h.service.GetAssetGroup(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to get asset group", "error", err, "group_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// UpdateAssetGroup handles asset group update.
// PUT /api/v1/asset-groups/:id
func (h *AssetHandler) UpdateAssetGroup(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	var req model.UpdateAssetGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	group, err := h.service.UpdateAssetGroup(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to update asset group", "error", err, "group_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// DeleteAssetGroup handles asset group deletion.
// DELETE /api/v1/asset-groups/:id
func (h *AssetHandler) DeleteAssetGroup(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeleteAssetGroup(c.Request.Context(), id, deletedBy)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to delete asset group", "error", err, "group_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// AddGroupMembers handles adding members to a group.
// POST /api/v1/asset-groups/:id/members
func (h *AssetHandler) AddGroupMembers(c *gin.Context) {
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	var req model.AddGroupMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if len(req.AssetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one asset_id is required"})
		return
	}

	addedBy := c.GetHeader("X-User-ID")
	if addedBy == "" {
		addedBy = "system"
	}

	err := h.service.AddGroupMembers(c.Request.Context(), groupID, req.AssetIDs, addedBy)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to add group members", "error", err, "group_id", groupID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "members added",
		"count":   len(req.AssetIDs),
	})
}

// RemoveGroupMembers handles removing members from a group.
// DELETE /api/v1/asset-groups/:id/members
func (h *AssetHandler) RemoveGroupMembers(c *gin.Context) {
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	var req model.RemoveGroupMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if len(req.AssetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one asset_id is required"})
		return
	}

	removedBy := c.GetHeader("X-User-ID")
	if removedBy == "" {
		removedBy = "system"
	}

	err := h.service.RemoveGroupMembers(c.Request.Context(), groupID, req.AssetIDs, removedBy)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to remove group members", "error", err, "group_id", groupID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "members removed",
		"count":   len(req.AssetIDs),
	})
}

// GetGroupMembers handles retrieving group members.
// GET /api/v1/asset-groups/:id/members
func (h *AssetHandler) GetGroupMembers(c *gin.Context) {
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group id is required"})
		return
	}

	limit := 20
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	response, err := h.service.GetGroupMembers(c.Request.Context(), groupID, limit, offset)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		h.logger.Error("failed to get group members", "error", err, "group_id", groupID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
