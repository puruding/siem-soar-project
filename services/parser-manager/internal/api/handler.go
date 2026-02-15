// Package api provides HTTP handlers for parser management.
package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/siem-soar-platform/services/parser-manager/internal/model"
	"github.com/siem-soar-platform/services/parser-manager/internal/service"
)

// ParserHandler handles HTTP requests for parser management.
type ParserHandler struct {
	service *service.ParserService
	logger  *slog.Logger
}

// NewParserHandler creates a new parser handler.
func NewParserHandler(svc *service.ParserService, logger *slog.Logger) *ParserHandler {
	return &ParserHandler{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers parser routes on a Gin router group.
func (h *ParserHandler) RegisterRoutes(rg *gin.RouterGroup) {
	// Products
	rg.GET("/products", h.ListProducts)
	rg.POST("/products", h.CreateProduct)
	rg.GET("/products/:id", h.GetProduct)
	rg.PUT("/products/:id", h.UpdateProduct)
	rg.DELETE("/products/:id", h.DeleteProduct)
	rg.GET("/products/:id/parsers", h.GetParsersByProduct)
	rg.POST("/products/:id/parsers", h.CreateParserForProduct)

	// Parsers
	rg.GET("/parsers", h.ListParsers)
	rg.GET("/parsers/:id", h.GetParser)
	rg.PUT("/parsers/:id", h.UpdateParser)
	rg.DELETE("/parsers/:id", h.DeleteParser)
	rg.POST("/parsers/:id/test", h.TestParser)
	rg.POST("/parsers/:id/deploy", h.DeployParser)

	// Hot Reload
	rg.GET("/parsers/reload-status", h.GetReloadStatus)
	rg.POST("/parsers/reload-all", h.ReloadAll)
}

// ListProducts handles product listing.
// GET /api/v1/products
func (h *ParserHandler) ListProducts(c *gin.Context) {
	filter := &model.ProductFilter{
		Vendor:   c.Query("vendor"),
		Category: c.Query("category"),
		Search:   c.Query("search"),
		TenantID: c.Query("tenant_id"),
	}

	if tags := c.QueryArray("tag"); len(tags) > 0 {
		filter.Tags = tags
	}

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

	filter.SortBy = c.DefaultQuery("sort_by", "name")
	filter.SortOrder = c.DefaultQuery("sort_order", "asc")

	result, err := h.service.ListProducts(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list products", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// CreateProduct handles product creation.
// POST /api/v1/products
func (h *ParserHandler) CreateProduct(c *gin.Context) {
	var req model.CreateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	product, err := h.service.CreateProduct(c.Request.Context(), &req, createdBy)
	if err != nil {
		h.logger.Error("failed to create product", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, product)
}

// GetProduct handles product retrieval.
// GET /api/v1/products/:id
func (h *ParserHandler) GetProduct(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "product id is required"})
		return
	}

	product, err := h.service.GetProduct(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "product not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
			return
		}
		h.logger.Error("failed to get product", "error", err, "product_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, product)
}

// UpdateProduct handles product update.
// PUT /api/v1/products/:id
func (h *ParserHandler) UpdateProduct(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "product id is required"})
		return
	}

	var req model.UpdateProductRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	product, err := h.service.UpdateProduct(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if err.Error() == "product not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
			return
		}
		h.logger.Error("failed to update product", "error", err, "product_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, product)
}

// DeleteProduct handles product deletion.
// DELETE /api/v1/products/:id
func (h *ParserHandler) DeleteProduct(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "product id is required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeleteProduct(c.Request.Context(), id, deletedBy)
	if err != nil {
		if err.Error() == "product not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
			return
		}
		h.logger.Error("failed to delete product", "error", err, "product_id", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// GetParsersByProduct handles getting parsers for a product.
// GET /api/v1/products/:id/parsers
func (h *ParserHandler) GetParsersByProduct(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "product id is required"})
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

	parsers, total, err := h.service.GetParsersByProduct(c.Request.Context(), productID, limit, offset)
	if err != nil {
		h.logger.Error("failed to get parsers by product", "error", err, "product_id", productID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"parsers":  parsers,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"has_more": offset+limit < total,
	})
}

// CreateParserForProduct handles creating a parser for a product.
// POST /api/v1/products/:id/parsers
func (h *ParserHandler) CreateParserForProduct(c *gin.Context) {
	productID := c.Param("id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "product id is required"})
		return
	}

	var req model.CreateParserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	req.ProductID = productID

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	parser, err := h.service.CreateParser(c.Request.Context(), &req, createdBy)
	if err != nil {
		if err.Error() == "product not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
			return
		}
		h.logger.Error("failed to create parser", "error", err, "product_id", productID)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, parser)
}

// ListParsers handles parser listing.
// GET /api/v1/parsers
func (h *ParserHandler) ListParsers(c *gin.Context) {
	filter := &model.ParserFilter2{
		ProductID: c.Query("product_id"),
		Search:    c.Query("search"),
		TenantID:  c.Query("tenant_id"),
	}

	if types := c.QueryArray("type"); len(types) > 0 {
		filter.Types = make([]model.ParserType, len(types))
		for i, t := range types {
			filter.Types[i] = model.ParserType(t)
		}
	}

	if statuses := c.QueryArray("status"); len(statuses) > 0 {
		filter.Statuses = make([]model.ParserStatus, len(statuses))
		for i, s := range statuses {
			filter.Statuses[i] = model.ParserStatus(s)
		}
	}

	if tags := c.QueryArray("tag"); len(tags) > 0 {
		filter.Tags = tags
	}

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

	filter.SortBy = c.DefaultQuery("sort_by", "priority")
	filter.SortOrder = c.DefaultQuery("sort_order", "desc")

	result, err := h.service.ListParsers(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list parsers", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetParser handles parser retrieval.
// GET /api/v1/parsers/:id
func (h *ParserHandler) GetParser(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parser id is required"})
		return
	}

	parser, err := h.service.GetParser(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "parser not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "parser not found"})
			return
		}
		h.logger.Error("failed to get parser", "error", err, "parser_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, parser)
}

// UpdateParser handles parser update.
// PUT /api/v1/parsers/:id
func (h *ParserHandler) UpdateParser(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parser id is required"})
		return
	}

	var req model.UpdateParserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	parser, err := h.service.UpdateParser(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if err.Error() == "parser not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "parser not found"})
			return
		}
		h.logger.Error("failed to update parser", "error", err, "parser_id", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, parser)
}

// DeleteParser handles parser deletion.
// DELETE /api/v1/parsers/:id
func (h *ParserHandler) DeleteParser(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parser id is required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeleteParser(c.Request.Context(), id, deletedBy)
	if err != nil {
		if err.Error() == "parser not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "parser not found"})
			return
		}
		h.logger.Error("failed to delete parser", "error", err, "parser_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// TestParser handles parser testing.
// POST /api/v1/parsers/:id/test
func (h *ParserHandler) TestParser(c *gin.Context) {
	parserID := c.Param("id")

	var req model.ParserTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if parserID != "" {
		req.ParserID = parserID
	}

	if len(req.Samples) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one sample is required"})
		return
	}

	results, err := h.service.TestParser(c.Request.Context(), &req)
	if err != nil {
		if err.Error() == "parser not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "parser not found"})
			return
		}
		h.logger.Error("failed to test parser", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Count success/failure
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
		"success": successCount,
		"failed":  len(results) - successCount,
	})
}

// DeployParser handles parser deployment.
// POST /api/v1/parsers/:id/deploy
func (h *ParserHandler) DeployParser(c *gin.Context) {
	parserID := c.Param("id")
	if parserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parser id is required"})
		return
	}

	var req model.ParserDeployRequest
	c.ShouldBindJSON(&req) // Optional body

	req.ParserID = parserID

	deployedBy := c.GetHeader("X-User-ID")
	if deployedBy == "" {
		deployedBy = "system"
	}

	result, err := h.service.DeployParser(c.Request.Context(), &req, deployedBy)
	if err != nil {
		if err.Error() == "parser not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "parser not found"})
			return
		}
		h.logger.Error("failed to deploy parser", "error", err, "parser_id", parserID)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetReloadStatus handles reload status retrieval.
// GET /api/v1/parsers/reload-status
func (h *ParserHandler) GetReloadStatus(c *gin.Context) {
	status := h.service.GetReloadStatus()
	c.JSON(http.StatusOK, status)
}

// ReloadAll handles reload all parsers.
// POST /api/v1/parsers/reload-all
func (h *ParserHandler) ReloadAll(c *gin.Context) {
	if err := h.service.ReloadAll(c.Request.Context()); err != nil {
		h.logger.Error("failed to reload all parsers", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "reload triggered",
	})
}
