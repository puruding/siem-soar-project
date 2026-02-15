// Package api provides HTTP handlers for policy management.
package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/siem-soar-platform/services/policy-engine/internal/model"
	"github.com/siem-soar-platform/services/policy-engine/internal/service"
)

// PolicyHandler handles HTTP requests for policy management.
type PolicyHandler struct {
	service *service.PolicyService
	logger  *slog.Logger
}

// NewPolicyHandler creates a new policy handler.
func NewPolicyHandler(svc *service.PolicyService, logger *slog.Logger) *PolicyHandler {
	return &PolicyHandler{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers policy routes on a Gin router group.
func (h *PolicyHandler) RegisterRoutes(rg *gin.RouterGroup) {
	// Policy CRUD
	rg.POST("/policies", h.CreatePolicy)
	rg.GET("/policies", h.ListPolicies)
	rg.GET("/policies/:id", h.GetPolicy)
	rg.PUT("/policies/:id", h.UpdatePolicy)
	rg.DELETE("/policies/:id", h.DeletePolicy)

	// Activation
	rg.POST("/policies/:id/activate", h.ActivatePolicy)
	rg.POST("/policies/:id/deactivate", h.DeactivatePolicy)

	// Versions
	rg.GET("/policies/:id/versions", h.GetVersionHistory)
	rg.POST("/policies/:id/rollback", h.RollbackPolicy)

	// Rules
	rg.POST("/policies/:id/rules", h.AddRule)
	rg.PUT("/policies/:id/rules/:ruleId", h.UpdateRule)
	rg.DELETE("/policies/:id/rules/:ruleId", h.DeleteRule)

	// Exceptions
	rg.POST("/policies/:id/exceptions", h.AddException)

	// Evaluate (for testing)
	rg.POST("/policies/evaluate", h.EvaluatePolicy)

	// Clone
	rg.POST("/policies/:id/clone", h.ClonePolicy)
}

// CreatePolicy handles policy creation.
// POST /api/v1/policies
func (h *PolicyHandler) CreatePolicy(c *gin.Context) {
	var req model.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	createdBy := c.GetHeader("X-User-ID")
	if createdBy == "" {
		createdBy = "system"
	}

	policy, err := h.service.CreatePolicy(c.Request.Context(), &req, createdBy)
	if err != nil {
		h.logger.Error("failed to create policy", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// GetPolicy handles policy retrieval.
// GET /api/v1/policies/:id
func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	policy, err := h.service.GetPolicy(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to get policy", "error", err, "policy_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// UpdatePolicy handles policy update.
// PUT /api/v1/policies/:id
func (h *PolicyHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	policy, err := h.service.UpdatePolicy(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to update policy", "error", err, "policy_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// DeletePolicy handles policy deletion.
// DELETE /api/v1/policies/:id
func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeletePolicy(c.Request.Context(), id, deletedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		if err.Error() == "cannot delete active policy, deactivate first" {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		h.logger.Error("failed to delete policy", "error", err, "policy_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// ListPolicies handles policy listing.
// GET /api/v1/policies
func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	filter := &model.PolicyFilter{}

	// Parse query parameters
	if types := c.QueryArray("type"); len(types) > 0 {
		filter.Types = make([]model.PolicyType, len(types))
		for i, t := range types {
			filter.Types[i] = model.PolicyType(t)
		}
	}

	if statuses := c.QueryArray("status"); len(statuses) > 0 {
		filter.Statuses = make([]model.PolicyStatus, len(statuses))
		for i, s := range statuses {
			filter.Statuses[i] = model.PolicyStatus(s)
		}
	}

	filter.Name = c.Query("name")
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

	result, err := h.service.ListPolicies(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list policies", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ActivatePolicy handles policy activation.
// POST /api/v1/policies/:id/activate
func (h *PolicyHandler) ActivatePolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.ActivateRequest
	c.ShouldBindJSON(&req) // Optional body

	activatedBy := c.GetHeader("X-User-ID")
	if activatedBy == "" {
		activatedBy = "system"
	}

	err := h.service.ActivatePolicy(c.Request.Context(), id, &req, activatedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to activate policy", "error", err, "policy_id", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "policy activated",
		"policy_id": id,
	})
}

// DeactivatePolicy handles policy deactivation.
// POST /api/v1/policies/:id/deactivate
func (h *PolicyHandler) DeactivatePolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.DeactivateRequest
	c.ShouldBindJSON(&req) // Optional body

	deactivatedBy := c.GetHeader("X-User-ID")
	if deactivatedBy == "" {
		deactivatedBy = "system"
	}

	err := h.service.DeactivatePolicy(c.Request.Context(), id, &req, deactivatedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to deactivate policy", "error", err, "policy_id", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "policy deactivated",
		"policy_id": id,
	})
}

// GetVersionHistory handles version history retrieval.
// GET /api/v1/policies/:id/versions
func (h *PolicyHandler) GetVersionHistory(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	history, err := h.service.GetVersionHistory(c.Request.Context(), id, limit)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to get version history", "error", err, "policy_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, history)
}

// RollbackPolicy handles policy rollback.
// POST /api/v1/policies/:id/rollback
func (h *PolicyHandler) RollbackPolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.RollbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if req.Version <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "version is required"})
		return
	}

	rolledBackBy := c.GetHeader("X-User-ID")
	if rolledBackBy == "" {
		rolledBackBy = "system"
	}

	policy, err := h.service.RollbackPolicy(c.Request.Context(), id, &req, rolledBackBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to rollback policy", "error", err, "policy_id", id)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "policy rolled back",
		"policy":  policy,
	})
}

// AddRule handles adding a rule to a policy.
// POST /api/v1/policies/:id/rules
func (h *PolicyHandler) AddRule(c *gin.Context) {
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.AddRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	addedBy := c.GetHeader("X-User-ID")
	if addedBy == "" {
		addedBy = "system"
	}

	rule, err := h.service.AddRule(c.Request.Context(), policyID, &req, addedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to add rule", "error", err, "policy_id", policyID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// UpdateRule handles updating a rule in a policy.
// PUT /api/v1/policies/:id/rules/:ruleId
func (h *PolicyHandler) UpdateRule(c *gin.Context) {
	policyID := c.Param("id")
	ruleID := c.Param("ruleId")
	if policyID == "" || ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id and rule id are required"})
		return
	}

	var req model.AddRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	updatedBy := c.GetHeader("X-User-ID")
	if updatedBy == "" {
		updatedBy = "system"
	}

	rule, err := h.service.UpdateRule(c.Request.Context(), policyID, ruleID, &req, updatedBy)
	if err != nil {
		if err.Error() == "policy not found" || err.Error() == "rule not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.logger.Error("failed to update rule", "error", err, "policy_id", policyID, "rule_id", ruleID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// DeleteRule handles deleting a rule from a policy.
// DELETE /api/v1/policies/:id/rules/:ruleId
func (h *PolicyHandler) DeleteRule(c *gin.Context) {
	policyID := c.Param("id")
	ruleID := c.Param("ruleId")
	if policyID == "" || ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id and rule id are required"})
		return
	}

	deletedBy := c.GetHeader("X-User-ID")
	if deletedBy == "" {
		deletedBy = "system"
	}

	err := h.service.DeleteRule(c.Request.Context(), policyID, ruleID, deletedBy)
	if err != nil {
		if err.Error() == "policy not found" || err.Error() == "rule not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.logger.Error("failed to delete rule", "error", err, "policy_id", policyID, "rule_id", ruleID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// AddException handles adding an exception to a policy.
// POST /api/v1/policies/:id/exceptions
func (h *PolicyHandler) AddException(c *gin.Context) {
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.AddExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	addedBy := c.GetHeader("X-User-ID")
	if addedBy == "" {
		addedBy = "system"
	}

	exception, err := h.service.AddException(c.Request.Context(), policyID, &req, addedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to add exception", "error", err, "policy_id", policyID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, exception)
}

// EvaluatePolicy handles policy evaluation for testing.
// POST /api/v1/policies/evaluate
func (h *PolicyHandler) EvaluatePolicy(c *gin.Context) {
	var req model.EvaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if len(req.Event) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "event is required"})
		return
	}

	results, err := h.service.EvaluatePolicy(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("failed to evaluate policy", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results":     results,
		"total":       len(results),
		"matched":     countMatched(results),
		"dry_run":     req.DryRun,
	})
}

// ClonePolicy handles policy cloning.
// POST /api/v1/policies/:id/clone
func (h *PolicyHandler) ClonePolicy(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy id is required"})
		return
	}

	var req model.CloneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "details": err.Error()})
		return
	}

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	clonedBy := c.GetHeader("X-User-ID")
	if clonedBy == "" {
		clonedBy = "system"
	}

	policy, err := h.service.ClonePolicy(c.Request.Context(), id, &req, clonedBy)
	if err != nil {
		if err.Error() == "policy not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		h.logger.Error("failed to clone policy", "error", err, "policy_id", id)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

func countMatched(results []*model.EvaluateResult) int {
	count := 0
	for _, r := range results {
		if r.Matched {
			count++
		}
	}
	return count
}
