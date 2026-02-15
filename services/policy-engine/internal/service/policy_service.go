// Package service provides business logic for policy management.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/policy-engine/internal/model"
	"github.com/siem-soar-platform/services/policy-engine/internal/repository"
)

// PolicyService provides business logic for policy management.
type PolicyService struct {
	repo   repository.PolicyRepository
	logger *slog.Logger
}

// NewPolicyService creates a new policy service.
func NewPolicyService(repo repository.PolicyRepository, logger *slog.Logger) *PolicyService {
	return &PolicyService{
		repo:   repo,
		logger: logger,
	}
}

// CreatePolicy creates a new policy.
func (s *PolicyService) CreatePolicy(ctx context.Context, req *model.CreatePolicyRequest, createdBy string) (*model.Policy, error) {
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.Type == "" {
		return nil, errors.New("type is required")
	}

	// Generate IDs for rules
	rules := make([]model.Rule, len(req.Rules))
	for i, rule := range req.Rules {
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
		rules[i] = rule
	}

	policy := &model.Policy{
		Name:         req.Name,
		Description:  req.Description,
		Type:         req.Type,
		Status:       req.Status,
		Priority:     req.Priority,
		Rules:        rules,
		Conditions:   req.Conditions,
		Actions:      req.Actions,
		Exceptions:   req.Exceptions,
		TargetAssets: req.TargetAssets,
		TargetGroups: req.TargetGroups,
		TargetTags:   req.TargetTags,
		Schedule:     req.Schedule,
		Tags:         req.Tags,
		Labels:       req.Labels,
		CreatedBy:    createdBy,
	}

	if policy.Status == "" {
		policy.Status = model.PolicyStatusDraft
	}

	if err := s.repo.Create(ctx, policy); err != nil {
		s.logger.Error("failed to create policy", "error", err)
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	s.logger.Info("policy created",
		"policy_id", policy.ID,
		"name", policy.Name,
		"type", policy.Type,
		"created_by", createdBy,
	)

	return policy, nil
}

// GetPolicy retrieves a policy by ID.
func (s *PolicyService) GetPolicy(ctx context.Context, id string) (*model.Policy, error) {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}
	return policy, nil
}

// UpdatePolicy updates an existing policy.
func (s *PolicyService) UpdatePolicy(ctx context.Context, id string, req *model.UpdatePolicyRequest, updatedBy string) (*model.Policy, error) {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	// Apply updates
	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Description != nil {
		policy.Description = *req.Description
	}
	if req.Status != nil {
		policy.Status = *req.Status
	}
	if req.Priority != nil {
		policy.Priority = *req.Priority
	}
	if req.Rules != nil {
		policy.Rules = req.Rules
	}
	if req.Conditions != nil {
		policy.Conditions = req.Conditions
	}
	if req.Actions != nil {
		policy.Actions = req.Actions
	}
	if req.TargetAssets != nil {
		policy.TargetAssets = req.TargetAssets
	}
	if req.TargetGroups != nil {
		policy.TargetGroups = req.TargetGroups
	}
	if req.TargetTags != nil {
		policy.TargetTags = req.TargetTags
	}
	if req.Schedule != nil {
		policy.Schedule = req.Schedule
	}
	if req.Tags != nil {
		policy.Tags = req.Tags
	}
	if req.Labels != nil {
		policy.Labels = req.Labels
	}

	policy.UpdatedBy = updatedBy

	if err := s.repo.Update(ctx, policy); err != nil {
		s.logger.Error("failed to update policy", "error", err, "policy_id", id)
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	s.logger.Info("policy updated",
		"policy_id", id,
		"updated_by", updatedBy,
	)

	return policy, nil
}

// DeletePolicy deletes a policy.
func (s *PolicyService) DeletePolicy(ctx context.Context, id string, deletedBy string) error {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	// Cannot delete active policy
	if policy.Status == model.PolicyStatusActive {
		return errors.New("cannot delete active policy, deactivate first")
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("failed to delete policy", "error", err, "policy_id", id)
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	s.logger.Info("policy deleted",
		"policy_id", id,
		"deleted_by", deletedBy,
	)

	return nil
}

// ListPolicies retrieves policies with filtering.
func (s *PolicyService) ListPolicies(ctx context.Context, filter *model.PolicyFilter) (*model.PolicyListResult, error) {
	result, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	return result, nil
}

// ActivatePolicy activates a policy.
func (s *PolicyService) ActivatePolicy(ctx context.Context, id string, req *model.ActivateRequest, activatedBy string) error {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	// Validate policy before activation
	if err := s.validatePolicy(policy); err != nil {
		if !req.Force {
			return fmt.Errorf("policy validation failed: %w", err)
		}
		s.logger.Warn("activating policy with validation warnings",
			"policy_id", id,
			"warning", err.Error(),
		)
	}

	if err := s.repo.Activate(ctx, id, activatedBy); err != nil {
		return fmt.Errorf("failed to activate policy: %w", err)
	}

	s.logger.Info("policy activated",
		"policy_id", id,
		"activated_by", activatedBy,
	)

	return nil
}

// DeactivatePolicy deactivates a policy.
func (s *PolicyService) DeactivatePolicy(ctx context.Context, id string, req *model.DeactivateRequest, deactivatedBy string) error {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	if policy.Status != model.PolicyStatusActive {
		return errors.New("policy is not active")
	}

	if err := s.repo.Deactivate(ctx, id); err != nil {
		return fmt.Errorf("failed to deactivate policy: %w", err)
	}

	s.logger.Info("policy deactivated",
		"policy_id", id,
		"reason", req.Reason,
		"deactivated_by", deactivatedBy,
	)

	return nil
}

// GetVersionHistory retrieves version history for a policy.
func (s *PolicyService) GetVersionHistory(ctx context.Context, id string, limit int) (*model.PolicyVersionHistory, error) {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	versions, err := s.repo.ListVersions(ctx, id, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}

	// Mark active version
	for i := range versions {
		if versions[i].Version == policy.Version {
			versions[i].IsActive = true
		}
	}

	return &model.PolicyVersionHistory{
		PolicyID:       policy.ID,
		PolicyName:     policy.Name,
		CurrentVersion: policy.Version,
		Versions:       versions,
	}, nil
}

// RollbackPolicy rolls back a policy to a previous version.
func (s *PolicyService) RollbackPolicy(ctx context.Context, id string, req *model.RollbackRequest, rolledBackBy string) (*model.Policy, error) {
	policy, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	// Get the target version
	snapshot, err := s.repo.GetVersion(ctx, id, req.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}
	if snapshot == nil {
		return nil, fmt.Errorf("version %d not found", req.Version)
	}

	// Restore policy data from snapshot
	var restoredPolicy model.Policy
	if err := json.Unmarshal(snapshot.Data, &restoredPolicy); err != nil {
		return nil, fmt.Errorf("failed to parse version data: %w", err)
	}

	// Update policy with restored data (keeping current ID and incrementing version)
	restoredPolicy.ID = policy.ID
	restoredPolicy.UpdatedBy = rolledBackBy
	restoredPolicy.ParentID = policy.ID

	if err := s.repo.Update(ctx, &restoredPolicy); err != nil {
		return nil, fmt.Errorf("failed to rollback policy: %w", err)
	}

	s.logger.Info("policy rolled back",
		"policy_id", id,
		"from_version", policy.Version,
		"to_version", req.Version,
		"rolled_back_by", rolledBackBy,
	)

	return &restoredPolicy, nil
}

// AddRule adds a rule to a policy.
func (s *PolicyService) AddRule(ctx context.Context, policyID string, req *model.AddRuleRequest, addedBy string) (*model.Rule, error) {
	if req.Name == "" {
		return nil, errors.New("rule name is required")
	}

	policy, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	rule := &model.Rule{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Enabled:     req.Enabled,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		Severity:    req.Severity,
	}

	if err := s.repo.AddRule(ctx, policyID, rule); err != nil {
		return nil, fmt.Errorf("failed to add rule: %w", err)
	}

	s.logger.Info("rule added to policy",
		"policy_id", policyID,
		"rule_id", rule.ID,
		"rule_name", rule.Name,
		"added_by", addedBy,
	)

	return rule, nil
}

// UpdateRule updates a rule in a policy.
func (s *PolicyService) UpdateRule(ctx context.Context, policyID, ruleID string, req *model.AddRuleRequest, updatedBy string) (*model.Rule, error) {
	policy, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	// Find existing rule
	var existingRule *model.Rule
	for _, r := range policy.Rules {
		if r.ID == ruleID {
			existingRule = &r
			break
		}
	}
	if existingRule == nil {
		return nil, errors.New("rule not found")
	}

	rule := &model.Rule{
		ID:          ruleID,
		Name:        req.Name,
		Description: req.Description,
		Enabled:     req.Enabled,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		Severity:    req.Severity,
	}

	if err := s.repo.UpdateRule(ctx, policyID, rule); err != nil {
		return nil, fmt.Errorf("failed to update rule: %w", err)
	}

	s.logger.Info("rule updated",
		"policy_id", policyID,
		"rule_id", ruleID,
		"updated_by", updatedBy,
	)

	return rule, nil
}

// DeleteRule deletes a rule from a policy.
func (s *PolicyService) DeleteRule(ctx context.Context, policyID, ruleID string, deletedBy string) error {
	if err := s.repo.DeleteRule(ctx, policyID, ruleID); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	s.logger.Info("rule deleted",
		"policy_id", policyID,
		"rule_id", ruleID,
		"deleted_by", deletedBy,
	)

	return nil
}

// AddException adds an exception to a policy.
func (s *PolicyService) AddException(ctx context.Context, policyID string, req *model.AddExceptionRequest, addedBy string) (*model.Exception, error) {
	if req.Name == "" {
		return nil, errors.New("exception name is required")
	}
	if len(req.Conditions) == 0 {
		return nil, errors.New("at least one condition is required")
	}

	policy, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil, errors.New("policy not found")
	}

	exception := model.Exception{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Enabled:     req.Enabled,
		Conditions:  req.Conditions,
		Reason:      req.Reason,
		ExpiresAt:   req.ExpiresAt,
		CreatedBy:   addedBy,
		CreatedAt:   time.Now(),
	}

	policy.Exceptions = append(policy.Exceptions, exception)
	policy.UpdatedBy = addedBy

	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to add exception: %w", err)
	}

	s.logger.Info("exception added to policy",
		"policy_id", policyID,
		"exception_id", exception.ID,
		"added_by", addedBy,
	)

	return &exception, nil
}

// GetActivePolicies retrieves all active policies of a type.
func (s *PolicyService) GetActivePolicies(ctx context.Context, policyType model.PolicyType) ([]*model.Policy, error) {
	return s.repo.GetActive(ctx, policyType)
}

// EvaluatePolicy evaluates a policy against an event (for testing).
func (s *PolicyService) EvaluatePolicy(ctx context.Context, req *model.EvaluateRequest) ([]*model.EvaluateResult, error) {
	startTime := time.Now()
	results := make([]*model.EvaluateResult, 0)

	var policies []*model.Policy
	var err error

	if len(req.PolicyIDs) > 0 {
		// Evaluate specific policies
		for _, id := range req.PolicyIDs {
			policy, err := s.repo.GetByID(ctx, id)
			if err != nil {
				continue
			}
			if policy != nil {
				policies = append(policies, policy)
			}
		}
	} else {
		// Evaluate all active policies
		for _, pType := range []model.PolicyType{
			model.PolicyTypeDetection,
			model.PolicyTypeRouting,
			model.PolicyTypeEnrichment,
			model.PolicyTypeFiltering,
		} {
			active, err := s.repo.GetActive(ctx, pType)
			if err != nil {
				continue
			}
			policies = append(policies, active...)
		}
	}

	for _, policy := range policies {
		result := s.evaluatePolicy(policy, req.Event, req.Context)
		result.DurationMs = float64(time.Since(startTime).Microseconds()) / 1000

		if !req.DryRun {
			// Update statistics
			s.repo.IncrementEvaluationCount(ctx, policy.ID)
			if result.Matched {
				s.repo.IncrementMatchCount(ctx, policy.ID)
			}
			s.repo.UpdateLastEvaluated(ctx, policy.ID, time.Now())
		}

		results = append(results, result)
	}

	return results, err
}

func (s *PolicyService) evaluatePolicy(policy *model.Policy, event map[string]interface{}, evalCtx map[string]interface{}) *model.EvaluateResult {
	result := &model.EvaluateResult{
		PolicyID:    policy.ID,
		PolicyName:  policy.Name,
		Matched:     false,
		EvaluatedAt: time.Now(),
	}

	// Check exceptions first
	for _, exception := range policy.Exceptions {
		if !exception.Enabled {
			continue
		}
		if exception.ExpiresAt != nil && exception.ExpiresAt.Before(time.Now()) {
			continue
		}
		if s.evaluateConditions(exception.Conditions, event) {
			result.Exceptions = append(result.Exceptions, exception.Name)
			return result // Exception matched, don't apply policy
		}
	}

	// Evaluate policy-level conditions
	if len(policy.Conditions) > 0 {
		if !s.evaluateConditions(policy.Conditions, event) {
			return result
		}
	}

	// Evaluate rules
	matchedRules := make([]string, 0)
	allActions := make([]model.Action, 0)

	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		if s.evaluateConditions(rule.Conditions, event) {
			matchedRules = append(matchedRules, rule.Name)
			allActions = append(allActions, rule.Actions...)
		}
	}

	if len(matchedRules) > 0 {
		result.Matched = true
		result.MatchedRules = matchedRules
		result.Actions = allActions
	}

	return result
}

func (s *PolicyService) evaluateConditions(conditions []model.Condition, event map[string]interface{}) bool {
	if len(conditions) == 0 {
		return true
	}

	result := true
	for i, condition := range conditions {
		conditionResult := s.evaluateCondition(condition, event)

		if i == 0 {
			result = conditionResult
		} else {
			switch condition.Logic {
			case "or":
				result = result || conditionResult
			default: // "and" or empty
				result = result && conditionResult
			}
		}
	}

	return result
}

func (s *PolicyService) evaluateCondition(condition model.Condition, event map[string]interface{}) bool {
	fieldValue, ok := event[condition.Field]
	if !ok {
		return false
	}

	// Convert to string for comparison
	fieldStr := fmt.Sprintf("%v", fieldValue)
	valueStr := fmt.Sprintf("%v", condition.Value)

	switch condition.Operator {
	case "eq":
		return fieldStr == valueStr
	case "ne":
		return fieldStr != valueStr
	case "contains":
		return containsString(fieldStr, valueStr)
	case "starts_with":
		return len(fieldStr) >= len(valueStr) && fieldStr[:len(valueStr)] == valueStr
	case "ends_with":
		return len(fieldStr) >= len(valueStr) && fieldStr[len(fieldStr)-len(valueStr):] == valueStr
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, v := range values {
				if fmt.Sprintf("%v", v) == fieldStr {
					return true
				}
			}
		}
		return false
	case "not_in":
		if values, ok := condition.Value.([]interface{}); ok {
			for _, v := range values {
				if fmt.Sprintf("%v", v) == fieldStr {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// validatePolicy validates a policy before activation.
func (s *PolicyService) validatePolicy(policy *model.Policy) error {
	if len(policy.Rules) == 0 && len(policy.Conditions) == 0 {
		return errors.New("policy must have at least one rule or condition")
	}

	// Validate rules
	for _, rule := range policy.Rules {
		if rule.Name == "" {
			return errors.New("rule name is required")
		}
		if len(rule.Conditions) == 0 && len(rule.Actions) == 0 {
			return fmt.Errorf("rule '%s' must have conditions or actions", rule.Name)
		}
	}

	return nil
}

// GetCacheStats returns cache statistics.
func (s *PolicyService) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	if cached, ok := s.repo.(*repository.CachedPolicyRepository); ok {
		return cached.CacheStats(ctx)
	}
	return map[string]interface{}{"cached": false}, nil
}

// ClonePolicy creates a copy of an existing policy.
func (s *PolicyService) ClonePolicy(ctx context.Context, id string, req *model.CloneRequest, clonedBy string) (*model.Policy, error) {
	original, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	if original == nil {
		return nil, errors.New("policy not found")
	}

	// Create new policy from original
	cloned := &model.Policy{
		TenantID:     original.TenantID,
		Name:         req.Name,
		Description:  req.Description,
		Type:         original.Type,
		Status:       model.PolicyStatusDraft,
		Priority:     original.Priority,
		Rules:        original.Rules,
		Conditions:   original.Conditions,
		Actions:      original.Actions,
		Exceptions:   original.Exceptions,
		TargetAssets: original.TargetAssets,
		TargetGroups: original.TargetGroups,
		TargetTags:   original.TargetTags,
		Schedule:     original.Schedule,
		Tags:         original.Tags,
		Labels:       original.Labels,
		ParentID:     original.ID,
		CreatedBy:    clonedBy,
	}

	if cloned.Description == "" {
		cloned.Description = fmt.Sprintf("Cloned from %s", original.Name)
	}

	// Generate new IDs for rules
	for i := range cloned.Rules {
		cloned.Rules[i].ID = uuid.New().String()
	}

	if err := s.repo.Create(ctx, cloned); err != nil {
		return nil, fmt.Errorf("failed to clone policy: %w", err)
	}

	s.logger.Info("policy cloned",
		"original_id", id,
		"cloned_id", cloned.ID,
		"cloned_by", clonedBy,
	)

	return cloned, nil
}
