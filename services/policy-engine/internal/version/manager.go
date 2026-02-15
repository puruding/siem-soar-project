// Package version provides version management for policies.
package version

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/siem-soar-platform/services/policy-engine/internal/model"
	"github.com/siem-soar-platform/services/policy-engine/internal/repository"
)

// Manager handles policy versioning and rollback.
type Manager struct {
	repo   repository.PolicyRepository
	logger *slog.Logger
}

// NewManager creates a new version manager.
func NewManager(repo repository.PolicyRepository, logger *slog.Logger) *Manager {
	return &Manager{
		repo:   repo,
		logger: logger.With("component", "version-manager"),
	}
}

// GetHistory retrieves version history for a policy.
func (m *Manager) GetHistory(ctx context.Context, policyID string, limit int) (*model.PolicyVersionHistory, error) {
	policy, err := m.repo.GetByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	versions, err := m.repo.ListVersions(ctx, policyID, limit)
	if err != nil {
		return nil, err
	}

	// Mark current version as active
	for i := range versions {
		versions[i].IsActive = versions[i].Version == policy.Version
	}

	return &model.PolicyVersionHistory{
		PolicyID:       policy.ID,
		PolicyName:     policy.Name,
		CurrentVersion: policy.Version,
		Versions:       versions,
	}, nil
}

// GetVersion retrieves a specific version of a policy.
func (m *Manager) GetVersion(ctx context.Context, policyID string, version int) (*model.Policy, error) {
	snapshot, err := m.repo.GetVersion(ctx, policyID, version)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, fmt.Errorf("version %d not found", version)
	}

	var policy model.Policy
	if err := json.Unmarshal(snapshot.Data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse version data: %w", err)
	}

	return &policy, nil
}

// Diff compares two versions of a policy.
func (m *Manager) Diff(ctx context.Context, policyID string, oldVersion, newVersion int) (*model.PolicyDiff, error) {
	oldPolicy, err := m.GetVersion(ctx, policyID, oldVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get old version: %w", err)
	}

	newPolicy, err := m.GetVersion(ctx, policyID, newVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get new version: %w", err)
	}

	diff := &model.PolicyDiff{
		OldVersion: oldVersion,
		NewVersion: newVersion,
		Changes:    make([]model.PolicyChange, 0),
	}

	// Compare fields
	diff.Changes = append(diff.Changes, m.compareField("name", oldPolicy.Name, newPolicy.Name)...)
	diff.Changes = append(diff.Changes, m.compareField("description", oldPolicy.Description, newPolicy.Description)...)
	diff.Changes = append(diff.Changes, m.compareField("status", string(oldPolicy.Status), string(newPolicy.Status))...)
	diff.Changes = append(diff.Changes, m.compareField("priority", oldPolicy.Priority, newPolicy.Priority)...)

	// Compare rules
	diff.Changes = append(diff.Changes, m.compareRules(oldPolicy.Rules, newPolicy.Rules)...)

	// Compare conditions
	diff.Changes = append(diff.Changes, m.compareConditions("conditions", oldPolicy.Conditions, newPolicy.Conditions)...)

	// Compare actions
	diff.Changes = append(diff.Changes, m.compareActions(oldPolicy.Actions, newPolicy.Actions)...)

	return diff, nil
}

func (m *Manager) compareField(field string, oldValue, newValue interface{}) []model.PolicyChange {
	if reflect.DeepEqual(oldValue, newValue) {
		return nil
	}

	oldJSON, _ := json.Marshal(oldValue)
	newJSON, _ := json.Marshal(newValue)

	return []model.PolicyChange{
		{
			Field:    field,
			Type:     "modified",
			OldValue: oldJSON,
			NewValue: newJSON,
		},
	}
}

func (m *Manager) compareRules(oldRules, newRules []model.Rule) []model.PolicyChange {
	changes := make([]model.PolicyChange, 0)

	oldRuleMap := make(map[string]model.Rule)
	for _, r := range oldRules {
		oldRuleMap[r.ID] = r
	}

	newRuleMap := make(map[string]model.Rule)
	for _, r := range newRules {
		newRuleMap[r.ID] = r
	}

	// Find removed rules
	for id, oldRule := range oldRuleMap {
		if _, exists := newRuleMap[id]; !exists {
			data, _ := json.Marshal(oldRule)
			changes = append(changes, model.PolicyChange{
				Field:    fmt.Sprintf("rules.%s", id),
				Type:     "removed",
				OldValue: data,
			})
		}
	}

	// Find added and modified rules
	for id, newRule := range newRuleMap {
		if oldRule, exists := oldRuleMap[id]; !exists {
			data, _ := json.Marshal(newRule)
			changes = append(changes, model.PolicyChange{
				Field:    fmt.Sprintf("rules.%s", id),
				Type:     "added",
				NewValue: data,
			})
		} else if !reflect.DeepEqual(oldRule, newRule) {
			oldData, _ := json.Marshal(oldRule)
			newData, _ := json.Marshal(newRule)
			changes = append(changes, model.PolicyChange{
				Field:    fmt.Sprintf("rules.%s", id),
				Type:     "modified",
				OldValue: oldData,
				NewValue: newData,
			})
		}
	}

	return changes
}

func (m *Manager) compareConditions(field string, oldConditions, newConditions []model.Condition) []model.PolicyChange {
	if reflect.DeepEqual(oldConditions, newConditions) {
		return nil
	}

	oldJSON, _ := json.Marshal(oldConditions)
	newJSON, _ := json.Marshal(newConditions)

	return []model.PolicyChange{
		{
			Field:    field,
			Type:     "modified",
			OldValue: oldJSON,
			NewValue: newJSON,
		},
	}
}

func (m *Manager) compareActions(oldActions, newActions []model.Action) []model.PolicyChange {
	if reflect.DeepEqual(oldActions, newActions) {
		return nil
	}

	oldJSON, _ := json.Marshal(oldActions)
	newJSON, _ := json.Marshal(newActions)

	return []model.PolicyChange{
		{
			Field:    "actions",
			Type:     "modified",
			OldValue: oldJSON,
			NewValue: newJSON,
		},
	}
}

// Rollback rolls back a policy to a previous version.
func (m *Manager) Rollback(ctx context.Context, policyID string, version int, rolledBackBy string) (*model.Policy, error) {
	snapshot, err := m.repo.GetVersion(ctx, policyID, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}
	if snapshot == nil {
		return nil, fmt.Errorf("version %d not found", version)
	}

	// Get current policy
	currentPolicy, err := m.repo.GetByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if currentPolicy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	// Parse snapshot data
	var restoredPolicy model.Policy
	if err := json.Unmarshal(snapshot.Data, &restoredPolicy); err != nil {
		return nil, fmt.Errorf("failed to parse version data: %w", err)
	}

	// Keep current ID and update metadata
	restoredPolicy.ID = currentPolicy.ID
	restoredPolicy.TenantID = currentPolicy.TenantID
	restoredPolicy.UpdatedBy = rolledBackBy
	restoredPolicy.ParentID = currentPolicy.ID
	// Version will be incremented by Update

	if err := m.repo.Update(ctx, &restoredPolicy); err != nil {
		return nil, fmt.Errorf("failed to rollback: %w", err)
	}

	m.logger.Info("policy rolled back",
		"policy_id", policyID,
		"from_version", currentPolicy.Version,
		"to_version", version,
		"rolled_back_by", rolledBackBy,
	)

	return &restoredPolicy, nil
}
