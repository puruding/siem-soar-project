// Package repository provides data access for policy management.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/siem-soar-platform/services/policy-engine/internal/model"
)

// PolicyRepository defines the interface for policy data access.
type PolicyRepository interface {
	// Policy CRUD
	Create(ctx context.Context, policy *model.Policy) error
	GetByID(ctx context.Context, id string) (*model.Policy, error)
	Update(ctx context.Context, policy *model.Policy) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *model.PolicyFilter) (*model.PolicyListResult, error)

	// Rule operations
	AddRule(ctx context.Context, policyID string, rule *model.Rule) error
	UpdateRule(ctx context.Context, policyID string, rule *model.Rule) error
	DeleteRule(ctx context.Context, policyID, ruleID string) error

	// Version operations
	CreateVersion(ctx context.Context, snapshot *model.PolicySnapshot) error
	GetVersion(ctx context.Context, policyID string, version int) (*model.PolicySnapshot, error)
	ListVersions(ctx context.Context, policyID string, limit int) ([]model.PolicyVersionInfo, error)

	// Activation
	Activate(ctx context.Context, id, activatedBy string) error
	Deactivate(ctx context.Context, id string) error
	GetActive(ctx context.Context, policyType model.PolicyType) ([]*model.Policy, error)

	// Statistics
	IncrementEvaluationCount(ctx context.Context, id string) error
	IncrementMatchCount(ctx context.Context, id string) error
	UpdateLastEvaluated(ctx context.Context, id string, timestamp time.Time) error
}

// PostgresPolicyRepository implements PolicyRepository using PostgreSQL.
type PostgresPolicyRepository struct {
	db *sqlx.DB
}

// NewPostgresPolicyRepository creates a new PostgreSQL policy repository.
func NewPostgresPolicyRepository(db *sqlx.DB) *PostgresPolicyRepository {
	return &PostgresPolicyRepository{db: db}
}

// Create creates a new policy.
func (r *PostgresPolicyRepository) Create(ctx context.Context, policy *model.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = policy.CreatedAt
	policy.Version = 1

	if policy.Status == "" {
		policy.Status = model.PolicyStatusDraft
	}

	rules, _ := json.Marshal(policy.Rules)
	conditions, _ := json.Marshal(policy.Conditions)
	actions, _ := json.Marshal(policy.Actions)
	exceptions, _ := json.Marshal(policy.Exceptions)
	targetAssets, _ := json.Marshal(policy.TargetAssets)
	targetGroups, _ := json.Marshal(policy.TargetGroups)
	targetTags, _ := json.Marshal(policy.TargetTags)
	schedule, _ := json.Marshal(policy.Schedule)
	tags, _ := json.Marshal(policy.Tags)
	labels, _ := json.Marshal(policy.Labels)

	query := `
		INSERT INTO policies.policies (
			id, tenant_id, name, description, type, status, priority,
			rules, conditions, actions, exceptions,
			target_assets, target_groups, target_tags, schedule,
			tags, labels, version, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		policy.ID, policy.TenantID, policy.Name, policy.Description,
		policy.Type, policy.Status, policy.Priority,
		rules, conditions, actions, exceptions,
		targetAssets, targetGroups, targetTags, schedule,
		tags, labels, policy.Version, policy.CreatedAt, policy.UpdatedAt,
		policy.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Create initial version snapshot
	r.createSnapshot(ctx, policy, "Initial version")

	return nil
}

// GetByID retrieves a policy by ID.
func (r *PostgresPolicyRepository) GetByID(ctx context.Context, id string) (*model.Policy, error) {
	query := `
		SELECT id, tenant_id, name, description, type, status, priority,
			rules, conditions, actions, exceptions,
			target_assets, target_groups, target_tags, schedule,
			tags, labels, version, parent_id,
			evaluation_count, match_count, last_evaluated_at,
			created_at, updated_at, created_by, updated_by,
			activated_at, activated_by
		FROM policies.policies
		WHERE id = $1
	`

	var policy model.Policy
	var rules, conditions, actions, exceptions []byte
	var targetAssets, targetGroups, targetTags, schedule []byte
	var tags, labels []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
		&policy.Type, &policy.Status, &policy.Priority,
		&rules, &conditions, &actions, &exceptions,
		&targetAssets, &targetGroups, &targetTags, &schedule,
		&tags, &labels, &policy.Version, &policy.ParentID,
		&policy.EvaluationCount, &policy.MatchCount, &policy.LastEvaluatedAt,
		&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy, &policy.UpdatedBy,
		&policy.ActivatedAt, &policy.ActivatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	// Unmarshal JSON fields
	json.Unmarshal(rules, &policy.Rules)
	json.Unmarshal(conditions, &policy.Conditions)
	json.Unmarshal(actions, &policy.Actions)
	json.Unmarshal(exceptions, &policy.Exceptions)
	json.Unmarshal(targetAssets, &policy.TargetAssets)
	json.Unmarshal(targetGroups, &policy.TargetGroups)
	json.Unmarshal(targetTags, &policy.TargetTags)
	json.Unmarshal(schedule, &policy.Schedule)
	json.Unmarshal(tags, &policy.Tags)
	json.Unmarshal(labels, &policy.Labels)

	return &policy, nil
}

// Update updates an existing policy.
func (r *PostgresPolicyRepository) Update(ctx context.Context, policy *model.Policy) error {
	policy.UpdatedAt = time.Now()
	policy.Version++

	rules, _ := json.Marshal(policy.Rules)
	conditions, _ := json.Marshal(policy.Conditions)
	actions, _ := json.Marshal(policy.Actions)
	exceptions, _ := json.Marshal(policy.Exceptions)
	targetAssets, _ := json.Marshal(policy.TargetAssets)
	targetGroups, _ := json.Marshal(policy.TargetGroups)
	targetTags, _ := json.Marshal(policy.TargetTags)
	schedule, _ := json.Marshal(policy.Schedule)
	tags, _ := json.Marshal(policy.Tags)
	labels, _ := json.Marshal(policy.Labels)

	query := `
		UPDATE policies.policies
		SET name = $2, description = $3, status = $4, priority = $5,
			rules = $6, conditions = $7, actions = $8, exceptions = $9,
			target_assets = $10, target_groups = $11, target_tags = $12, schedule = $13,
			tags = $14, labels = $15, version = $16, updated_at = $17, updated_by = $18
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Status, policy.Priority,
		rules, conditions, actions, exceptions,
		targetAssets, targetGroups, targetTags, schedule,
		tags, labels, policy.Version, policy.UpdatedAt, policy.UpdatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	// Create version snapshot
	r.createSnapshot(ctx, policy, "Updated")

	return nil
}

// Delete soft-deletes a policy.
func (r *PostgresPolicyRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM policies.policies WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// List retrieves policies with filtering and pagination.
func (r *PostgresPolicyRepository) List(ctx context.Context, filter *model.PolicyFilter) (*model.PolicyListResult, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}
	argIndex := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID)
		argIndex++
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, t)
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("type IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s)
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Name+"%")
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(name ILIKE $%d OR description ILIKE $%d)",
			argIndex, argIndex,
		))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policies.policies WHERE %s", whereClause)
	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, fmt.Errorf("failed to count policies: %w", err)
	}

	// Build ORDER BY
	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		order := "ASC"
		if filter.SortOrder == "desc" {
			order = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
	}

	// Set defaults
	limit := filter.Limit
	if limit == 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, type, status, priority,
			rules, tags, labels, version, evaluation_count, match_count,
			created_at, updated_at, activated_at
		FROM policies.policies
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*model.Policy, 0)
	for rows.Next() {
		var policy model.Policy
		var rules, tags, labels []byte

		err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&policy.Type, &policy.Status, &policy.Priority,
			&rules, &tags, &labels, &policy.Version,
			&policy.EvaluationCount, &policy.MatchCount,
			&policy.CreatedAt, &policy.UpdatedAt, &policy.ActivatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		json.Unmarshal(rules, &policy.Rules)
		json.Unmarshal(tags, &policy.Tags)
		json.Unmarshal(labels, &policy.Labels)

		policies = append(policies, &policy)
	}

	return &model.PolicyListResult{
		Policies: policies,
		Total:    total,
		Limit:    limit,
		Offset:   filter.Offset,
		HasMore:  int64(filter.Offset+limit) < total,
	}, nil
}

// AddRule adds a rule to a policy.
func (r *PostgresPolicyRepository) AddRule(ctx context.Context, policyID string, rule *model.Rule) error {
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	policy.Rules = append(policy.Rules, *rule)
	return r.Update(ctx, policy)
}

// UpdateRule updates a rule in a policy.
func (r *PostgresPolicyRepository) UpdateRule(ctx context.Context, policyID string, rule *model.Rule) error {
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	found := false
	for i, existingRule := range policy.Rules {
		if existingRule.ID == rule.ID {
			policy.Rules[i] = *rule
			found = true
			break
		}
	}

	if !found {
		return errors.New("rule not found")
	}

	return r.Update(ctx, policy)
}

// DeleteRule deletes a rule from a policy.
func (r *PostgresPolicyRepository) DeleteRule(ctx context.Context, policyID, ruleID string) error {
	policy, err := r.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("policy not found")
	}

	newRules := make([]model.Rule, 0)
	found := false
	for _, rule := range policy.Rules {
		if rule.ID == ruleID {
			found = true
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		return errors.New("rule not found")
	}

	policy.Rules = newRules
	return r.Update(ctx, policy)
}

// createSnapshot creates a version snapshot of the policy.
func (r *PostgresPolicyRepository) createSnapshot(ctx context.Context, policy *model.Policy, changeLog string) error {
	data, _ := json.Marshal(policy)

	snapshot := &model.PolicySnapshot{
		ID:        uuid.New().String(),
		PolicyID:  policy.ID,
		Version:   policy.Version,
		Data:      data,
		ChangeLog: changeLog,
		CreatedAt: time.Now(),
		CreatedBy: policy.UpdatedBy,
	}
	if snapshot.CreatedBy == "" {
		snapshot.CreatedBy = policy.CreatedBy
	}

	return r.CreateVersion(ctx, snapshot)
}

// CreateVersion creates a version snapshot.
func (r *PostgresPolicyRepository) CreateVersion(ctx context.Context, snapshot *model.PolicySnapshot) error {
	query := `
		INSERT INTO policies.policy_versions (
			id, policy_id, version, data, change_log, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(ctx, query,
		snapshot.ID, snapshot.PolicyID, snapshot.Version,
		snapshot.Data, snapshot.ChangeLog, snapshot.CreatedAt, snapshot.CreatedBy,
	)

	return err
}

// GetVersion retrieves a specific version of a policy.
func (r *PostgresPolicyRepository) GetVersion(ctx context.Context, policyID string, version int) (*model.PolicySnapshot, error) {
	query := `
		SELECT id, policy_id, version, data, change_log, created_at, created_by
		FROM policies.policy_versions
		WHERE policy_id = $1 AND version = $2
	`

	var snapshot model.PolicySnapshot
	err := r.db.QueryRowContext(ctx, query, policyID, version).Scan(
		&snapshot.ID, &snapshot.PolicyID, &snapshot.Version,
		&snapshot.Data, &snapshot.ChangeLog, &snapshot.CreatedAt, &snapshot.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &snapshot, nil
}

// ListVersions lists all versions of a policy.
func (r *PostgresPolicyRepository) ListVersions(ctx context.Context, policyID string, limit int) ([]model.PolicyVersionInfo, error) {
	if limit == 0 {
		limit = 50
	}

	query := `
		SELECT version, created_at, created_by, change_log
		FROM policies.policy_versions
		WHERE policy_id = $1
		ORDER BY version DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, policyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make([]model.PolicyVersionInfo, 0)
	for rows.Next() {
		var v model.PolicyVersionInfo
		err := rows.Scan(&v.Version, &v.CreatedAt, &v.CreatedBy, &v.ChangeLog)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}

	return versions, nil
}

// Activate activates a policy.
func (r *PostgresPolicyRepository) Activate(ctx context.Context, id, activatedBy string) error {
	query := `
		UPDATE policies.policies
		SET status = $2, activated_at = $3, activated_by = $4, updated_at = $3
		WHERE id = $1
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, id, model.PolicyStatusActive, now, activatedBy)
	return err
}

// Deactivate deactivates a policy.
func (r *PostgresPolicyRepository) Deactivate(ctx context.Context, id string) error {
	query := `
		UPDATE policies.policies
		SET status = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, model.PolicyStatusInactive)
	return err
}

// GetActive retrieves all active policies of a specific type.
func (r *PostgresPolicyRepository) GetActive(ctx context.Context, policyType model.PolicyType) ([]*model.Policy, error) {
	filter := &model.PolicyFilter{
		Types:    []model.PolicyType{policyType},
		Statuses: []model.PolicyStatus{model.PolicyStatusActive},
		Limit:    1000,
	}

	result, err := r.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return result.Policies, nil
}

// IncrementEvaluationCount increments the evaluation counter.
func (r *PostgresPolicyRepository) IncrementEvaluationCount(ctx context.Context, id string) error {
	query := `UPDATE policies.policies SET evaluation_count = evaluation_count + 1 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// IncrementMatchCount increments the match counter.
func (r *PostgresPolicyRepository) IncrementMatchCount(ctx context.Context, id string) error {
	query := `UPDATE policies.policies SET match_count = match_count + 1 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// UpdateLastEvaluated updates the last evaluated timestamp.
func (r *PostgresPolicyRepository) UpdateLastEvaluated(ctx context.Context, id string, timestamp time.Time) error {
	query := `UPDATE policies.policies SET last_evaluated_at = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, timestamp)
	return err
}
