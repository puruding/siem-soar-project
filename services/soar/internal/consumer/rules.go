// Package consumer provides Kafka consumer for ML-enriched alerts.
package consumer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// PlaybookRule defines when to trigger a playbook based on alert/ML conditions.
type PlaybookRule struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	PlaybookID      string          `json:"playbook_id"`
	Priority        int             `json:"priority"`        // Lower = higher priority
	Enabled         bool            `json:"enabled"`
	RequireApproval bool            `json:"require_approval"` // Human-in-the-loop
	Conditions      []RuleCondition `json:"conditions"`       // CEL expressions
	MLConditions    *MLConditions   `json:"ml_conditions,omitempty"`
	TenantID        string          `json:"tenant_id,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// MLConditions defines ML-specific conditions for rule matching.
type MLConditions struct {
	MinRiskScore       *float64 `json:"min_risk_score,omitempty"`       // >= threshold
	MaxRiskScore       *float64 `json:"max_risk_score,omitempty"`       // <= threshold
	Priorities         []string `json:"priorities,omitempty"`           // critical, high
	ExcludeFP          bool     `json:"exclude_fp"`                     // Skip if is_false_positive
	MinFPConfidence    *float64 `json:"min_fp_confidence,omitempty"`    // FP confidence threshold
	RequiredTactics    []string `json:"required_tactics,omitempty"`     // MITRE tactics
	RequiredTechniques []string `json:"required_techniques,omitempty"` // MITRE techniques
}

// RuleCondition defines a condition for matching alerts.
type RuleCondition struct {
	Field    string `json:"field"`    // CEL field path: alert.severity, ml.risk_score
	Operator string `json:"operator"` // eq, neq, gt, lt, in, contains, matches
	Value    any    `json:"value"`
}

// PlaybookRuleStore manages playbook mapping rules.
type PlaybookRuleStore struct {
	db        *sql.DB
	cache     *redis.Client
	cacheTTL  time.Duration
	logger    *slog.Logger

	mu          sync.RWMutex
	memoryCache map[string][]*PlaybookRule // tenant_id -> rules
	lastRefresh time.Time
}

// PlaybookRuleStoreConfig holds configuration for the store.
type PlaybookRuleStoreConfig struct {
	CacheTTL       time.Duration `json:"cache_ttl"`
	RefreshOnStart bool          `json:"refresh_on_start"`
}

// DefaultRuleStoreConfig returns default configuration.
func DefaultRuleStoreConfig() PlaybookRuleStoreConfig {
	return PlaybookRuleStoreConfig{
		CacheTTL:       5 * time.Minute,
		RefreshOnStart: true,
	}
}

// NewPlaybookRuleStore creates a new PlaybookRuleStore instance.
func NewPlaybookRuleStore(db *sql.DB, cache *redis.Client, logger *slog.Logger) *PlaybookRuleStore {
	if logger == nil {
		logger = slog.Default()
	}

	store := &PlaybookRuleStore{
		db:          db,
		cache:       cache,
		cacheTTL:    5 * time.Minute,
		logger:      logger,
		memoryCache: make(map[string][]*PlaybookRule),
	}

	return store
}

// FindMatchingRules finds all rules that match the given alert.
func (s *PlaybookRuleStore) FindMatchingRules(ctx context.Context, alert *MLEnrichedAlert) ([]*PlaybookRule, error) {
	// Get all enabled rules for tenant
	rules, err := s.getEnabledRules(ctx, alert.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled rules: %w", err)
	}

	// Filter rules by conditions
	var matchingRules []*PlaybookRule
	for _, rule := range rules {
		if s.ruleMatches(rule, alert) {
			matchingRules = append(matchingRules, rule)
		}
	}

	// Sort by priority (lower = higher priority)
	sort.Slice(matchingRules, func(i, j int) bool {
		return matchingRules[i].Priority < matchingRules[j].Priority
	})

	return matchingRules, nil
}

// getEnabledRules retrieves all enabled rules for a tenant.
func (s *PlaybookRuleStore) getEnabledRules(ctx context.Context, tenantID string) ([]*PlaybookRule, error) {
	// Check memory cache first
	s.mu.RLock()
	if rules, ok := s.memoryCache[tenantID]; ok && time.Since(s.lastRefresh) < s.cacheTTL {
		s.mu.RUnlock()
		return rules, nil
	}
	s.mu.RUnlock()

	// Check Redis cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("soar:rules:enabled:%s", tenantID)
		data, err := s.cache.Get(ctx, cacheKey).Bytes()
		if err == nil {
			var rules []*PlaybookRule
			if err := json.Unmarshal(data, &rules); err == nil {
				// Update memory cache
				s.mu.Lock()
				s.memoryCache[tenantID] = rules
				s.lastRefresh = time.Now()
				s.mu.Unlock()
				return rules, nil
			}
		}
	}

	// Load from database
	rules, err := s.loadRulesFromDB(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Update caches
	s.mu.Lock()
	s.memoryCache[tenantID] = rules
	s.lastRefresh = time.Now()
	s.mu.Unlock()

	if s.cache != nil {
		cacheKey := fmt.Sprintf("soar:rules:enabled:%s", tenantID)
		data, _ := json.Marshal(rules)
		s.cache.Set(ctx, cacheKey, data, s.cacheTTL)
	}

	return rules, nil
}

// loadRulesFromDB loads enabled rules from the database.
func (s *PlaybookRuleStore) loadRulesFromDB(ctx context.Context, tenantID string) ([]*PlaybookRule, error) {
	if s.db == nil {
		// Return empty list if no database
		return []*PlaybookRule{}, nil
	}

	query := `
		SELECT id, name, description, playbook_id, priority, enabled,
		       require_approval, conditions, ml_conditions, tenant_id,
		       created_at, updated_at
		FROM soar.playbook_rules
		WHERE enabled = true
	`

	args := []interface{}{}
	if tenantID != "" {
		query += " AND (tenant_id = $1 OR tenant_id IS NULL)"
		args = append(args, tenantID)
	}

	query += " ORDER BY priority ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var rules []*PlaybookRule
	for rows.Next() {
		rule := &PlaybookRule{}
		var conditionsJSON, mlConditionsJSON sql.NullString
		var tenantIDNull sql.NullString

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.PlaybookID,
			&rule.Priority,
			&rule.Enabled,
			&rule.RequireApproval,
			&conditionsJSON,
			&mlConditionsJSON,
			&tenantIDNull,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}

		// Parse conditions JSON
		if conditionsJSON.Valid {
			if err := json.Unmarshal([]byte(conditionsJSON.String), &rule.Conditions); err != nil {
				s.logger.Warn("Failed to parse conditions JSON", "rule_id", rule.ID, "error", err)
			}
		}

		// Parse ML conditions JSON
		if mlConditionsJSON.Valid {
			rule.MLConditions = &MLConditions{}
			if err := json.Unmarshal([]byte(mlConditionsJSON.String), rule.MLConditions); err != nil {
				s.logger.Warn("Failed to parse ML conditions JSON", "rule_id", rule.ID, "error", err)
				rule.MLConditions = nil
			}
		}

		if tenantIDNull.Valid {
			rule.TenantID = tenantIDNull.String
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// ruleMatches checks if a rule matches the given alert.
func (s *PlaybookRuleStore) ruleMatches(rule *PlaybookRule, alert *MLEnrichedAlert) bool {
	// Check ML conditions first
	if rule.MLConditions != nil && !s.mlConditionsMatch(rule.MLConditions, alert) {
		return false
	}

	// Check regular conditions
	for _, cond := range rule.Conditions {
		if !s.conditionMatches(cond, alert) {
			return false
		}
	}

	return true
}

// mlConditionsMatch checks if ML conditions match the alert.
func (s *PlaybookRuleStore) mlConditionsMatch(mlCond *MLConditions, alert *MLEnrichedAlert) bool {
	ml := alert.MLAnalysis
	if ml == nil {
		// If no ML analysis, only match if no ML conditions are set
		return mlCond.MinRiskScore == nil &&
			mlCond.MaxRiskScore == nil &&
			len(mlCond.Priorities) == 0 &&
			len(mlCond.RequiredTactics) == 0 &&
			len(mlCond.RequiredTechniques) == 0
	}

	// Check exclude FP
	if mlCond.ExcludeFP && ml.IsFalsePositive {
		return false
	}

	// Check FP confidence threshold
	if mlCond.MinFPConfidence != nil && ml.IsFalsePositive {
		if ml.FPConfidence < *mlCond.MinFPConfidence {
			return false
		}
	}

	// Check min risk score
	if mlCond.MinRiskScore != nil && ml.RiskScore < *mlCond.MinRiskScore {
		return false
	}

	// Check max risk score
	if mlCond.MaxRiskScore != nil && ml.RiskScore > *mlCond.MaxRiskScore {
		return false
	}

	// Check priorities
	if len(mlCond.Priorities) > 0 {
		found := false
		for _, p := range mlCond.Priorities {
			if strings.EqualFold(p, ml.Priority) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check required tactics
	if len(mlCond.RequiredTactics) > 0 {
		if !hasAnyMatch(ml.MITRETactics, mlCond.RequiredTactics) {
			return false
		}
	}

	// Check required techniques
	if len(mlCond.RequiredTechniques) > 0 {
		if !hasAnyMatch(ml.MITRETechniques, mlCond.RequiredTechniques) {
			return false
		}
	}

	return true
}

// conditionMatches checks if a single condition matches the alert.
func (s *PlaybookRuleStore) conditionMatches(cond RuleCondition, alert *MLEnrichedAlert) bool {
	// Get field value from alert
	value := s.getFieldValue(cond.Field, alert)
	if value == nil {
		return cond.Operator == "not_exists" || cond.Operator == "neq"
	}

	// Evaluate condition
	switch cond.Operator {
	case "eq":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", cond.Value)
	case "neq":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", cond.Value)
	case "gt":
		return compareNumbers(value, cond.Value) > 0
	case "lt":
		return compareNumbers(value, cond.Value) < 0
	case "gte":
		return compareNumbers(value, cond.Value) >= 0
	case "lte":
		return compareNumbers(value, cond.Value) <= 0
	case "in":
		return isInList(value, cond.Value)
	case "not_in":
		return !isInList(value, cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case "not_contains":
		return !strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", cond.Value))
	case "exists":
		return value != nil
	case "not_exists":
		return value == nil
	default:
		s.logger.Warn("Unknown operator", "operator", cond.Operator)
		return false
	}
}

// getFieldValue extracts a field value from the alert using dot notation.
func (s *PlaybookRuleStore) getFieldValue(field string, alert *MLEnrichedAlert) interface{} {
	parts := strings.Split(field, ".")
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "alert":
		if len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "id":
			return alert.AlertID
		case "tenant_id":
			return alert.TenantID
		case "rule_id":
			return alert.RuleID
		case "rule_name":
			return alert.RuleName
		case "severity":
			return alert.Severity
		case "title":
			return alert.Title
		case "description":
			return alert.Description
		}

	case "ml":
		if alert.MLAnalysis == nil || len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "risk_score":
			return alert.MLAnalysis.RiskScore
		case "priority":
			return alert.MLAnalysis.Priority
		case "is_false_positive":
			return alert.MLAnalysis.IsFalsePositive
		case "fp_confidence":
			return alert.MLAnalysis.FPConfidence
		case "tactics":
			return alert.MLAnalysis.MITRETactics
		case "techniques":
			return alert.MLAnalysis.MITRETechniques
		}
		if alert.MLAnalysis.Classification != nil {
			switch parts[1] {
			case "category":
				return alert.MLAnalysis.Classification.Category
			case "confidence":
				return alert.MLAnalysis.Classification.Confidence
			}
		}

	case "attack":
		if alert.ATTACKMapping == nil || len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "tactics":
			return alert.ATTACKMapping.Tactics
		case "techniques":
			return alert.ATTACKMapping.Techniques
		}

	case "matched_fields":
		if len(parts) < 2 {
			return nil
		}
		if alert.MatchedFields != nil {
			return alert.MatchedFields[parts[1]]
		}
	}

	return nil
}

// Create creates a new playbook rule.
func (s *PlaybookRuleStore) Create(ctx context.Context, rule *PlaybookRule) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	conditionsJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	var mlConditionsJSON []byte
	if rule.MLConditions != nil {
		mlConditionsJSON, err = json.Marshal(rule.MLConditions)
		if err != nil {
			return fmt.Errorf("failed to marshal ML conditions: %w", err)
		}
	}

	query := `
		INSERT INTO soar.playbook_rules
		(id, name, description, playbook_id, priority, enabled, require_approval,
		 conditions, ml_conditions, tenant_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = s.db.ExecContext(ctx, query,
		rule.ID,
		rule.Name,
		rule.Description,
		rule.PlaybookID,
		rule.Priority,
		rule.Enabled,
		rule.RequireApproval,
		conditionsJSON,
		mlConditionsJSON,
		sql.NullString{String: rule.TenantID, Valid: rule.TenantID != ""},
		rule.CreatedAt,
		rule.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert rule: %w", err)
	}

	// Invalidate cache
	s.invalidateCache(ctx, rule.TenantID)

	return nil
}

// Update updates an existing playbook rule.
func (s *PlaybookRuleStore) Update(ctx context.Context, rule *PlaybookRule) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}

	rule.UpdatedAt = time.Now().UTC()

	conditionsJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	var mlConditionsJSON []byte
	if rule.MLConditions != nil {
		mlConditionsJSON, err = json.Marshal(rule.MLConditions)
		if err != nil {
			return fmt.Errorf("failed to marshal ML conditions: %w", err)
		}
	}

	query := `
		UPDATE soar.playbook_rules
		SET name = $2, description = $3, playbook_id = $4, priority = $5,
		    enabled = $6, require_approval = $7, conditions = $8,
		    ml_conditions = $9, updated_at = $10
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query,
		rule.ID,
		rule.Name,
		rule.Description,
		rule.PlaybookID,
		rule.Priority,
		rule.Enabled,
		rule.RequireApproval,
		conditionsJSON,
		mlConditionsJSON,
		rule.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("rule not found: %s", rule.ID)
	}

	// Invalidate cache
	s.invalidateCache(ctx, rule.TenantID)

	return nil
}

// Delete deletes a playbook rule.
func (s *PlaybookRuleStore) Delete(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}

	// Get tenant ID before delete for cache invalidation
	var tenantID sql.NullString
	s.db.QueryRowContext(ctx, "SELECT tenant_id FROM soar.playbook_rules WHERE id = $1", id).Scan(&tenantID)

	query := `DELETE FROM soar.playbook_rules WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}

	// Invalidate cache
	if tenantID.Valid {
		s.invalidateCache(ctx, tenantID.String)
	} else {
		s.invalidateCache(ctx, "")
	}

	return nil
}

// RuleFilter defines filters for listing rules.
type RuleFilter struct {
	PlaybookID string `json:"playbook_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	Enabled    *bool  `json:"enabled,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// List lists playbook rules with optional filters.
func (s *PlaybookRuleStore) List(ctx context.Context, filter *RuleFilter) ([]*PlaybookRule, error) {
	if s.db == nil {
		return []*PlaybookRule{}, nil
	}

	query := `
		SELECT id, name, description, playbook_id, priority, enabled,
		       require_approval, conditions, ml_conditions, tenant_id,
		       created_at, updated_at
		FROM soar.playbook_rules
		WHERE 1=1
	`

	args := []interface{}{}
	argNum := 1

	if filter != nil {
		if filter.PlaybookID != "" {
			query += fmt.Sprintf(" AND playbook_id = $%d", argNum)
			args = append(args, filter.PlaybookID)
			argNum++
		}

		if filter.TenantID != "" {
			query += fmt.Sprintf(" AND (tenant_id = $%d OR tenant_id IS NULL)", argNum)
			args = append(args, filter.TenantID)
			argNum++
		}

		if filter.Enabled != nil {
			query += fmt.Sprintf(" AND enabled = $%d", argNum)
			args = append(args, *filter.Enabled)
			argNum++
		}
	}

	query += " ORDER BY priority ASC, created_at DESC"

	if filter != nil && filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argNum)
		args = append(args, filter.Limit)
		argNum++

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argNum)
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var rules []*PlaybookRule
	for rows.Next() {
		rule := &PlaybookRule{}
		var conditionsJSON, mlConditionsJSON sql.NullString
		var tenantIDNull sql.NullString

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.PlaybookID,
			&rule.Priority,
			&rule.Enabled,
			&rule.RequireApproval,
			&conditionsJSON,
			&mlConditionsJSON,
			&tenantIDNull,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}

		if conditionsJSON.Valid {
			json.Unmarshal([]byte(conditionsJSON.String), &rule.Conditions)
		}

		if mlConditionsJSON.Valid {
			rule.MLConditions = &MLConditions{}
			json.Unmarshal([]byte(mlConditionsJSON.String), rule.MLConditions)
		}

		if tenantIDNull.Valid {
			rule.TenantID = tenantIDNull.String
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// Get retrieves a single rule by ID.
func (s *PlaybookRuleStore) Get(ctx context.Context, id string) (*PlaybookRule, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	query := `
		SELECT id, name, description, playbook_id, priority, enabled,
		       require_approval, conditions, ml_conditions, tenant_id,
		       created_at, updated_at
		FROM soar.playbook_rules
		WHERE id = $1
	`

	rule := &PlaybookRule{}
	var conditionsJSON, mlConditionsJSON sql.NullString
	var tenantIDNull sql.NullString

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.PlaybookID,
		&rule.Priority,
		&rule.Enabled,
		&rule.RequireApproval,
		&conditionsJSON,
		&mlConditionsJSON,
		&tenantIDNull,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}

	if conditionsJSON.Valid {
		json.Unmarshal([]byte(conditionsJSON.String), &rule.Conditions)
	}

	if mlConditionsJSON.Valid {
		rule.MLConditions = &MLConditions{}
		json.Unmarshal([]byte(mlConditionsJSON.String), rule.MLConditions)
	}

	if tenantIDNull.Valid {
		rule.TenantID = tenantIDNull.String
	}

	return rule, nil
}

// invalidateCache invalidates the cache for a tenant.
func (s *PlaybookRuleStore) invalidateCache(ctx context.Context, tenantID string) {
	// Clear memory cache
	s.mu.Lock()
	delete(s.memoryCache, tenantID)
	s.mu.Unlock()

	// Clear Redis cache
	if s.cache != nil {
		cacheKey := fmt.Sprintf("soar:rules:enabled:%s", tenantID)
		s.cache.Del(ctx, cacheKey)
	}
}

// RefreshCache forces a cache refresh.
func (s *PlaybookRuleStore) RefreshCache(ctx context.Context) error {
	s.mu.Lock()
	s.memoryCache = make(map[string][]*PlaybookRule)
	s.lastRefresh = time.Time{}
	s.mu.Unlock()

	// Clear all Redis cache keys
	if s.cache != nil {
		pattern := "soar:rules:enabled:*"
		var cursor uint64
		for {
			keys, nextCursor, err := s.cache.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				return fmt.Errorf("failed to scan cache keys: %w", err)
			}
			if len(keys) > 0 {
				s.cache.Del(ctx, keys...)
			}
			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}
	}

	return nil
}

// Helper functions

func hasAnyMatch(list1, list2 []string) bool {
	for _, item1 := range list1 {
		for _, item2 := range list2 {
			if strings.EqualFold(item1, item2) {
				return true
			}
		}
	}
	return false
}

func compareNumbers(a, b interface{}) int {
	af := toFloat64(a)
	bf := toFloat64(b)

	if af < bf {
		return -1
	}
	if af > bf {
		return 1
	}
	return 0
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case int32:
		return float64(val)
	case string:
		var f float64
		fmt.Sscanf(val, "%f", &f)
		return f
	}
	return 0
}

func isInList(value interface{}, list interface{}) bool {
	valStr := fmt.Sprintf("%v", value)

	switch l := list.(type) {
	case []interface{}:
		for _, item := range l {
			if fmt.Sprintf("%v", item) == valStr {
				return true
			}
		}
	case []string:
		for _, item := range l {
			if item == valStr {
				return true
			}
		}
	case string:
		// Comma-separated list
		items := strings.Split(l, ",")
		for _, item := range items {
			if strings.TrimSpace(item) == valStr {
				return true
			}
		}
	}

	return false
}
