package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// ============================================================================
// PostgreSQL Configuration
// ============================================================================

// PostgresConfig holds PostgreSQL connection configuration.
type PostgresConfig struct {
	Host            string        `json:"host" yaml:"host"`
	Port            int           `json:"port" yaml:"port"`
	Database        string        `json:"database" yaml:"database"`
	Username        string        `json:"username" yaml:"username"`
	Password        string        `json:"password" yaml:"password"`
	SSLMode         string        `json:"ssl_mode" yaml:"ssl_mode"`
	MaxOpenConns    int           `json:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time" yaml:"conn_max_idle_time"`
}

// DefaultPostgresConfig returns default PostgreSQL configuration.
func DefaultPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Host:            "localhost",
		Port:            5432,
		Database:        "siem",
		Username:        "siem_app",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: 30 * time.Minute,
	}
}

// DSN returns the connection string.
func (c PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.Host, c.Port, c.Database, c.Username, c.Password, c.SSLMode,
	)
}

// ============================================================================
// PostgreSQL Connection
// ============================================================================

// PostgresConn represents a PostgreSQL database connection.
type PostgresConn struct {
	db     *sqlx.DB
	config PostgresConfig
}

// NewPostgresConn creates a new PostgreSQL connection.
func NewPostgresConn(cfg PostgresConfig) (*PostgresConn, error) {
	db, err := sqlx.Connect("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	return &PostgresConn{
		db:     db,
		config: cfg,
	}, nil
}

// Close closes the PostgreSQL connection.
func (c *PostgresConn) Close() error {
	return c.db.Close()
}

// Ping tests the connection.
func (c *PostgresConn) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// IsHealthy returns true if the connection is healthy.
func (c *PostgresConn) IsHealthy(ctx context.Context) bool {
	return c.Ping(ctx) == nil
}

// DB returns the sqlx.DB instance.
func (c *PostgresConn) DB() *sqlx.DB {
	return c.db
}

// ============================================================================
// PostgreSQL Transaction
// ============================================================================

// pgTransaction implements Transaction interface.
type pgTransaction struct {
	tx *sqlx.Tx
}

func (t *pgTransaction) Commit() error {
	return t.tx.Commit()
}

func (t *pgTransaction) Rollback() error {
	return t.tx.Rollback()
}

// WithTransaction executes a function within a transaction.
func (c *PostgresConn) WithTransaction(ctx context.Context, fn TxFunc) error {
	tx, err := c.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	pgTx := &pgTransaction{tx: tx}

	if err := fn(ctx, pgTx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	return tx.Commit()
}

// ============================================================================
// PostgreSQL User Repository Implementation
// ============================================================================

// postgresUserRepository implements UserRepository.
type postgresUserRepository struct {
	conn *PostgresConn
}

// NewPostgresUserRepository creates a new PostgreSQL user repository.
func NewPostgresUserRepository(conn *PostgresConn) UserRepository {
	return &postgresUserRepository{conn: conn}
}

// Create creates a new user.
func (r *postgresUserRepository) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO auth.users (
			id, tenant_id, email, username, display_name, password_hash, role, status,
			mfa_enabled, created_at, updated_at
		) VALUES (
			COALESCE(NULLIF($1, ''), uuid_generate_v4()::text), $2, $3, $4, $5, $6, $7, $8,
			$9, COALESCE($10, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
		)
		RETURNING id, created_at, updated_at
	`

	err := r.conn.db.QueryRowContext(ctx, query,
		user.ID, user.TenantID, user.Email, user.Username, user.DisplayName,
		user.PasswordHash, user.Role, user.Status, user.MFAEnabled, user.CreatedAt,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID.
func (r *postgresUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, tenant_id, email, username, display_name, password_hash, role, status,
			mfa_enabled, last_login_at, failed_login_attempts, created_at, updated_at
		FROM auth.users
		WHERE id = $1 AND status != 'DELETED'
	`

	var user User
	err := r.conn.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email.
func (r *postgresUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, tenant_id, email, username, display_name, password_hash, role, status,
			mfa_enabled, last_login_at, failed_login_attempts, created_at, updated_at
		FROM auth.users
		WHERE email = $1 AND status != 'DELETED'
	`

	var user User
	err := r.conn.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username within a tenant.
func (r *postgresUserRepository) GetByUsername(ctx context.Context, tenantID, username string) (*User, error) {
	query := `
		SELECT id, tenant_id, email, username, display_name, password_hash, role, status,
			mfa_enabled, last_login_at, failed_login_attempts, created_at, updated_at
		FROM auth.users
		WHERE tenant_id = $1 AND username = $2 AND status != 'DELETED'
	`

	var user User
	err := r.conn.db.GetContext(ctx, &user, query, tenantID, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// Update updates a user.
func (r *postgresUserRepository) Update(ctx context.Context, user *User) error {
	query := `
		UPDATE auth.users
		SET email = $2, username = $3, display_name = $4, role = $5, status = $6,
			mfa_enabled = $7, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.conn.db.QueryRowContext(ctx, query,
		user.ID, user.Email, user.Username, user.DisplayName, user.Role,
		user.Status, user.MFAEnabled,
	).Scan(&user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// Delete soft-deletes a user.
func (r *postgresUserRepository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE auth.users
		SET status = 'DELETED', updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	result, err := r.conn.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// List retrieves users with filtering and pagination.
func (r *postgresUserRepository) List(ctx context.Context, opts QueryOptions) ([]*User, int, error) {
	// Build WHERE clause
	conditions := []string{"status != 'DELETED'"}
	args := []interface{}{}
	argIndex := 1

	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}

	for _, f := range opts.Filters {
		switch f.Operator {
		case OpEq:
			conditions = append(conditions, fmt.Sprintf("%s = $%d", f.Field, argIndex))
			args = append(args, f.Value)
			argIndex++
		case OpLike:
			conditions = append(conditions, fmt.Sprintf("%s ILIKE $%d", f.Field, argIndex))
			args = append(args, "%"+f.Value.(string)+"%")
			argIndex++
		case OpIn:
			values := f.Value.([]string)
			placeholders := make([]string, len(values))
			for i, v := range values {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, v)
				argIndex++
			}
			conditions = append(conditions, fmt.Sprintf("%s IN (%s)", f.Field, strings.Join(placeholders, ", ")))
		}
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM auth.users WHERE %s", whereClause)
	var total int
	if err := r.conn.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Build ORDER BY
	orderBy := "created_at DESC"
	if len(opts.Sorts) > 0 {
		orders := make([]string, len(opts.Sorts))
		for i, s := range opts.Sorts {
			orders[i] = fmt.Sprintf("%s %s", s.Field, s.Order)
		}
		orderBy = strings.Join(orders, ", ")
	}

	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT id, tenant_id, email, username, display_name, role, status,
			mfa_enabled, last_login_at, failed_login_attempts, created_at, updated_at
		FROM auth.users
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, opts.Pagination.Limit(), opts.Pagination.Offset())

	var users []*User
	if err := r.conn.db.SelectContext(ctx, &users, dataQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}

// Exists checks if a user exists.
func (r *postgresUserRepository) Exists(ctx context.Context, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM auth.users WHERE id = $1 AND status != 'DELETED')`
	var exists bool
	err := r.conn.db.GetContext(ctx, &exists, query, id)
	return exists, err
}

// UpdatePassword updates user password.
func (r *postgresUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	query := `
		UPDATE auth.users
		SET password_hash = $2, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	_, err := r.conn.db.ExecContext(ctx, query, userID, passwordHash)
	return err
}

// UpdateLastLogin updates last login information.
func (r *postgresUserRepository) UpdateLastLogin(ctx context.Context, userID, ip string) error {
	query := `
		UPDATE auth.users
		SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = $2, failed_login_attempts = 0
		WHERE id = $1
	`
	_, err := r.conn.db.ExecContext(ctx, query, userID, ip)
	return err
}

// IncrementFailedLogin increments failed login counter.
func (r *postgresUserRepository) IncrementFailedLogin(ctx context.Context, userID string) error {
	query := `
		UPDATE auth.users
		SET failed_login_attempts = failed_login_attempts + 1
		WHERE id = $1
	`
	_, err := r.conn.db.ExecContext(ctx, query, userID)
	return err
}

// ResetFailedLogin resets failed login counter.
func (r *postgresUserRepository) ResetFailedLogin(ctx context.Context, userID string) error {
	query := `UPDATE auth.users SET failed_login_attempts = 0 WHERE id = $1`
	_, err := r.conn.db.ExecContext(ctx, query, userID)
	return err
}

// ListByTenant retrieves users for a tenant.
func (r *postgresUserRepository) ListByTenant(ctx context.Context, tenantID string, opts QueryOptions) ([]*User, int, error) {
	opts.TenantID = tenantID
	return r.List(ctx, opts)
}

// GetUserGroups retrieves group IDs for a user.
func (r *postgresUserRepository) GetUserGroups(ctx context.Context, userID string) ([]string, error) {
	query := `SELECT group_id FROM auth.user_group_memberships WHERE user_id = $1`
	var groups []string
	err := r.conn.db.SelectContext(ctx, &groups, query, userID)
	return groups, err
}

// ============================================================================
// PostgreSQL Tenant Repository Implementation
// ============================================================================

// postgresTenantRepository implements TenantRepository.
type postgresTenantRepository struct {
	conn *PostgresConn
}

// NewPostgresTenantRepository creates a new PostgreSQL tenant repository.
func NewPostgresTenantRepository(conn *PostgresConn) TenantRepository {
	return &postgresTenantRepository{conn: conn}
}

// Create creates a new tenant.
func (r *postgresTenantRepository) Create(ctx context.Context, tenant *Tenant) error {
	query := `
		INSERT INTO meta.tenants (
			id, name, slug, display_name, tier, status, max_users, max_events_per_day,
			retention_days, features, settings, created_at, updated_at
		) VALUES (
			COALESCE(NULLIF($1, ''), uuid_generate_v4()::text), $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, COALESCE($12, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
		)
		RETURNING id, created_at, updated_at
	`

	err := r.conn.db.QueryRowContext(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.DisplayName, tenant.Tier, tenant.Status,
		tenant.MaxUsers, tenant.MaxEventsPerDay, tenant.RetentionDays, tenant.Features,
		tenant.Settings, tenant.CreatedAt,
	).Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetByID retrieves a tenant by ID.
func (r *postgresTenantRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, display_name, tier, status, max_users, max_events_per_day,
			retention_days, features, settings, created_at, updated_at
		FROM meta.tenants
		WHERE id = $1 AND status != 'DELETED'
	`

	var tenant Tenant
	err := r.conn.db.GetContext(ctx, &tenant, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return &tenant, nil
}

// GetBySlug retrieves a tenant by slug.
func (r *postgresTenantRepository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	query := `
		SELECT id, name, slug, display_name, tier, status, max_users, max_events_per_day,
			retention_days, features, settings, created_at, updated_at
		FROM meta.tenants
		WHERE slug = $1 AND status != 'DELETED'
	`

	var tenant Tenant
	err := r.conn.db.GetContext(ctx, &tenant, query, slug)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	return &tenant, nil
}

// Update updates a tenant.
func (r *postgresTenantRepository) Update(ctx context.Context, tenant *Tenant) error {
	query := `
		UPDATE meta.tenants
		SET name = $2, display_name = $3, tier = $4, status = $5, max_users = $6,
			max_events_per_day = $7, retention_days = $8, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at
	`

	err := r.conn.db.QueryRowContext(ctx, query,
		tenant.ID, tenant.Name, tenant.DisplayName, tenant.Tier, tenant.Status,
		tenant.MaxUsers, tenant.MaxEventsPerDay, tenant.RetentionDays,
	).Scan(&tenant.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	return nil
}

// Delete soft-deletes a tenant.
func (r *postgresTenantRepository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE meta.tenants
		SET status = 'DELETED', deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	_, err := r.conn.db.ExecContext(ctx, query, id)
	return err
}

// List retrieves tenants with filtering and pagination.
func (r *postgresTenantRepository) List(ctx context.Context, opts QueryOptions) ([]*Tenant, int, error) {
	conditions := []string{"status != 'DELETED'"}
	args := []interface{}{}
	argIndex := 1

	for _, f := range opts.Filters {
		switch f.Operator {
		case OpEq:
			conditions = append(conditions, fmt.Sprintf("%s = $%d", f.Field, argIndex))
			args = append(args, f.Value)
			argIndex++
		}
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM meta.tenants WHERE %s", whereClause)
	var total int
	if err := r.conn.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	// Data
	orderBy := "created_at DESC"
	dataQuery := fmt.Sprintf(`
		SELECT id, name, slug, display_name, tier, status, max_users, max_events_per_day,
			retention_days, features, settings, created_at, updated_at
		FROM meta.tenants
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, opts.Pagination.Limit(), opts.Pagination.Offset())

	var tenants []*Tenant
	if err := r.conn.db.SelectContext(ctx, &tenants, dataQuery, args...); err != nil {
		return nil, 0, err
	}

	return tenants, total, nil
}

// Exists checks if a tenant exists.
func (r *postgresTenantRepository) Exists(ctx context.Context, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM meta.tenants WHERE id = $1 AND status != 'DELETED')`
	var exists bool
	err := r.conn.db.GetContext(ctx, &exists, query, id)
	return exists, err
}

// UpdateFeatures updates tenant features.
func (r *postgresTenantRepository) UpdateFeatures(ctx context.Context, tenantID string, features map[string]bool) error {
	query := `UPDATE meta.tenants SET features = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, features)
	return err
}

// UpdateSettings updates tenant settings.
func (r *postgresTenantRepository) UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error {
	query := `UPDATE meta.tenants SET settings = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, settings)
	return err
}

// GetUsage retrieves tenant usage for a date.
func (r *postgresTenantRepository) GetUsage(ctx context.Context, tenantID string, date time.Time) (*TenantUsage, error) {
	query := `
		SELECT tenant_id, date, events_ingested, bytes_ingested, active_users,
			api_calls, alerts_generated
		FROM meta.tenant_usage
		WHERE tenant_id = $1 AND date = $2
	`

	var usage TenantUsage
	err := r.conn.db.GetContext(ctx, &usage, query, tenantID, date)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &usage, nil
}

// RecordUsage records tenant usage.
func (r *postgresTenantRepository) RecordUsage(ctx context.Context, usage *TenantUsage) error {
	query := `
		INSERT INTO meta.tenant_usage (
			tenant_id, date, events_ingested, bytes_ingested, active_users, api_calls, alerts_generated
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, date) DO UPDATE SET
			events_ingested = tenant_usage.events_ingested + EXCLUDED.events_ingested,
			bytes_ingested = tenant_usage.bytes_ingested + EXCLUDED.bytes_ingested,
			active_users = GREATEST(tenant_usage.active_users, EXCLUDED.active_users),
			api_calls = tenant_usage.api_calls + EXCLUDED.api_calls,
			alerts_generated = tenant_usage.alerts_generated + EXCLUDED.alerts_generated
	`

	_, err := r.conn.db.ExecContext(ctx, query,
		usage.TenantID, usage.Date, usage.EventsIngested, usage.BytesIngested,
		usage.ActiveUsers, usage.APICalls, usage.AlertsGenerated,
	)

	return err
}

// ============================================================================
// PostgreSQL Detection Rule Repository Implementation
// ============================================================================

// postgresDetectionRuleRepository implements DetectionRuleRepository.
type postgresDetectionRuleRepository struct {
	conn *PostgresConn
}

// NewPostgresDetectionRuleRepository creates a new PostgreSQL detection rule repository.
func NewPostgresDetectionRuleRepository(conn *PostgresConn) DetectionRuleRepository {
	return &postgresDetectionRuleRepository{conn: conn}
}

// Create creates a new detection rule.
func (r *postgresDetectionRuleRepository) Create(ctx context.Context, rule *DetectionRule) error {
	query := `
		INSERT INTO meta.detection_rules (
			id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		) VALUES (
			COALESCE(NULLIF($1, ''), uuid_generate_v4()::text), $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, COALESCE($16, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
		)
		RETURNING id, created_at, updated_at
	`

	err := r.conn.db.QueryRowContext(ctx, query,
		rule.ID, rule.TenantID, rule.RuleID, rule.Name, rule.Description, rule.RuleType,
		rule.Severity, rule.RuleContent, rule.CompiledQuery, rule.Status, rule.IsEnabled,
		rule.MITRETactics, rule.MITRETechniques, rule.Tags, rule.Version, rule.CreatedAt,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)

	return err
}

// GetByID retrieves a rule by ID.
func (r *postgresDetectionRuleRepository) GetByID(ctx context.Context, id string) (*DetectionRule, error) {
	query := `
		SELECT id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		FROM meta.detection_rules
		WHERE id = $1 AND status != 'ARCHIVED'
	`

	var rule DetectionRule
	err := r.conn.db.GetContext(ctx, &rule, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &rule, nil
}

// GetByRuleID retrieves a rule by rule_id.
func (r *postgresDetectionRuleRepository) GetByRuleID(ctx context.Context, tenantID, ruleID string) (*DetectionRule, error) {
	query := `
		SELECT id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		FROM meta.detection_rules
		WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true AND status != 'ARCHIVED'
	`

	var rule DetectionRule
	err := r.conn.db.GetContext(ctx, &rule, query, tenantID, ruleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &rule, nil
}

// Update updates a detection rule.
func (r *postgresDetectionRuleRepository) Update(ctx context.Context, rule *DetectionRule) error {
	query := `
		UPDATE meta.detection_rules
		SET name = $2, description = $3, rule_type = $4, severity = $5, rule_content = $6,
			compiled_query = $7, mitre_tactics = $8, mitre_techniques = $9, tags = $10,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at
	`

	return r.conn.db.QueryRowContext(ctx, query,
		rule.ID, rule.Name, rule.Description, rule.RuleType, rule.Severity, rule.RuleContent,
		rule.CompiledQuery, rule.MITRETactics, rule.MITRETechniques, rule.Tags,
	).Scan(&rule.UpdatedAt)
}

// Delete soft-deletes a detection rule.
func (r *postgresDetectionRuleRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE meta.detection_rules SET status = 'ARCHIVED', updated_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := r.conn.db.ExecContext(ctx, query, id)
	return err
}

// List retrieves rules with filtering and pagination.
func (r *postgresDetectionRuleRepository) List(ctx context.Context, opts QueryOptions) ([]*DetectionRule, int, error) {
	conditions := []string{"status != 'ARCHIVED'", "is_latest = true"}
	args := []interface{}{}
	argIndex := 1

	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM meta.detection_rules WHERE %s", whereClause)
	var total int
	if err := r.conn.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	// Data
	dataQuery := fmt.Sprintf(`
		SELECT id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		FROM meta.detection_rules
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, opts.Pagination.Limit(), opts.Pagination.Offset())

	var rules []*DetectionRule
	if err := r.conn.db.SelectContext(ctx, &rules, dataQuery, args...); err != nil {
		return nil, 0, err
	}

	return rules, total, nil
}

// Exists checks if a rule exists.
func (r *postgresDetectionRuleRepository) Exists(ctx context.Context, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM meta.detection_rules WHERE id = $1 AND status != 'ARCHIVED')`
	var exists bool
	err := r.conn.db.GetContext(ctx, &exists, query, id)
	return exists, err
}

// ListEnabled retrieves enabled rules for a tenant.
func (r *postgresDetectionRuleRepository) ListEnabled(ctx context.Context, tenantID string) ([]*DetectionRule, error) {
	query := `
		SELECT id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		FROM meta.detection_rules
		WHERE tenant_id = $1 AND is_enabled = true AND status = 'ENABLED' AND is_latest = true
		ORDER BY severity DESC, name
	`

	var rules []*DetectionRule
	err := r.conn.db.SelectContext(ctx, &rules, query, tenantID)
	return rules, err
}

// UpdateStatus updates rule status.
func (r *postgresDetectionRuleRepository) UpdateStatus(ctx context.Context, tenantID, ruleID, status string) error {
	query := `
		UPDATE meta.detection_rules
		SET status = $3, updated_at = CURRENT_TIMESTAMP
		WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true
	`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, ruleID, status)
	return err
}

// Enable enables a rule.
func (r *postgresDetectionRuleRepository) Enable(ctx context.Context, tenantID, ruleID string) error {
	query := `
		UPDATE meta.detection_rules
		SET is_enabled = true, status = 'ENABLED', updated_at = CURRENT_TIMESTAMP
		WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true
	`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, ruleID)
	return err
}

// Disable disables a rule.
func (r *postgresDetectionRuleRepository) Disable(ctx context.Context, tenantID, ruleID string) error {
	query := `
		UPDATE meta.detection_rules
		SET is_enabled = false, status = 'DISABLED', updated_at = CURRENT_TIMESTAMP
		WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true
	`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, ruleID)
	return err
}

// IncrementExecutions increments rule execution counters.
func (r *postgresDetectionRuleRepository) IncrementExecutions(ctx context.Context, tenantID, ruleID string, matches int64) error {
	query := `
		UPDATE meta.detection_rules
		SET executions_total = executions_total + 1,
			matches_total = matches_total + $3,
			last_executed_at = CURRENT_TIMESTAMP
		WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true
	`
	_, err := r.conn.db.ExecContext(ctx, query, tenantID, ruleID, matches)
	return err
}

// CreateVersion creates a new version of a rule.
func (r *postgresDetectionRuleRepository) CreateVersion(ctx context.Context, rule *DetectionRule) error {
	// Start transaction
	return r.conn.WithTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		pgTx := tx.(*pgTransaction)

		// Set old version as not latest
		_, err := pgTx.tx.ExecContext(ctx, `
			UPDATE meta.detection_rules
			SET is_latest = false
			WHERE tenant_id = $1 AND rule_id = $2 AND is_latest = true
		`, rule.TenantID, rule.RuleID)
		if err != nil {
			return err
		}

		// Insert new version
		rule.ID = "" // Generate new ID
		rule.Version++
		return r.Create(ctx, rule)
	})
}

// GetVersions retrieves all versions of a rule.
func (r *postgresDetectionRuleRepository) GetVersions(ctx context.Context, tenantID, ruleID string) ([]*DetectionRule, error) {
	query := `
		SELECT id, tenant_id, rule_id, name, description, rule_type, severity, rule_content,
			compiled_query, status, is_enabled, mitre_tactics, mitre_techniques, tags,
			version, created_at, updated_at
		FROM meta.detection_rules
		WHERE tenant_id = $1 AND rule_id = $2
		ORDER BY version DESC
	`

	var rules []*DetectionRule
	err := r.conn.db.SelectContext(ctx, &rules, query, tenantID, ruleID)
	return rules, err
}
