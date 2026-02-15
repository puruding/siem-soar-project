package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ============================================================================
// ClickHouse Configuration
// ============================================================================

// ClickHouseConfig holds ClickHouse connection configuration.
type ClickHouseConfig struct {
	Hosts             []string      `json:"hosts" yaml:"hosts"`
	Database          string        `json:"database" yaml:"database"`
	Username          string        `json:"username" yaml:"username"`
	Password          string        `json:"password" yaml:"password"`
	Debug             bool          `json:"debug" yaml:"debug"`
	DialTimeout       time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	MaxOpenConns      int           `json:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns      int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime   time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
	Compression       string        `json:"compression" yaml:"compression"` // none, lz4, zstd
	AsyncInsert       bool          `json:"async_insert" yaml:"async_insert"`
	WaitForAsyncInsert bool         `json:"wait_for_async_insert" yaml:"wait_for_async_insert"`
}

// DefaultClickHouseConfig returns default ClickHouse configuration.
func DefaultClickHouseConfig() ClickHouseConfig {
	return ClickHouseConfig{
		Hosts:             []string{"localhost:9000"},
		Database:          "siem",
		Username:          "siem_app",
		DialTimeout:       10 * time.Second,
		MaxOpenConns:      20,
		MaxIdleConns:      5,
		ConnMaxLifetime:   time.Hour,
		Compression:       "lz4",
		AsyncInsert:       true,
		WaitForAsyncInsert: false,
	}
}

// ============================================================================
// ClickHouse Connection
// ============================================================================

// ClickHouseConn represents a ClickHouse database connection.
type ClickHouseConn struct {
	conn   driver.Conn
	db     *sql.DB
	config ClickHouseConfig
}

// NewClickHouseConn creates a new ClickHouse connection.
func NewClickHouseConn(cfg ClickHouseConfig) (*ClickHouseConn, error) {
	options := &clickhouse.Options{
		Addr: cfg.Hosts,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Debug: cfg.Debug,
		Settings: clickhouse.Settings{
			"max_execution_time":             300,
			"max_memory_usage":               10000000000,
			"async_insert":                   boolToInt(cfg.AsyncInsert),
			"wait_for_async_insert":          boolToInt(cfg.WaitForAsyncInsert),
		},
		DialTimeout:     cfg.DialTimeout,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: cfg.ConnMaxLifetime,
	}

	// Set compression
	switch cfg.Compression {
	case "lz4":
		options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	case "zstd":
		options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionZSTD}
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("failed to open clickhouse connection: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping clickhouse: %w", err)
	}

	// Also create sql.DB for compatibility
	db := clickhouse.OpenDB(options)

	return &ClickHouseConn{
		conn:   conn,
		db:     db,
		config: cfg,
	}, nil
}

// Close closes the ClickHouse connection.
func (c *ClickHouseConn) Close() error {
	if c.db != nil {
		c.db.Close()
	}
	return c.conn.Close()
}

// Ping tests the connection.
func (c *ClickHouseConn) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// IsHealthy returns true if the connection is healthy.
func (c *ClickHouseConn) IsHealthy(ctx context.Context) bool {
	return c.Ping(ctx) == nil
}

// Conn returns the native driver connection.
func (c *ClickHouseConn) Conn() driver.Conn {
	return c.conn
}

// DB returns the sql.DB instance.
func (c *ClickHouseConn) DB() *sql.DB {
	return c.db
}

// ============================================================================
// ClickHouse Event Repository Implementation
// ============================================================================

// clickHouseEventRepository implements EventRepository.
type clickHouseEventRepository struct {
	conn *ClickHouseConn
}

// NewClickHouseEventRepository creates a new ClickHouse event repository.
func NewClickHouseEventRepository(conn *ClickHouseConn) EventRepository {
	return &clickHouseEventRepository{conn: conn}
}

// Insert inserts events into ClickHouse.
func (r *clickHouseEventRepository) Insert(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := r.conn.conn.PrepareBatch(ctx, `
		INSERT INTO events (
			event_id, tenant_id, timestamp, event_type, vendor_name, product_name,
			security_severity, principal_hostname, principal_ip, principal_user_id,
			target_hostname, target_ip, security_action, security_rule_name, description, raw_log
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, e := range events {
		err := batch.Append(
			e.EventID,
			e.TenantID,
			e.Timestamp,
			e.EventType,
			e.VendorName,
			e.ProductName,
			e.Severity,
			e.PrincipalHostname,
			stringSliceToIPv6(e.PrincipalIP),
			e.PrincipalUserID,
			e.TargetHostname,
			stringSliceToIPv6(e.TargetIP),
			e.SecurityAction,
			e.SecurityRuleName,
			e.Description,
			e.RawLog,
		)
		if err != nil {
			return fmt.Errorf("failed to append to batch: %w", err)
		}
	}

	return batch.Send()
}

// InsertBatch inserts events in batches.
func (r *clickHouseEventRepository) InsertBatch(ctx context.Context, events []*Event, batchSize int) error {
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}
		if err := r.Insert(ctx, events[i:end]); err != nil {
			return fmt.Errorf("failed to insert batch %d-%d: %w", i, end, err)
		}
	}
	return nil
}

// GetByID retrieves an event by ID.
func (r *clickHouseEventRepository) GetByID(ctx context.Context, tenantID, eventID string) (*Event, error) {
	query := `
		SELECT
			event_id, tenant_id, timestamp, event_type, vendor_name, product_name,
			security_severity, principal_hostname, principal_ip, principal_user_id,
			target_hostname, target_ip, security_action, security_rule_name, description, raw_log
		FROM events_distributed
		WHERE tenant_id = ? AND event_id = ?
		LIMIT 1
	`

	row := r.conn.conn.QueryRow(ctx, query, tenantID, eventID)

	var e Event
	var principalIP, targetIP []string

	err := row.Scan(
		&e.EventID, &e.TenantID, &e.Timestamp, &e.EventType, &e.VendorName, &e.ProductName,
		&e.Severity, &e.PrincipalHostname, &principalIP, &e.PrincipalUserID,
		&e.TargetHostname, &targetIP, &e.SecurityAction, &e.SecurityRuleName, &e.Description, &e.RawLog,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan event: %w", err)
	}

	e.PrincipalIP = principalIP
	e.TargetIP = targetIP
	return &e, nil
}

// Search searches events with filters.
func (r *clickHouseEventRepository) Search(ctx context.Context, filter EventFilter, opts QueryOptions) ([]*Event, int64, error) {
	// Build WHERE clause
	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.TimeRange.End)
	}
	if len(filter.EventTypes) > 0 {
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", placeholders(len(filter.EventTypes))))
		for _, et := range filter.EventTypes {
			args = append(args, et)
		}
	}
	if len(filter.Severity) > 0 {
		conditions = append(conditions, fmt.Sprintf("security_severity IN (%s)", placeholders(len(filter.Severity))))
		for _, s := range filter.Severity {
			args = append(args, s)
		}
	}
	if len(filter.PrincipalIPs) > 0 {
		conditions = append(conditions, fmt.Sprintf("hasAny(principal_ip, [%s])", placeholders(len(filter.PrincipalIPs))))
		for _, ip := range filter.PrincipalIPs {
			args = append(args, ip)
		}
	}
	if len(filter.Hostnames) > 0 {
		conditions = append(conditions, fmt.Sprintf("(principal_hostname IN (%s) OR target_hostname IN (%s))",
			placeholders(len(filter.Hostnames)), placeholders(len(filter.Hostnames))))
		for _, h := range filter.Hostnames {
			args = append(args, h)
		}
		for _, h := range filter.Hostnames {
			args = append(args, h)
		}
	}
	if filter.TIMatched != nil && *filter.TIMatched {
		conditions = append(conditions, "ti_matched = 1")
	}
	if filter.SearchQuery != "" {
		conditions = append(conditions, "(description ILIKE ? OR raw_log ILIKE ?)")
		searchPattern := "%" + filter.SearchQuery + "%"
		args = append(args, searchPattern, searchPattern)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT count() FROM events_distributed WHERE %s", whereClause)
	var total int64
	row := r.conn.conn.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count events: %w", err)
	}

	// Build ORDER BY
	orderBy := "timestamp DESC"
	if len(opts.Sorts) > 0 {
		orders := make([]string, len(opts.Sorts))
		for i, s := range opts.Sorts {
			orders[i] = fmt.Sprintf("%s %s", s.Field, s.Order)
		}
		orderBy = strings.Join(orders, ", ")
	}

	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT
			event_id, tenant_id, timestamp, event_type, vendor_name, product_name,
			security_severity, principal_hostname, principal_ip, principal_user_id,
			target_hostname, target_ip, security_action, security_rule_name, description
		FROM events_distributed
		WHERE %s
		ORDER BY %s
		LIMIT ? OFFSET ?
	`, whereClause, orderBy)

	args = append(args, opts.Pagination.Limit(), opts.Pagination.Offset())

	rows, err := r.conn.conn.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var e Event
		var principalIP, targetIP []string

		err := rows.Scan(
			&e.EventID, &e.TenantID, &e.Timestamp, &e.EventType, &e.VendorName, &e.ProductName,
			&e.Severity, &e.PrincipalHostname, &principalIP, &e.PrincipalUserID,
			&e.TargetHostname, &targetIP, &e.SecurityAction, &e.SecurityRuleName, &e.Description,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan event row: %w", err)
		}

		e.PrincipalIP = principalIP
		e.TargetIP = targetIP
		events = append(events, &e)
	}

	return events, total, nil
}

// GetStats retrieves event statistics.
func (r *clickHouseEventRepository) GetStats(ctx context.Context, filter EventFilter) (*EventStats, error) {
	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.TimeRange.End)
	}

	whereClause := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT
			count() AS total_events,
			uniq(principal_hostname) AS unique_hosts,
			uniq(principal_user_id) AS unique_users,
			sum(ti_matched) AS ti_matches,
			sum(length(raw_log)) AS bytes_total
		FROM events_distributed
		WHERE %s
	`, whereClause)

	var stats EventStats
	row := r.conn.conn.QueryRow(ctx, query, args...)
	err := row.Scan(&stats.TotalEvents, &stats.UniqueHosts, &stats.UniqueUsers, &stats.TIMatches, &stats.BytesTotal)
	if err != nil {
		return nil, fmt.Errorf("failed to get event stats: %w", err)
	}

	stats.TimeRange = filter.TimeRange

	// Get counts by event type
	stats.EventsByType, err = r.CountByField(ctx, filter, "event_type", 20)
	if err != nil {
		return nil, err
	}

	// Get counts by severity
	stats.EventsBySeverity, err = r.CountByField(ctx, filter, "security_severity", 10)
	if err != nil {
		return nil, err
	}

	// Get counts by vendor
	stats.EventsByVendor, err = r.CountByField(ctx, filter, "vendor_name", 20)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

// CountByField counts events grouped by a field.
func (r *clickHouseEventRepository) CountByField(ctx context.Context, filter EventFilter, field string, limit int) (map[string]int64, error) {
	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.TimeRange.End)
	}

	whereClause := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT %s, count() AS cnt
		FROM events_distributed
		WHERE %s
		GROUP BY %s
		ORDER BY cnt DESC
		LIMIT %d
	`, field, whereClause, field, limit)

	rows, err := r.conn.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to count by field: %w", err)
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return nil, fmt.Errorf("failed to scan count result: %w", err)
		}
		result[key] = count
	}

	return result, nil
}

// Timeline returns event counts over time.
func (r *clickHouseEventRepository) Timeline(ctx context.Context, filter EventFilter, interval string) ([]TimelinePoint, error) {
	// Validate interval
	intervalFunc := "toStartOfHour"
	switch interval {
	case "minute":
		intervalFunc = "toStartOfMinute"
	case "hour":
		intervalFunc = "toStartOfHour"
	case "day":
		intervalFunc = "toStartOfDay"
	case "week":
		intervalFunc = "toStartOfWeek"
	}

	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.TimeRange.End)
	}

	whereClause := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT %s(timestamp) AS time_bucket, count() AS cnt
		FROM events_distributed
		WHERE %s
		GROUP BY time_bucket
		ORDER BY time_bucket
	`, intervalFunc, whereClause)

	rows, err := r.conn.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get timeline: %w", err)
	}
	defer rows.Close()

	var points []TimelinePoint
	for rows.Next() {
		var point TimelinePoint
		if err := rows.Scan(&point.Time, &point.Count); err != nil {
			return nil, fmt.Errorf("failed to scan timeline point: %w", err)
		}
		points = append(points, point)
	}

	return points, nil
}

// Query executes a raw query.
func (r *clickHouseEventRepository) Query(ctx context.Context, query string, args ...interface{}) ([]map[string]interface{}, error) {
	rows, err := r.conn.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	columns := rows.Columns()
	columnTypes := rows.ColumnTypes()

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
			_ = columnTypes[i] // Can be used for type hints
		}
		results = append(results, row)
	}

	return results, nil
}

// ============================================================================
// ClickHouse Alert Repository Implementation
// ============================================================================

// clickHouseAlertRepository implements AlertRepository.
type clickHouseAlertRepository struct {
	conn *ClickHouseConn
}

// NewClickHouseAlertRepository creates a new ClickHouse alert repository.
func NewClickHouseAlertRepository(conn *ClickHouseConn) AlertRepository {
	return &clickHouseAlertRepository{conn: conn}
}

// Insert inserts alerts into ClickHouse.
func (r *clickHouseAlertRepository) Insert(ctx context.Context, alerts []*Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	batch, err := r.conn.conn.PrepareBatch(ctx, `
		INSERT INTO alerts (
			alert_id, tenant_id, created_at, alert_name, alert_type, severity, status,
			resolution, rule_id, rule_name, event_count, assignee_id, case_id,
			ai_triage_score, ai_triage_label
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, a := range alerts {
		err := batch.Append(
			a.AlertID, a.TenantID, a.CreatedAt, a.AlertName, a.AlertType, a.Severity,
			a.Status, a.Resolution, a.RuleID, a.RuleName, a.EventCount,
			a.AssigneeID, a.CaseID, a.AITriageScore, a.AITriageLabel,
		)
		if err != nil {
			return fmt.Errorf("failed to append to batch: %w", err)
		}
	}

	return batch.Send()
}

// GetByID retrieves an alert by ID.
func (r *clickHouseAlertRepository) GetByID(ctx context.Context, tenantID, alertID string) (*Alert, error) {
	query := `
		SELECT
			alert_id, tenant_id, created_at, alert_name, alert_type, severity, status,
			resolution, rule_id, rule_name, event_count, assignee_id, case_id,
			ai_triage_score, ai_triage_label
		FROM alerts_distributed
		WHERE tenant_id = ? AND alert_id = ?
		LIMIT 1
	`

	row := r.conn.conn.QueryRow(ctx, query, tenantID, alertID)

	var a Alert
	err := row.Scan(
		&a.AlertID, &a.TenantID, &a.CreatedAt, &a.AlertName, &a.AlertType, &a.Severity,
		&a.Status, &a.Resolution, &a.RuleID, &a.RuleName, &a.EventCount,
		&a.AssigneeID, &a.CaseID, &a.AITriageScore, &a.AITriageLabel,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan alert: %w", err)
	}

	return &a, nil
}

// Search searches alerts with filters.
func (r *clickHouseAlertRepository) Search(ctx context.Context, filter AlertFilter, opts QueryOptions) ([]*Alert, int64, error) {
	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, filter.TimeRange.End)
	}
	if len(filter.Statuses) > 0 {
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", placeholders(len(filter.Statuses))))
		for _, s := range filter.Statuses {
			args = append(args, s)
		}
	}
	if len(filter.Severities) > 0 {
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", placeholders(len(filter.Severities))))
		for _, s := range filter.Severities {
			args = append(args, s)
		}
	}
	if len(filter.AssigneeIDs) > 0 {
		conditions = append(conditions, fmt.Sprintf("assignee_id IN (%s)", placeholders(len(filter.AssigneeIDs))))
		for _, id := range filter.AssigneeIDs {
			args = append(args, id)
		}
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT count() FROM alerts_distributed WHERE %s", whereClause)
	var total int64
	row := r.conn.conn.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count alerts: %w", err)
	}

	// Data query
	orderBy := "created_at DESC"
	if len(opts.Sorts) > 0 {
		orders := make([]string, len(opts.Sorts))
		for i, s := range opts.Sorts {
			orders[i] = fmt.Sprintf("%s %s", s.Field, s.Order)
		}
		orderBy = strings.Join(orders, ", ")
	}

	dataQuery := fmt.Sprintf(`
		SELECT
			alert_id, tenant_id, created_at, alert_name, alert_type, severity, status,
			resolution, rule_id, rule_name, event_count, assignee_id, case_id,
			ai_triage_score, ai_triage_label
		FROM alerts_distributed
		WHERE %s
		ORDER BY %s
		LIMIT ? OFFSET ?
	`, whereClause, orderBy)

	args = append(args, opts.Pagination.Limit(), opts.Pagination.Offset())

	rows, err := r.conn.conn.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*Alert
	for rows.Next() {
		var a Alert
		err := rows.Scan(
			&a.AlertID, &a.TenantID, &a.CreatedAt, &a.AlertName, &a.AlertType, &a.Severity,
			&a.Status, &a.Resolution, &a.RuleID, &a.RuleName, &a.EventCount,
			&a.AssigneeID, &a.CaseID, &a.AITriageScore, &a.AITriageLabel,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan alert row: %w", err)
		}
		alerts = append(alerts, &a)
	}

	return alerts, total, nil
}

// UpdateStatus updates alert status.
func (r *clickHouseAlertRepository) UpdateStatus(ctx context.Context, tenantID, alertID, status, resolution string) error {
	// ClickHouse doesn't support UPDATE directly on MergeTree
	// Use ALTER TABLE ... UPDATE for mutations (async) or use PostgreSQL for mutable data
	query := `
		ALTER TABLE alerts_distributed
		UPDATE status = ?, resolution = ?, updated_at = now64(3)
		WHERE tenant_id = ? AND alert_id = ?
	`
	return r.conn.conn.Exec(ctx, query, status, resolution, tenantID, alertID)
}

// AssignTo assigns alert to a user.
func (r *clickHouseAlertRepository) AssignTo(ctx context.Context, tenantID, alertID, assigneeID string) error {
	query := `
		ALTER TABLE alerts_distributed
		UPDATE assignee_id = ?, updated_at = now64(3)
		WHERE tenant_id = ? AND alert_id = ?
	`
	return r.conn.conn.Exec(ctx, query, assigneeID, tenantID, alertID)
}

// LinkToCase links alert to a case.
func (r *clickHouseAlertRepository) LinkToCase(ctx context.Context, tenantID, alertID, caseID string) error {
	query := `
		ALTER TABLE alerts_distributed
		UPDATE case_id = ?, updated_at = now64(3)
		WHERE tenant_id = ? AND alert_id = ?
	`
	return r.conn.conn.Exec(ctx, query, caseID, tenantID, alertID)
}

// GetStats retrieves alert statistics.
func (r *clickHouseAlertRepository) GetStats(ctx context.Context, filter AlertFilter) (*AlertStats, error) {
	conditions := []string{"tenant_id = ?"}
	args := []interface{}{filter.TenantID}

	if !filter.TimeRange.Start.IsZero() {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, filter.TimeRange.Start)
	}
	if !filter.TimeRange.End.IsZero() {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, filter.TimeRange.End)
	}

	whereClause := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT
			count() AS total_alerts,
			countIf(status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS')) AS open_alerts,
			avg(ai_triage_score) AS avg_triage_score,
			countIf(sla_breached = 1) AS sla_breached
		FROM alerts_distributed
		WHERE %s
	`, whereClause)

	var stats AlertStats
	row := r.conn.conn.QueryRow(ctx, query, args...)
	err := row.Scan(&stats.TotalAlerts, &stats.OpenAlerts, &stats.AvgTriageScore, &stats.SLABreached)
	if err != nil {
		return nil, fmt.Errorf("failed to get alert stats: %w", err)
	}

	// Get counts by status
	stats.AlertsByStatus = make(map[string]int64)
	statusQuery := fmt.Sprintf(`
		SELECT status, count() FROM alerts_distributed WHERE %s GROUP BY status
	`, whereClause)
	rows, err := r.conn.conn.Query(ctx, statusQuery, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var status string
			var count int64
			if rows.Scan(&status, &count) == nil {
				stats.AlertsByStatus[status] = count
			}
		}
	}

	// Get counts by severity
	stats.AlertsBySeverity = make(map[string]int64)
	sevQuery := fmt.Sprintf(`
		SELECT severity, count() FROM alerts_distributed WHERE %s GROUP BY severity
	`, whereClause)
	rows, err = r.conn.conn.Query(ctx, sevQuery, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count int64
			if rows.Scan(&severity, &count) == nil {
				stats.AlertsBySeverity[severity] = count
			}
		}
	}

	return &stats, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

func stringSliceToIPv6(ips []string) []string {
	// In production, convert string IPs to proper IPv6 format
	return ips
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
