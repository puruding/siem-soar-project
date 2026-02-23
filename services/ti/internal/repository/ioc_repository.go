// Package repository provides PostgreSQL storage for IOCs.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
)

// PostgresIOCRepository implements ioc.Repository with PostgreSQL.
type PostgresIOCRepository struct {
	db *sql.DB
}

// NewPostgresIOCRepository creates a new PostgreSQL IOC repository.
func NewPostgresIOCRepository(db *sql.DB) *PostgresIOCRepository {
	return &PostgresIOCRepository{db: db}
}

// InitSchema creates the IOC tables if they don't exist.
func (r *PostgresIOCRepository) InitSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS iocs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
			type VARCHAR(32) NOT NULL,
			value TEXT NOT NULL,
			name VARCHAR(255),
			description TEXT,
			source VARCHAR(255) NOT NULL,
			feed_id VARCHAR(64),
			threat_type VARCHAR(64) NOT NULL DEFAULT 'unknown',
			threat_name VARCHAR(255),
			severity VARCHAR(16) NOT NULL DEFAULT 'medium',
			confidence INTEGER NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
			tlp VARCHAR(16) DEFAULT 'AMBER',
			mitre_attack TEXT[],
			malware_families TEXT[],
			campaigns TEXT[],
			threat_actors TEXT[],
			labels TEXT[],
			attributes JSONB DEFAULT '{}',
			related_iocs TEXT[],
			valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			valid_until TIMESTAMPTZ,
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
			hit_count BIGINT NOT NULL DEFAULT 0,
			last_hit_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(tenant_id, type, value)
		);

		CREATE INDEX IF NOT EXISTS idx_iocs_tenant_id ON iocs(tenant_id);
		CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
		CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
		CREATE INDEX IF NOT EXISTS idx_iocs_threat_type ON iocs(threat_type);
		CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
		CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
		CREATE INDEX IF NOT EXISTS idx_iocs_is_active ON iocs(is_active);
		CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs(confidence);
		CREATE INDEX IF NOT EXISTS idx_iocs_valid_from ON iocs(valid_from);
		CREATE INDEX IF NOT EXISTS idx_iocs_expires_at ON iocs(expires_at);
		CREATE INDEX IF NOT EXISTS idx_iocs_created_at ON iocs(created_at);
		CREATE INDEX IF NOT EXISTS idx_iocs_labels ON iocs USING GIN(labels);

		CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
		CREATE INDEX IF NOT EXISTS idx_iocs_tenant_active ON iocs(tenant_id, is_active);
	`

	_, err := r.db.ExecContext(ctx, schema)
	return err
}

// Save saves an IOC to the database.
func (r *PostgresIOCRepository) Save(ctx context.Context, i *ioc.IOC) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	if i.CreatedAt.IsZero() {
		i.CreatedAt = time.Now()
	}
	i.UpdatedAt = time.Now()

	attributesJSON, err := json.Marshal(i.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		INSERT INTO iocs (
			id, tenant_id, type, value, name, description, source, feed_id,
			threat_type, threat_name, severity, confidence, tlp,
			mitre_attack, malware_families, campaigns, threat_actors, labels, attributes,
			related_iocs, valid_from, valid_until, first_seen, last_seen, expires_at,
			is_active, is_whitelisted, hit_count, last_hit_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25,
			$26, $27, $28, $29, $30, $31
		)
		ON CONFLICT (tenant_id, type, value) DO UPDATE SET
			name = COALESCE(EXCLUDED.name, iocs.name),
			description = COALESCE(EXCLUDED.description, iocs.description),
			source = EXCLUDED.source,
			feed_id = COALESCE(EXCLUDED.feed_id, iocs.feed_id),
			threat_type = EXCLUDED.threat_type,
			threat_name = COALESCE(EXCLUDED.threat_name, iocs.threat_name),
			severity = EXCLUDED.severity,
			confidence = (iocs.confidence + EXCLUDED.confidence) / 2,
			tlp = EXCLUDED.tlp,
			mitre_attack = array_cat(iocs.mitre_attack, EXCLUDED.mitre_attack),
			malware_families = array_cat(iocs.malware_families, EXCLUDED.malware_families),
			campaigns = array_cat(iocs.campaigns, EXCLUDED.campaigns),
			threat_actors = array_cat(iocs.threat_actors, EXCLUDED.threat_actors),
			labels = array_cat(iocs.labels, EXCLUDED.labels),
			attributes = iocs.attributes || EXCLUDED.attributes,
			related_iocs = array_cat(iocs.related_iocs, EXCLUDED.related_iocs),
			valid_until = EXCLUDED.valid_until,
			last_seen = EXCLUDED.last_seen,
			expires_at = EXCLUDED.expires_at,
			is_active = EXCLUDED.is_active,
			is_whitelisted = EXCLUDED.is_whitelisted,
			updated_at = NOW()
		RETURNING id
	`

	var lastHitAt *time.Time
	if !i.LastHitAt.IsZero() {
		lastHitAt = &i.LastHitAt
	}
	var validUntil *time.Time
	if !i.ValidUntil.IsZero() {
		validUntil = &i.ValidUntil
	}
	var expiresAt *time.Time
	if !i.ExpiresAt.IsZero() {
		expiresAt = &i.ExpiresAt
	}

	err = r.db.QueryRowContext(ctx, query,
		i.ID, i.TenantID, string(i.Type), i.Value, i.Name, i.Description, i.Source, i.FeedID,
		string(i.ThreatType), i.ThreatName, string(i.Severity), i.Confidence, string(i.TLP),
		pq.Array(i.MITREAttack), pq.Array(i.MalwareFamilies), pq.Array(i.Campaigns),
		pq.Array(i.ThreatActors), pq.Array(i.Labels), attributesJSON,
		pq.Array(i.RelatedIOCs), i.ValidFrom, validUntil, i.FirstSeen, i.LastSeen, expiresAt,
		i.IsActive, i.IsWhitelisted, i.HitCount, lastHitAt, i.CreatedAt, i.UpdatedAt,
	).Scan(&i.ID)

	if err != nil {
		return fmt.Errorf("failed to save IOC: %w", err)
	}

	return nil
}

// SaveBatch saves multiple IOCs in a single transaction.
func (r *PostgresIOCRepository) SaveBatch(ctx context.Context, iocs []*ioc.IOC) error {
	if len(iocs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO iocs (
			id, tenant_id, type, value, name, description, source, feed_id,
			threat_type, threat_name, severity, confidence, tlp,
			mitre_attack, malware_families, campaigns, threat_actors, labels, attributes,
			related_iocs, valid_from, valid_until, first_seen, last_seen, expires_at,
			is_active, is_whitelisted, hit_count, last_hit_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25,
			$26, $27, $28, $29, $30, $31
		)
		ON CONFLICT (tenant_id, type, value) DO UPDATE SET
			last_seen = EXCLUDED.last_seen,
			confidence = (iocs.confidence + EXCLUDED.confidence) / 2,
			updated_at = NOW()
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, i := range iocs {
		if i.ID == "" {
			i.ID = uuid.New().String()
		}
		if i.CreatedAt.IsZero() {
			i.CreatedAt = time.Now()
		}
		i.UpdatedAt = time.Now()

		attributesJSON, err := json.Marshal(i.Attributes)
		if err != nil {
			return fmt.Errorf("failed to marshal attributes: %w", err)
		}

		var lastHitAt *time.Time
		if !i.LastHitAt.IsZero() {
			lastHitAt = &i.LastHitAt
		}
		var validUntil *time.Time
		if !i.ValidUntil.IsZero() {
			validUntil = &i.ValidUntil
		}
		var expiresAt *time.Time
		if !i.ExpiresAt.IsZero() {
			expiresAt = &i.ExpiresAt
		}

		_, err = stmt.ExecContext(ctx,
			i.ID, i.TenantID, string(i.Type), i.Value, i.Name, i.Description, i.Source, i.FeedID,
			string(i.ThreatType), i.ThreatName, string(i.Severity), i.Confidence, string(i.TLP),
			pq.Array(i.MITREAttack), pq.Array(i.MalwareFamilies), pq.Array(i.Campaigns),
			pq.Array(i.ThreatActors), pq.Array(i.Labels), attributesJSON,
			pq.Array(i.RelatedIOCs), i.ValidFrom, validUntil, i.FirstSeen, i.LastSeen, expiresAt,
			i.IsActive, i.IsWhitelisted, i.HitCount, lastHitAt, i.CreatedAt, i.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert IOC %s: %w", i.Value, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByID retrieves an IOC by its ID.
func (r *PostgresIOCRepository) GetByID(ctx context.Context, id string) (*ioc.IOC, error) {
	query := `
		SELECT
			id, tenant_id, type, value, name, description, source, feed_id,
			threat_type, threat_name, severity, confidence, tlp,
			mitre_attack, malware_families, campaigns, threat_actors, labels, attributes,
			related_iocs, valid_from, valid_until, first_seen, last_seen, expires_at,
			is_active, is_whitelisted, hit_count, last_hit_at, created_at, updated_at
		FROM iocs WHERE id = $1
	`

	return r.scanIOC(r.db.QueryRowContext(ctx, query, id))
}

// GetByTypeAndValue retrieves an IOC by type and value.
func (r *PostgresIOCRepository) GetByTypeAndValue(ctx context.Context, iocType ioc.IOCType, value string) (*ioc.IOC, error) {
	query := `
		SELECT
			id, tenant_id, type, value, name, description, source, feed_id,
			threat_type, threat_name, severity, confidence, tlp,
			mitre_attack, malware_families, campaigns, threat_actors, labels, attributes,
			related_iocs, valid_from, valid_until, first_seen, last_seen, expires_at,
			is_active, is_whitelisted, hit_count, last_hit_at, created_at, updated_at
		FROM iocs WHERE type = $1 AND value = $2 AND is_active = TRUE
	`

	return r.scanIOC(r.db.QueryRowContext(ctx, query, string(iocType), value))
}

// List retrieves IOCs matching the filter with pagination.
func (r *PostgresIOCRepository) List(ctx context.Context, filter ioc.IOCFilter, limit, offset int) ([]*ioc.IOC, int64, error) {
	whereClause, args := r.buildWhereClause(filter)

	// Count query
	countQuery := "SELECT COUNT(*) FROM iocs" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count IOCs: %w", err)
	}

	if total == 0 {
		return []*ioc.IOC{}, 0, nil
	}

	// Data query
	query := `
		SELECT
			id, tenant_id, type, value, name, description, source, feed_id,
			threat_type, threat_name, severity, confidence, tlp,
			mitre_attack, malware_families, campaigns, threat_actors, labels, attributes,
			related_iocs, valid_from, valid_until, first_seen, last_seen, expires_at,
			is_active, is_whitelisted, hit_count, last_hit_at, created_at, updated_at
		FROM iocs
	` + whereClause + " ORDER BY created_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query IOCs: %w", err)
	}
	defer rows.Close()

	var iocs []*ioc.IOC
	for rows.Next() {
		i, err := r.scanIOCFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		iocs = append(iocs, i)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating IOCs: %w", err)
	}

	return iocs, total, nil
}

// Delete removes an IOC by ID.
func (r *PostgresIOCRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM iocs WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete IOC: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// DeleteExpired removes expired IOCs.
func (r *PostgresIOCRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM iocs
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		   OR (valid_until IS NOT NULL AND valid_until < NOW())
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired IOCs: %w", err)
	}

	return result.RowsAffected()
}

// GetStats retrieves IOC statistics for a tenant.
func (r *PostgresIOCRepository) GetStats(ctx context.Context, tenantID string) (*ioc.IOCStats, error) {
	stats := &ioc.IOCStats{
		IOCsByType:     make(map[string]int64),
		IOCsByThreat:   make(map[string]int64),
		IOCsBySeverity: make(map[string]int64),
		IOCsBySource:   make(map[string]int64),
	}

	// Total and active IOCs
	var tenantFilter string
	var args []interface{}
	if tenantID != "" {
		tenantFilter = " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}

	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs"+tenantFilter, args...).Scan(&stats.TotalIOCs)
	if err != nil {
		return nil, err
	}

	activeFilter := tenantFilter
	if activeFilter == "" {
		activeFilter = " WHERE is_active = TRUE"
	} else {
		activeFilter += " AND is_active = TRUE"
	}
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs"+activeFilter, args...).Scan(&stats.ActiveIOCs)
	if err != nil {
		return nil, err
	}

	// IOCs by type
	rows, err := r.db.QueryContext(ctx, "SELECT type, COUNT(*) FROM iocs"+tenantFilter+" GROUP BY type", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var count int64
		if err := rows.Scan(&t, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.IOCsByType[t] = count
	}
	rows.Close()

	// IOCs by threat type
	rows, err = r.db.QueryContext(ctx, "SELECT threat_type, COUNT(*) FROM iocs"+tenantFilter+" GROUP BY threat_type", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var count int64
		if err := rows.Scan(&t, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.IOCsByThreat[t] = count
	}
	rows.Close()

	// IOCs by severity
	rows, err = r.db.QueryContext(ctx, "SELECT severity, COUNT(*) FROM iocs"+tenantFilter+" GROUP BY severity", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		var count int64
		if err := rows.Scan(&s, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.IOCsBySeverity[s] = count
	}
	rows.Close()

	// IOCs by source
	rows, err = r.db.QueryContext(ctx, "SELECT source, COUNT(*) FROM iocs"+tenantFilter+" GROUP BY source", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		var count int64
		if err := rows.Scan(&s, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.IOCsBySource[s] = count
	}
	rows.Close()

	// Total hits
	err = r.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(hit_count), 0) FROM iocs"+tenantFilter, args...).Scan(&stats.TotalHits)
	if err != nil {
		return nil, err
	}

	// Expiring today
	expiringFilter := tenantFilter
	if expiringFilter == "" {
		expiringFilter = " WHERE expires_at >= NOW() AND expires_at < NOW() + INTERVAL '1 day'"
	} else {
		expiringFilter += " AND expires_at >= NOW() AND expires_at < NOW() + INTERVAL '1 day'"
	}
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs"+expiringFilter, args...).Scan(&stats.ExpiringToday)
	if err != nil {
		return nil, err
	}

	// Expiring soon (7 days)
	expiringSoonFilter := tenantFilter
	if expiringSoonFilter == "" {
		expiringSoonFilter = " WHERE expires_at >= NOW() AND expires_at < NOW() + INTERVAL '7 days'"
	} else {
		expiringSoonFilter += " AND expires_at >= NOW() AND expires_at < NOW() + INTERVAL '7 days'"
	}
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM iocs"+expiringSoonFilter, args...).Scan(&stats.ExpiringSoon)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// Update updates an existing IOC.
func (r *PostgresIOCRepository) Update(ctx context.Context, i *ioc.IOC) error {
	i.UpdatedAt = time.Now()

	attributesJSON, err := json.Marshal(i.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	var lastHitAt *time.Time
	if !i.LastHitAt.IsZero() {
		lastHitAt = &i.LastHitAt
	}
	var validUntil *time.Time
	if !i.ValidUntil.IsZero() {
		validUntil = &i.ValidUntil
	}
	var expiresAt *time.Time
	if !i.ExpiresAt.IsZero() {
		expiresAt = &i.ExpiresAt
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE iocs SET
			name = $2, description = $3, source = $4, feed_id = $5,
			threat_type = $6, threat_name = $7, severity = $8, confidence = $9, tlp = $10,
			mitre_attack = $11, malware_families = $12, campaigns = $13, threat_actors = $14,
			labels = $15, attributes = $16, related_iocs = $17,
			valid_from = $18, valid_until = $19, first_seen = $20, last_seen = $21, expires_at = $22,
			is_active = $23, is_whitelisted = $24, hit_count = $25, last_hit_at = $26, updated_at = $27
		WHERE id = $1
	`,
		i.ID, i.Name, i.Description, i.Source, i.FeedID,
		string(i.ThreatType), i.ThreatName, string(i.Severity), i.Confidence, string(i.TLP),
		pq.Array(i.MITREAttack), pq.Array(i.MalwareFamilies), pq.Array(i.Campaigns), pq.Array(i.ThreatActors),
		pq.Array(i.Labels), attributesJSON, pq.Array(i.RelatedIOCs),
		i.ValidFrom, validUntil, i.FirstSeen, i.LastSeen, expiresAt,
		i.IsActive, i.IsWhitelisted, i.HitCount, lastHitAt, i.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update IOC: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// IncrementHitCount increments the hit count for an IOC.
func (r *PostgresIOCRepository) IncrementHitCount(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE iocs SET
			hit_count = hit_count + 1,
			last_hit_at = NOW(),
			last_seen = NOW(),
			updated_at = NOW()
		WHERE id = $1
	`, id)
	return err
}

// buildWhereClause constructs the WHERE clause from filter.
func (r *PostgresIOCRepository) buildWhereClause(filter ioc.IOCFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, filter.TenantID)
		argNum++
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, string(t))
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("type IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.ThreatTypes) > 0 {
		placeholders := make([]string, len(filter.ThreatTypes))
		for i, t := range filter.ThreatTypes {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, string(t))
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("threat_type IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, string(s))
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, s := range filter.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, s)
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.FeedIDs) > 0 {
		placeholders := make([]string, len(filter.FeedIDs))
		for i, f := range filter.FeedIDs {
			placeholders[i] = fmt.Sprintf("$%d", argNum)
			args = append(args, f)
			argNum++
		}
		conditions = append(conditions, fmt.Sprintf("feed_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.Labels) > 0 {
		conditions = append(conditions, fmt.Sprintf("labels && $%d", argNum))
		args = append(args, pq.Array(filter.Labels))
		argNum++
	}

	if filter.MinConfidence > 0 {
		conditions = append(conditions, fmt.Sprintf("confidence >= $%d", argNum))
		args = append(args, filter.MinConfidence)
		argNum++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argNum))
		args = append(args, *filter.IsActive)
		argNum++
	}

	if filter.IsWhitelisted != nil {
		conditions = append(conditions, fmt.Sprintf("is_whitelisted = $%d", argNum))
		args = append(args, *filter.IsWhitelisted)
		argNum++
	}

	if !filter.ValidAt.IsZero() {
		conditions = append(conditions, fmt.Sprintf("(valid_from <= $%d AND (valid_until IS NULL OR valid_until >= $%d))", argNum, argNum+1))
		args = append(args, filter.ValidAt, filter.ValidAt)
		argNum += 2
	}

	if !filter.ModifiedSince.IsZero() {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argNum))
		args = append(args, filter.ModifiedSince)
		argNum++
	}

	if filter.SearchQuery != "" {
		conditions = append(conditions, fmt.Sprintf("(value ILIKE $%d OR description ILIKE $%d OR name ILIKE $%d)", argNum, argNum+1, argNum+2))
		searchPattern := "%" + filter.SearchQuery + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
		argNum += 3
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return " WHERE " + strings.Join(conditions, " AND "), args
}

// scanIOC scans a single row into an IOC.
func (r *PostgresIOCRepository) scanIOC(row *sql.Row) (*ioc.IOC, error) {
	i := &ioc.IOC{}
	var (
		iocType, threatType, severity, tlp string
		name, description, feedID, threatName sql.NullString
		validUntil, expiresAt, lastHitAt sql.NullTime
		attributesJSON []byte
	)

	err := row.Scan(
		&i.ID, &i.TenantID, &iocType, &i.Value, &name, &description, &i.Source, &feedID,
		&threatType, &threatName, &severity, &i.Confidence, &tlp,
		pq.Array(&i.MITREAttack), pq.Array(&i.MalwareFamilies), pq.Array(&i.Campaigns),
		pq.Array(&i.ThreatActors), pq.Array(&i.Labels), &attributesJSON,
		pq.Array(&i.RelatedIOCs), &i.ValidFrom, &validUntil, &i.FirstSeen, &i.LastSeen, &expiresAt,
		&i.IsActive, &i.IsWhitelisted, &i.HitCount, &lastHitAt, &i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan IOC: %w", err)
	}

	i.Type = ioc.IOCType(iocType)
	i.ThreatType = ioc.ThreatType(threatType)
	i.Severity = ioc.Severity(severity)
	i.TLP = ioc.TLP(tlp)

	if name.Valid {
		i.Name = name.String
	}
	if description.Valid {
		i.Description = description.String
	}
	if feedID.Valid {
		i.FeedID = feedID.String
	}
	if threatName.Valid {
		i.ThreatName = threatName.String
	}
	if validUntil.Valid {
		i.ValidUntil = validUntil.Time
	}
	if expiresAt.Valid {
		i.ExpiresAt = expiresAt.Time
	}
	if lastHitAt.Valid {
		i.LastHitAt = lastHitAt.Time
	}

	if len(attributesJSON) > 0 {
		json.Unmarshal(attributesJSON, &i.Attributes)
	}
	if i.Attributes == nil {
		i.Attributes = make(map[string]string)
	}

	return i, nil
}

// scanIOCFromRows scans a rows iterator into an IOC.
func (r *PostgresIOCRepository) scanIOCFromRows(rows *sql.Rows) (*ioc.IOC, error) {
	i := &ioc.IOC{}
	var (
		iocType, threatType, severity, tlp string
		name, description, feedID, threatName sql.NullString
		validUntil, expiresAt, lastHitAt sql.NullTime
		attributesJSON []byte
	)

	err := rows.Scan(
		&i.ID, &i.TenantID, &iocType, &i.Value, &name, &description, &i.Source, &feedID,
		&threatType, &threatName, &severity, &i.Confidence, &tlp,
		pq.Array(&i.MITREAttack), pq.Array(&i.MalwareFamilies), pq.Array(&i.Campaigns),
		pq.Array(&i.ThreatActors), pq.Array(&i.Labels), &attributesJSON,
		pq.Array(&i.RelatedIOCs), &i.ValidFrom, &validUntil, &i.FirstSeen, &i.LastSeen, &expiresAt,
		&i.IsActive, &i.IsWhitelisted, &i.HitCount, &lastHitAt, &i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan IOC: %w", err)
	}

	i.Type = ioc.IOCType(iocType)
	i.ThreatType = ioc.ThreatType(threatType)
	i.Severity = ioc.Severity(severity)
	i.TLP = ioc.TLP(tlp)

	if name.Valid {
		i.Name = name.String
	}
	if description.Valid {
		i.Description = description.String
	}
	if feedID.Valid {
		i.FeedID = feedID.String
	}
	if threatName.Valid {
		i.ThreatName = threatName.String
	}
	if validUntil.Valid {
		i.ValidUntil = validUntil.Time
	}
	if expiresAt.Valid {
		i.ExpiresAt = expiresAt.Time
	}
	if lastHitAt.Valid {
		i.LastHitAt = lastHitAt.Time
	}

	if len(attributesJSON) > 0 {
		json.Unmarshal(attributesJSON, &i.Attributes)
	}
	if i.Attributes == nil {
		i.Attributes = make(map[string]string)
	}

	return i, nil
}
