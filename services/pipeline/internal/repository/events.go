// Package repository provides data access for pipeline events.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

// TimelineEntry represents an entry in the event timeline.
type TimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Stage     string    `json:"stage"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// EventFilter represents filters for querying events.
type EventFilter struct {
	TenantID string
	Severity []string
	Source   []string
	Stage    string
	From     time.Time
	To       time.Time
	Page     int
	Limit    int
}

// EventRepository handles pipeline event persistence with ClickHouse for OLAP queries.
type EventRepository struct {
	clickhouse *sql.DB
	postgres   *sql.DB
}

// NewEventRepository creates a new event repository.
func NewEventRepository(clickhouse, postgres *sql.DB) *EventRepository {
	return &EventRepository{
		clickhouse: clickhouse,
		postgres:   postgres,
	}
}

// ListEvents retrieves events with filtering and pagination from ClickHouse.
func (r *EventRepository) ListEvents(ctx context.Context, filter EventFilter) ([]model.PipelineEvent, int64, error) {
	// Use ClickHouse for analytical queries if available, fallback to PostgreSQL
	if r.clickhouse != nil {
		return r.listEventsClickHouse(ctx, filter)
	}
	if r.postgres != nil {
		return r.listEventsPostgres(ctx, filter)
	}
	return []model.PipelineEvent{}, 0, nil
}

// listEventsClickHouse queries events from ClickHouse.
func (r *EventRepository) listEventsClickHouse(ctx context.Context, filter EventFilter) ([]model.PipelineEvent, int64, error) {
	// Build the WHERE clause
	whereClauses := []string{"1=1"}
	args := make([]interface{}, 0)
	argIndex := 1

	if filter.TenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID)
		argIndex++
	}

	// Severity filter (IN clause)
	if len(filter.Severity) > 0 {
		placeholders := make([]string, len(filter.Severity))
		for i, sev := range filter.Severity {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, sev)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	// Source filter (IN clause)
	if len(filter.Source) > 0 {
		placeholders := make([]string, len(filter.Source))
		for i, src := range filter.Source {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, src)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
	}

	// Stage filter
	if filter.Stage != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("stage = $%d", argIndex))
		args = append(args, filter.Stage)
		argIndex++
	}

	// Time range filter
	if !filter.From.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, filter.From)
		argIndex++
	}
	if !filter.To.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, filter.To)
		argIndex++
	}

	whereClause := strings.Join(whereClauses, " AND ")

	// Count total
	countQuery := fmt.Sprintf(`
		SELECT count(*)
		FROM siem.pipeline_events
		WHERE %s
	`, whereClause)

	var total int64
	if err := r.clickhouse.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count query failed: %w", err)
	}

	// Calculate offset from page
	offset := (filter.Page - 1) * filter.Limit
	if offset < 0 {
		offset = 0
	}

	// Fetch events
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at
		FROM siem.pipeline_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, offset)

	rows, err := r.clickhouse.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("select query failed: %w", err)
	}
	defer rows.Close()

	return r.scanEvents(rows, total)
}

// listEventsPostgres queries events from PostgreSQL (fallback).
func (r *EventRepository) listEventsPostgres(ctx context.Context, filter EventFilter) ([]model.PipelineEvent, int64, error) {
	// Build the WHERE clause
	whereClauses := []string{"1=1"}
	args := make([]interface{}, 0)
	argIndex := 1

	if filter.TenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID)
		argIndex++
	}

	// Severity filter (IN clause)
	if len(filter.Severity) > 0 {
		placeholders := make([]string, len(filter.Severity))
		for i, sev := range filter.Severity {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, sev)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	// Source filter (IN clause)
	if len(filter.Source) > 0 {
		placeholders := make([]string, len(filter.Source))
		for i, src := range filter.Source {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, src)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
	}

	// Stage filter
	if filter.Stage != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("stage = $%d", argIndex))
		args = append(args, filter.Stage)
		argIndex++
	}

	// Time range filter
	if !filter.From.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, filter.From)
		argIndex++
	}
	if !filter.To.IsZero() {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, filter.To)
		argIndex++
	}

	whereClause := strings.Join(whereClauses, " AND ")

	// Count total
	countQuery := fmt.Sprintf(`
		SELECT count(*)
		FROM pipeline_events
		WHERE %s
	`, whereClause)

	var total int64
	if err := r.postgres.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count query failed: %w", err)
	}

	// Calculate offset from page
	offset := (filter.Page - 1) * filter.Limit
	if offset < 0 {
		offset = 0
	}

	// Fetch events
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at
		FROM pipeline_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, offset)

	rows, err := r.postgres.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("select query failed: %w", err)
	}
	defer rows.Close()

	return r.scanEvents(rows, total)
}

// scanEvents scans rows into PipelineEvent objects.
func (r *EventRepository) scanEvents(rows *sql.Rows, total int64) ([]model.PipelineEvent, int64, error) {
	events := make([]model.PipelineEvent, 0)

	for rows.Next() {
		var event model.PipelineEvent
		var classificationJSON, playbookMatchJSON, executionJSON []byte

		if err := rows.Scan(
			&event.ID,
			&event.TenantID,
			&event.RawLog,
			&event.Source,
			&event.Severity,
			&event.Stage,
			&classificationJSON,
			&playbookMatchJSON,
			&executionJSON,
			&event.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan failed: %w", err)
		}

		// Unmarshal JSON fields
		if len(classificationJSON) > 0 && string(classificationJSON) != "null" {
			var classification model.Classification
			if err := json.Unmarshal(classificationJSON, &classification); err == nil {
				event.Classification = &classification
			}
		}

		if len(playbookMatchJSON) > 0 && string(playbookMatchJSON) != "null" {
			var playbookMatch model.PlaybookMatch
			if err := json.Unmarshal(playbookMatchJSON, &playbookMatch); err == nil {
				event.PlaybookMatch = &playbookMatch
			}
		}

		if len(executionJSON) > 0 && string(executionJSON) != "null" {
			var execution model.ExecutionStatus
			if err := json.Unmarshal(executionJSON, &execution); err == nil {
				event.Execution = &execution
			}
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration failed: %w", err)
	}

	return events, total, nil
}

// GetEventByID retrieves a single event with full details.
func (r *EventRepository) GetEventByID(ctx context.Context, tenantID, eventID string) (*model.PipelineEvent, error) {
	// Prefer ClickHouse, fallback to PostgreSQL
	if r.clickhouse != nil {
		return r.getEventByIDClickHouse(ctx, tenantID, eventID)
	}
	if r.postgres != nil {
		return r.getEventByIDPostgres(ctx, tenantID, eventID)
	}
	return nil, fmt.Errorf("no database connection available")
}

// getEventByIDClickHouse retrieves an event from ClickHouse.
func (r *EventRepository) getEventByIDClickHouse(ctx context.Context, tenantID, eventID string) (*model.PipelineEvent, error) {
	query := `
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at
		FROM siem.pipeline_events
		WHERE id = $1
	`

	args := []interface{}{eventID}

	// Add tenant filter if provided
	if tenantID != "" {
		query = `
			SELECT id, tenant_id, raw_log, source, severity, stage,
				   classification, playbook_match, execution, created_at
			FROM siem.pipeline_events
			WHERE id = $1 AND tenant_id = $2
		`
		args = append(args, tenantID)
	}

	return r.scanSingleEvent(r.clickhouse.QueryRowContext(ctx, query, args...))
}

// getEventByIDPostgres retrieves an event from PostgreSQL.
func (r *EventRepository) getEventByIDPostgres(ctx context.Context, tenantID, eventID string) (*model.PipelineEvent, error) {
	query := `
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at
		FROM pipeline_events
		WHERE id = $1
	`

	args := []interface{}{eventID}

	// Add tenant filter if provided
	if tenantID != "" {
		query = `
			SELECT id, tenant_id, raw_log, source, severity, stage,
				   classification, playbook_match, execution, created_at
			FROM pipeline_events
			WHERE id = $1 AND tenant_id = $2
		`
		args = append(args, tenantID)
	}

	return r.scanSingleEvent(r.postgres.QueryRowContext(ctx, query, args...))
}

// scanSingleEvent scans a single row into a PipelineEvent.
func (r *EventRepository) scanSingleEvent(row *sql.Row) (*model.PipelineEvent, error) {
	var event model.PipelineEvent
	var classificationJSON, playbookMatchJSON, executionJSON []byte

	err := row.Scan(
		&event.ID,
		&event.TenantID,
		&event.RawLog,
		&event.Source,
		&event.Severity,
		&event.Stage,
		&classificationJSON,
		&playbookMatchJSON,
		&executionJSON,
		&event.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Unmarshal JSON fields
	if len(classificationJSON) > 0 && string(classificationJSON) != "null" {
		var classification model.Classification
		if err := json.Unmarshal(classificationJSON, &classification); err == nil {
			event.Classification = &classification
		}
	}

	if len(playbookMatchJSON) > 0 && string(playbookMatchJSON) != "null" {
		var playbookMatch model.PlaybookMatch
		if err := json.Unmarshal(playbookMatchJSON, &playbookMatch); err == nil {
			event.PlaybookMatch = &playbookMatch
		}
	}

	if len(executionJSON) > 0 && string(executionJSON) != "null" {
		var execution model.ExecutionStatus
		if err := json.Unmarshal(executionJSON, &execution); err == nil {
			event.Execution = &execution
		}
	}

	return &event, nil
}

// GetEventTimeline retrieves timeline entries for an event.
func (r *EventRepository) GetEventTimeline(ctx context.Context, eventID string) ([]TimelineEntry, error) {
	// Prefer ClickHouse, fallback to PostgreSQL
	if r.clickhouse != nil {
		return r.getEventTimelineClickHouse(ctx, eventID)
	}
	if r.postgres != nil {
		return r.getEventTimelinePostgres(ctx, eventID)
	}
	return []TimelineEntry{}, nil
}

// getEventTimelineClickHouse retrieves timeline from ClickHouse audit logs.
func (r *EventRepository) getEventTimelineClickHouse(ctx context.Context, eventID string) ([]TimelineEntry, error) {
	query := `
		SELECT created_at, event_type, actor_type, message
		FROM siem.pipeline_audit_logs
		WHERE related_event_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.clickhouse.QueryContext(ctx, query, eventID)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	return r.scanTimeline(rows)
}

// getEventTimelinePostgres retrieves timeline from PostgreSQL audit logs.
func (r *EventRepository) getEventTimelinePostgres(ctx context.Context, eventID string) ([]TimelineEntry, error) {
	query := `
		SELECT created_at, event_type, actor_type, message
		FROM pipeline_audit_logs
		WHERE related_event_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.postgres.QueryContext(ctx, query, eventID)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	return r.scanTimeline(rows)
}

// scanTimeline scans rows into TimelineEntry objects.
func (r *EventRepository) scanTimeline(rows *sql.Rows) ([]TimelineEntry, error) {
	timeline := make([]TimelineEntry, 0)

	for rows.Next() {
		var entry TimelineEntry
		var eventType, actorType string

		if err := rows.Scan(
			&entry.Timestamp,
			&eventType,
			&actorType,
			&entry.Details,
		); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		// Map event_type to stage and action
		entry.Stage = mapEventTypeToStage(eventType)
		entry.Action = fmt.Sprintf("%s by %s", eventType, actorType)

		timeline = append(timeline, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return timeline, nil
}

// mapEventTypeToStage maps audit event types to pipeline stages.
func mapEventTypeToStage(eventType string) string {
	switch eventType {
	case "EVENT_RECEIVED":
		return "event_receive"
	case "EVENT_CLASSIFIED":
		return "classification"
	case "PLAYBOOK_MATCHED":
		return "playbook_select"
	case "EXECUTION_STARTED", "EXECUTION_COMPLETED", "EXECUTION_FAILED":
		return "flow_execution"
	case "APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_REJECTED":
		return "approval"
	default:
		return "unknown"
	}
}

// SaveEvent saves an event to ClickHouse (for analytics) and PostgreSQL (for OLTP).
func (r *EventRepository) SaveEvent(ctx context.Context, event *model.PipelineEvent) error {
	classificationJSON, err := json.Marshal(event.Classification)
	if err != nil {
		classificationJSON = []byte("null")
	}

	playbookMatchJSON, err := json.Marshal(event.PlaybookMatch)
	if err != nil {
		playbookMatchJSON = []byte("null")
	}

	executionJSON, err := json.Marshal(event.Execution)
	if err != nil {
		executionJSON = []byte("null")
	}

	// Save to ClickHouse for analytics
	if r.clickhouse != nil {
		query := `
			INSERT INTO siem.pipeline_events (
				id, tenant_id, raw_log, source, severity, stage,
				classification, playbook_match, execution, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`

		if _, err := r.clickhouse.ExecContext(ctx, query,
			event.ID,
			event.TenantID,
			event.RawLog,
			event.Source,
			event.Severity,
			event.Stage,
			string(classificationJSON),
			string(playbookMatchJSON),
			string(executionJSON),
			event.CreatedAt,
		); err != nil {
			// Log but don't fail - ClickHouse is for analytics
			return fmt.Errorf("clickhouse insert failed: %w", err)
		}
	}

	// Save to PostgreSQL for OLTP (upsert)
	if r.postgres != nil {
		query := `
			INSERT INTO pipeline_events (
				id, tenant_id, raw_log, source, severity, stage,
				classification, playbook_match, execution, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				stage = EXCLUDED.stage,
				classification = EXCLUDED.classification,
				playbook_match = EXCLUDED.playbook_match,
				execution = EXCLUDED.execution,
				updated_at = EXCLUDED.updated_at
		`

		if _, err := r.postgres.ExecContext(ctx, query,
			event.ID,
			event.TenantID,
			event.RawLog,
			event.Source,
			event.Severity,
			event.Stage,
			classificationJSON,
			playbookMatchJSON,
			executionJSON,
			event.CreatedAt,
			time.Now(),
		); err != nil {
			return fmt.Errorf("postgres insert failed: %w", err)
		}
	}

	return nil
}

// SaveTimelineEntry saves a timeline entry to the audit log.
func (r *EventRepository) SaveTimelineEntry(ctx context.Context, eventID string, entry TimelineEntry) error {
	// Save to PostgreSQL
	if r.postgres != nil {
		query := `
			INSERT INTO pipeline_audit_logs (
				id, tenant_id, event_type, actor_type, actor_id,
				message, details, related_event_id, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`

		_, err := r.postgres.ExecContext(ctx, query,
			fmt.Sprintf("audit-%d", time.Now().UnixNano()),
			"", // tenant_id would be fetched from event
			entry.Stage,
			"SYSTEM",
			"pipeline-service",
			entry.Action,
			entry.Details,
			eventID,
			entry.Timestamp,
		)

		if err != nil {
			return fmt.Errorf("postgres insert failed: %w", err)
		}
	}

	return nil
}
