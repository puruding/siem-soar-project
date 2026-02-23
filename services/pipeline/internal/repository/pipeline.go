// Package repository provides data access for pipeline events.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

// PipelineRepository handles pipeline event persistence.
type PipelineRepository struct {
	db *sql.DB
}

// NewPipelineRepository creates a new pipeline repository.
func NewPipelineRepository(db *sql.DB) *PipelineRepository {
	return &PipelineRepository{db: db}
}

// SaveEvent saves a pipeline event to the database.
func (r *PipelineRepository) SaveEvent(ctx context.Context, event *model.PipelineEvent) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

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

	_, err = r.db.ExecContext(ctx, query,
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
	)

	return err
}

// GetEventByID retrieves a pipeline event by ID.
func (r *PipelineRepository) GetEventByID(ctx context.Context, id string) (*model.PipelineEvent, error) {
	if r.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	query := `
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at, updated_at
		FROM pipeline_events
		WHERE id = $1
	`

	var event model.PipelineEvent
	var classificationJSON, playbookMatchJSON, executionJSON []byte
	var updatedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found: %s", id)
	}
	if err != nil {
		return nil, err
	}

	if updatedAt.Valid {
		event.UpdatedAt = updatedAt.Time
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

// ListEvents retrieves pipeline events based on filter criteria.
func (r *PipelineRepository) ListEvents(ctx context.Context, filter model.PipelineEventFilter) ([]*model.PipelineEvent, int, error) {
	if r.db == nil {
		return nil, 0, fmt.Errorf("database connection not available")
	}

	// Build query with filters
	baseQuery := `FROM pipeline_events WHERE 1=1`
	args := make([]interface{}, 0)
	argIndex := 1

	if filter.TenantID != "" {
		baseQuery += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, filter.TenantID)
		argIndex++
	}

	if filter.Source != "" {
		baseQuery += fmt.Sprintf(" AND source = $%d", argIndex)
		args = append(args, filter.Source)
		argIndex++
	}

	if filter.Severity != "" {
		baseQuery += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, filter.Severity)
		argIndex++
	}

	if filter.Stage != "" {
		baseQuery += fmt.Sprintf(" AND stage = $%d", argIndex)
		args = append(args, filter.Stage)
		argIndex++
	}

	if !filter.StartTime.IsZero() {
		baseQuery += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}

	if !filter.EndTime.IsZero() {
		baseQuery += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Fetch events
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, raw_log, source, severity, stage,
			   classification, playbook_match, execution, created_at, updated_at
		%s ORDER BY created_at DESC LIMIT $%d OFFSET $%d
	`, baseQuery, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	events := make([]*model.PipelineEvent, 0)
	for rows.Next() {
		var event model.PipelineEvent
		var classificationJSON, playbookMatchJSON, executionJSON []byte
		var updatedAt sql.NullTime

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
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}

		if updatedAt.Valid {
			event.UpdatedAt = updatedAt.Time
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

		events = append(events, &event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// UpdateEventStage updates the stage of a pipeline event.
func (r *PipelineRepository) UpdateEventStage(ctx context.Context, id string, stage model.PipelineStage) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	query := `UPDATE pipeline_events SET stage = $1, updated_at = $2 WHERE id = $3`
	result, err := r.db.ExecContext(ctx, query, stage, time.Now(), id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("event not found: %s", id)
	}

	return nil
}

// SaveAuditLog saves an audit log entry.
func (r *PipelineRepository) SaveAuditLog(ctx context.Context, log *model.AuditLog) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	query := `
		INSERT INTO pipeline_audit_logs (
			id, tenant_id, event_type, actor_type, actor_id,
			message, details, related_event_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		log.ID,
		log.TenantID,
		log.EventType,
		log.ActorType,
		log.ActorID,
		log.Message,
		log.Details,
		log.RelatedEventID,
		log.CreatedAt,
	)

	return err
}

// GetStats retrieves pipeline statistics.
func (r *PipelineRepository) GetStats(ctx context.Context, tenantID string) (*model.PipelineStats, error) {
	if r.db == nil {
		// Return empty stats if no database
		return &model.PipelineStats{}, nil
	}

	query := `
		SELECT
			COUNT(*) as total_events,
			COUNT(CASE WHEN stage != 'event_receive' THEN 1 END) as processed_events,
			COUNT(CASE WHEN classification IS NOT NULL THEN 1 END) as auto_classified,
			COALESCE(AVG(CASE
				WHEN classification->>'processing_time_ms' IS NOT NULL
				THEN (classification->>'processing_time_ms')::float
			END), 0) as avg_processing_ms
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
	`

	var stats model.PipelineStats
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(
		&stats.TotalEvents,
		&stats.ProcessedEvents,
		&stats.AutoClassified,
		&stats.AvgProcessingMs,
	)

	if err != nil {
		return nil, err
	}

	// Calculate automation rate
	if stats.TotalEvents > 0 {
		stats.AutomationRate = float32(stats.AutoClassified) / float32(stats.TotalEvents)
	}

	return &stats, nil
}

// GetStatsWithTimeRange retrieves pipeline statistics for a time range.
func (r *PipelineRepository) GetStatsWithTimeRange(ctx context.Context, tenantID string, from, to time.Time) (*model.PipelineStats, error) {
	if r.db == nil {
		stats := &model.PipelineStats{}
		stats.TimeRange.From = from
		stats.TimeRange.To = to
		return stats, nil
	}

	query := `
		SELECT
			COUNT(*) as total_events,
			COUNT(CASE WHEN stage != 'event_receive' THEN 1 END) as processed_events,
			COUNT(CASE WHEN classification IS NOT NULL AND classification->>'method' != 'MANUAL' THEN 1 END) as auto_classified,
			COUNT(CASE WHEN classification IS NOT NULL AND classification->>'method' = 'MANUAL' THEN 1 END) as manual_classified,
			COALESCE(AVG(CASE
				WHEN classification->>'processing_time_ms' IS NOT NULL
				THEN (classification->>'processing_time_ms')::float
			END), 0) as avg_processing_ms
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND created_at >= $2
		  AND created_at <= $3
	`

	var stats model.PipelineStats
	err := r.db.QueryRowContext(ctx, query, tenantID, from, to).Scan(
		&stats.TotalEvents,
		&stats.ProcessedEvents,
		&stats.AutoClassified,
		&stats.ManualClassified,
		&stats.AvgProcessingMs,
	)

	if err != nil {
		return nil, err
	}

	stats.TimeRange.From = from
	stats.TimeRange.To = to

	// Calculate automation rate
	if stats.TotalEvents > 0 {
		stats.AutomationRate = float32(stats.AutoClassified) / float32(stats.TotalEvents)
	}

	// Get by-stage statistics
	stats.ByStage, err = r.getStatsByStage(ctx, tenantID, from, to)
	if err != nil {
		return nil, err
	}

	// Get by-severity statistics
	stats.BySeverity, err = r.getStatsBySeverity(ctx, tenantID, from, to)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

// getStatsByStage retrieves statistics grouped by pipeline stage.
func (r *PipelineRepository) getStatsByStage(ctx context.Context, tenantID string, from, to time.Time) (map[string]model.StageStat, error) {
	query := `
		SELECT
			stage,
			COUNT(*) as entered,
			COUNT(CASE WHEN stage = 'flow_execution' THEN 1 END) as completed,
			COUNT(CASE WHEN execution->>'status' = 'FAILED' THEN 1 END) as failed,
			COALESCE(AVG(CASE
				WHEN classification->>'processing_time_ms' IS NOT NULL
				THEN (classification->>'processing_time_ms')::float
			END), 0) as avg_time_ms
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND created_at >= $2
		  AND created_at <= $3
		GROUP BY stage
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]model.StageStat)
	for rows.Next() {
		var stage string
		var stat model.StageStat
		if err := rows.Scan(&stage, &stat.Entered, &stat.Completed, &stat.Failed, &stat.AvgTimeMs); err != nil {
			return nil, err
		}
		result[stage] = stat
	}

	return result, rows.Err()
}

// getStatsBySeverity retrieves event counts grouped by severity.
func (r *PipelineRepository) getStatsBySeverity(ctx context.Context, tenantID string, from, to time.Time) (map[string]int64, error) {
	query := `
		SELECT severity, COUNT(*) as cnt
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND created_at >= $2
		  AND created_at <= $3
		GROUP BY severity
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		result[severity] = count
	}

	return result, rows.Err()
}

// GetPipelineStatus retrieves the current pipeline status.
func (r *PipelineRepository) GetPipelineStatus(ctx context.Context, tenantID string) (*model.PipelineStatus, error) {
	if r.db == nil {
		return &model.PipelineStatus{
			Status:       "healthy",
			IsProcessing: false,
			LastEventAt:  time.Time{},
			Stages:       []model.StageStatus{},
		}, nil
	}

	// Get last event time
	var lastEventAt sql.NullTime
	lastEventQuery := `
		SELECT MAX(created_at) FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
	`
	if err := r.db.QueryRowContext(ctx, lastEventQuery, tenantID).Scan(&lastEventAt); err != nil {
		return nil, err
	}

	// Get processing status (events in non-terminal stages)
	var processingCount int
	processingQuery := `
		SELECT COUNT(*) FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND stage NOT IN ('flow_execution')
		  AND created_at > $2
	`
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
	if err := r.db.QueryRowContext(ctx, processingQuery, tenantID, fiveMinutesAgo).Scan(&processingCount); err != nil {
		return nil, err
	}

	// Get stage statuses
	stageStatusQuery := `
		SELECT
			stage,
			COUNT(*) as current_count,
			COUNT(CASE WHEN created_at > $2 THEN 1 END) as processed_5min
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND stage NOT IN ('flow_execution')
		GROUP BY stage
	`

	rows, err := r.db.QueryContext(ctx, stageStatusQuery, tenantID, fiveMinutesAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stageStatusMap := make(map[string]model.StageStatus)
	for rows.Next() {
		var ss model.StageStatus
		if err := rows.Scan(&ss.Name, &ss.CurrentCount, &ss.ProcessedLast5Min); err != nil {
			return nil, err
		}
		if ss.CurrentCount > 0 {
			ss.Status = "active"
		} else {
			ss.Status = "idle"
		}
		stageStatusMap[ss.Name] = ss
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Build ordered stage status list
	stages := []model.StageStatus{}
	stageOrder := []model.PipelineStage{
		model.StageEventReceive,
		model.StageClassification,
		model.StagePlaybookSelect,
		model.StageFlowExecution,
	}

	for _, stage := range stageOrder {
		stageName := string(stage)
		if ss, exists := stageStatusMap[stageName]; exists {
			stages = append(stages, ss)
		} else {
			stages = append(stages, model.StageStatus{
				Name:             stageName,
				Status:           "idle",
				CurrentCount:     0,
				ProcessedLast5Min: 0,
			})
		}
	}

	// Determine overall status
	overallStatus := "healthy"
	if processingCount > 100 {
		overallStatus = "degraded"
	}

	status := &model.PipelineStatus{
		Status:       overallStatus,
		IsProcessing: processingCount > 0,
		Stages:       stages,
	}

	if lastEventAt.Valid {
		status.LastEventAt = lastEventAt.Time
	}

	return status, nil
}

// GetStageDetails retrieves detailed information about all pipeline stages.
func (r *PipelineRepository) GetStageDetails(ctx context.Context, tenantID string) ([]model.StageDetail, error) {
	if r.db == nil {
		return []model.StageDetail{}, nil
	}

	stageOrder := []model.PipelineStage{
		model.StageEventReceive,
		model.StageClassification,
		model.StagePlaybookSelect,
		model.StageFlowExecution,
	}

	details := make([]model.StageDetail, 0, len(stageOrder))

	for _, stage := range stageOrder {
		stageName := string(stage)
		displayInfo := model.StageDisplayInfo[stage]

		detail := model.StageDetail{
			Name:        stageName,
			DisplayName: displayInfo.DisplayName,
			Description: displayInfo.Description,
			Status:      "idle",
		}

		// Get stage stats
		stats, err := r.getSingleStageStats(ctx, tenantID, stageName)
		if err != nil {
			return nil, err
		}
		detail.Stats = stats

		// Get recent events for this stage
		recentEvents, err := r.getRecentEventsForStage(ctx, tenantID, stageName, 5)
		if err != nil {
			return nil, err
		}
		detail.RecentEvents = recentEvents

		// Determine status based on recent activity
		if stats.Entered > 0 {
			detail.Status = "active"
		}
		if stats.Failed > stats.Completed/10 { // >10% failure rate
			detail.Status = "error"
		}

		details = append(details, detail)
	}

	return details, nil
}

// getSingleStageStats retrieves statistics for a single stage.
func (r *PipelineRepository) getSingleStageStats(ctx context.Context, tenantID, stage string) (model.StageStat, error) {
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	query := `
		SELECT
			COUNT(*) as entered,
			COUNT(CASE WHEN stage = 'flow_execution' THEN 1 END) as completed,
			COUNT(CASE WHEN execution->>'status' = 'FAILED' THEN 1 END) as failed,
			COALESCE(AVG(CASE
				WHEN classification->>'processing_time_ms' IS NOT NULL
				THEN (classification->>'processing_time_ms')::float
			END), 0) as avg_time_ms
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND stage = $2
		  AND created_at > $3
	`

	var stat model.StageStat
	err := r.db.QueryRowContext(ctx, query, tenantID, stage, fiveMinutesAgo).Scan(
		&stat.Entered, &stat.Completed, &stat.Failed, &stat.AvgTimeMs,
	)

	return stat, err
}

// getRecentEventsForStage retrieves recent events for a specific stage.
func (r *PipelineRepository) getRecentEventsForStage(ctx context.Context, tenantID, stage string, limit int) ([]model.EventSummary, error) {
	query := `
		SELECT id, source, severity, classification->>'label' as label, created_at
		FROM pipeline_events
		WHERE ($1 = '' OR tenant_id = $1)
		  AND stage = $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, stage, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]model.EventSummary, 0, limit)
	for rows.Next() {
		var e model.EventSummary
		var label sql.NullString
		if err := rows.Scan(&e.ID, &e.Source, &e.Severity, &label, &e.Timestamp); err != nil {
			return nil, err
		}
		if label.Valid {
			e.Label = label.String
		}
		events = append(events, e)
	}

	return events, rows.Err()
}

// DeleteEvent deletes a pipeline event.
func (r *PipelineRepository) DeleteEvent(ctx context.Context, id string) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	query := `DELETE FROM pipeline_events WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("event not found: %s", id)
	}

	return nil
}
