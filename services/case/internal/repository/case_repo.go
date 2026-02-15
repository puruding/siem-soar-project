// Package repository provides data access layer for cases.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/siem-soar-platform/services/case/internal/model"
)

// CaseRepository handles case data persistence.
type CaseRepository struct {
	db *sqlx.DB
}

// NewCaseRepository creates a new case repository.
func NewCaseRepository(db *sqlx.DB) *CaseRepository {
	return &CaseRepository{db: db}
}

// Create creates a new case.
func (r *CaseRepository) Create(ctx context.Context, caseObj *model.Case) error {
	query := `
		INSERT INTO cases (
			id, number, title, description, type, severity, priority, status,
			assignee, assignee_email, team, source, source_id, playbook_id,
			classification, classification_reason, impact_score, data_breached,
			business_impact, sla_deadline, response_time, resolution_time,
			ticket_id, ticket_url, evidence_count, comment_count, task_count,
			created_at, updated_at, created_by, tenant_id,
			collaborators, alert_ids, tags, labels, tactics, techniques,
			affected_assets, affected_users, external_refs, custom_fields
		) VALUES (
			:id, :number, :title, :description, :type, :severity, :priority, :status,
			:assignee, :assignee_email, :team, :source, :source_id, :playbook_id,
			:classification, :classification_reason, :impact_score, :data_breached,
			:business_impact, :sla_deadline, :response_time, :resolution_time,
			:ticket_id, :ticket_url, :evidence_count, :comment_count, :task_count,
			:created_at, :updated_at, :created_by, :tenant_id,
			:collaborators, :alert_ids, :tags, :labels, :tactics, :techniques,
			:affected_assets, :affected_users, :external_refs, :custom_fields
		)
	`

	_, err := r.db.NamedExecContext(ctx, query, r.toDBCase(caseObj))
	return err
}

// Get retrieves a case by ID.
func (r *CaseRepository) Get(ctx context.Context, id string) (*model.Case, error) {
	var dbCase dbCase
	query := `SELECT * FROM cases WHERE id = $1`

	err := r.db.GetContext(ctx, &dbCase, query, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("case not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get case: %w", err)
	}

	return r.fromDBCase(&dbCase), nil
}

// Update updates an existing case.
func (r *CaseRepository) Update(ctx context.Context, caseObj *model.Case) error {
	query := `
		UPDATE cases SET
			title = :title,
			description = :description,
			type = :type,
			severity = :severity,
			priority = :priority,
			status = :status,
			assignee = :assignee,
			assignee_email = :assignee_email,
			team = :team,
			classification = :classification,
			classification_reason = :classification_reason,
			impact_score = :impact_score,
			data_breached = :data_breached,
			business_impact = :business_impact,
			resolution = :resolution,
			resolution_notes = :resolution_notes,
			resolved_at = :resolved_at,
			resolved_by = :resolved_by,
			root_cause = :root_cause,
			lessons_learned = :lessons_learned,
			sla_deadline = :sla_deadline,
			sla_breached = :sla_breached,
			ticket_id = :ticket_id,
			ticket_url = :ticket_url,
			updated_at = :updated_at,
			updated_by = :updated_by,
			closed_at = :closed_at,
			closed_by = :closed_by,
			collaborators = :collaborators,
			alert_ids = :alert_ids,
			tags = :tags,
			labels = :labels,
			tactics = :tactics,
			techniques = :techniques,
			affected_assets = :affected_assets,
			affected_users = :affected_users,
			external_refs = :external_refs,
			custom_fields = :custom_fields
		WHERE id = :id
	`

	result, err := r.db.NamedExecContext(ctx, query, r.toDBCase(caseObj))
	if err != nil {
		return fmt.Errorf("failed to update case: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("case not found: %s", caseObj.ID)
	}

	return nil
}

// Delete deletes a case.
func (r *CaseRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM cases WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete case: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("case not found: %s", id)
	}

	return nil
}

// List retrieves cases based on filter criteria.
func (r *CaseRepository) List(ctx context.Context, filter *model.CaseFilter) (*model.CaseListResult, error) {
	conditions := []string{"1=1"}
	args := make(map[string]interface{})
	argIndex := 1

	// Build WHERE clause
	if len(filter.Status) > 0 {
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = pq.Array(filter.Status)
		argIndex++
	}

	if len(filter.Severity) > 0 {
		conditions = append(conditions, fmt.Sprintf("severity = ANY($%d)", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = pq.Array(filter.Severity)
		argIndex++
	}

	if len(filter.Priority) > 0 {
		conditions = append(conditions, fmt.Sprintf("priority = ANY($%d)", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = pq.Array(filter.Priority)
		argIndex++
	}

	if len(filter.Type) > 0 {
		conditions = append(conditions, fmt.Sprintf("type = ANY($%d)", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = pq.Array(filter.Type)
		argIndex++
	}

	if filter.Assignee != "" {
		conditions = append(conditions, fmt.Sprintf("assignee = $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = filter.Assignee
		argIndex++
	}

	if filter.Team != "" {
		conditions = append(conditions, fmt.Sprintf("team = $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = filter.Team
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = "%" + filter.Search + "%"
		argIndex++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = filter.CreatedFrom
		argIndex++
	}

	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = filter.CreatedTo
		argIndex++
	}

	if filter.SLABreached != nil {
		conditions = append(conditions, fmt.Sprintf("sla_breached = $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = *filter.SLABreached
		argIndex++
	}

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args[fmt.Sprintf("arg%d", argIndex)] = filter.TenantID
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM cases WHERE %s", whereClause)
	var total int64
	err := r.db.GetContext(ctx, &total, countQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to count cases: %w", err)
	}

	// Build ORDER BY clause
	sortBy := "created_at"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	// Build pagination
	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	// Query cases
	query := fmt.Sprintf(`
		SELECT * FROM cases
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortBy, sortOrder, argIndex, argIndex+1)

	args[fmt.Sprintf("arg%d", argIndex)] = limit
	args[fmt.Sprintf("arg%d", argIndex+1)] = offset

	var dbCases []dbCase
	err = r.db.SelectContext(ctx, &dbCases, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list cases: %w", err)
	}

	cases := make([]*model.Case, len(dbCases))
	for i, dbCase := range dbCases {
		cases[i] = r.fromDBCase(&dbCase)
	}

	return &model.CaseListResult{
		Cases:   cases,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+limit) < total,
	}, nil
}

// GetSummary retrieves case statistics.
func (r *CaseRepository) GetSummary(ctx context.Context, tenantID string) (*model.CaseSummary, error) {
	summary := &model.CaseSummary{
		ByStatus:   make(map[model.CaseStatus]int64),
		BySeverity: make(map[model.CaseSeverity]int64),
		ByAssignee: make(map[string]int64),
	}

	// Total counts
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN status IN ('open', 'in_progress', 'pending') THEN 1 END) as open_cases,
			COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_cases,
			COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_cases,
			COUNT(CASE WHEN sla_breached = true THEN 1 END) as overdue_cases,
			AVG(CASE WHEN response_time > 0 THEN response_time END) as avg_response,
			AVG(CASE WHEN resolution_time > 0 THEN resolution_time END) as avg_resolution
		FROM cases
		WHERE ($1 = '' OR tenant_id = $1)
	`

	var stats struct {
		Total         int64         `db:"total"`
		OpenCases     int64         `db:"open_cases"`
		CriticalCases int64         `db:"critical_cases"`
		HighCases     int64         `db:"high_cases"`
		OverdueCases  int64         `db:"overdue_cases"`
		AvgResponse   sql.NullInt64 `db:"avg_response"`
		AvgResolution sql.NullInt64 `db:"avg_resolution"`
	}

	err := r.db.GetContext(ctx, &stats, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get case summary: %w", err)
	}

	summary.TotalCases = stats.Total
	summary.OpenCases = stats.OpenCases
	summary.CriticalCases = stats.CriticalCases
	summary.HighCases = stats.HighCases
	summary.OverdueCases = stats.OverdueCases
	if stats.AvgResponse.Valid {
		summary.AvgResponseTime = stats.AvgResponse.Int64
	}
	if stats.AvgResolution.Valid {
		summary.AvgResolutionTime = stats.AvgResolution.Int64
	}

	// By status
	statusQuery := `
		SELECT status, COUNT(*) as count
		FROM cases
		WHERE ($1 = '' OR tenant_id = $1)
		GROUP BY status
	`
	var statusCounts []struct {
		Status model.CaseStatus `db:"status"`
		Count  int64            `db:"count"`
	}
	err = r.db.SelectContext(ctx, &statusCounts, statusQuery, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get status counts: %w", err)
	}
	for _, sc := range statusCounts {
		summary.ByStatus[sc.Status] = sc.Count
	}

	// By severity
	severityQuery := `
		SELECT severity, COUNT(*) as count
		FROM cases
		WHERE ($1 = '' OR tenant_id = $1)
		GROUP BY severity
	`
	var severityCounts []struct {
		Severity model.CaseSeverity `db:"severity"`
		Count    int64              `db:"count"`
	}
	err = r.db.SelectContext(ctx, &severityCounts, severityQuery, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get severity counts: %w", err)
	}
	for _, sc := range severityCounts {
		summary.BySeverity[sc.Severity] = sc.Count
	}

	// By assignee
	assigneeQuery := `
		SELECT assignee, COUNT(*) as count
		FROM cases
		WHERE assignee IS NOT NULL AND assignee != ''
		  AND ($1 = '' OR tenant_id = $1)
		GROUP BY assignee
		ORDER BY count DESC
		LIMIT 20
	`
	var assigneeCounts []struct {
		Assignee string `db:"assignee"`
		Count    int64  `db:"count"`
	}
	err = r.db.SelectContext(ctx, &assigneeCounts, assigneeQuery, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get assignee counts: %w", err)
	}
	for _, ac := range assigneeCounts {
		summary.ByAssignee[ac.Assignee] = ac.Count
	}

	return summary, nil
}

// AddHistory adds a history entry for a case.
func (r *CaseRepository) AddHistory(ctx context.Context, history *model.CaseHistory) error {
	query := `
		INSERT INTO case_history (
			id, case_id, action, field, old_value, new_value,
			actor, actor_name, timestamp, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`

	metadataJSON, _ := json.Marshal(history.Metadata)

	_, err := r.db.ExecContext(ctx, query,
		history.ID, history.CaseID, history.Action, history.Field,
		history.OldValue, history.NewValue, history.Actor, history.ActorName,
		history.Timestamp, metadataJSON,
	)

	return err
}

// GetHistory retrieves history for a case.
func (r *CaseRepository) GetHistory(ctx context.Context, caseID string, limit int) ([]*model.CaseHistory, error) {
	query := `
		SELECT * FROM case_history
		WHERE case_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`

	if limit <= 0 {
		limit = 100
	}

	var dbHistories []struct {
		model.CaseHistory
		Metadata []byte `db:"metadata"`
	}

	err := r.db.SelectContext(ctx, &dbHistories, query, caseID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get case history: %w", err)
	}

	histories := make([]*model.CaseHistory, len(dbHistories))
	for i, dbHistory := range dbHistories {
		histories[i] = &dbHistory.CaseHistory
		if len(dbHistory.Metadata) > 0 {
			json.Unmarshal(dbHistory.Metadata, &histories[i].Metadata)
		}
	}

	return histories, nil
}

// dbCase represents the database schema for cases.
type dbCase struct {
	ID                   string         `db:"id"`
	Number               string         `db:"number"`
	Title                string         `db:"title"`
	Description          string         `db:"description"`
	Type                 string         `db:"type"`
	Severity             string         `db:"severity"`
	Priority             string         `db:"priority"`
	Status               string         `db:"status"`
	Assignee             sql.NullString `db:"assignee"`
	AssigneeEmail        sql.NullString `db:"assignee_email"`
	Team                 sql.NullString `db:"team"`
	Source               sql.NullString `db:"source"`
	SourceID             sql.NullString `db:"source_id"`
	PlaybookID           sql.NullString `db:"playbook_id"`
	Classification       sql.NullString `db:"classification"`
	ClassificationReason sql.NullString `db:"classification_reason"`
	ImpactScore          int            `db:"impact_score"`
	DataBreached         bool           `db:"data_breached"`
	BusinessImpact       sql.NullString `db:"business_impact"`
	Resolution           sql.NullString `db:"resolution"`
	ResolutionNotes      sql.NullString `db:"resolution_notes"`
	ResolvedAt           *time.Time     `db:"resolved_at"`
	ResolvedBy           sql.NullString `db:"resolved_by"`
	RootCause            sql.NullString `db:"root_cause"`
	LessonsLearned       sql.NullString `db:"lessons_learned"`
	SLADeadline          *time.Time     `db:"sla_deadline"`
	SLABreached          bool           `db:"sla_breached"`
	ResponseTime         int64          `db:"response_time"`
	ResolutionTime       int64          `db:"resolution_time"`
	TicketID             sql.NullString `db:"ticket_id"`
	TicketURL            sql.NullString `db:"ticket_url"`
	EvidenceCount        int            `db:"evidence_count"`
	CommentCount         int            `db:"comment_count"`
	TaskCount            int            `db:"task_count"`
	CreatedAt            time.Time      `db:"created_at"`
	UpdatedAt            time.Time      `db:"updated_at"`
	CreatedBy            string         `db:"created_by"`
	UpdatedBy            sql.NullString `db:"updated_by"`
	ClosedAt             *time.Time     `db:"closed_at"`
	ClosedBy             sql.NullString `db:"closed_by"`
	TenantID             sql.NullString `db:"tenant_id"`
	Collaborators        []byte         `db:"collaborators"`
	AlertIDs             []byte         `db:"alert_ids"`
	Tags                 []byte         `db:"tags"`
	Labels               []byte         `db:"labels"`
	Tactics              []byte         `db:"tactics"`
	Techniques           []byte         `db:"techniques"`
	AffectedAssets       []byte         `db:"affected_assets"`
	AffectedUsers        []byte         `db:"affected_users"`
	ExternalRefs         []byte         `db:"external_refs"`
	CustomFields         []byte         `db:"custom_fields"`
}

// Helper methods to convert between model and database types.
func (r *CaseRepository) toDBCase(c *model.Case) *dbCase {
	db := &dbCase{
		ID:             c.ID,
		Number:         c.Number,
		Title:          c.Title,
		Description:    c.Description,
		Type:           string(c.Type),
		Severity:       string(c.Severity),
		Priority:       string(c.Priority),
		Status:         string(c.Status),
		ImpactScore:    c.ImpactScore,
		DataBreached:   c.DataBreached,
		SLABreached:    c.SLABreached,
		ResponseTime:   c.ResponseTime,
		ResolutionTime: c.ResolutionTime,
		EvidenceCount:  c.EvidenceCount,
		CommentCount:   c.CommentCount,
		TaskCount:      c.TaskCount,
		CreatedAt:      c.CreatedAt,
		UpdatedAt:      c.UpdatedAt,
		CreatedBy:      c.CreatedBy,
		ResolvedAt:     c.ResolvedAt,
		SLADeadline:    c.SLADeadline,
		ClosedAt:       c.ClosedAt,
	}

	if c.Assignee != "" {
		db.Assignee = sql.NullString{String: c.Assignee, Valid: true}
	}
	if c.AssigneeEmail != "" {
		db.AssigneeEmail = sql.NullString{String: c.AssigneeEmail, Valid: true}
	}
	if c.Team != "" {
		db.Team = sql.NullString{String: c.Team, Valid: true}
	}
	if c.Source != "" {
		db.Source = sql.NullString{String: c.Source, Valid: true}
	}
	if c.SourceID != "" {
		db.SourceID = sql.NullString{String: c.SourceID, Valid: true}
	}
	if c.PlaybookID != "" {
		db.PlaybookID = sql.NullString{String: c.PlaybookID, Valid: true}
	}
	if c.Classification != "" {
		db.Classification = sql.NullString{String: c.Classification, Valid: true}
	}
	if c.ClassificationReason != "" {
		db.ClassificationReason = sql.NullString{String: c.ClassificationReason, Valid: true}
	}
	if c.BusinessImpact != "" {
		db.BusinessImpact = sql.NullString{String: c.BusinessImpact, Valid: true}
	}
	if c.Resolution != "" {
		db.Resolution = sql.NullString{String: c.Resolution, Valid: true}
	}
	if c.ResolutionNotes != "" {
		db.ResolutionNotes = sql.NullString{String: c.ResolutionNotes, Valid: true}
	}
	if c.ResolvedBy != "" {
		db.ResolvedBy = sql.NullString{String: c.ResolvedBy, Valid: true}
	}
	if c.RootCause != "" {
		db.RootCause = sql.NullString{String: c.RootCause, Valid: true}
	}
	if c.LessonsLearned != "" {
		db.LessonsLearned = sql.NullString{String: c.LessonsLearned, Valid: true}
	}
	if c.TicketID != "" {
		db.TicketID = sql.NullString{String: c.TicketID, Valid: true}
	}
	if c.TicketURL != "" {
		db.TicketURL = sql.NullString{String: c.TicketURL, Valid: true}
	}
	if c.UpdatedBy != "" {
		db.UpdatedBy = sql.NullString{String: c.UpdatedBy, Valid: true}
	}
	if c.ClosedBy != "" {
		db.ClosedBy = sql.NullString{String: c.ClosedBy, Valid: true}
	}
	if c.TenantID != "" {
		db.TenantID = sql.NullString{String: c.TenantID, Valid: true}
	}

	// Marshal JSON fields
	if len(c.Collaborators) > 0 {
		db.Collaborators, _ = json.Marshal(c.Collaborators)
	}
	if len(c.AlertIDs) > 0 {
		db.AlertIDs, _ = json.Marshal(c.AlertIDs)
	}
	if len(c.Tags) > 0 {
		db.Tags, _ = json.Marshal(c.Tags)
	}
	if len(c.Labels) > 0 {
		db.Labels, _ = json.Marshal(c.Labels)
	}
	if len(c.Tactics) > 0 {
		db.Tactics, _ = json.Marshal(c.Tactics)
	}
	if len(c.Techniques) > 0 {
		db.Techniques, _ = json.Marshal(c.Techniques)
	}
	if len(c.AffectedAssets) > 0 {
		db.AffectedAssets, _ = json.Marshal(c.AffectedAssets)
	}
	if len(c.AffectedUsers) > 0 {
		db.AffectedUsers, _ = json.Marshal(c.AffectedUsers)
	}
	if len(c.ExternalRefs) > 0 {
		db.ExternalRefs, _ = json.Marshal(c.ExternalRefs)
	}
	if len(c.CustomFields) > 0 {
		db.CustomFields, _ = json.Marshal(c.CustomFields)
	}

	return db
}

func (r *CaseRepository) fromDBCase(db *dbCase) *model.Case {
	c := &model.Case{
		ID:             db.ID,
		Number:         db.Number,
		Title:          db.Title,
		Description:    db.Description,
		Type:           model.CaseType(db.Type),
		Severity:       model.CaseSeverity(db.Severity),
		Priority:       model.CasePriority(db.Priority),
		Status:         model.CaseStatus(db.Status),
		ImpactScore:    db.ImpactScore,
		DataBreached:   db.DataBreached,
		SLABreached:    db.SLABreached,
		ResponseTime:   db.ResponseTime,
		ResolutionTime: db.ResolutionTime,
		EvidenceCount:  db.EvidenceCount,
		CommentCount:   db.CommentCount,
		TaskCount:      db.TaskCount,
		CreatedAt:      db.CreatedAt,
		UpdatedAt:      db.UpdatedAt,
		CreatedBy:      db.CreatedBy,
		ResolvedAt:     db.ResolvedAt,
		SLADeadline:    db.SLADeadline,
		ClosedAt:       db.ClosedAt,
	}

	if db.Assignee.Valid {
		c.Assignee = db.Assignee.String
	}
	if db.AssigneeEmail.Valid {
		c.AssigneeEmail = db.AssigneeEmail.String
	}
	if db.Team.Valid {
		c.Team = db.Team.String
	}
	if db.Source.Valid {
		c.Source = db.Source.String
	}
	if db.SourceID.Valid {
		c.SourceID = db.SourceID.String
	}
	if db.PlaybookID.Valid {
		c.PlaybookID = db.PlaybookID.String
	}
	if db.Classification.Valid {
		c.Classification = db.Classification.String
	}
	if db.ClassificationReason.Valid {
		c.ClassificationReason = db.ClassificationReason.String
	}
	if db.BusinessImpact.Valid {
		c.BusinessImpact = db.BusinessImpact.String
	}
	if db.Resolution.Valid {
		c.Resolution = db.Resolution.String
	}
	if db.ResolutionNotes.Valid {
		c.ResolutionNotes = db.ResolutionNotes.String
	}
	if db.ResolvedBy.Valid {
		c.ResolvedBy = db.ResolvedBy.String
	}
	if db.RootCause.Valid {
		c.RootCause = db.RootCause.String
	}
	if db.LessonsLearned.Valid {
		c.LessonsLearned = db.LessonsLearned.String
	}
	if db.TicketID.Valid {
		c.TicketID = db.TicketID.String
	}
	if db.TicketURL.Valid {
		c.TicketURL = db.TicketURL.String
	}
	if db.UpdatedBy.Valid {
		c.UpdatedBy = db.UpdatedBy.String
	}
	if db.ClosedBy.Valid {
		c.ClosedBy = db.ClosedBy.String
	}
	if db.TenantID.Valid {
		c.TenantID = db.TenantID.String
	}

	// Unmarshal JSON fields
	if len(db.Collaborators) > 0 {
		json.Unmarshal(db.Collaborators, &c.Collaborators)
	}
	if len(db.AlertIDs) > 0 {
		json.Unmarshal(db.AlertIDs, &c.AlertIDs)
	}
	if len(db.Tags) > 0 {
		json.Unmarshal(db.Tags, &c.Tags)
	}
	if len(db.Labels) > 0 {
		json.Unmarshal(db.Labels, &c.Labels)
	}
	if len(db.Tactics) > 0 {
		json.Unmarshal(db.Tactics, &c.Tactics)
	}
	if len(db.Techniques) > 0 {
		json.Unmarshal(db.Techniques, &c.Techniques)
	}
	if len(db.AffectedAssets) > 0 {
		json.Unmarshal(db.AffectedAssets, &c.AffectedAssets)
	}
	if len(db.AffectedUsers) > 0 {
		json.Unmarshal(db.AffectedUsers, &c.AffectedUsers)
	}
	if len(db.ExternalRefs) > 0 {
		json.Unmarshal(db.ExternalRefs, &c.ExternalRefs)
	}
	if len(db.CustomFields) > 0 {
		json.Unmarshal(db.CustomFields, &c.CustomFields)
	}

	return c
}
