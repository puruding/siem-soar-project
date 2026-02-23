// Package playbook provides playbook execution storage and retrieval.
package playbook

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// PostgresExecutionStore implements ExecutionStore using PostgreSQL.
type PostgresExecutionStore struct {
	db *sql.DB
}

// NewPostgresExecutionStore creates a new PostgreSQL execution store.
func NewPostgresExecutionStore(db *sql.DB) *PostgresExecutionStore {
	return &PostgresExecutionStore{db: db}
}

// Create creates a new execution record.
func (s *PostgresExecutionStore) Create(ctx context.Context, exec *Execution) error {
	if exec.ID == "" {
		exec.ID = uuid.New().String()
	}

	// Marshal JSON fields
	inputsJSON, err := json.Marshal(exec.Inputs)
	if err != nil {
		return fmt.Errorf("failed to marshal inputs: %w", err)
	}

	outputsJSON, err := json.Marshal(exec.Outputs)
	if err != nil {
		return fmt.Errorf("failed to marshal outputs: %w", err)
	}

	triggerInfoJSON, err := json.Marshal(exec.TriggerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger_info: %w", err)
	}

	stepResultsJSON, err := json.Marshal(exec.StepResults)
	if err != nil {
		return fmt.Errorf("failed to marshal step_results: %w", err)
	}

	query := `
		INSERT INTO soar.executions (
			id, tenant_id, playbook_id, playbook_name, playbook_version,
			status, workflow_id, run_id, trigger_type, trigger_info,
			alert_id, case_id, inputs, outputs, current_step,
			step_results, error, executed_by, started_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19
		)`

	// Convert alert_id and case_id to nullable UUIDs
	var alertID, caseID *uuid.UUID
	if exec.AlertID != "" {
		if id, err := uuid.Parse(exec.AlertID); err == nil {
			alertID = &id
		}
	}
	if exec.CaseID != "" {
		if id, err := uuid.Parse(exec.CaseID); err == nil {
			caseID = &id
		}
	}

	_, err = s.db.ExecContext(ctx, query,
		exec.ID,
		exec.TenantID,
		exec.PlaybookID,
		exec.PlaybookName,
		exec.Version,
		string(exec.Status),
		nullString(exec.WorkflowID),
		nullString(exec.RunID),
		string(exec.TriggerType),
		triggerInfoJSON,
		alertID,
		caseID,
		inputsJSON,
		outputsJSON,
		nullString(exec.CurrentStep),
		stepResultsJSON,
		nullString(exec.Error),
		nullString(exec.ExecutedBy),
		exec.StartedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert execution: %w", err)
	}

	return nil
}

// Get retrieves an execution by ID.
func (s *PostgresExecutionStore) Get(ctx context.Context, id string) (*Execution, error) {
	query := `
		SELECT
			id, tenant_id, playbook_id, playbook_name, playbook_version,
			status, workflow_id, run_id, trigger_type, trigger_info,
			alert_id, case_id, inputs, outputs, current_step,
			step_results, error, executed_by, started_at, completed_at,
			created_at, updated_at
		FROM soar.executions
		WHERE id = $1`

	exec := &Execution{}
	var (
		inputsJSON, outputsJSON, triggerInfoJSON, stepResultsJSON []byte
		workflowID, runID, currentStep, errMsg, executedBy         sql.NullString
		alertID, caseID                                            *uuid.UUID
		completedAt                                                 sql.NullTime
	)

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&exec.ID,
		&exec.TenantID,
		&exec.PlaybookID,
		&exec.PlaybookName,
		&exec.Version,
		&exec.Status,
		&workflowID,
		&runID,
		&exec.TriggerType,
		&triggerInfoJSON,
		&alertID,
		&caseID,
		&inputsJSON,
		&outputsJSON,
		&currentStep,
		&stepResultsJSON,
		&errMsg,
		&executedBy,
		&exec.StartedAt,
		&completedAt,
		&exec.StartedAt, // created_at -> using StartedAt as fallback
		&exec.StartedAt, // updated_at -> using StartedAt as fallback
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("execution %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get execution: %w", err)
	}

	// Parse nullable fields
	exec.WorkflowID = workflowID.String
	exec.RunID = runID.String
	exec.CurrentStep = currentStep.String
	exec.Error = errMsg.String
	exec.ExecutedBy = executedBy.String

	if alertID != nil {
		exec.AlertID = alertID.String()
	}
	if caseID != nil {
		exec.CaseID = caseID.String()
	}
	if completedAt.Valid {
		t := completedAt.Time
		exec.CompletedAt = &t
	}

	// Unmarshal JSON fields
	if len(inputsJSON) > 0 {
		if err := json.Unmarshal(inputsJSON, &exec.Inputs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal inputs: %w", err)
		}
	}
	if len(outputsJSON) > 0 {
		if err := json.Unmarshal(outputsJSON, &exec.Outputs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal outputs: %w", err)
		}
	}
	if len(triggerInfoJSON) > 0 {
		if err := json.Unmarshal(triggerInfoJSON, &exec.TriggerInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal trigger_info: %w", err)
		}
	}
	if len(stepResultsJSON) > 0 {
		if err := json.Unmarshal(stepResultsJSON, &exec.StepResults); err != nil {
			return nil, fmt.Errorf("failed to unmarshal step_results: %w", err)
		}
	}

	return exec, nil
}

// Update updates an execution.
func (s *PostgresExecutionStore) Update(ctx context.Context, exec *Execution) error {
	outputsJSON, err := json.Marshal(exec.Outputs)
	if err != nil {
		return fmt.Errorf("failed to marshal outputs: %w", err)
	}

	stepResultsJSON, err := json.Marshal(exec.StepResults)
	if err != nil {
		return fmt.Errorf("failed to marshal step_results: %w", err)
	}

	query := `
		UPDATE soar.executions SET
			status = $2,
			workflow_id = $3,
			run_id = $4,
			outputs = $5,
			current_step = $6,
			step_results = $7,
			error = $8,
			completed_at = $9,
			updated_at = NOW()
		WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query,
		exec.ID,
		string(exec.Status),
		nullString(exec.WorkflowID),
		nullString(exec.RunID),
		outputsJSON,
		nullString(exec.CurrentStep),
		stepResultsJSON,
		nullString(exec.Error),
		exec.CompletedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update execution: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("execution %s not found", exec.ID)
	}

	return nil
}

// List lists executions with optional filters.
func (s *PostgresExecutionStore) List(ctx context.Context, filter *ExecutionFilter) (*ExecutionListResult, error) {
	var args []interface{}
	argIndex := 1

	whereClause := "WHERE 1=1"

	if filter.TenantID != "" {
		whereClause += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
		args = append(args, filter.TenantID)
		argIndex++
	}

	if filter.PlaybookID != "" {
		whereClause += fmt.Sprintf(" AND playbook_id = $%d", argIndex)
		args = append(args, filter.PlaybookID)
		argIndex++
	}

	if filter.AlertID != "" {
		whereClause += fmt.Sprintf(" AND alert_id = $%d", argIndex)
		alertUUID, err := uuid.Parse(filter.AlertID)
		if err != nil {
			return nil, fmt.Errorf("invalid alert_id: %w", err)
		}
		args = append(args, alertUUID)
		argIndex++
	}

	if filter.CaseID != "" {
		whereClause += fmt.Sprintf(" AND case_id = $%d", argIndex)
		caseUUID, err := uuid.Parse(filter.CaseID)
		if err != nil {
			return nil, fmt.Errorf("invalid case_id: %w", err)
		}
		args = append(args, caseUUID)
		argIndex++
	}

	if len(filter.Status) > 0 {
		statusStrings := make([]string, len(filter.Status))
		for i, s := range filter.Status {
			statusStrings[i] = string(s)
		}
		whereClause += fmt.Sprintf(" AND status = ANY($%d)", argIndex)
		args = append(args, pq.Array(statusStrings))
		argIndex++
	}

	if !filter.StartTime.IsZero() {
		whereClause += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}

	if !filter.EndTime.IsZero() {
		whereClause += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM soar.executions " + whereClause
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count executions: %w", err)
	}

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset

	orderClause := " ORDER BY created_at DESC"
	limitClause := fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	selectQuery := `
		SELECT
			id, tenant_id, playbook_id, playbook_name, playbook_version,
			status, workflow_id, run_id, trigger_type, trigger_info,
			alert_id, case_id, inputs, outputs, current_step,
			step_results, error, executed_by, started_at, completed_at
		FROM soar.executions ` + whereClause + orderClause + limitClause

	rows, err := s.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list executions: %w", err)
	}
	defer rows.Close()

	var executions []*Execution
	for rows.Next() {
		exec := &Execution{}
		var (
			inputsJSON, outputsJSON, triggerInfoJSON, stepResultsJSON []byte
			workflowID, runID, currentStep, errMsg, executedBy         sql.NullString
			alertID, caseID                                            *uuid.UUID
			completedAt                                                 sql.NullTime
		)

		err := rows.Scan(
			&exec.ID,
			&exec.TenantID,
			&exec.PlaybookID,
			&exec.PlaybookName,
			&exec.Version,
			&exec.Status,
			&workflowID,
			&runID,
			&exec.TriggerType,
			&triggerInfoJSON,
			&alertID,
			&caseID,
			&inputsJSON,
			&outputsJSON,
			&currentStep,
			&stepResultsJSON,
			&errMsg,
			&executedBy,
			&exec.StartedAt,
			&completedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan execution: %w", err)
		}

		// Parse nullable fields
		exec.WorkflowID = workflowID.String
		exec.RunID = runID.String
		exec.CurrentStep = currentStep.String
		exec.Error = errMsg.String
		exec.ExecutedBy = executedBy.String

		if alertID != nil {
			exec.AlertID = alertID.String()
		}
		if caseID != nil {
			exec.CaseID = caseID.String()
		}
		if completedAt.Valid {
			t := completedAt.Time
			exec.CompletedAt = &t
		}

		// Unmarshal JSON fields
		if len(inputsJSON) > 0 {
			json.Unmarshal(inputsJSON, &exec.Inputs)
		}
		if len(outputsJSON) > 0 {
			json.Unmarshal(outputsJSON, &exec.Outputs)
		}
		if len(triggerInfoJSON) > 0 {
			json.Unmarshal(triggerInfoJSON, &exec.TriggerInfo)
		}
		if len(stepResultsJSON) > 0 {
			json.Unmarshal(stepResultsJSON, &exec.StepResults)
		}

		executions = append(executions, exec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating executions: %w", err)
	}

	return &ExecutionListResult{
		Executions: executions,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		HasMore:    int64(offset+len(executions)) < total,
	}, nil
}

// GetByWorkflowID retrieves an execution by Temporal workflow ID.
func (s *PostgresExecutionStore) GetByWorkflowID(ctx context.Context, workflowID string) (*Execution, error) {
	query := `
		SELECT id FROM soar.executions
		WHERE workflow_id = $1
		ORDER BY created_at DESC
		LIMIT 1`

	var id string
	err := s.db.QueryRowContext(ctx, query, workflowID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("execution with workflow ID %s not found", workflowID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get execution by workflow ID: %w", err)
	}

	return s.Get(ctx, id)
}

// GetByAlertID retrieves executions for a specific alert.
func (s *PostgresExecutionStore) GetByAlertID(ctx context.Context, alertID string) ([]*Execution, error) {
	alertUUID, err := uuid.Parse(alertID)
	if err != nil {
		// If alertID is not a valid UUID, try to use it as-is (for TEXT-based IDs)
		filter := &ExecutionFilter{
			Limit: 100,
		}
		result, err := s.List(ctx, filter)
		if err != nil {
			return nil, err
		}

		// Filter manually for non-UUID alert IDs
		var executions []*Execution
		for _, exec := range result.Executions {
			if exec.AlertID == alertID {
				executions = append(executions, exec)
			}
		}
		return executions, nil
	}

	query := `
		SELECT
			id, tenant_id, playbook_id, playbook_name, playbook_version,
			status, workflow_id, run_id, trigger_type, trigger_info,
			alert_id, case_id, inputs, outputs, current_step,
			step_results, error, executed_by, started_at, completed_at
		FROM soar.executions
		WHERE alert_id = $1
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, alertUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get executions by alert ID: %w", err)
	}
	defer rows.Close()

	var executions []*Execution
	for rows.Next() {
		exec := &Execution{}
		var (
			inputsJSON, outputsJSON, triggerInfoJSON, stepResultsJSON []byte
			workflowID, runID, currentStep, errMsg, executedBy         sql.NullString
			aID, caseID                                                *uuid.UUID
			completedAt                                                 sql.NullTime
		)

		err := rows.Scan(
			&exec.ID,
			&exec.TenantID,
			&exec.PlaybookID,
			&exec.PlaybookName,
			&exec.Version,
			&exec.Status,
			&workflowID,
			&runID,
			&exec.TriggerType,
			&triggerInfoJSON,
			&aID,
			&caseID,
			&inputsJSON,
			&outputsJSON,
			&currentStep,
			&stepResultsJSON,
			&errMsg,
			&executedBy,
			&exec.StartedAt,
			&completedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan execution: %w", err)
		}

		// Parse nullable fields
		exec.WorkflowID = workflowID.String
		exec.RunID = runID.String
		exec.CurrentStep = currentStep.String
		exec.Error = errMsg.String
		exec.ExecutedBy = executedBy.String

		if aID != nil {
			exec.AlertID = aID.String()
		}
		if caseID != nil {
			exec.CaseID = caseID.String()
		}
		if completedAt.Valid {
			t := completedAt.Time
			exec.CompletedAt = &t
		}

		// Unmarshal JSON fields
		if len(inputsJSON) > 0 {
			json.Unmarshal(inputsJSON, &exec.Inputs)
		}
		if len(outputsJSON) > 0 {
			json.Unmarshal(outputsJSON, &exec.Outputs)
		}
		if len(triggerInfoJSON) > 0 {
			json.Unmarshal(triggerInfoJSON, &exec.TriggerInfo)
		}
		if len(stepResultsJSON) > 0 {
			json.Unmarshal(stepResultsJSON, &exec.StepResults)
		}

		executions = append(executions, exec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating executions: %w", err)
	}

	return executions, nil
}

// AddStepResult adds a step result to an execution.
func (s *PostgresExecutionStore) AddStepResult(ctx context.Context, executionID string, result *StepResult) error {
	// Get current step results
	var stepResultsJSON []byte
	query := "SELECT step_results FROM soar.executions WHERE id = $1"
	err := s.db.QueryRowContext(ctx, query, executionID).Scan(&stepResultsJSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("execution %s not found", executionID)
	}
	if err != nil {
		return fmt.Errorf("failed to get step results: %w", err)
	}

	// Parse existing results
	var stepResults []StepResult
	if len(stepResultsJSON) > 0 {
		if err := json.Unmarshal(stepResultsJSON, &stepResults); err != nil {
			return fmt.Errorf("failed to unmarshal step results: %w", err)
		}
	}

	// Add new result
	stepResults = append(stepResults, *result)

	// Marshal updated results
	updatedJSON, err := json.Marshal(stepResults)
	if err != nil {
		return fmt.Errorf("failed to marshal step results: %w", err)
	}

	// Update database
	updateQuery := `
		UPDATE soar.executions SET
			step_results = $2,
			current_step = $3,
			updated_at = NOW()
		WHERE id = $1`

	_, err = s.db.ExecContext(ctx, updateQuery, executionID, updatedJSON, result.StepID)
	if err != nil {
		return fmt.Errorf("failed to add step result: %w", err)
	}

	return nil
}

// UpdateStatus updates the execution status.
func (s *PostgresExecutionStore) UpdateStatus(ctx context.Context, id string, status ExecutionStatus, errMsg string) error {
	var completedAt *time.Time
	if status == StatusCompleted || status == StatusFailed || status == StatusCancelled || status == StatusTimedOut {
		now := time.Now()
		completedAt = &now
	}

	query := `
		UPDATE soar.executions SET
			status = $2,
			error = $3,
			completed_at = $4,
			updated_at = NOW()
		WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, id, string(status), nullString(errMsg), completedAt)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("execution %s not found", id)
	}

	return nil
}

// Helper function to create nullable string
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
