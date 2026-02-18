// Package playbook provides PostgreSQL storage for playbooks.
package playbook

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// PostgresStore implements the Store interface using PostgreSQL.
type PostgresStore struct {
	db        *sql.DB
	validator *Validator
}

// NewPostgresStore creates a new PostgreSQL store.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:        db,
		validator: NewValidator(),
	}
}

// PlaybookDefinition represents the JSONB definition stored in database.
type PlaybookDefinition struct {
	Nodes     json.RawMessage `json:"nodes"`
	Edges     json.RawMessage `json:"edges"`
	Variables json.RawMessage `json:"variables,omitempty"`
	Steps     []Step          `json:"steps,omitempty"`
	Inputs    []InputParameter `json:"inputs,omitempty"`
	Outputs   []OutputField    `json:"outputs,omitempty"`
}

// Create creates a new playbook in the database.
func (s *PostgresStore) Create(ctx context.Context, playbook *Playbook) error {
	// Generate ID if not provided
	if playbook.ID == "" {
		playbook.ID = fmt.Sprintf("PB-%d", time.Now().UnixMilli())
	}

	// Set timestamps
	now := time.Now()
	playbook.CreatedAt = now
	playbook.UpdatedAt = now
	playbook.Version = 1

	// Validate playbook
	result := s.validator.Validate(playbook)
	if !result.Valid {
		return fmt.Errorf("validation failed: %s", result.Error())
	}

	// Prepare definition JSONB
	definition, err := json.Marshal(map[string]interface{}{
		"steps":     playbook.Steps,
		"inputs":    playbook.Inputs,
		"outputs":   playbook.Outputs,
		"variables": playbook.Variables,
		"secrets":   playbook.Secrets,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}

	// Prepare trigger config JSONB
	triggerConfig, err := json.Marshal(playbook.Trigger)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger config: %w", err)
	}

	// Default tenant ID
	tenantID := playbook.TenantID
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000000" // Default tenant
	}

	query := `
		INSERT INTO soar.playbooks (
			id, tenant_id, name, display_name, description, category,
			version, definition, trigger_config, trigger_type,
			status, is_enabled, tags, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			'DRAFT', $11, $12, $13, $14
		)
	`

	_, err = s.db.ExecContext(ctx, query,
		playbook.ID,
		tenantID,
		playbook.Name,
		playbook.DisplayName,
		playbook.Description,
		string(playbook.Category),
		playbook.Version,
		definition,
		triggerConfig,
		string(playbook.Trigger.Type),
		playbook.Enabled,
		pq.Array(playbook.Tags),
		playbook.CreatedAt,
		playbook.UpdatedAt,
	)

	if err != nil {
		// Check for duplicate
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return fmt.Errorf("playbook with ID %s already exists", playbook.ID)
		}
		return fmt.Errorf("failed to create playbook: %w", err)
	}

	return nil
}

// Get retrieves a playbook by ID.
func (s *PostgresStore) Get(ctx context.Context, id string) (*Playbook, error) {
	query := `
		SELECT
			id, tenant_id, name, display_name, description, category,
			version, definition, trigger_config, trigger_type,
			is_enabled, tags, created_at, updated_at
		FROM soar.playbooks
		WHERE id = $1 AND is_latest = TRUE
	`

	var pb Playbook
	var definition, triggerConfig []byte
	var tags pq.StringArray
	var category, triggerType string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&pb.ID,
		&pb.TenantID,
		&pb.Name,
		&pb.DisplayName,
		&pb.Description,
		&category,
		&pb.Version,
		&definition,
		&triggerConfig,
		&triggerType,
		&pb.Enabled,
		&tags,
		&pb.CreatedAt,
		&pb.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("playbook %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook: %w", err)
	}

	pb.Category = Category(category)
	pb.Trigger.Type = TriggerType(triggerType)
	pb.Tags = []string(tags)

	// Parse definition
	var def PlaybookDefinition
	if err := json.Unmarshal(definition, &def); err == nil {
		pb.Steps = def.Steps
		pb.Inputs = def.Inputs
		pb.Outputs = def.Outputs
	}

	// Parse trigger config
	if err := json.Unmarshal(triggerConfig, &pb.Trigger); err != nil {
		// Ignore error, keep default trigger
	}

	return &pb, nil
}

// GetByName retrieves a playbook by name.
func (s *PostgresStore) GetByName(ctx context.Context, name string) (*Playbook, error) {
	query := `
		SELECT id FROM soar.playbooks
		WHERE name = $1 AND is_latest = TRUE
		LIMIT 1
	`

	var id string
	err := s.db.QueryRowContext(ctx, query, name).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("playbook with name %s not found", name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook by name: %w", err)
	}

	return s.Get(ctx, id)
}

// GetVersion retrieves a specific version of a playbook.
func (s *PostgresStore) GetVersion(ctx context.Context, id string, version int) (*Playbook, error) {
	// For soft versioning, we only keep the latest version
	// So this just returns the current if version matches
	pb, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if pb.Version != version {
		return nil, fmt.Errorf("playbook %s version %d not found (current: %d)", id, version, pb.Version)
	}
	return pb, nil
}

// Update updates an existing playbook.
func (s *PostgresStore) Update(ctx context.Context, playbook *Playbook) error {
	// Validate playbook
	result := s.validator.Validate(playbook)
	if !result.Valid {
		return fmt.Errorf("validation failed: %s", result.Error())
	}

	// Prepare definition JSONB
	definition, err := json.Marshal(map[string]interface{}{
		"steps":     playbook.Steps,
		"inputs":    playbook.Inputs,
		"outputs":   playbook.Outputs,
		"variables": playbook.Variables,
		"secrets":   playbook.Secrets,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}

	// Prepare trigger config JSONB
	triggerConfig, err := json.Marshal(playbook.Trigger)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger config: %w", err)
	}

	// Update with version increment
	query := `
		UPDATE soar.playbooks SET
			name = $2,
			display_name = $3,
			description = $4,
			category = $5,
			version = version + 1,
			definition = $6,
			trigger_config = $7,
			trigger_type = $8,
			is_enabled = $9,
			tags = $10,
			updated_at = $11
		WHERE id = $1
		RETURNING version
	`

	var newVersion int
	err = s.db.QueryRowContext(ctx, query,
		playbook.ID,
		playbook.Name,
		playbook.DisplayName,
		playbook.Description,
		string(playbook.Category),
		definition,
		triggerConfig,
		string(playbook.Trigger.Type),
		playbook.Enabled,
		pq.Array(playbook.Tags),
		time.Now(),
	).Scan(&newVersion)

	if err == sql.ErrNoRows {
		return fmt.Errorf("playbook %s not found", playbook.ID)
	}
	if err != nil {
		return fmt.Errorf("failed to update playbook: %w", err)
	}

	playbook.Version = newVersion
	return nil
}

// Delete soft-deletes a playbook.
func (s *PostgresStore) Delete(ctx context.Context, id string) error {
	// Soft delete by setting status to DEPRECATED and is_enabled to false
	query := `
		UPDATE soar.playbooks
		SET status = 'DEPRECATED', is_enabled = FALSE, updated_at = $2
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete playbook: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("playbook %s not found", id)
	}

	return nil
}

// List lists playbooks with optional filters.
func (s *PostgresStore) List(ctx context.Context, filter *ListFilter) (*ListResult, error) {
	// Build query
	query := `
		SELECT
			id, tenant_id, name, display_name, description, category,
			version, definition, trigger_config, trigger_type,
			is_enabled, tags, created_at, updated_at
		FROM soar.playbooks
		WHERE is_latest = TRUE AND status != 'DEPRECATED'
	`

	var args []interface{}
	argIndex := 1

	if filter != nil {
		if filter.Category != "" {
			query += fmt.Sprintf(" AND category = $%d", argIndex)
			args = append(args, string(filter.Category))
			argIndex++
		}
		if filter.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
			args = append(args, filter.TenantID)
			argIndex++
		}
		if filter.Enabled != nil {
			query += fmt.Sprintf(" AND is_enabled = $%d", argIndex)
			args = append(args, *filter.Enabled)
			argIndex++
		}
		if filter.Trigger != "" {
			query += fmt.Sprintf(" AND trigger_type = $%d", argIndex)
			args = append(args, string(filter.Trigger))
			argIndex++
		}
		if filter.Search != "" {
			query += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex)
			args = append(args, "%"+filter.Search+"%")
			argIndex++
		}
	}

	// Count total
	countQuery := strings.Replace(query, "SELECT \n\t\t\tid, tenant_id, name, display_name, description, category,\n\t\t\tversion, definition, trigger_config, trigger_type,\n\t\t\tis_enabled, tags, created_at, updated_at", "SELECT COUNT(*)", 1)

	var total int64
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count playbooks: %w", err)
	}

	// Add ordering and pagination
	query += " ORDER BY updated_at DESC"

	limit := 100
	offset := 0
	if filter != nil {
		if filter.Limit > 0 {
			limit = filter.Limit
		}
		offset = filter.Offset
	}

	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	// Execute query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list playbooks: %w", err)
	}
	defer rows.Close()

	var playbooks []*Playbook
	for rows.Next() {
		var pb Playbook
		var definition, triggerConfig []byte
		var tags pq.StringArray
		var category, triggerType string

		err := rows.Scan(
			&pb.ID,
			&pb.TenantID,
			&pb.Name,
			&pb.DisplayName,
			&pb.Description,
			&category,
			&pb.Version,
			&definition,
			&triggerConfig,
			&triggerType,
			&pb.Enabled,
			&tags,
			&pb.CreatedAt,
			&pb.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan playbook: %w", err)
		}

		pb.Category = Category(category)
		pb.Trigger.Type = TriggerType(triggerType)
		pb.Tags = []string(tags)

		playbooks = append(playbooks, &pb)
	}

	return &ListResult{
		Playbooks: playbooks,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
		HasMore:   int64(offset+limit) < total,
	}, nil
}

// ListVersions lists all versions of a playbook.
func (s *PostgresStore) ListVersions(ctx context.Context, id string) ([]*PlaybookVersion, error) {
	// For soft versioning, we only have current version
	pb, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return []*PlaybookVersion{
		{
			ID:        pb.ID,
			Version:   pb.Version,
			CreatedAt: pb.UpdatedAt,
			CreatedBy: pb.Author,
		},
	}, nil
}

// Enable enables a playbook.
func (s *PostgresStore) Enable(ctx context.Context, id string) error {
	query := `UPDATE soar.playbooks SET is_enabled = TRUE, updated_at = $2 WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id, time.Now())
	return err
}

// Disable disables a playbook.
func (s *PostgresStore) Disable(ctx context.Context, id string) error {
	query := `UPDATE soar.playbooks SET is_enabled = FALSE, updated_at = $2 WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id, time.Now())
	return err
}

// Import imports playbooks from YAML.
func (s *PostgresStore) Import(ctx context.Context, data []byte) ([]*Playbook, error) {
	multiParser := NewMultiDocParser()
	playbooks, err := multiParser.Parse(bytesReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse playbooks: %w", err)
	}

	var imported []*Playbook
	for _, pb := range playbooks {
		if err := s.Create(ctx, pb); err != nil {
			return imported, fmt.Errorf("failed to import playbook %s: %w", pb.Name, err)
		}
		imported = append(imported, pb)
	}

	return imported, nil
}

// Export exports playbooks to YAML.
func (s *PostgresStore) Export(ctx context.Context, ids []string) ([]byte, error) {
	var playbooks []*Playbook
	for _, id := range ids {
		pb, err := s.Get(ctx, id)
		if err == nil {
			playbooks = append(playbooks, pb)
		}
	}

	if len(playbooks) == 0 {
		return nil, fmt.Errorf("no playbooks found")
	}

	var result []byte
	for i, pb := range playbooks {
		data, err := Serialize(pb)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize playbook %s: %w", pb.ID, err)
		}
		if i > 0 {
			result = append(result, []byte("\n---\n")...)
		}
		result = append(result, data...)
	}

	return result, nil
}

// SaveWithDefinition saves a playbook with raw definition JSONB (for frontend compatibility).
func (s *PostgresStore) SaveWithDefinition(ctx context.Context, id, name, displayName, description, category string,
	definition json.RawMessage, triggerType string, enabled bool, tags []string) error {

	now := time.Now()
	tenantID := "00000000-0000-0000-0000-000000000000"

	// Check if exists
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM soar.playbooks WHERE id = $1)", id).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check playbook existence: %w", err)
	}

	if exists {
		// Update
		query := `
			UPDATE soar.playbooks SET
				name = $2,
				display_name = $3,
				description = $4,
				category = $5,
				definition = $6,
				trigger_type = $7,
				is_enabled = $8,
				tags = $9,
				version = version + 1,
				updated_at = $10
			WHERE id = $1
		`
		_, err = s.db.ExecContext(ctx, query, id, name, displayName, description, category,
			definition, triggerType, enabled, pq.Array(tags), now)
	} else {
		// Insert
		query := `
			INSERT INTO soar.playbooks (
				id, tenant_id, name, display_name, description, category,
				version, definition, trigger_type, status, is_enabled, tags,
				created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				1, $7, $8, 'DRAFT', $9, $10, $11, $12
			)
		`
		_, err = s.db.ExecContext(ctx, query, id, tenantID, name, displayName, description, category,
			definition, triggerType, enabled, pq.Array(tags), now, now)
	}

	if err != nil {
		return fmt.Errorf("failed to save playbook: %w", err)
	}

	return nil
}

// GetWithDefinition retrieves a playbook with raw definition JSONB.
func (s *PostgresStore) GetWithDefinition(ctx context.Context, id string) (map[string]interface{}, error) {
	query := `
		SELECT
			id, name, display_name, description, category,
			version, definition, trigger_type, is_enabled, tags,
			created_at, updated_at
		FROM soar.playbooks
		WHERE id = $1 AND is_latest = TRUE AND status != 'DEPRECATED'
	`

	var (
		pbID, name, displayName, description, category, triggerType string
		version                                                      int
		definition                                                   []byte
		enabled                                                      bool
		tags                                                         pq.StringArray
		createdAt, updatedAt                                         time.Time
	)

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&pbID, &name, &displayName, &description, &category,
		&version, &definition, &triggerType, &enabled, &tags,
		&createdAt, &updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("playbook %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get playbook: %w", err)
	}

	// Parse definition
	var def map[string]interface{}
	if err := json.Unmarshal(definition, &def); err != nil {
		def = make(map[string]interface{})
	}

	return map[string]interface{}{
		"id":           pbID,
		"name":         name,
		"display_name": displayName,
		"description":  description,
		"category":     category,
		"version":      version,
		"definition":   def,
		"trigger_type": triggerType,
		"enabled":      enabled,
		"tags":         []string(tags),
		"created_at":   createdAt.Format(time.RFC3339),
		"updated_at":   updatedAt.Format(time.RFC3339),
	}, nil
}

// ListWithDefinitions lists playbooks with raw definitions.
func (s *PostgresStore) ListWithDefinitions(ctx context.Context) ([]map[string]interface{}, error) {
	query := `
		SELECT
			id, name, display_name, description, category,
			version, definition, trigger_type, is_enabled, tags,
			created_at, updated_at
		FROM soar.playbooks
		WHERE is_latest = TRUE AND status != 'DEPRECATED'
		ORDER BY updated_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list playbooks: %w", err)
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var (
			pbID, name, displayName, description, category, triggerType string
			version                                                      int
			definition                                                   []byte
			enabled                                                      bool
			tags                                                         pq.StringArray
			createdAt, updatedAt                                         time.Time
		)

		err := rows.Scan(
			&pbID, &name, &displayName, &description, &category,
			&version, &definition, &triggerType, &enabled, &tags,
			&createdAt, &updatedAt,
		)
		if err != nil {
			continue
		}

		var def map[string]interface{}
		json.Unmarshal(definition, &def)

		result = append(result, map[string]interface{}{
			"id":           pbID,
			"name":         name,
			"display_name": displayName,
			"description":  description,
			"category":     category,
			"version":      version,
			"definition":   def,
			"trigger_type": triggerType,
			"enabled":      enabled,
			"tags":         []string(tags),
			"created_at":   createdAt.Format(time.RFC3339),
			"updated_at":   updatedAt.Format(time.RFC3339),
		})
	}

	return result, nil
}

// DeletePermanently permanently deletes a playbook.
func (s *PostgresStore) DeletePermanently(ctx context.Context, id string) error {
	query := `DELETE FROM soar.playbooks WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete playbook: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("playbook %s not found", id)
	}

	return nil
}

// Helper function to generate playbook ID
func GeneratePlaybookID() string {
	return fmt.Sprintf("PB-%d", time.Now().UnixMilli())
}

// Ensure PostgresStore implements Store interface
var _ Store = (*PostgresStore)(nil)
