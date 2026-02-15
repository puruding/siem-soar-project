// Package repository provides data access for asset management.
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
	"github.com/siem-soar-platform/services/asset-registry/internal/model"
)

// AssetRepository defines the interface for asset data access.
type AssetRepository interface {
	// Asset CRUD
	Create(ctx context.Context, asset *model.Asset) error
	GetByID(ctx context.Context, id string) (*model.Asset, error)
	Update(ctx context.Context, asset *model.Asset) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *model.AssetFilter) (*model.AssetListResult, error)

	// Identifier operations
	AddIdentifier(ctx context.Context, assetID string, identifier *model.AssetIdentifier) error
	GetIdentifiers(ctx context.Context, assetID string) ([]*model.AssetIdentifier, error)
	RemoveIdentifier(ctx context.Context, identifierID string) error
	LookupByIdentifier(ctx context.Context, identType, value string) (*model.Asset, error)

	// Group operations
	CreateGroup(ctx context.Context, group *model.AssetGroup) error
	GetGroup(ctx context.Context, id string) (*model.AssetGroup, error)
	ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]*model.AssetGroup, int, error)
	UpdateGroup(ctx context.Context, group *model.AssetGroup) error
	DeleteGroup(ctx context.Context, id string) error
	AddToGroup(ctx context.Context, assetID, groupID string) error
	RemoveFromGroup(ctx context.Context, assetID, groupID string) error

	// History operations
	RecordHistory(ctx context.Context, history *model.AssetHistory) error
	GetHistory(ctx context.Context, assetID string, limit int) ([]*model.AssetHistory, error)

	// Special operations
	RegisterUnknownIP(ctx context.Context, req *model.UnknownIPRequest) (*model.Asset, error)
	UpdateLastSeen(ctx context.Context, assetID string, lastSeen time.Time) error
}

// PostgresAssetRepository implements AssetRepository using PostgreSQL.
type PostgresAssetRepository struct {
	db *sqlx.DB
}

// NewPostgresAssetRepository creates a new PostgreSQL asset repository.
func NewPostgresAssetRepository(db *sqlx.DB) *PostgresAssetRepository {
	return &PostgresAssetRepository{db: db}
}

// Create creates a new asset.
func (r *PostgresAssetRepository) Create(ctx context.Context, asset *model.Asset) error {
	if asset.ID == "" {
		asset.ID = uuid.New().String()
	}
	asset.CreatedAt = time.Now()
	asset.UpdatedAt = asset.CreatedAt
	asset.Version = 1

	if asset.Status == "" {
		asset.Status = model.AssetStatusActive
	}
	if asset.Criticality == "" {
		asset.Criticality = model.CriticalityMedium
	}

	ipAddresses, _ := json.Marshal(asset.IPAddresses)
	macAddresses, _ := json.Marshal(asset.MACAddresses)
	groupIDs, _ := json.Marshal(asset.GroupIDs)
	tags, _ := json.Marshal(asset.Tags)
	labels, _ := json.Marshal(asset.Labels)
	customFields, _ := json.Marshal(asset.CustomFields)
	metadata, _ := json.Marshal(asset.Metadata)

	query := `
		INSERT INTO assets.assets (
			id, tenant_id, name, hostname, description, type, status, criticality,
			ip_addresses, mac_addresses, fqdn, os, os_version, vendor, model,
			serial_number, asset_tag, location, data_center, rack, zone, environment,
			cloud_provider, cloud_region, cloud_account_id, cloud_instance_id,
			owner, owner_email, team, department, cost_center, group_ids,
			tags, labels, risk_score, vulnerabilities_count, compliance_score,
			agent_id, agent_version, agent_status, discovery_source,
			custom_fields, metadata, created_at, updated_at, created_by, version
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28,
			$29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41,
			$42, $43, $44, $45, $46, $47
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		asset.ID, asset.TenantID, asset.Name, asset.Hostname, asset.Description,
		asset.Type, asset.Status, asset.Criticality, ipAddresses, macAddresses,
		asset.FQDN, asset.OS, asset.OSVersion, asset.Vendor, asset.Model,
		asset.SerialNumber, asset.AssetTag, asset.Location, asset.DataCenter,
		asset.Rack, asset.Zone, asset.Environment, asset.CloudProvider,
		asset.CloudRegion, asset.CloudAccountID, asset.CloudInstanceID,
		asset.Owner, asset.OwnerEmail, asset.Team, asset.Department,
		asset.CostCenter, groupIDs, tags, labels, asset.RiskScore,
		asset.Vulnerabilities, asset.ComplianceScore, asset.AgentID,
		asset.AgentVersion, asset.AgentStatus, asset.DiscoverySource,
		customFields, metadata, asset.CreatedAt, asset.UpdatedAt,
		asset.CreatedBy, asset.Version,
	)

	if err != nil {
		return fmt.Errorf("failed to create asset: %w", err)
	}

	// Add identifiers for IP addresses
	for _, ip := range asset.IPAddresses {
		identifier := &model.AssetIdentifier{
			ID:         uuid.New().String(),
			AssetID:    asset.ID,
			Type:       "ip",
			Value:      ip,
			IsPrimary:  false,
			ValidFrom:  asset.CreatedAt,
			LastSeenAt: asset.CreatedAt,
			Confidence: 1.0,
			Source:     "registration",
			CreatedAt:  asset.CreatedAt,
		}
		r.AddIdentifier(ctx, asset.ID, identifier)
	}

	return nil
}

// GetByID retrieves an asset by ID.
func (r *PostgresAssetRepository) GetByID(ctx context.Context, id string) (*model.Asset, error) {
	query := `
		SELECT id, tenant_id, name, hostname, description, type, status, criticality,
			ip_addresses, mac_addresses, fqdn, os, os_version, vendor, model,
			serial_number, asset_tag, location, data_center, rack, zone, environment,
			cloud_provider, cloud_region, cloud_account_id, cloud_instance_id,
			owner, owner_email, team, department, cost_center, group_ids,
			tags, labels, risk_score, vulnerabilities_count, compliance_score,
			last_scan_time, agent_id, agent_version, agent_status, last_seen_at,
			discovery_source, discovered_at, first_seen_at, custom_fields, metadata,
			created_at, updated_at, created_by, updated_by, version
		FROM assets.assets
		WHERE id = $1 AND deleted_at IS NULL
	`

	var asset model.Asset
	var ipAddresses, macAddresses, groupIDs, tags, labels, customFields, metadata []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&asset.ID, &asset.TenantID, &asset.Name, &asset.Hostname, &asset.Description,
		&asset.Type, &asset.Status, &asset.Criticality, &ipAddresses, &macAddresses,
		&asset.FQDN, &asset.OS, &asset.OSVersion, &asset.Vendor, &asset.Model,
		&asset.SerialNumber, &asset.AssetTag, &asset.Location, &asset.DataCenter,
		&asset.Rack, &asset.Zone, &asset.Environment, &asset.CloudProvider,
		&asset.CloudRegion, &asset.CloudAccountID, &asset.CloudInstanceID,
		&asset.Owner, &asset.OwnerEmail, &asset.Team, &asset.Department,
		&asset.CostCenter, &groupIDs, &tags, &labels, &asset.RiskScore,
		&asset.Vulnerabilities, &asset.ComplianceScore, &asset.LastScanTime,
		&asset.AgentID, &asset.AgentVersion, &asset.AgentStatus, &asset.LastSeenAt,
		&asset.DiscoverySource, &asset.DiscoveredAt, &asset.FirstSeenAt,
		&customFields, &metadata, &asset.CreatedAt, &asset.UpdatedAt,
		&asset.CreatedBy, &asset.UpdatedBy, &asset.Version,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}

	// Unmarshal JSON fields
	json.Unmarshal(ipAddresses, &asset.IPAddresses)
	json.Unmarshal(macAddresses, &asset.MACAddresses)
	json.Unmarshal(groupIDs, &asset.GroupIDs)
	json.Unmarshal(tags, &asset.Tags)
	json.Unmarshal(labels, &asset.Labels)
	json.Unmarshal(customFields, &asset.CustomFields)
	json.Unmarshal(metadata, &asset.Metadata)

	return &asset, nil
}

// Update updates an existing asset.
func (r *PostgresAssetRepository) Update(ctx context.Context, asset *model.Asset) error {
	asset.UpdatedAt = time.Now()
	asset.Version++

	ipAddresses, _ := json.Marshal(asset.IPAddresses)
	macAddresses, _ := json.Marshal(asset.MACAddresses)
	groupIDs, _ := json.Marshal(asset.GroupIDs)
	tags, _ := json.Marshal(asset.Tags)
	labels, _ := json.Marshal(asset.Labels)
	customFields, _ := json.Marshal(asset.CustomFields)
	metadata, _ := json.Marshal(asset.Metadata)

	query := `
		UPDATE assets.assets
		SET name = $2, hostname = $3, description = $4, type = $5, status = $6,
			criticality = $7, ip_addresses = $8, mac_addresses = $9, fqdn = $10,
			os = $11, os_version = $12, vendor = $13, model = $14, location = $15,
			environment = $16, owner = $17, owner_email = $18, team = $19,
			group_ids = $20, tags = $21, labels = $22, custom_fields = $23,
			metadata = $24, updated_at = $25, updated_by = $26, version = $27
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query,
		asset.ID, asset.Name, asset.Hostname, asset.Description, asset.Type,
		asset.Status, asset.Criticality, ipAddresses, macAddresses, asset.FQDN,
		asset.OS, asset.OSVersion, asset.Vendor, asset.Model, asset.Location,
		asset.Environment, asset.Owner, asset.OwnerEmail, asset.Team,
		groupIDs, tags, labels, customFields, metadata, asset.UpdatedAt,
		asset.UpdatedBy, asset.Version,
	)

	if err != nil {
		return fmt.Errorf("failed to update asset: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// Delete soft-deletes an asset.
func (r *PostgresAssetRepository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE assets.assets
		SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// List retrieves assets with filtering and pagination.
func (r *PostgresAssetRepository) List(ctx context.Context, filter *model.AssetFilter) (*model.AssetListResult, error) {
	conditions := []string{"deleted_at IS NULL"}
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

	if filter.IPAddress != "" {
		conditions = append(conditions, fmt.Sprintf("ip_addresses @> $%d::jsonb", argIndex))
		args = append(args, fmt.Sprintf(`["%s"]`, filter.IPAddress))
		argIndex++
	}

	if filter.Hostname != "" {
		conditions = append(conditions, fmt.Sprintf("hostname ILIKE $%d", argIndex))
		args = append(args, "%"+filter.Hostname+"%")
		argIndex++
	}

	if filter.Environment != "" {
		conditions = append(conditions, fmt.Sprintf("environment = $%d", argIndex))
		args = append(args, filter.Environment)
		argIndex++
	}

	if filter.Team != "" {
		conditions = append(conditions, fmt.Sprintf("team = $%d", argIndex))
		args = append(args, filter.Team)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(name ILIKE $%d OR hostname ILIKE $%d OR description ILIKE $%d)",
			argIndex, argIndex, argIndex,
		))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM assets.assets WHERE %s", whereClause)
	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, fmt.Errorf("failed to count assets: %w", err)
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
		SELECT id, tenant_id, name, hostname, description, type, status, criticality,
			ip_addresses, mac_addresses, fqdn, os, os_version, vendor, model,
			location, environment, owner, team, tags, labels, risk_score,
			created_at, updated_at
		FROM assets.assets
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	defer rows.Close()

	assets := make([]*model.Asset, 0)
	for rows.Next() {
		var asset model.Asset
		var ipAddresses, macAddresses, tags, labels []byte

		err := rows.Scan(
			&asset.ID, &asset.TenantID, &asset.Name, &asset.Hostname,
			&asset.Description, &asset.Type, &asset.Status, &asset.Criticality,
			&ipAddresses, &macAddresses, &asset.FQDN, &asset.OS, &asset.OSVersion,
			&asset.Vendor, &asset.Model, &asset.Location, &asset.Environment,
			&asset.Owner, &asset.Team, &tags, &labels, &asset.RiskScore,
			&asset.CreatedAt, &asset.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan asset: %w", err)
		}

		json.Unmarshal(ipAddresses, &asset.IPAddresses)
		json.Unmarshal(macAddresses, &asset.MACAddresses)
		json.Unmarshal(tags, &asset.Tags)
		json.Unmarshal(labels, &asset.Labels)

		assets = append(assets, &asset)
	}

	return &model.AssetListResult{
		Assets:  assets,
		Total:   total,
		Limit:   limit,
		Offset:  filter.Offset,
		HasMore: int64(filter.Offset+limit) < total,
	}, nil
}

// AddIdentifier adds an identifier to an asset.
func (r *PostgresAssetRepository) AddIdentifier(ctx context.Context, assetID string, identifier *model.AssetIdentifier) error {
	if identifier.ID == "" {
		identifier.ID = uuid.New().String()
	}
	identifier.AssetID = assetID
	identifier.CreatedAt = time.Now()
	if identifier.ValidFrom.IsZero() {
		identifier.ValidFrom = identifier.CreatedAt
	}
	if identifier.LastSeenAt.IsZero() {
		identifier.LastSeenAt = identifier.CreatedAt
	}
	if identifier.Confidence == 0 {
		identifier.Confidence = 1.0
	}

	query := `
		INSERT INTO assets.asset_identifiers (
			id, asset_id, type, value, is_primary, valid_from, valid_to,
			last_seen_at, confidence, source, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (type, value) WHERE valid_to IS NULL
		DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, confidence = EXCLUDED.confidence
	`

	_, err := r.db.ExecContext(ctx, query,
		identifier.ID, identifier.AssetID, identifier.Type, identifier.Value,
		identifier.IsPrimary, identifier.ValidFrom, identifier.ValidTo,
		identifier.LastSeenAt, identifier.Confidence, identifier.Source,
		identifier.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to add identifier: %w", err)
	}

	return nil
}

// GetIdentifiers retrieves identifiers for an asset.
func (r *PostgresAssetRepository) GetIdentifiers(ctx context.Context, assetID string) ([]*model.AssetIdentifier, error) {
	query := `
		SELECT id, asset_id, type, value, is_primary, valid_from, valid_to,
			last_seen_at, confidence, source, created_at
		FROM assets.asset_identifiers
		WHERE asset_id = $1 AND valid_to IS NULL
		ORDER BY is_primary DESC, type, created_at
	`

	var identifiers []*model.AssetIdentifier
	err := r.db.SelectContext(ctx, &identifiers, query, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get identifiers: %w", err)
	}

	return identifiers, nil
}

// RemoveIdentifier removes an identifier.
func (r *PostgresAssetRepository) RemoveIdentifier(ctx context.Context, identifierID string) error {
	query := `UPDATE assets.asset_identifiers SET valid_to = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, identifierID)
	return err
}

// LookupByIdentifier finds an asset by identifier.
func (r *PostgresAssetRepository) LookupByIdentifier(ctx context.Context, identType, value string) (*model.Asset, error) {
	query := `
		SELECT a.id
		FROM assets.assets a
		INNER JOIN assets.asset_identifiers i ON a.id = i.asset_id
		WHERE i.type = $1 AND i.value = $2 AND i.valid_to IS NULL AND a.deleted_at IS NULL
		ORDER BY i.confidence DESC, i.last_seen_at DESC
		LIMIT 1
	`

	var assetID string
	err := r.db.GetContext(ctx, &assetID, query, identType, value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to lookup by identifier: %w", err)
	}

	return r.GetByID(ctx, assetID)
}

// CreateGroup creates an asset group.
func (r *PostgresAssetRepository) CreateGroup(ctx context.Context, group *model.AssetGroup) error {
	if group.ID == "" {
		group.ID = uuid.New().String()
	}
	group.CreatedAt = time.Now()
	group.UpdatedAt = group.CreatedAt

	assetIDs, _ := json.Marshal(group.AssetIDs)
	childIDs, _ := json.Marshal(group.ChildIDs)
	tags, _ := json.Marshal(group.Tags)
	labels, _ := json.Marshal(group.Labels)

	query := `
		INSERT INTO assets.asset_groups (
			id, tenant_id, name, description, type, query, asset_ids,
			parent_id, child_ids, tags, labels, asset_count,
			created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err := r.db.ExecContext(ctx, query,
		group.ID, group.TenantID, group.Name, group.Description, group.Type,
		group.Query, assetIDs, group.ParentID, childIDs, tags, labels,
		group.AssetCount, group.CreatedAt, group.UpdatedAt, group.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create asset group: %w", err)
	}

	return nil
}

// GetGroup retrieves an asset group by ID.
func (r *PostgresAssetRepository) GetGroup(ctx context.Context, id string) (*model.AssetGroup, error) {
	query := `
		SELECT id, tenant_id, name, description, type, query, asset_ids,
			parent_id, child_ids, tags, labels, asset_count,
			created_at, updated_at, created_by, updated_by
		FROM assets.asset_groups
		WHERE id = $1
	`

	var group model.AssetGroup
	var assetIDs, childIDs, tags, labels []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.TenantID, &group.Name, &group.Description, &group.Type,
		&group.Query, &assetIDs, &group.ParentID, &childIDs, &tags, &labels,
		&group.AssetCount, &group.CreatedAt, &group.UpdatedAt, &group.CreatedBy,
		&group.UpdatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get asset group: %w", err)
	}

	json.Unmarshal(assetIDs, &group.AssetIDs)
	json.Unmarshal(childIDs, &group.ChildIDs)
	json.Unmarshal(tags, &group.Tags)
	json.Unmarshal(labels, &group.Labels)

	return &group, nil
}

// ListGroups retrieves asset groups for a tenant.
func (r *PostgresAssetRepository) ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]*model.AssetGroup, int, error) {
	if limit == 0 {
		limit = 20
	}

	countQuery := `SELECT COUNT(*) FROM assets.asset_groups WHERE tenant_id = $1`
	var total int
	if err := r.db.GetContext(ctx, &total, countQuery, tenantID); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, tenant_id, name, description, type, query, asset_ids,
			parent_id, child_ids, tags, labels, asset_count,
			created_at, updated_at, created_by
		FROM assets.asset_groups
		WHERE tenant_id = $1
		ORDER BY name
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	groups := make([]*model.AssetGroup, 0)
	for rows.Next() {
		var group model.AssetGroup
		var assetIDs, childIDs, tags, labels []byte

		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.Description, &group.Type,
			&group.Query, &assetIDs, &group.ParentID, &childIDs, &tags, &labels,
			&group.AssetCount, &group.CreatedAt, &group.UpdatedAt, &group.CreatedBy,
		)
		if err != nil {
			return nil, 0, err
		}

		json.Unmarshal(assetIDs, &group.AssetIDs)
		json.Unmarshal(childIDs, &group.ChildIDs)
		json.Unmarshal(tags, &group.Tags)
		json.Unmarshal(labels, &group.Labels)

		groups = append(groups, &group)
	}

	return groups, total, nil
}

// UpdateGroup updates an asset group.
func (r *PostgresAssetRepository) UpdateGroup(ctx context.Context, group *model.AssetGroup) error {
	group.UpdatedAt = time.Now()

	assetIDs, _ := json.Marshal(group.AssetIDs)
	tags, _ := json.Marshal(group.Tags)
	labels, _ := json.Marshal(group.Labels)

	query := `
		UPDATE assets.asset_groups
		SET name = $2, description = $3, query = $4, asset_ids = $5,
			tags = $6, labels = $7, asset_count = $8, updated_at = $9, updated_by = $10
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		group.ID, group.Name, group.Description, group.Query, assetIDs,
		tags, labels, group.AssetCount, group.UpdatedAt, group.UpdatedBy,
	)

	return err
}

// DeleteGroup deletes an asset group.
func (r *PostgresAssetRepository) DeleteGroup(ctx context.Context, id string) error {
	query := `DELETE FROM assets.asset_groups WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// AddToGroup adds an asset to a group.
func (r *PostgresAssetRepository) AddToGroup(ctx context.Context, assetID, groupID string) error {
	// Get the group
	group, err := r.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return errors.New("group not found")
	}

	// Add asset ID if not already present
	for _, id := range group.AssetIDs {
		if id == assetID {
			return nil // Already in group
		}
	}

	group.AssetIDs = append(group.AssetIDs, assetID)
	group.AssetCount = len(group.AssetIDs)

	return r.UpdateGroup(ctx, group)
}

// RemoveFromGroup removes an asset from a group.
func (r *PostgresAssetRepository) RemoveFromGroup(ctx context.Context, assetID, groupID string) error {
	group, err := r.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if group == nil {
		return errors.New("group not found")
	}

	newAssetIDs := make([]string, 0)
	for _, id := range group.AssetIDs {
		if id != assetID {
			newAssetIDs = append(newAssetIDs, id)
		}
	}

	group.AssetIDs = newAssetIDs
	group.AssetCount = len(newAssetIDs)

	return r.UpdateGroup(ctx, group)
}

// RecordHistory records a history entry for an asset.
func (r *PostgresAssetRepository) RecordHistory(ctx context.Context, history *model.AssetHistory) error {
	if history.ID == "" {
		history.ID = uuid.New().String()
	}
	history.Timestamp = time.Now()

	metadata, _ := json.Marshal(history.Metadata)

	query := `
		INSERT INTO assets.asset_history (
			id, asset_id, action, field, old_value, new_value,
			actor, actor_name, source, ip_address, timestamp, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		history.ID, history.AssetID, history.Action, history.Field,
		history.OldValue, history.NewValue, history.Actor, history.ActorName,
		history.Source, history.IPAddress, history.Timestamp, metadata,
	)

	if err != nil {
		return fmt.Errorf("failed to record history: %w", err)
	}

	return nil
}

// GetHistory retrieves history for an asset.
func (r *PostgresAssetRepository) GetHistory(ctx context.Context, assetID string, limit int) ([]*model.AssetHistory, error) {
	if limit == 0 {
		limit = 100
	}

	query := `
		SELECT id, asset_id, action, field, old_value, new_value,
			actor, actor_name, source, ip_address, timestamp, metadata
		FROM assets.asset_history
		WHERE asset_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, assetID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}
	defer rows.Close()

	history := make([]*model.AssetHistory, 0)
	for rows.Next() {
		var h model.AssetHistory
		var metadata []byte

		err := rows.Scan(
			&h.ID, &h.AssetID, &h.Action, &h.Field, &h.OldValue, &h.NewValue,
			&h.Actor, &h.ActorName, &h.Source, &h.IPAddress, &h.Timestamp, &metadata,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(metadata, &h.Metadata)
		history = append(history, &h)
	}

	return history, nil
}

// RegisterUnknownIP registers an unknown IP as a new asset.
func (r *PostgresAssetRepository) RegisterUnknownIP(ctx context.Context, req *model.UnknownIPRequest) (*model.Asset, error) {
	// First check if asset already exists with this IP
	existing, err := r.LookupByIdentifier(ctx, "ip", req.IPAddress)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Update last seen and return existing
		r.UpdateLastSeen(ctx, existing.ID, time.Now())
		return existing, nil
	}

	// Create new unknown asset
	asset := &model.Asset{
		ID:          uuid.New().String(),
		Name:        fmt.Sprintf("Unknown-%s", req.IPAddress),
		Hostname:    req.Hostname,
		Type:        model.AssetTypeUnknown,
		Status:      model.AssetStatusUnknown,
		Criticality: model.CriticalityMedium,
		IPAddresses: []string{req.IPAddress},
		DiscoverySource: req.DiscoverySource,
		Metadata:    req.Metadata,
		CreatedBy:   "system",
	}

	if req.MACAddress != "" {
		asset.MACAddresses = []string{req.MACAddress}
	}

	if !req.FirstSeenAt.IsZero() {
		asset.FirstSeenAt = &req.FirstSeenAt
	} else {
		now := time.Now()
		asset.FirstSeenAt = &now
	}
	asset.DiscoveredAt = asset.FirstSeenAt
	asset.LastSeenAt = asset.FirstSeenAt

	err = r.Create(ctx, asset)
	if err != nil {
		return nil, err
	}

	return asset, nil
}

// UpdateLastSeen updates the last seen timestamp for an asset.
func (r *PostgresAssetRepository) UpdateLastSeen(ctx context.Context, assetID string, lastSeen time.Time) error {
	query := `UPDATE assets.assets SET last_seen_at = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, assetID, lastSeen)
	return err
}
