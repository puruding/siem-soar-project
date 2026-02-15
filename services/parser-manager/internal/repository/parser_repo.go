// Package repository provides data access for parser management.
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
	"github.com/siem-soar-platform/services/parser-manager/internal/model"
)

// ParserRepository defines the interface for parser data access.
type ParserRepository interface {
	// Product operations
	CreateProduct(ctx context.Context, product *model.Product) error
	GetProduct(ctx context.Context, id string) (*model.Product, error)
	UpdateProduct(ctx context.Context, product *model.Product) error
	DeleteProduct(ctx context.Context, id string) error
	ListProducts(ctx context.Context, filter *model.ProductFilter) (*model.ProductListResult, error)

	// Parser operations
	CreateParser(ctx context.Context, parser *model.Parser) error
	GetParser(ctx context.Context, id string) (*model.Parser, error)
	UpdateParser(ctx context.Context, parser *model.Parser) error
	DeleteParser(ctx context.Context, id string) error
	ListParsers(ctx context.Context, filter *model.ParserFilter2) (*model.ParserListResult, error)
	GetParsersByProduct(ctx context.Context, productID string, limit, offset int) ([]*model.Parser, int, error)

	// Statistics
	UpdateParserStats(ctx context.Context, id string, parseCount, errorCount int64, avgParseTimeMs float64) error
	GetParserStats(ctx context.Context, id string) (map[string]interface{}, error)

	// Hot reload
	MarkDeployed(ctx context.Context, id, deployedBy string) error
	GetActiveParsers(ctx context.Context) ([]*model.Parser, error)
}

// PostgresParserRepository implements ParserRepository using PostgreSQL.
type PostgresParserRepository struct {
	db *sqlx.DB
}

// NewPostgresParserRepository creates a new PostgreSQL parser repository.
func NewPostgresParserRepository(db *sqlx.DB) *PostgresParserRepository {
	return &PostgresParserRepository{db: db}
}

// CreateProduct creates a new product.
func (r *PostgresParserRepository) CreateProduct(ctx context.Context, product *model.Product) error {
	if product.ID == "" {
		product.ID = uuid.New().String()
	}
	product.CreatedAt = time.Now()
	product.UpdatedAt = product.CreatedAt

	logFormats, _ := json.Marshal(product.LogFormats)
	sampleLogs, _ := json.Marshal(product.SampleLogs)
	tags, _ := json.Marshal(product.Tags)
	labels, _ := json.Marshal(product.Labels)
	metadata, _ := json.Marshal(product.Metadata)

	query := `
		INSERT INTO parsers.products (
			id, tenant_id, name, vendor, version, description, category,
			log_formats, sample_logs, tags, labels, metadata,
			parser_count, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	_, err := r.db.ExecContext(ctx, query,
		product.ID, product.TenantID, product.Name, product.Vendor, product.Version,
		product.Description, product.Category, logFormats, sampleLogs, tags,
		labels, metadata, product.ParserCount, product.CreatedAt, product.UpdatedAt,
		product.CreatedBy,
	)

	return err
}

// GetProduct retrieves a product by ID.
func (r *PostgresParserRepository) GetProduct(ctx context.Context, id string) (*model.Product, error) {
	query := `
		SELECT id, tenant_id, name, vendor, version, description, category,
			log_formats, sample_logs, tags, labels, metadata, parser_count,
			created_at, updated_at, created_by, updated_by
		FROM parsers.products
		WHERE id = $1
	`

	var product model.Product
	var logFormats, sampleLogs, tags, labels, metadata []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&product.ID, &product.TenantID, &product.Name, &product.Vendor, &product.Version,
		&product.Description, &product.Category, &logFormats, &sampleLogs, &tags,
		&labels, &metadata, &product.ParserCount, &product.CreatedAt, &product.UpdatedAt,
		&product.CreatedBy, &product.UpdatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	json.Unmarshal(logFormats, &product.LogFormats)
	json.Unmarshal(sampleLogs, &product.SampleLogs)
	json.Unmarshal(tags, &product.Tags)
	json.Unmarshal(labels, &product.Labels)
	json.Unmarshal(metadata, &product.Metadata)

	return &product, nil
}

// UpdateProduct updates a product.
func (r *PostgresParserRepository) UpdateProduct(ctx context.Context, product *model.Product) error {
	product.UpdatedAt = time.Now()

	logFormats, _ := json.Marshal(product.LogFormats)
	sampleLogs, _ := json.Marshal(product.SampleLogs)
	tags, _ := json.Marshal(product.Tags)
	labels, _ := json.Marshal(product.Labels)

	query := `
		UPDATE parsers.products
		SET name = $2, vendor = $3, version = $4, description = $5, category = $6,
			log_formats = $7, sample_logs = $8, tags = $9, labels = $10,
			updated_at = $11, updated_by = $12
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		product.ID, product.Name, product.Vendor, product.Version, product.Description,
		product.Category, logFormats, sampleLogs, tags, labels,
		product.UpdatedAt, product.UpdatedBy,
	)

	return err
}

// DeleteProduct deletes a product.
func (r *PostgresParserRepository) DeleteProduct(ctx context.Context, id string) error {
	query := `DELETE FROM parsers.products WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// ListProducts lists products with filtering.
func (r *PostgresParserRepository) ListProducts(ctx context.Context, filter *model.ProductFilter) (*model.ProductListResult, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}
	argIndex := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID)
		argIndex++
	}

	if filter.Vendor != "" {
		conditions = append(conditions, fmt.Sprintf("vendor = $%d", argIndex))
		args = append(args, filter.Vendor)
		argIndex++
	}

	if filter.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, filter.Category)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR vendor ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM parsers.products WHERE %s", whereClause)
	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, err
	}

	// Set defaults
	limit := filter.Limit
	if limit == 0 {
		limit = 20
	}

	orderBy := "name ASC"
	if filter.SortBy != "" {
		order := "ASC"
		if filter.SortOrder == "desc" {
			order = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
	}

	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT id, tenant_id, name, vendor, version, description, category,
			tags, labels, parser_count, created_at, updated_at
		FROM parsers.products
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := make([]*model.Product, 0)
	for rows.Next() {
		var product model.Product
		var tags, labels []byte

		err := rows.Scan(
			&product.ID, &product.TenantID, &product.Name, &product.Vendor, &product.Version,
			&product.Description, &product.Category, &tags, &labels, &product.ParserCount,
			&product.CreatedAt, &product.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(tags, &product.Tags)
		json.Unmarshal(labels, &product.Labels)
		products = append(products, &product)
	}

	return &model.ProductListResult{
		Products: products,
		Total:    total,
		Limit:    limit,
		Offset:   filter.Offset,
		HasMore:  int64(filter.Offset+limit) < total,
	}, nil
}

// CreateParser creates a new parser.
func (r *PostgresParserRepository) CreateParser(ctx context.Context, parser *model.Parser) error {
	if parser.ID == "" {
		parser.ID = uuid.New().String()
	}
	parser.CreatedAt = time.Now()
	parser.UpdatedAt = parser.CreatedAt
	parser.Version = 1

	if parser.Status == "" {
		parser.Status = model.ParserStatusInactive
	}

	grokPatterns, _ := json.Marshal(parser.GrokPatterns)
	fieldMapping, _ := json.Marshal(parser.FieldMapping)
	transforms, _ := json.Marshal(parser.Transforms)
	filters, _ := json.Marshal(parser.Filters)
	config, _ := json.Marshal(parser.Config)
	udmMapping, _ := json.Marshal(parser.UDMMapping)
	tags, _ := json.Marshal(parser.Tags)
	labels, _ := json.Marshal(parser.Labels)

	query := `
		INSERT INTO parsers.parsers (
			id, tenant_id, product_id, name, description, type, status, priority,
			pattern, grok_patterns, field_mapping, transforms, filters, config,
			normalize_to_udm, udm_mapping, detection_pattern, version,
			tags, labels, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20, $21, $22, $23
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		parser.ID, parser.TenantID, parser.ProductID, parser.Name, parser.Description,
		parser.Type, parser.Status, parser.Priority, parser.Pattern, grokPatterns,
		fieldMapping, transforms, filters, config, parser.NormalizeToUDM, udmMapping,
		parser.DetectionPattern, parser.Version, tags, labels,
		parser.CreatedAt, parser.UpdatedAt, parser.CreatedBy,
	)

	if err != nil {
		return err
	}

	// Update product parser count
	r.updateProductParserCount(ctx, parser.ProductID)

	return nil
}

// GetParser retrieves a parser by ID.
func (r *PostgresParserRepository) GetParser(ctx context.Context, id string) (*model.Parser, error) {
	query := `
		SELECT id, tenant_id, product_id, name, description, type, status, priority,
			pattern, grok_patterns, field_mapping, transforms, filters, config,
			normalize_to_udm, udm_mapping, detection_pattern, version, parent_id,
			parse_count, error_count, last_used_at, avg_parse_time_ms,
			loaded_at, deployed_at, deployed_by, reload_count, last_reload_at, last_reload_by,
			tags, labels, created_at, updated_at, created_by, updated_by
		FROM parsers.parsers
		WHERE id = $1
	`

	var parser model.Parser
	var grokPatterns, fieldMapping, transforms, filters, config, udmMapping []byte
	var tags, labels []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&parser.ID, &parser.TenantID, &parser.ProductID, &parser.Name, &parser.Description,
		&parser.Type, &parser.Status, &parser.Priority, &parser.Pattern, &grokPatterns,
		&fieldMapping, &transforms, &filters, &config, &parser.NormalizeToUDM, &udmMapping,
		&parser.DetectionPattern, &parser.Version, &parser.ParentID,
		&parser.ParseCount, &parser.ErrorCount, &parser.LastUsedAt, &parser.AvgParseTimeMs,
		&parser.LoadedAt, &parser.DeployedAt, &parser.DeployedBy, &parser.ReloadCount,
		&parser.LastReloadAt, &parser.LastReloadBy, &tags, &labels,
		&parser.CreatedAt, &parser.UpdatedAt, &parser.CreatedBy, &parser.UpdatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	json.Unmarshal(grokPatterns, &parser.GrokPatterns)
	json.Unmarshal(fieldMapping, &parser.FieldMapping)
	json.Unmarshal(transforms, &parser.Transforms)
	json.Unmarshal(filters, &parser.Filters)
	json.Unmarshal(config, &parser.Config)
	json.Unmarshal(udmMapping, &parser.UDMMapping)
	json.Unmarshal(tags, &parser.Tags)
	json.Unmarshal(labels, &parser.Labels)

	return &parser, nil
}

// UpdateParser updates a parser.
func (r *PostgresParserRepository) UpdateParser(ctx context.Context, parser *model.Parser) error {
	parser.UpdatedAt = time.Now()
	parser.Version++

	grokPatterns, _ := json.Marshal(parser.GrokPatterns)
	fieldMapping, _ := json.Marshal(parser.FieldMapping)
	transforms, _ := json.Marshal(parser.Transforms)
	filters, _ := json.Marshal(parser.Filters)
	config, _ := json.Marshal(parser.Config)
	udmMapping, _ := json.Marshal(parser.UDMMapping)
	tags, _ := json.Marshal(parser.Tags)
	labels, _ := json.Marshal(parser.Labels)

	query := `
		UPDATE parsers.parsers
		SET name = $2, description = $3, status = $4, priority = $5,
			pattern = $6, grok_patterns = $7, field_mapping = $8, transforms = $9,
			filters = $10, config = $11, normalize_to_udm = $12, udm_mapping = $13,
			detection_pattern = $14, version = $15, tags = $16, labels = $17,
			updated_at = $18, updated_by = $19
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query,
		parser.ID, parser.Name, parser.Description, parser.Status, parser.Priority,
		parser.Pattern, grokPatterns, fieldMapping, transforms, filters, config,
		parser.NormalizeToUDM, udmMapping, parser.DetectionPattern, parser.Version,
		tags, labels, parser.UpdatedAt, parser.UpdatedBy,
	)

	return err
}

// DeleteParser deletes a parser.
func (r *PostgresParserRepository) DeleteParser(ctx context.Context, id string) error {
	// Get product ID for count update
	parser, _ := r.GetParser(ctx, id)

	query := `DELETE FROM parsers.parsers WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)

	if err == nil && parser != nil {
		r.updateProductParserCount(ctx, parser.ProductID)
	}

	return err
}

// ListParsers lists parsers with filtering.
func (r *PostgresParserRepository) ListParsers(ctx context.Context, filter *model.ParserFilter2) (*model.ParserListResult, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}
	argIndex := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID)
		argIndex++
	}

	if filter.ProductID != "" {
		conditions = append(conditions, fmt.Sprintf("product_id = $%d", argIndex))
		args = append(args, filter.ProductID)
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

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM parsers.parsers WHERE %s", whereClause)
	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, err
	}

	limit := filter.Limit
	if limit == 0 {
		limit = 20
	}

	orderBy := "priority DESC, name ASC"
	if filter.SortBy != "" {
		order := "ASC"
		if filter.SortOrder == "desc" {
			order = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", filter.SortBy, order)
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, tenant_id, product_id, name, description, type, status, priority,
			pattern, tags, labels, parse_count, error_count, version,
			created_at, updated_at, deployed_at
		FROM parsers.parsers
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIndex, argIndex+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	parsers := make([]*model.Parser, 0)
	for rows.Next() {
		var parser model.Parser
		var tags, labels []byte

		err := rows.Scan(
			&parser.ID, &parser.TenantID, &parser.ProductID, &parser.Name, &parser.Description,
			&parser.Type, &parser.Status, &parser.Priority, &parser.Pattern, &tags, &labels,
			&parser.ParseCount, &parser.ErrorCount, &parser.Version,
			&parser.CreatedAt, &parser.UpdatedAt, &parser.DeployedAt,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal(tags, &parser.Tags)
		json.Unmarshal(labels, &parser.Labels)
		parsers = append(parsers, &parser)
	}

	return &model.ParserListResult{
		Parsers: parsers,
		Total:   total,
		Limit:   limit,
		Offset:  filter.Offset,
		HasMore: int64(filter.Offset+limit) < total,
	}, nil
}

// GetParsersByProduct retrieves parsers for a product.
func (r *PostgresParserRepository) GetParsersByProduct(ctx context.Context, productID string, limit, offset int) ([]*model.Parser, int, error) {
	filter := &model.ParserFilter2{
		ProductID: productID,
		Limit:     limit,
		Offset:    offset,
	}

	result, err := r.ListParsers(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	return result.Parsers, int(result.Total), nil
}

// UpdateParserStats updates parser statistics.
func (r *PostgresParserRepository) UpdateParserStats(ctx context.Context, id string, parseCount, errorCount int64, avgParseTimeMs float64) error {
	query := `
		UPDATE parsers.parsers
		SET parse_count = parse_count + $2,
			error_count = error_count + $3,
			avg_parse_time_ms = $4,
			last_used_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, parseCount, errorCount, avgParseTimeMs)
	return err
}

// GetParserStats retrieves parser statistics.
func (r *PostgresParserRepository) GetParserStats(ctx context.Context, id string) (map[string]interface{}, error) {
	query := `
		SELECT parse_count, error_count, avg_parse_time_ms, last_used_at
		FROM parsers.parsers
		WHERE id = $1
	`

	var parseCount, errorCount int64
	var avgParseTimeMs float64
	var lastUsedAt *time.Time

	err := r.db.QueryRowContext(ctx, query, id).Scan(&parseCount, &errorCount, &avgParseTimeMs, &lastUsedAt)
	if err != nil {
		return nil, err
	}

	errorRate := float64(0)
	if parseCount > 0 {
		errorRate = float64(errorCount) / float64(parseCount) * 100
	}

	return map[string]interface{}{
		"parse_count":      parseCount,
		"error_count":      errorCount,
		"avg_parse_time_ms": avgParseTimeMs,
		"error_rate_pct":   errorRate,
		"last_used_at":     lastUsedAt,
	}, nil
}

// MarkDeployed marks a parser as deployed.
func (r *PostgresParserRepository) MarkDeployed(ctx context.Context, id, deployedBy string) error {
	query := `
		UPDATE parsers.parsers
		SET status = $2, deployed_at = CURRENT_TIMESTAMP, deployed_by = $3,
			reload_count = reload_count + 1, last_reload_at = CURRENT_TIMESTAMP,
			last_reload_by = $3
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, model.ParserStatusActive, deployedBy)
	return err
}

// GetActiveParsers retrieves all active parsers.
func (r *PostgresParserRepository) GetActiveParsers(ctx context.Context) ([]*model.Parser, error) {
	filter := &model.ParserFilter2{
		Statuses: []model.ParserStatus{model.ParserStatusActive},
		Limit:    1000,
	}

	result, err := r.ListParsers(ctx, filter)
	if err != nil {
		return nil, err
	}

	return result.Parsers, nil
}

func (r *PostgresParserRepository) updateProductParserCount(ctx context.Context, productID string) {
	query := `
		UPDATE parsers.products
		SET parser_count = (SELECT COUNT(*) FROM parsers.parsers WHERE product_id = $1)
		WHERE id = $1
	`
	r.db.ExecContext(ctx, query, productID)
}
