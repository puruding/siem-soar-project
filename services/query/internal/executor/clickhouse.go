// Package executor provides ClickHouse query execution backend.
package executor

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ClickHouseConfig holds ClickHouse connection configuration.
type ClickHouseConfig struct {
	Hosts             []string      `json:"hosts"`
	Database          string        `json:"database"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	Debug             bool          `json:"debug"`
	DialTimeout       time.Duration `json:"dial_timeout"`
	MaxOpenConns      int           `json:"max_open_conns"`
	MaxIdleConns      int           `json:"max_idle_conns"`
	ConnMaxLifetime   time.Duration `json:"conn_max_lifetime"`
	MaxExecutionTime  int           `json:"max_execution_time"`
	MaxMemoryUsage    int64         `json:"max_memory_usage"`
	Compression       string        `json:"compression"`
}

// DefaultClickHouseConfig returns default ClickHouse configuration.
func DefaultClickHouseConfig() ClickHouseConfig {
	return ClickHouseConfig{
		Hosts:            []string{"localhost:9000"},
		Database:         "siem",
		Username:         "default",
		Password:         "",
		Debug:            false,
		DialTimeout:      10 * time.Second,
		MaxOpenConns:     20,
		MaxIdleConns:     5,
		ConnMaxLifetime:  time.Hour,
		MaxExecutionTime: 300,
		MaxMemoryUsage:   10000000000,
		Compression:      "lz4",
	}
}

// LoadClickHouseConfigFromEnv loads configuration from environment variables.
func LoadClickHouseConfigFromEnv() ClickHouseConfig {
	cfg := DefaultClickHouseConfig()

	if host := os.Getenv("CLICKHOUSE_HOST"); host != "" {
		port := os.Getenv("CLICKHOUSE_PORT")
		if port == "" {
			port = "9000"
		}
		cfg.Hosts = []string{host + ":" + port}
	}
	if db := os.Getenv("CLICKHOUSE_DATABASE"); db != "" {
		cfg.Database = db
	}
	if user := os.Getenv("CLICKHOUSE_USER"); user != "" {
		cfg.Username = user
	}
	if pass := os.Getenv("CLICKHOUSE_PASSWORD"); pass != "" {
		cfg.Password = pass
	}
	if debug := os.Getenv("CLICKHOUSE_DEBUG"); debug == "true" {
		cfg.Debug = true
	}
	if timeout := os.Getenv("CLICKHOUSE_DIAL_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.DialTimeout = d
		}
	}
	if maxConns := os.Getenv("CLICKHOUSE_MAX_OPEN_CONNS"); maxConns != "" {
		if n, err := strconv.Atoi(maxConns); err == nil {
			cfg.MaxOpenConns = n
		}
	}

	return cfg
}

// ClickHouseBackend implements the Backend interface for ClickHouse.
type ClickHouseBackend struct {
	conn   driver.Conn
	db     *sql.DB
	config ClickHouseConfig
	logger *slog.Logger
}

// NewClickHouseBackend creates a new ClickHouse backend.
func NewClickHouseBackend(cfg ClickHouseConfig, logger *slog.Logger) (*ClickHouseBackend, error) {
	options := &clickhouse.Options{
		Addr: cfg.Hosts,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Debug: cfg.Debug,
		Settings: clickhouse.Settings{
			"max_execution_time": cfg.MaxExecutionTime,
			"max_memory_usage":   cfg.MaxMemoryUsage,
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

	return &ClickHouseBackend{
		conn:   conn,
		db:     db,
		config: cfg,
		logger: logger.With("component", "clickhouse-backend"),
	}, nil
}

// Execute executes a query against ClickHouse.
func (b *ClickHouseBackend) Execute(ctx context.Context, req *QueryRequest) (*QueryResult, error) {
	startTime := time.Now()

	result := &QueryResult{
		ID:     req.ID,
		Status: QueryStatusRunning,
		Metadata: QueryMetadata{
			TablesRead: extractTableNames(req.Query),
		},
	}

	// Execute query
	rows, err := b.conn.Query(ctx, req.Query)
	if err != nil {
		result.Status = QueryStatusFailed
		result.Error = err.Error()
		result.ExecutionMS = time.Since(startTime).Milliseconds()
		return result, err
	}
	defer rows.Close()

	// Get column info
	columns := rows.Columns()
	columnTypes := rows.ColumnTypes()

	result.Columns = make([]ColumnInfo, len(columns))
	for i, col := range columns {
		nullable := false
		if i < len(columnTypes) && columnTypes[i] != nil {
			nullable = columnTypes[i].Nullable()
		}
		result.Columns[i] = ColumnInfo{
			Name:     col,
			Type:     getColumnTypeName(columnTypes, i),
			Nullable: nullable,
		}
	}

	// Read rows
	var rowsData []map[string]interface{}
	var bytesRead int64

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			result.Status = QueryStatusFailed
			result.Error = fmt.Sprintf("failed to scan row: %v", err)
			result.ExecutionMS = time.Since(startTime).Milliseconds()
			return result, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = convertValue(values[i])
			bytesRead += estimateSize(values[i])
		}
		rowsData = append(rowsData, row)

		// Check max results
		if req.MaxResults > 0 && int64(len(rowsData)) >= req.MaxResults {
			break
		}
	}

	if err := rows.Err(); err != nil {
		result.Status = QueryStatusFailed
		result.Error = err.Error()
		result.ExecutionMS = time.Since(startTime).Milliseconds()
		return result, err
	}

	result.Status = QueryStatusCompleted
	result.Rows = rowsData
	result.RowCount = int64(len(rowsData))
	result.TotalCount = int64(len(rowsData)) // Would need COUNT(*) for accurate total
	result.BytesRead = bytesRead
	result.ExecutionMS = time.Since(startTime).Milliseconds()

	b.logger.Info("query executed",
		"query_id", req.ID,
		"row_count", result.RowCount,
		"execution_ms", result.ExecutionMS,
		"bytes_read", result.BytesRead,
	)

	return result, nil
}

// ExecuteWithCount executes a query and returns total count separately.
func (b *ClickHouseBackend) ExecuteWithCount(ctx context.Context, req *QueryRequest, countQuery string) (*QueryResult, error) {
	result, err := b.Execute(ctx, req)
	if err != nil {
		return result, err
	}

	// Execute count query if provided
	if countQuery != "" {
		var total int64
		row := b.conn.QueryRow(ctx, countQuery)
		if err := row.Scan(&total); err == nil {
			result.TotalCount = total
		}
	}

	return result, nil
}

// Health checks the ClickHouse connection health.
func (b *ClickHouseBackend) Health(ctx context.Context) error {
	return b.conn.Ping(ctx)
}

// Close closes the ClickHouse connection.
func (b *ClickHouseBackend) Close() error {
	if b.db != nil {
		b.db.Close()
	}
	return b.conn.Close()
}

// GetTableSchema returns the schema for a table.
func (b *ClickHouseBackend) GetTableSchema(ctx context.Context, database, table string) ([]ColumnInfo, error) {
	query := `
		SELECT name, type, default_kind != '' AS has_default
		FROM system.columns
		WHERE database = ? AND table = ?
		ORDER BY position
	`

	rows, err := b.conn.Query(ctx, query, database, table)
	if err != nil {
		return nil, fmt.Errorf("failed to get table schema: %w", err)
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var col ColumnInfo
		var hasDefault bool
		if err := rows.Scan(&col.Name, &col.Type, &hasDefault); err != nil {
			return nil, fmt.Errorf("failed to scan column: %w", err)
		}
		col.Nullable = strings.HasPrefix(col.Type, "Nullable")
		columns = append(columns, col)
	}

	return columns, nil
}

// GetDatabases returns available databases.
func (b *ClickHouseBackend) GetDatabases(ctx context.Context) ([]string, error) {
	rows, err := b.conn.Query(ctx, "SHOW DATABASES")
	if err != nil {
		return nil, fmt.Errorf("failed to get databases: %w", err)
	}
	defer rows.Close()

	var databases []string
	for rows.Next() {
		var db string
		if err := rows.Scan(&db); err != nil {
			return nil, err
		}
		databases = append(databases, db)
	}

	return databases, nil
}

// GetTables returns tables in a database.
func (b *ClickHouseBackend) GetTables(ctx context.Context, database string) ([]string, error) {
	query := "SHOW TABLES FROM " + database
	rows, err := b.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}

	return tables, nil
}

// ExplainQuery returns the query execution plan.
func (b *ClickHouseBackend) ExplainQuery(ctx context.Context, query string) (string, error) {
	explainQuery := "EXPLAIN " + query
	rows, err := b.conn.Query(ctx, explainQuery)
	if err != nil {
		return "", fmt.Errorf("failed to explain query: %w", err)
	}
	defer rows.Close()

	var plans []string
	for rows.Next() {
		var plan string
		if err := rows.Scan(&plan); err != nil {
			return "", err
		}
		plans = append(plans, plan)
	}

	return strings.Join(plans, "\n"), nil
}

// Helper functions

func getColumnTypeName(columnTypes []driver.ColumnType, index int) string {
	if index < len(columnTypes) && columnTypes[index] != nil {
		return columnTypes[index].DatabaseTypeName()
	}
	return "unknown"
}

func convertValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case time.Time:
		return val.Format(time.RFC3339Nano)
	case []byte:
		return string(val)
	case [16]byte:
		// UUID
		return formatUUID(val)
	default:
		return val
	}
}

func formatUUID(b [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func estimateSize(v interface{}) int64 {
	if v == nil {
		return 0
	}

	switch val := v.(type) {
	case string:
		return int64(len(val))
	case []byte:
		return int64(len(val))
	case int, int8, int16, int32, int64:
		return 8
	case uint, uint8, uint16, uint32, uint64:
		return 8
	case float32:
		return 4
	case float64:
		return 8
	case bool:
		return 1
	case time.Time:
		return 8
	default:
		return 16 // default estimate
	}
}

func extractTableNames(query string) []string {
	var tables []string
	upper := strings.ToUpper(query)

	// Simple extraction - find FROM and JOIN clauses
	keywords := []string{"FROM", "JOIN"}
	for _, kw := range keywords {
		idx := 0
		for {
			pos := strings.Index(upper[idx:], kw)
			if pos == -1 {
				break
			}
			pos += idx

			// Find table name after keyword
			start := pos + len(kw)
			for start < len(query) && (query[start] == ' ' || query[start] == '\t' || query[start] == '\n') {
				start++
			}

			// Find end of table name
			end := start
			for end < len(query) && query[end] != ' ' && query[end] != '\t' && query[end] != '\n' && query[end] != '(' && query[end] != ',' {
				end++
			}

			if end > start {
				tableName := strings.TrimSpace(query[start:end])
				if tableName != "" && !containsString(tables, tableName) {
					tables = append(tables, tableName)
				}
			}

			idx = end
		}
	}

	return tables
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
