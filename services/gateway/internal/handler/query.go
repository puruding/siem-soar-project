package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SavedQuery represents a saved query
type SavedQuery struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Query       string    `json:"query"`
	Language    string    `json:"language"`
	Tags        []string  `json:"tags"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// QueryResult represents query execution results (matches frontend QueryResponseData)
type QueryResult struct {
	Columns         []string        `json:"columns"`
	Rows            [][]interface{} `json:"rows"`
	Total           int             `json:"total"`
	ExecutionTimeMs int64           `json:"executionTimeMs"`
}

// QueryHistory represents a query execution history entry
type QueryHistory struct {
	ID              string    `json:"id"`
	Query           string    `json:"query"`
	Language        string    `json:"language"`
	ExecutedAt      time.Time `json:"executed_at"`
	ExecutionTimeMs int64     `json:"execution_time_ms"`
	RowCount        int       `json:"row_count"`
	Status          string    `json:"status"` // "success" or "error"
	Error           string    `json:"error,omitempty"`
}

// SchemaTable represents a database table schema
type SchemaTable struct {
	Name    string         `json:"name"`
	Columns []SchemaColumn `json:"columns"`
}

// SchemaColumn represents a column in a table
type SchemaColumn struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Nullable    bool   `json:"nullable"`
}

// In-memory stores
var (
	savedQueryStore     = make([]SavedQuery, 0)
	savedQueryMu        sync.RWMutex
	savedQueryCounter   = 0
	queryHistoryStore   = make([]QueryHistory, 0)
	queryHistoryMu      sync.RWMutex
	queryHistoryCounter = 0
	maxQueryHistory     = 100
)

// Sample schema for demo
var databaseSchema = []SchemaTable{
	{
		Name: "events",
		Columns: []SchemaColumn{
			{Name: "id", Type: "String", Description: "Unique event identifier"},
			{Name: "tenant_id", Type: "String", Description: "Tenant identifier"},
			{Name: "event_time", Type: "DateTime64", Description: "Event timestamp"},
			{Name: "ingest_time", Type: "DateTime64", Description: "Ingestion timestamp"},
			{Name: "source", Type: "String", Description: "Event source"},
			{Name: "source_type", Type: "String", Description: "Source type (firewall, edr, etc.)"},
			{Name: "event_type", Type: "String", Description: "Type of event"},
			{Name: "severity", Type: "String", Description: "Event severity level"},
			{Name: "source_ip", Type: "String", Description: "Source IP address"},
			{Name: "dest_ip", Type: "String", Description: "Destination IP address"},
			{Name: "source_port", Type: "Int", Description: "Source port"},
			{Name: "dest_port", Type: "Int", Description: "Destination port"},
			{Name: "user", Type: "String", Description: "Username"},
			{Name: "hostname", Type: "String", Description: "Hostname"},
			{Name: "action", Type: "String", Description: "Action taken"},
			{Name: "status", Type: "String", Description: "Event status"},
			{Name: "message", Type: "String", Description: "Event message"},
			{Name: "raw_log", Type: "String", Description: "Original raw log data"},
			{Name: "asset_id", Type: "String", Description: "Asset identifier"},
			{Name: "product_id", Type: "String", Description: "Product identifier"},
		},
	},
	{
		Name: "alerts",
		Columns: []SchemaColumn{
			{Name: "alert_id", Type: "String", Description: "Unique alert identifier"},
			{Name: "event_id", Type: "String", Description: "Related event ID"},
			{Name: "rule_id", Type: "String", Description: "Detection rule ID"},
			{Name: "rule_name", Type: "String", Description: "Detection rule name"},
			{Name: "severity", Type: "String", Description: "Alert severity"},
			{Name: "status", Type: "String", Description: "Alert status"},
			{Name: "created_at", Type: "DateTime64", Description: "Creation timestamp"},
		},
	},
	{
		Name: "network_flows",
		Columns: []SchemaColumn{
			{Name: "flow_id", Type: "String", Description: "Flow identifier"},
			{Name: "timestamp", Type: "DateTime64", Description: "Flow timestamp"},
			{Name: "src_ip", Type: "String", Description: "Source IP"},
			{Name: "dst_ip", Type: "String", Description: "Destination IP"},
			{Name: "src_port", Type: "UInt16", Description: "Source port"},
			{Name: "dst_port", Type: "UInt16", Description: "Destination port"},
			{Name: "protocol", Type: "String", Description: "Protocol"},
			{Name: "bytes_sent", Type: "UInt64", Description: "Bytes sent"},
			{Name: "bytes_received", Type: "UInt64", Description: "Bytes received"},
		},
	},
}

// Condition represents a parsed WHERE condition
type Condition struct {
	Field    string
	Operator string // =, !=, <, >, <=, >=, LIKE
	Value    string
}

// ParsedQuery represents a parsed SQL query
type ParsedQuery struct {
	Columns    []string
	Table      string
	Conditions []Condition
	LogicOps   []string // AND, OR between conditions
	Limit      int
	IsSelectAll bool
}

// ExecuteQueryHandler handles query execution
func ExecuteQueryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		Query    string `json:"query"`
		Language string `json:"language"`
		Timeout  int    `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Query == "" {
		http.Error(w, `{"error":"Query is required"}`, http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	// Execute query on real events
	results, err := executeQueryOnEvents(req.Query)

	duration := time.Since(startTime).Milliseconds()
	results.ExecutionTimeMs = duration

	// Record query history
	historyEntry := QueryHistory{
		Query:           req.Query,
		Language:        req.Language,
		ExecutedAt:      time.Now(),
		ExecutionTimeMs: duration,
		RowCount:        results.Total,
		Status:          "success",
	}

	if err != nil {
		historyEntry.Status = "error"
		historyEntry.Error = err.Error()
		historyEntry.RowCount = 0
		addQueryHistory(historyEntry)

		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	addQueryHistory(historyEntry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"success": true,
			"data":    results,
		},
	})
}

// executeQueryOnEvents parses and executes a SQL-like query on the event store
func executeQueryOnEvents(query string) (QueryResult, error) {
	parsed, err := parseQuery(query)
	if err != nil {
		return QueryResult{}, err
	}

	if strings.ToLower(parsed.Table) != "events" {
		return QueryResult{}, fmt.Errorf("unsupported table: %s (only 'events' is supported)", parsed.Table)
	}

	eventMu.RLock()
	defer eventMu.RUnlock()

	var matchedEvents []Event
	for _, event := range eventStore {
		if matchesConditions(event, parsed.Conditions, parsed.LogicOps) {
			matchedEvents = append(matchedEvents, event)
		}
	}

	// Apply limit
	if parsed.Limit > 0 && len(matchedEvents) > parsed.Limit {
		matchedEvents = matchedEvents[:parsed.Limit]
	}

	// Determine columns
	columns := parsed.Columns
	if parsed.IsSelectAll {
		columns = getAllEventColumns()
	}

	// Build rows
	rows := make([][]interface{}, 0, len(matchedEvents))
	for _, event := range matchedEvents {
		row := eventToRow(event, columns)
		rows = append(rows, row)
	}

	return QueryResult{
		Columns: columns,
		Rows:    rows,
		Total:   len(rows),
	}, nil
}

// parseQuery parses a simple SQL-like query
func parseQuery(query string) (ParsedQuery, error) {
	result := ParsedQuery{
		Limit: 100, // default limit
	}

	// Normalize whitespace
	query = strings.TrimSpace(query)
	queryLower := strings.ToLower(query)

	// Must start with SELECT
	if !strings.HasPrefix(queryLower, "select ") {
		return result, fmt.Errorf("query must start with SELECT")
	}

	// Extract LIMIT if present
	limitRegex := regexp.MustCompile(`(?i)\s+LIMIT\s+(\d+)\s*$`)
	if matches := limitRegex.FindStringSubmatch(query); len(matches) > 1 {
		if limit, err := strconv.Atoi(matches[1]); err == nil {
			result.Limit = limit
		}
		query = limitRegex.ReplaceAllString(query, "")
		queryLower = strings.ToLower(query)
	}

	// Find FROM position
	fromIdx := strings.Index(queryLower, " from ")
	if fromIdx == -1 {
		return result, fmt.Errorf("query must contain FROM clause")
	}

	// Extract columns (between SELECT and FROM)
	columnsStr := strings.TrimSpace(query[7:fromIdx])
	if columnsStr == "*" {
		result.IsSelectAll = true
	} else {
		columns := strings.Split(columnsStr, ",")
		for _, col := range columns {
			col = strings.TrimSpace(col)
			if col != "" {
				result.Columns = append(result.Columns, col)
			}
		}
	}

	// Extract table name and WHERE clause
	afterFrom := strings.TrimSpace(query[fromIdx+6:])
	whereIdx := strings.Index(strings.ToLower(afterFrom), " where ")

	if whereIdx == -1 {
		// No WHERE clause
		result.Table = strings.TrimSpace(afterFrom)
	} else {
		result.Table = strings.TrimSpace(afterFrom[:whereIdx])
		whereClause := strings.TrimSpace(afterFrom[whereIdx+7:])

		// Parse WHERE conditions
		conditions, logicOps, err := parseWhereClause(whereClause)
		if err != nil {
			return result, err
		}
		result.Conditions = conditions
		result.LogicOps = logicOps
	}

	return result, nil
}

// parseWhereClause parses WHERE conditions
func parseWhereClause(whereClause string) ([]Condition, []string, error) {
	var conditions []Condition
	var logicOps []string

	// Split by AND/OR while preserving the operators
	// Use regex to split while keeping delimiters
	parts := splitByLogicOps(whereClause)

	for i, part := range parts.conditions {
		cond, err := parseCondition(strings.TrimSpace(part))
		if err != nil {
			return nil, nil, err
		}
		conditions = append(conditions, cond)

		if i < len(parts.operators) {
			logicOps = append(logicOps, strings.ToUpper(parts.operators[i]))
		}
	}

	return conditions, logicOps, nil
}

type splitResult struct {
	conditions []string
	operators  []string
}

// splitByLogicOps splits a WHERE clause by AND/OR
func splitByLogicOps(clause string) splitResult {
	result := splitResult{}

	// Simple approach: find AND/OR positions
	clauseLower := strings.ToLower(clause)

	var current strings.Builder
	i := 0
	for i < len(clause) {
		// Check for AND
		if i+4 <= len(clauseLower) && clauseLower[i:i+4] == " and" &&
			(i+4 == len(clauseLower) || clauseLower[i+4] == ' ') {
			result.conditions = append(result.conditions, current.String())
			result.operators = append(result.operators, "AND")
			current.Reset()
			i += 5 // skip " AND "
			continue
		}
		// Check for OR
		if i+3 <= len(clauseLower) && clauseLower[i:i+3] == " or" &&
			(i+3 == len(clauseLower) || clauseLower[i+3] == ' ') {
			result.conditions = append(result.conditions, current.String())
			result.operators = append(result.operators, "OR")
			current.Reset()
			i += 4 // skip " OR "
			continue
		}
		current.WriteByte(clause[i])
		i++
	}

	if current.Len() > 0 {
		result.conditions = append(result.conditions, current.String())
	}

	return result
}

// parseCondition parses a single condition like "severity = 'high'"
func parseCondition(condStr string) (Condition, error) {
	cond := Condition{}

	// Supported operators in order of precedence (longer first)
	operators := []string{">=", "<=", "!=", "<>", "=", ">", "<", " LIKE ", " like "}

	for _, op := range operators {
		idx := strings.Index(condStr, op)
		if idx != -1 {
			cond.Field = strings.TrimSpace(condStr[:idx])
			cond.Operator = strings.TrimSpace(strings.ToUpper(op))
			valueStr := strings.TrimSpace(condStr[idx+len(op):])

			// Remove quotes from value
			cond.Value = stripQuotes(valueStr)
			return cond, nil
		}
	}

	return cond, fmt.Errorf("invalid condition: %s", condStr)
}

// stripQuotes removes surrounding quotes from a string
func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// matchesConditions checks if an event matches all conditions
func matchesConditions(event Event, conditions []Condition, logicOps []string) bool {
	if len(conditions) == 0 {
		return true
	}

	results := make([]bool, len(conditions))
	for i, cond := range conditions {
		results[i] = matchCondition(event, cond)
	}

	// Evaluate with logic operators (simple left-to-right, no precedence)
	result := results[0]
	for i := 0; i < len(logicOps) && i+1 < len(results); i++ {
		if logicOps[i] == "AND" {
			result = result && results[i+1]
		} else if logicOps[i] == "OR" {
			result = result || results[i+1]
		}
	}

	return result
}

// matchCondition checks if an event matches a single condition
func matchCondition(event Event, cond Condition) bool {
	fieldValue := getEventFieldValue(event, cond.Field)

	switch cond.Operator {
	case "=":
		return strings.EqualFold(fieldValue, cond.Value)
	case "!=", "<>":
		return !strings.EqualFold(fieldValue, cond.Value)
	case "LIKE":
		return matchLike(fieldValue, cond.Value)
	case ">", "<", ">=", "<=":
		return compareNumeric(fieldValue, cond.Value, cond.Operator)
	default:
		return false
	}
}

// matchLike implements SQL LIKE pattern matching
func matchLike(value, pattern string) bool {
	// Convert SQL LIKE pattern to regex
	// % matches any sequence, _ matches single char
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Escape regex special chars except % and _
	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, "%", ".*")
	regexPattern = strings.ReplaceAll(regexPattern, "_", ".")
	regexPattern = "^" + regexPattern + "$"

	matched, _ := regexp.MatchString(regexPattern, value)
	return matched
}

// compareNumeric compares numeric values
func compareNumeric(fieldValue, condValue, operator string) bool {
	fv, err1 := strconv.ParseFloat(fieldValue, 64)
	cv, err2 := strconv.ParseFloat(condValue, 64)

	// If both aren't numeric, fall back to string comparison
	if err1 != nil || err2 != nil {
		switch operator {
		case ">":
			return fieldValue > condValue
		case "<":
			return fieldValue < condValue
		case ">=":
			return fieldValue >= condValue
		case "<=":
			return fieldValue <= condValue
		}
		return false
	}

	switch operator {
	case ">":
		return fv > cv
	case "<":
		return fv < cv
	case ">=":
		return fv >= cv
	case "<=":
		return fv <= cv
	}
	return false
}

// getEventFieldValue returns the value of a field from an event
func getEventFieldValue(event Event, field string) string {
	fieldLower := strings.ToLower(field)

	switch fieldLower {
	case "id":
		return event.ID
	case "tenant_id":
		return event.TenantID
	case "event_time":
		return event.EventTime.Format(time.RFC3339)
	case "ingest_time":
		return event.IngestTime.Format(time.RFC3339)
	case "source":
		return event.Source
	case "source_type":
		return event.SourceType
	case "event_type":
		return event.EventType
	case "severity":
		return event.Severity
	case "source_ip":
		return event.SourceIP
	case "dest_ip":
		return event.DestIP
	case "source_port":
		return strconv.Itoa(event.SourcePort)
	case "dest_port":
		return strconv.Itoa(event.DestPort)
	case "user":
		return event.User
	case "hostname":
		return event.Hostname
	case "action":
		return event.Action
	case "status":
		return event.Status
	case "message":
		return event.Message
	case "raw_log":
		return event.RawLog
	case "asset_id":
		return event.AssetID
	case "product_id":
		return event.ProductID
	default:
		// Check parsed_fields
		if event.ParsedFields != nil {
			if val, ok := event.ParsedFields[field]; ok {
				return fmt.Sprintf("%v", val)
			}
		}
		return ""
	}
}

// getAllEventColumns returns all available event columns
func getAllEventColumns() []string {
	return []string{
		"id", "tenant_id", "event_time", "ingest_time", "source", "source_type",
		"event_type", "severity", "source_ip", "dest_ip", "source_port", "dest_port",
		"user", "hostname", "action", "status", "message", "raw_log", "asset_id", "product_id",
	}
}

// eventToRow converts an event to a row based on requested columns
func eventToRow(event Event, columns []string) []interface{} {
	row := make([]interface{}, len(columns))
	for i, col := range columns {
		row[i] = getEventFieldValueTyped(event, col)
	}
	return row
}

// getEventFieldValueTyped returns the typed value of a field
func getEventFieldValueTyped(event Event, field string) interface{} {
	fieldLower := strings.ToLower(field)

	switch fieldLower {
	case "id":
		return event.ID
	case "tenant_id":
		return event.TenantID
	case "event_time":
		return event.EventTime.Format(time.RFC3339)
	case "ingest_time":
		return event.IngestTime.Format(time.RFC3339)
	case "source":
		return event.Source
	case "source_type":
		return event.SourceType
	case "event_type":
		return event.EventType
	case "severity":
		return event.Severity
	case "source_ip":
		return event.SourceIP
	case "dest_ip":
		return event.DestIP
	case "source_port":
		return event.SourcePort
	case "dest_port":
		return event.DestPort
	case "user":
		return event.User
	case "hostname":
		return event.Hostname
	case "action":
		return event.Action
	case "status":
		return event.Status
	case "message":
		return event.Message
	case "raw_log":
		return event.RawLog
	case "asset_id":
		return event.AssetID
	case "product_id":
		return event.ProductID
	default:
		if event.ParsedFields != nil {
			if val, ok := event.ParsedFields[field]; ok {
				return val
			}
		}
		return nil
	}
}

// addQueryHistory adds a query to the history store
func addQueryHistory(entry QueryHistory) {
	queryHistoryMu.Lock()
	defer queryHistoryMu.Unlock()

	queryHistoryCounter++
	entry.ID = fmt.Sprintf("qh-%d", queryHistoryCounter)

	queryHistoryStore = append(queryHistoryStore, entry)

	// Keep only last maxQueryHistory entries
	if len(queryHistoryStore) > maxQueryHistory {
		queryHistoryStore = queryHistoryStore[len(queryHistoryStore)-maxQueryHistory:]
	}
}

// GetQueryHistoryHandler returns query execution history
func GetQueryHistoryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	queryHistoryMu.RLock()
	defer queryHistoryMu.RUnlock()

	// Return in reverse order (newest first)
	history := make([]QueryHistory, len(queryHistoryStore))
	for i, h := range queryHistoryStore {
		history[len(queryHistoryStore)-1-i] = h
	}

	// Parse query params for pagination
	query := r.URL.Query()
	limit := 50
	if l := query.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	if len(history) > limit {
		history = history[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items": history,
			"total": len(queryHistoryStore),
		},
	})
}

// ValidateQueryHandler validates SQL syntax
func ValidateQueryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		Query    string `json:"query"`
		Language string `json:"language"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": "Query cannot be empty",
		})
		return
	}

	// Attempt to parse the query
	_, err := parseQuery(req.Query)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   true,
			"message": "Query syntax is valid",
		})
	}
}

// GetSchemaHandler returns database schema
func GetSchemaHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"tables": databaseSchema,
		},
	})
}

// ListSavedQueriesHandler returns saved queries
func ListSavedQueriesHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	savedQueryMu.RLock()
	defer savedQueryMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items": savedQueryStore,
			"total": len(savedQueryStore),
		},
	})
}

// CreateSavedQueryHandler creates a new saved query
func CreateSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Query       string   `json:"query"`
		Language    string   `json:"language"`
		Tags        []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	savedQueryMu.Lock()
	defer savedQueryMu.Unlock()

	savedQueryCounter++
	query := SavedQuery{
		ID:          fmt.Sprintf("sq-%d", savedQueryCounter),
		Name:        req.Name,
		Description: req.Description,
		Query:       req.Query,
		Language:    req.Language,
		Tags:        req.Tags,
		CreatedBy:   "admin",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	savedQueryStore = append(savedQueryStore, query)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    query,
	})
}

// GetSavedQueryHandler returns a specific saved query
func GetSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	savedQueryMu.RLock()
	defer savedQueryMu.RUnlock()

	for _, q := range savedQueryStore {
		if q.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    q,
			})
			return
		}
	}

	http.Error(w, `{"error":"Query not found"}`, http.StatusNotFound)
}

// DeleteSavedQueryHandler deletes a saved query
func DeleteSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	savedQueryMu.Lock()
	defer savedQueryMu.Unlock()

	for i, q := range savedQueryStore {
		if q.ID == id {
			savedQueryStore = append(savedQueryStore[:i], savedQueryStore[i+1:]...)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Query deleted",
			})
			return
		}
	}

	http.Error(w, `{"error":"Query not found"}`, http.StatusNotFound)
}

// Helper to set CORS headers
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
