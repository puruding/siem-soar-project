// Package parser provides SQL query parsing capabilities.
package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// QueryType represents the type of SQL query.
type QueryType string

const (
	QueryTypeSelect   QueryType = "SELECT"
	QueryTypeInsert   QueryType = "INSERT"
	QueryTypeUpdate   QueryType = "UPDATE"
	QueryTypeDelete   QueryType = "DELETE"
	QueryTypeCreate   QueryType = "CREATE"
	QueryTypeDrop     QueryType = "DROP"
	QueryTypeAlter    QueryType = "ALTER"
	QueryTypeShow     QueryType = "SHOW"
	QueryTypeDescribe QueryType = "DESCRIBE"
	QueryTypeExplain  QueryType = "EXPLAIN"
	QueryTypeUnknown  QueryType = "UNKNOWN"
)

// ParsedQuery represents a parsed SQL query.
type ParsedQuery struct {
	Type        QueryType              `json:"type"`
	Tables      []TableReference       `json:"tables"`
	Columns     []ColumnReference      `json:"columns"`
	Conditions  []Condition            `json:"conditions"`
	GroupBy     []string               `json:"group_by,omitempty"`
	OrderBy     []OrderClause          `json:"order_by,omitempty"`
	Limit       *int                   `json:"limit,omitempty"`
	Offset      *int                   `json:"offset,omitempty"`
	Subqueries  []*ParsedQuery         `json:"subqueries,omitempty"`
	Joins       []JoinClause           `json:"joins,omitempty"`
	CTEs        []CTE                  `json:"ctes,omitempty"`
	Aggregates  []AggregateFunction    `json:"aggregates,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	RawQuery    string                 `json:"-"`
}

// TableReference represents a table reference in a query.
type TableReference struct {
	Database string `json:"database,omitempty"`
	Table    string `json:"table"`
	Alias    string `json:"alias,omitempty"`
	Schema   string `json:"schema,omitempty"`
}

// ColumnReference represents a column reference.
type ColumnReference struct {
	Table    string `json:"table,omitempty"`
	Column   string `json:"column"`
	Alias    string `json:"alias,omitempty"`
	Function string `json:"function,omitempty"`
}

// Condition represents a WHERE condition.
type Condition struct {
	Left     string      `json:"left"`
	Operator string      `json:"operator"`
	Right    interface{} `json:"right"`
	Type     string      `json:"type"` // column, literal, subquery
	Logic    string      `json:"logic,omitempty"` // AND, OR
}

// OrderClause represents an ORDER BY clause.
type OrderClause struct {
	Column    string `json:"column"`
	Direction string `json:"direction"` // ASC, DESC
	NullsPos  string `json:"nulls,omitempty"` // FIRST, LAST
}

// JoinClause represents a JOIN clause.
type JoinClause struct {
	Type      string           `json:"type"` // INNER, LEFT, RIGHT, FULL, CROSS
	Table     TableReference   `json:"table"`
	Condition string           `json:"condition"`
	Columns   []ColumnReference `json:"columns,omitempty"`
}

// CTE represents a Common Table Expression.
type CTE struct {
	Name    string       `json:"name"`
	Columns []string     `json:"columns,omitempty"`
	Query   *ParsedQuery `json:"query"`
}

// AggregateFunction represents an aggregate function.
type AggregateFunction struct {
	Name     string   `json:"name"`
	Column   string   `json:"column"`
	Distinct bool     `json:"distinct"`
	Filter   string   `json:"filter,omitempty"`
	Args     []string `json:"args,omitempty"`
}

// Parser parses SQL queries.
type Parser struct {
	dialect string
}

// NewParser creates a new SQL parser.
func NewParser(dialect string) *Parser {
	return &Parser{dialect: dialect}
}

// Parse parses a SQL query.
func (p *Parser) Parse(query string) (*ParsedQuery, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}

	parsed := &ParsedQuery{
		RawQuery:   query,
		Parameters: make(map[string]interface{}),
	}

	// Determine query type
	parsed.Type = p.detectQueryType(query)

	// Parse based on type
	var err error
	switch parsed.Type {
	case QueryTypeSelect:
		err = p.parseSelect(query, parsed)
	case QueryTypeInsert:
		err = p.parseInsert(query, parsed)
	case QueryTypeUpdate:
		err = p.parseUpdate(query, parsed)
	case QueryTypeDelete:
		err = p.parseDelete(query, parsed)
	default:
		// Basic parsing for other types
		err = p.parseGeneric(query, parsed)
	}

	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return parsed, nil
}

// detectQueryType determines the type of SQL query.
func (p *Parser) detectQueryType(query string) QueryType {
	upper := strings.ToUpper(strings.TrimSpace(query))

	// Handle CTEs
	if strings.HasPrefix(upper, "WITH") {
		// Find the main query after WITH clause
		idx := strings.Index(upper, "SELECT")
		if idx > 0 {
			return QueryTypeSelect
		}
	}

	keywords := []struct {
		prefix    string
		queryType QueryType
	}{
		{"SELECT", QueryTypeSelect},
		{"INSERT", QueryTypeInsert},
		{"UPDATE", QueryTypeUpdate},
		{"DELETE", QueryTypeDelete},
		{"CREATE", QueryTypeCreate},
		{"DROP", QueryTypeDrop},
		{"ALTER", QueryTypeAlter},
		{"SHOW", QueryTypeShow},
		{"DESCRIBE", QueryTypeDescribe},
		{"DESC ", QueryTypeDescribe},
		{"EXPLAIN", QueryTypeExplain},
	}

	for _, kw := range keywords {
		if strings.HasPrefix(upper, kw.prefix) {
			return kw.queryType
		}
	}

	return QueryTypeUnknown
}

// parseSelect parses a SELECT query.
func (p *Parser) parseSelect(query string, parsed *ParsedQuery) error {
	upper := strings.ToUpper(query)

	// Parse CTEs
	if strings.HasPrefix(upper, "WITH") {
		ctes, remaining, err := p.parseCTEs(query)
		if err != nil {
			return err
		}
		parsed.CTEs = ctes
		query = remaining
		upper = strings.ToUpper(query)
	}

	// Parse columns
	columns, err := p.parseColumns(query)
	if err != nil {
		return err
	}
	parsed.Columns = columns

	// Parse tables
	tables, err := p.parseTables(query)
	if err != nil {
		return err
	}
	parsed.Tables = tables

	// Parse JOINs
	joins, err := p.parseJoins(query)
	if err != nil {
		return err
	}
	parsed.Joins = joins

	// Parse WHERE conditions
	conditions, err := p.parseConditions(query)
	if err != nil {
		return err
	}
	parsed.Conditions = conditions

	// Parse GROUP BY
	groupBy := p.parseGroupBy(query)
	parsed.GroupBy = groupBy

	// Parse ORDER BY
	orderBy := p.parseOrderBy(query)
	parsed.OrderBy = orderBy

	// Parse LIMIT/OFFSET
	limit, offset := p.parseLimitOffset(query)
	parsed.Limit = limit
	parsed.Offset = offset

	// Parse aggregate functions
	aggregates := p.parseAggregates(query)
	parsed.Aggregates = aggregates

	// Parse subqueries
	subqueries, err := p.parseSubqueries(query)
	if err != nil {
		return err
	}
	parsed.Subqueries = subqueries

	return nil
}

// parseInsert parses an INSERT query.
func (p *Parser) parseInsert(query string, parsed *ParsedQuery) error {
	// Extract table name
	re := regexp.MustCompile(`(?i)INSERT\s+INTO\s+(\w+(?:\.\w+)?)\s*`)
	matches := re.FindStringSubmatch(query)
	if len(matches) > 1 {
		parsed.Tables = []TableReference{{Table: matches[1]}}
	}

	// Extract columns if specified
	colRe := regexp.MustCompile(`\(([^)]+)\)\s*VALUES`)
	colMatches := colRe.FindStringSubmatch(query)
	if len(colMatches) > 1 {
		cols := strings.Split(colMatches[1], ",")
		for _, col := range cols {
			parsed.Columns = append(parsed.Columns, ColumnReference{
				Column: strings.TrimSpace(col),
			})
		}
	}

	return nil
}

// parseUpdate parses an UPDATE query.
func (p *Parser) parseUpdate(query string, parsed *ParsedQuery) error {
	// Extract table name
	re := regexp.MustCompile(`(?i)UPDATE\s+(\w+(?:\.\w+)?)\s+SET`)
	matches := re.FindStringSubmatch(query)
	if len(matches) > 1 {
		parsed.Tables = []TableReference{{Table: matches[1]}}
	}

	// Parse WHERE conditions
	conditions, err := p.parseConditions(query)
	if err != nil {
		return err
	}
	parsed.Conditions = conditions

	return nil
}

// parseDelete parses a DELETE query.
func (p *Parser) parseDelete(query string, parsed *ParsedQuery) error {
	// Extract table name
	re := regexp.MustCompile(`(?i)DELETE\s+FROM\s+(\w+(?:\.\w+)?)`)
	matches := re.FindStringSubmatch(query)
	if len(matches) > 1 {
		parsed.Tables = []TableReference{{Table: matches[1]}}
	}

	// Parse WHERE conditions
	conditions, err := p.parseConditions(query)
	if err != nil {
		return err
	}
	parsed.Conditions = conditions

	return nil
}

// parseGeneric parses a generic query.
func (p *Parser) parseGeneric(query string, parsed *ParsedQuery) error {
	// Extract any table references
	tables, _ := p.parseTables(query)
	parsed.Tables = tables
	return nil
}

// parseCTEs parses Common Table Expressions.
func (p *Parser) parseCTEs(query string) ([]CTE, string, error) {
	// Simplified CTE parsing
	ctes := make([]CTE, 0)

	// Find the main SELECT after WITH clause
	_ = strings.ToUpper(query) // placeholder for future CTE parsing
	selectIdx := -1

	// Find the last SELECT that's not inside parentheses
	depth := 0
	for i := 0; i < len(query)-6; i++ {
		if query[i] == '(' {
			depth++
		} else if query[i] == ')' {
			depth--
		} else if depth == 0 && strings.ToUpper(query[i:i+6]) == "SELECT" && i > 0 {
			selectIdx = i
		}
	}

	if selectIdx == -1 {
		return nil, query, nil
	}

	return ctes, query[selectIdx:], nil
}

// parseColumns parses SELECT columns.
func (p *Parser) parseColumns(query string) ([]ColumnReference, error) {
	columns := make([]ColumnReference, 0)

	// Find SELECT ... FROM
	upper := strings.ToUpper(query)
	selectIdx := strings.Index(upper, "SELECT")
	fromIdx := strings.Index(upper, "FROM")

	if selectIdx == -1 || fromIdx == -1 || fromIdx < selectIdx {
		return columns, nil
	}

	columnStr := strings.TrimSpace(query[selectIdx+6 : fromIdx])

	// Handle SELECT DISTINCT
	if strings.HasPrefix(strings.ToUpper(columnStr), "DISTINCT") {
		columnStr = strings.TrimSpace(columnStr[8:])
	}

	// Split by comma (simplified, doesn't handle nested functions)
	parts := splitColumns(columnStr)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		col := ColumnReference{}

		// Check for alias
		upperPart := strings.ToUpper(part)
		asIdx := strings.LastIndex(upperPart, " AS ")
		if asIdx > 0 {
			col.Alias = strings.TrimSpace(part[asIdx+4:])
			part = strings.TrimSpace(part[:asIdx])
		}

		// Check for function
		if strings.Contains(part, "(") {
			parenIdx := strings.Index(part, "(")
			col.Function = part[:parenIdx]
			inner := part[parenIdx+1 : len(part)-1]
			col.Column = strings.TrimSpace(inner)
		} else if strings.Contains(part, ".") {
			// Table.column format
			dotParts := strings.Split(part, ".")
			col.Table = dotParts[0]
			col.Column = dotParts[1]
		} else {
			col.Column = part
		}

		columns = append(columns, col)
	}

	return columns, nil
}

// parseTables parses FROM tables.
func (p *Parser) parseTables(query string) ([]TableReference, error) {
	tables := make([]TableReference, 0)

	upper := strings.ToUpper(query)
	fromIdx := strings.Index(upper, "FROM")
	if fromIdx == -1 {
		return tables, nil
	}

	// Find the end of FROM clause
	endIdx := len(query)
	for _, kw := range []string{"WHERE", "GROUP BY", "ORDER BY", "LIMIT", "HAVING", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS"} {
		idx := strings.Index(upper[fromIdx+4:], kw)
		if idx > 0 && fromIdx+4+idx < endIdx {
			endIdx = fromIdx + 4 + idx
		}
	}

	tableStr := strings.TrimSpace(query[fromIdx+4 : endIdx])

	// Parse table references
	parts := strings.Split(tableStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		table := TableReference{}

		// Check for alias
		spaceParts := strings.Fields(part)
		if len(spaceParts) >= 2 {
			table.Table = spaceParts[0]
			if strings.ToUpper(spaceParts[1]) == "AS" && len(spaceParts) >= 3 {
				table.Alias = spaceParts[2]
			} else {
				table.Alias = spaceParts[1]
			}
		} else {
			table.Table = part
		}

		// Check for database.table format
		if strings.Contains(table.Table, ".") {
			dotParts := strings.Split(table.Table, ".")
			if len(dotParts) == 2 {
				table.Database = dotParts[0]
				table.Table = dotParts[1]
			}
		}

		tables = append(tables, table)
	}

	return tables, nil
}

// parseConditions parses WHERE conditions.
func (p *Parser) parseConditions(query string) ([]Condition, error) {
	conditions := make([]Condition, 0)

	upper := strings.ToUpper(query)
	whereIdx := strings.Index(upper, "WHERE")
	if whereIdx == -1 {
		return conditions, nil
	}

	// Find the end of WHERE clause
	endIdx := len(query)
	for _, kw := range []string{"GROUP BY", "ORDER BY", "LIMIT", "HAVING"} {
		idx := strings.Index(upper[whereIdx+5:], kw)
		if idx > 0 && whereIdx+5+idx < endIdx {
			endIdx = whereIdx + 5 + idx
		}
	}

	whereStr := strings.TrimSpace(query[whereIdx+5 : endIdx])

	// Split by AND/OR (simplified)
	conditions = p.parseConditionString(whereStr)

	return conditions, nil
}

// parseConditionString parses a condition string.
func (p *Parser) parseConditionString(condStr string) []Condition {
	conditions := make([]Condition, 0)

	// Split by AND (simplified, doesn't handle nested parentheses well)
	parts := regexp.MustCompile(`(?i)\s+AND\s+`).Split(condStr, -1)

	operators := []string{">=", "<=", "!=", "<>", "=", ">", "<", " LIKE ", " IN ", " BETWEEN ", " IS "}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		cond := Condition{Logic: "AND"}

		// Find operator
		for _, op := range operators {
			upperPart := strings.ToUpper(part)
			idx := strings.Index(upperPart, strings.ToUpper(op))
			if idx > 0 {
				cond.Left = strings.TrimSpace(part[:idx])
				cond.Operator = strings.TrimSpace(op)
				cond.Right = strings.TrimSpace(part[idx+len(op):])
				cond.Type = "literal"
				break
			}
		}

		if cond.Left != "" {
			conditions = append(conditions, cond)
		}
	}

	return conditions
}

// parseJoins parses JOIN clauses.
func (p *Parser) parseJoins(query string) ([]JoinClause, error) {
	joins := make([]JoinClause, 0)

	joinTypes := []string{"LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "FULL JOIN", "CROSS JOIN", "JOIN"}

	upper := strings.ToUpper(query)

	for _, jt := range joinTypes {
		idx := 0
		for {
			joinIdx := strings.Index(upper[idx:], jt)
			if joinIdx == -1 {
				break
			}
			joinIdx += idx

			// Find ON clause
			onIdx := strings.Index(upper[joinIdx:], " ON ")
			if onIdx == -1 {
				idx = joinIdx + len(jt)
				continue
			}
			onIdx += joinIdx

			// Extract table name
			tableStr := strings.TrimSpace(query[joinIdx+len(jt) : onIdx])
			table := TableReference{}

			spaceParts := strings.Fields(tableStr)
			if len(spaceParts) >= 1 {
				table.Table = spaceParts[0]
				if len(spaceParts) >= 2 {
					if strings.ToUpper(spaceParts[1]) == "AS" && len(spaceParts) >= 3 {
						table.Alias = spaceParts[2]
					} else {
						table.Alias = spaceParts[1]
					}
				}
			}

			// Find condition end
			condEnd := len(query)
			for _, kw := range []string{"WHERE", "GROUP BY", "ORDER BY", "LIMIT", "LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "FULL JOIN", "CROSS JOIN", "JOIN"} {
				kwIdx := strings.Index(upper[onIdx+4:], kw)
				if kwIdx > 0 && onIdx+4+kwIdx < condEnd {
					condEnd = onIdx + 4 + kwIdx
				}
			}

			condition := strings.TrimSpace(query[onIdx+4 : condEnd])

			join := JoinClause{
				Type:      strings.TrimSpace(strings.Replace(jt, "JOIN", "", 1)),
				Table:     table,
				Condition: condition,
			}

			if join.Type == "" {
				join.Type = "INNER"
			}

			joins = append(joins, join)

			idx = condEnd
		}
	}

	return joins, nil
}

// parseGroupBy parses GROUP BY clause.
func (p *Parser) parseGroupBy(query string) []string {
	groupBy := make([]string, 0)

	upper := strings.ToUpper(query)
	groupIdx := strings.Index(upper, "GROUP BY")
	if groupIdx == -1 {
		return groupBy
	}

	// Find end of GROUP BY
	endIdx := len(query)
	for _, kw := range []string{"HAVING", "ORDER BY", "LIMIT"} {
		idx := strings.Index(upper[groupIdx+8:], kw)
		if idx > 0 && groupIdx+8+idx < endIdx {
			endIdx = groupIdx + 8 + idx
		}
	}

	groupStr := strings.TrimSpace(query[groupIdx+8 : endIdx])
	parts := strings.Split(groupStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			groupBy = append(groupBy, part)
		}
	}

	return groupBy
}

// parseOrderBy parses ORDER BY clause.
func (p *Parser) parseOrderBy(query string) []OrderClause {
	orderBy := make([]OrderClause, 0)

	upper := strings.ToUpper(query)
	orderIdx := strings.Index(upper, "ORDER BY")
	if orderIdx == -1 {
		return orderBy
	}

	// Find end of ORDER BY
	endIdx := len(query)
	for _, kw := range []string{"LIMIT", "OFFSET"} {
		idx := strings.Index(upper[orderIdx+8:], kw)
		if idx > 0 && orderIdx+8+idx < endIdx {
			endIdx = orderIdx + 8 + idx
		}
	}

	orderStr := strings.TrimSpace(query[orderIdx+8 : endIdx])
	parts := strings.Split(orderStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		order := OrderClause{Direction: "ASC"}

		fields := strings.Fields(part)
		if len(fields) >= 1 {
			order.Column = fields[0]
		}
		if len(fields) >= 2 {
			if strings.ToUpper(fields[1]) == "DESC" {
				order.Direction = "DESC"
			}
		}

		orderBy = append(orderBy, order)
	}

	return orderBy
}

// parseLimitOffset parses LIMIT and OFFSET clauses.
func (p *Parser) parseLimitOffset(query string) (*int, *int) {
	upper := strings.ToUpper(query)

	var limit, offset *int

	// Parse LIMIT
	limitIdx := strings.Index(upper, "LIMIT")
	if limitIdx > 0 {
		re := regexp.MustCompile(`(?i)LIMIT\s+(\d+)`)
		matches := re.FindStringSubmatch(query[limitIdx:])
		if len(matches) > 1 {
			var l int
			fmt.Sscanf(matches[1], "%d", &l)
			limit = &l
		}
	}

	// Parse OFFSET
	offsetIdx := strings.Index(upper, "OFFSET")
	if offsetIdx > 0 {
		re := regexp.MustCompile(`(?i)OFFSET\s+(\d+)`)
		matches := re.FindStringSubmatch(query[offsetIdx:])
		if len(matches) > 1 {
			var o int
			fmt.Sscanf(matches[1], "%d", &o)
			offset = &o
		}
	}

	return limit, offset
}

// parseAggregates parses aggregate functions.
func (p *Parser) parseAggregates(query string) []AggregateFunction {
	aggregates := make([]AggregateFunction, 0)

	funcs := []string{"COUNT", "SUM", "AVG", "MIN", "MAX", "GROUP_CONCAT", "ARRAY_AGG"}

	for _, fn := range funcs {
		re := regexp.MustCompile(fmt.Sprintf(`(?i)\b%s\s*\(\s*(DISTINCT\s+)?([^)]+)\)`, fn))
		matches := re.FindAllStringSubmatch(query, -1)

		for _, match := range matches {
			agg := AggregateFunction{
				Name:     fn,
				Distinct: strings.TrimSpace(match[1]) != "",
				Column:   strings.TrimSpace(match[2]),
			}
			aggregates = append(aggregates, agg)
		}
	}

	return aggregates
}

// parseSubqueries parses subqueries.
func (p *Parser) parseSubqueries(query string) ([]*ParsedQuery, error) {
	subqueries := make([]*ParsedQuery, 0)

	// Find nested SELECT statements
	depth := 0
	start := -1

	for i := 0; i < len(query); i++ {
		if query[i] == '(' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if query[i] == ')' {
			depth--
			if depth == 0 && start >= 0 {
				inner := strings.TrimSpace(query[start+1 : i])
				if strings.HasPrefix(strings.ToUpper(inner), "SELECT") {
					subquery, err := p.Parse(inner)
					if err == nil {
						subqueries = append(subqueries, subquery)
					}
				}
				start = -1
			}
		}
	}

	return subqueries, nil
}

// splitColumns splits column list respecting parentheses.
func splitColumns(s string) []string {
	result := make([]string, 0)
	depth := 0
	start := 0

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}

	if start < len(s) {
		result = append(result, strings.TrimSpace(s[start:]))
	}

	return result
}
