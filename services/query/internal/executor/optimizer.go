// Package executor provides query optimization capabilities.
package executor

import (
	"regexp"
	"strings"
)

// OptimizationRule represents a query optimization rule.
type OptimizationRule struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Apply       func(query string) string
	Priority    int
}

// Optimizer optimizes SQL queries for ClickHouse.
type Optimizer struct {
	rules []OptimizationRule
}

// NewOptimizer creates a new query optimizer.
func NewOptimizer() *Optimizer {
	o := &Optimizer{
		rules: make([]OptimizationRule, 0),
	}
	o.registerDefaultRules()
	return o
}

// Optimize optimizes a query and returns hints.
func (o *Optimizer) Optimize(query string, queryType QueryType) (string, map[string]string) {
	hints := make(map[string]string)
	optimized := query

	// Apply optimization rules
	for _, rule := range o.rules {
		if rule.Pattern != nil && rule.Pattern.MatchString(optimized) {
			before := optimized
			optimized = rule.Apply(optimized)
			if optimized != before {
				hints[rule.Name] = rule.Description
			}
		}
	}

	// Add query-type specific optimizations
	switch queryType {
	case QueryTypeAggregate:
		optimized, hints = o.optimizeAggregate(optimized, hints)
	case QueryTypeTimeSeries:
		optimized, hints = o.optimizeTimeSeries(optimized, hints)
	case QueryTypeSearch:
		optimized, hints = o.optimizeSearch(optimized, hints)
	}

	// Add FINAL if needed
	optimized = o.addFinalIfNeeded(optimized, hints)

	return optimized, hints
}

// AnalyzeQuery analyzes a query and returns optimization suggestions.
func (o *Optimizer) AnalyzeQuery(query string) []OptimizationSuggestion {
	suggestions := make([]OptimizationSuggestion, 0)

	// Check for SELECT *
	if strings.Contains(strings.ToUpper(query), "SELECT *") {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "column_selection",
			Severity:    SeverityWarning,
			Message:     "Avoid SELECT *, specify required columns explicitly",
			Improvement: "Reduces data transfer and improves performance",
		})
	}

	// Check for missing time filter
	if !hasTimeFilter(query) {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "time_filter",
			Severity:    SeverityCritical,
			Message:     "Query lacks time-based filtering",
			Improvement: "Add WHERE timestamp >= ... to limit data scan",
		})
	}

	// Check for LIKE with leading wildcard
	if hasLeadingWildcard(query) {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "wildcard_search",
			Severity:    SeverityWarning,
			Message:     "LIKE pattern with leading wildcard prevents index usage",
			Improvement: "Consider using full-text search or ngram index",
		})
	}

	// Check for ORDER BY without LIMIT
	if hasOrderByWithoutLimit(query) {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "unbounded_sort",
			Severity:    SeverityWarning,
			Message:     "ORDER BY without LIMIT causes full table sort",
			Improvement: "Add LIMIT to restrict sorted results",
		})
	}

	// Check for missing PREWHERE
	if shouldUsePrewhere(query) {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "prewhere_optimization",
			Severity:    SeverityInfo,
			Message:     "Consider using PREWHERE for better performance",
			Improvement: "PREWHERE filters data before reading columns",
		})
	}

	// Check for suboptimal GROUP BY
	if hasSuboptimalGroupBy(query) {
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "group_by_order",
			Severity:    SeverityInfo,
			Message:     "GROUP BY column order may not be optimal",
			Improvement: "Order columns by cardinality (low to high)",
		})
	}

	return suggestions
}

// OptimizationSuggestion represents an optimization suggestion.
type OptimizationSuggestion struct {
	Type        string              `json:"type"`
	Severity    OptimizationSeverity `json:"severity"`
	Message     string              `json:"message"`
	Improvement string              `json:"improvement"`
}

// OptimizationSeverity represents the severity of an optimization suggestion.
type OptimizationSeverity string

const (
	SeverityCritical OptimizationSeverity = "critical"
	SeverityWarning  OptimizationSeverity = "warning"
	SeverityInfo     OptimizationSeverity = "info"
)

func (o *Optimizer) registerDefaultRules() {
	// Rule: Convert UNION to UNION ALL where possible
	o.rules = append(o.rules, OptimizationRule{
		Name:        "union_all",
		Description: "Converted UNION to UNION ALL (eliminates deduplication)",
		Pattern:     regexp.MustCompile(`(?i)\bUNION\s+(?!ALL)`),
		Apply: func(query string) string {
			// Only convert if safe (no duplicates expected)
			// This is a simplified version; production would be more sophisticated
			return query
		},
		Priority: 1,
	})

	// Rule: Add SETTINGS optimize_read_in_order
	o.rules = append(o.rules, OptimizationRule{
		Name:        "read_in_order",
		Description: "Added optimize_read_in_order setting",
		Pattern:     regexp.MustCompile(`(?i)ORDER BY.*timestamp`),
		Apply: func(query string) string {
			if !strings.Contains(strings.ToLower(query), "settings") {
				return query + " SETTINGS optimize_read_in_order = 1"
			}
			return query
		},
		Priority: 2,
	})

	// Rule: Convert IN to global IN for distributed queries
	o.rules = append(o.rules, OptimizationRule{
		Name:        "global_in",
		Description: "Consider using GLOBAL IN for distributed queries",
		Pattern:     regexp.MustCompile(`(?i)\bIN\s*\(`),
		Apply: func(query string) string {
			// This needs context about whether query is distributed
			return query
		},
		Priority: 3,
	})

	// Rule: Use PREWHERE instead of WHERE for filtering columns
	o.rules = append(o.rules, OptimizationRule{
		Name:        "prewhere",
		Description: "Moved filtering condition to PREWHERE",
		Pattern:     regexp.MustCompile(`(?i)\bWHERE\b`),
		Apply: func(query string) string {
			// Only apply if single simple condition
			return o.convertToPrewhere(query)
		},
		Priority: 4,
	})

	// Rule: Add LIMIT for safety
	o.rules = append(o.rules, OptimizationRule{
		Name:        "safety_limit",
		Description: "Added safety LIMIT clause",
		Pattern:     regexp.MustCompile(`(?i)SELECT.*FROM`),
		Apply: func(query string) string {
			if !strings.Contains(strings.ToLower(query), "limit") {
				return query + " LIMIT 10000"
			}
			return query
		},
		Priority: 10,
	})
}

func (o *Optimizer) optimizeAggregate(query string, hints map[string]string) (string, map[string]string) {
	// Use sampling for large aggregations
	if shouldUseSampling(query) {
		hints["sampling"] = "Consider SAMPLE clause for approximation"
	}

	// Suggest approximate functions
	if strings.Contains(strings.ToLower(query), "count(distinct") {
		hints["approx_distinct"] = "Consider uniqHLL12 for approximate distinct count"
	}

	return query, hints
}

func (o *Optimizer) optimizeTimeSeries(query string, hints map[string]string) (string, map[string]string) {
	// Suggest toStartOfInterval for time bucketing
	if !strings.Contains(strings.ToLower(query), "tostartof") {
		hints["time_bucket"] = "Consider toStartOfInterval for time bucketing"
	}

	// Suggest with fill for missing time points
	hints["with_fill"] = "Consider WITH FILL for continuous time series"

	return query, hints
}

func (o *Optimizer) optimizeSearch(query string, hints map[string]string) (string, map[string]string) {
	// Suggest full-text search functions
	if strings.Contains(query, "%") {
		hints["fulltext"] = "Consider using ngramSearch or tokenbf_v1 for text search"
	}

	return query, hints
}

func (o *Optimizer) addFinalIfNeeded(query string, hints map[string]string) string {
	// Add FINAL for ReplacingMergeTree queries
	// This is a simplified check; production would check table engine
	upperQuery := strings.ToUpper(query)
	if strings.Contains(upperQuery, "FROM") && !strings.Contains(upperQuery, "FINAL") {
		// Would need metadata about table engine
		// hints["final"] = "Consider FINAL modifier for ReplacingMergeTree tables"
	}
	return query
}

func (o *Optimizer) convertToPrewhere(query string) string {
	// Convert simple WHERE clauses to PREWHERE
	// PREWHERE is applied before reading non-filtered columns
	upperQuery := strings.ToUpper(query)

	// Only convert if simple condition on indexed column
	whereIdx := strings.Index(upperQuery, "WHERE")
	if whereIdx == -1 {
		return query
	}

	// Find the end of WHERE clause
	andIdx := strings.Index(upperQuery[whereIdx:], " AND ")
	if andIdx == -1 {
		// Single condition - safe to convert
		// But check if it's a simple equality on timestamp
		condition := query[whereIdx:]
		if isSimpleTimeCondition(condition) {
			return query[:whereIdx] + "PREWHERE" + query[whereIdx+5:]
		}
	}

	return query
}

// Helper functions
func hasTimeFilter(query string) bool {
	upperQuery := strings.ToUpper(query)
	timeKeywords := []string{"TIMESTAMP", "DATE", "TIME", "CREATED_AT", "EVENT_TIME"}
	for _, kw := range timeKeywords {
		if strings.Contains(upperQuery, kw) {
			return true
		}
	}
	return false
}

func hasLeadingWildcard(query string) bool {
	return strings.Contains(query, "LIKE '%") || strings.Contains(query, "like '%")
}

func hasOrderByWithoutLimit(query string) bool {
	upperQuery := strings.ToUpper(query)
	hasOrder := strings.Contains(upperQuery, "ORDER BY")
	hasLimit := strings.Contains(upperQuery, "LIMIT")
	return hasOrder && !hasLimit
}

func shouldUsePrewhere(query string) bool {
	upperQuery := strings.ToUpper(query)
	return strings.Contains(upperQuery, "WHERE") && !strings.Contains(upperQuery, "PREWHERE")
}

func hasSuboptimalGroupBy(query string) bool {
	// Simplified check - would need column cardinality info
	return false
}

func shouldUseSampling(query string) bool {
	// Simplified check - would need table size info
	upperQuery := strings.ToUpper(query)
	return strings.Contains(upperQuery, "COUNT(") || strings.Contains(upperQuery, "SUM(")
}

func isSimpleTimeCondition(condition string) bool {
	upperCondition := strings.ToUpper(condition)
	timeKeywords := []string{"TIMESTAMP", "DATE", "TIME", "CREATED_AT", "EVENT_TIME"}
	for _, kw := range timeKeywords {
		if strings.Contains(upperCondition, kw) {
			return true
		}
	}
	return false
}
