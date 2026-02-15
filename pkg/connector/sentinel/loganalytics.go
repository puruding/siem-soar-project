// Package sentinel provides Log Analytics query implementation.
package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"siem-soar-project/pkg/connector"
)

// QueryRequest represents a Log Analytics query request.
type QueryRequest struct {
	Query      string   `json:"query"`
	Timespan   string   `json:"timespan,omitempty"`
	Workspaces []string `json:"workspaces,omitempty"`
}

// QueryResponse represents a Log Analytics query response.
type QueryResponse struct {
	Tables []Table `json:"tables"`
}

// Table represents a query result table.
type Table struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
}

// Column represents a table column.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Query executes a KQL query against Log Analytics.
func (c *Client) Query(ctx context.Context, req *connector.QueryRequest) (*connector.QueryResult, error) {
	startTime := time.Now()

	// Build time range
	timespan := c.config.Query.DefaultTimespan
	if !req.TimeRange.Start.IsZero() && !req.TimeRange.End.IsZero() {
		timespan = fmt.Sprintf("%s/%s",
			req.TimeRange.Start.Format(time.RFC3339),
			req.TimeRange.End.Format(time.RFC3339),
		)
	} else if req.TimeRange.Relative != "" {
		timespan = req.TimeRange.Relative
	}

	// Build query request
	queryReq := QueryRequest{
		Query:    req.Query,
		Timespan: timespan,
	}

	// Execute query
	queryURL := c.config.GetQueryURL()
	resp, err := c.doJSONRequest(ctx, "POST", queryURL, queryReq)
	if err != nil {
		return nil, fmt.Errorf("query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed: %s - %s", resp.Status, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("failed to parse query response: %w", err)
	}

	// Convert response to results
	results := c.convertQueryResponse(&queryResp)

	return &connector.QueryResult{
		ID:        req.ID,
		Status:    connector.QueryStatusCompleted,
		Query:     req.Query,
		Language:  connector.QueryLanguageKQL,
		Results:   results,
		StartTime: startTime,
		EndTime:   time.Now(),
		Metadata: connector.QueryMetadata{
			TotalResults:    int64(len(results)),
			ReturnedResults: len(results),
			ExecutionTime:   time.Since(startTime),
			SIEM:            connector.SIEMSentinel,
		},
	}, nil
}

// convertQueryResponse converts the query response to a slice of maps.
func (c *Client) convertQueryResponse(resp *QueryResponse) []map[string]interface{} {
	if len(resp.Tables) == 0 {
		return nil
	}

	table := resp.Tables[0]
	results := make([]map[string]interface{}, len(table.Rows))

	for i, row := range table.Rows {
		result := make(map[string]interface{})
		for j, col := range table.Columns {
			if j < len(row) {
				result[col.Name] = row[j]
			}
		}
		results[i] = result
	}

	return results
}

// AsyncQuery starts an asynchronous query (not supported in Log Analytics).
func (c *Client) AsyncQuery(ctx context.Context, req *connector.QueryRequest) (string, error) {
	// Log Analytics doesn't support true async queries via the standard API
	// We'll implement a pseudo-async using goroutines
	return "", fmt.Errorf("async queries not supported for Sentinel - use synchronous Query")
}

// GetQueryStatus gets the status of an async query.
func (c *Client) GetQueryStatus(ctx context.Context, queryID string) (*connector.QueryResult, error) {
	return nil, fmt.Errorf("async queries not supported for Sentinel")
}

// CancelQuery cancels a running query.
func (c *Client) CancelQuery(ctx context.Context, queryID string) error {
	return fmt.Errorf("async queries not supported for Sentinel")
}

// QueryWithTimeout executes a query with a server-side timeout.
func (c *Client) QueryWithTimeout(ctx context.Context, query string, timespan string, timeout time.Duration) (*QueryResponse, error) {
	// Build query request
	queryReq := QueryRequest{
		Query:    query,
		Timespan: timespan,
	}

	// Build URL with prefer header for timeout
	queryURL := c.config.GetQueryURL()

	resp, err := c.doJSONRequest(ctx, "POST", queryURL, queryReq)
	if err != nil {
		return nil, fmt.Errorf("query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed: %s - %s", resp.Status, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("failed to parse query response: %w", err)
	}

	return &queryResp, nil
}

// QueryBatch executes multiple queries in a batch.
func (c *Client) QueryBatch(ctx context.Context, queries []string, timespan string) ([]*QueryResponse, error) {
	// Log Analytics supports batch queries
	batchURL := c.config.GetLogAnalyticsURL() + "/v1/$batch"

	type batchRequest struct {
		ID      string       `json:"id"`
		Body    QueryRequest `json:"body"`
		Headers map[string]string `json:"headers"`
	}

	type batchPayload struct {
		Requests []batchRequest `json:"requests"`
	}

	requests := make([]batchRequest, len(queries))
	for i, query := range queries {
		requests[i] = batchRequest{
			ID: fmt.Sprintf("%d", i),
			Body: QueryRequest{
				Query:    query,
				Timespan: timespan,
			},
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}
	}

	payload := batchPayload{Requests: requests}

	resp, err := c.doJSONRequest(ctx, "POST", batchURL, payload)
	if err != nil {
		return nil, fmt.Errorf("batch query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("batch query failed: %s - %s", resp.Status, string(body))
	}

	type batchResponse struct {
		Responses []struct {
			ID     string        `json:"id"`
			Status int           `json:"status"`
			Body   QueryResponse `json:"body"`
		} `json:"responses"`
	}

	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to parse batch response: %w", err)
	}

	results := make([]*QueryResponse, len(queries))
	for _, r := range batchResp.Responses {
		var idx int
		fmt.Sscanf(r.ID, "%d", &idx)
		if idx < len(results) {
			results[idx] = &r.Body
		}
	}

	return results, nil
}

// GetTables returns available tables in the workspace.
func (c *Client) GetTables(ctx context.Context) ([]TableMetadata, error) {
	query := `
		search *
		| getschema
		| distinct TableName
		| order by TableName asc
	`

	queryReq := QueryRequest{
		Query:    query,
		Timespan: "P1D",
	}

	resp, err := c.doJSONRequest(ctx, "POST", c.config.GetQueryURL(), queryReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get tables failed: %s - %s", resp.Status, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	tables := make([]TableMetadata, 0)
	if len(queryResp.Tables) > 0 {
		for _, row := range queryResp.Tables[0].Rows {
			if len(row) > 0 {
				if name, ok := row[0].(string); ok {
					tables = append(tables, TableMetadata{Name: name})
				}
			}
		}
	}

	return tables, nil
}

// TableMetadata holds table metadata.
type TableMetadata struct {
	Name        string `json:"name"`
	Schema      string `json:"schema,omitempty"`
	RetentionDays int  `json:"retention_days,omitempty"`
}

// GetTableSchema returns the schema for a table.
func (c *Client) GetTableSchema(ctx context.Context, tableName string) ([]Column, error) {
	query := fmt.Sprintf(`
		%s
		| getschema
		| project ColumnName, DataType
	`, tableName)

	queryReq := QueryRequest{
		Query:    query,
		Timespan: "P1D",
	}

	resp, err := c.doJSONRequest(ctx, "POST", c.config.GetQueryURL(), queryReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get schema failed: %s - %s", resp.Status, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	columns := make([]Column, 0)
	if len(queryResp.Tables) > 0 {
		for _, row := range queryResp.Tables[0].Rows {
			if len(row) >= 2 {
				col := Column{}
				if name, ok := row[0].(string); ok {
					col.Name = name
				}
				if dtype, ok := row[1].(string); ok {
					col.Type = dtype
				}
				columns = append(columns, col)
			}
		}
	}

	return columns, nil
}
