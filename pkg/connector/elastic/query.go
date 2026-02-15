// Package elastic provides Elasticsearch query implementation.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"

	"siem-soar-project/pkg/connector"
)

// SearchResponse represents an Elasticsearch search response.
type SearchResponse struct {
	Took         int            `json:"took"`
	TimedOut     bool           `json:"timed_out"`
	Shards       ShardInfo      `json:"_shards"`
	Hits         HitsInfo       `json:"hits"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty"`
	ScrollID     string         `json:"_scroll_id,omitempty"`
	PitID        string         `json:"pit_id,omitempty"`
}

// ShardInfo holds shard information.
type ShardInfo struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Skipped    int `json:"skipped"`
	Failed     int `json:"failed"`
}

// HitsInfo holds hits information.
type HitsInfo struct {
	Total    TotalHits   `json:"total"`
	MaxScore *float64    `json:"max_score"`
	Hits     []Hit       `json:"hits"`
}

// TotalHits holds total hits information.
type TotalHits struct {
	Value    int64  `json:"value"`
	Relation string `json:"relation"`
}

// Hit represents a single search hit.
type Hit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Score  *float64               `json:"_score"`
	Source map[string]interface{} `json:"_source"`
	Fields map[string]interface{} `json:"fields,omitempty"`
	Sort   []interface{}          `json:"sort,omitempty"`
}

// QueryBuilder helps build Elasticsearch queries.
type QueryBuilder struct {
	query map[string]interface{}
}

// NewQueryBuilder creates a new query builder.
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		query: make(map[string]interface{}),
	}
}

// Match adds a match query.
func (qb *QueryBuilder) Match(field, value string) *QueryBuilder {
	qb.query["match"] = map[string]interface{}{
		field: value,
	}
	return qb
}

// MatchAll adds a match_all query.
func (qb *QueryBuilder) MatchAll() *QueryBuilder {
	qb.query["match_all"] = map[string]interface{}{}
	return qb
}

// Term adds a term query.
func (qb *QueryBuilder) Term(field string, value interface{}) *QueryBuilder {
	qb.query["term"] = map[string]interface{}{
		field: value,
	}
	return qb
}

// Terms adds a terms query.
func (qb *QueryBuilder) Terms(field string, values []interface{}) *QueryBuilder {
	qb.query["terms"] = map[string]interface{}{
		field: values,
	}
	return qb
}

// Range adds a range query.
func (qb *QueryBuilder) Range(field string, gte, lte interface{}) *QueryBuilder {
	rangeQ := make(map[string]interface{})
	if gte != nil {
		rangeQ["gte"] = gte
	}
	if lte != nil {
		rangeQ["lte"] = lte
	}
	qb.query["range"] = map[string]interface{}{
		field: rangeQ,
	}
	return qb
}

// Bool adds a bool query.
func (qb *QueryBuilder) Bool() *BoolQueryBuilder {
	bqb := &BoolQueryBuilder{
		parent: qb,
		must:   make([]map[string]interface{}, 0),
		should: make([]map[string]interface{}, 0),
		filter: make([]map[string]interface{}, 0),
		mustNot: make([]map[string]interface{}, 0),
	}
	return bqb
}

// Build returns the built query.
func (qb *QueryBuilder) Build() map[string]interface{} {
	return qb.query
}

// BoolQueryBuilder helps build bool queries.
type BoolQueryBuilder struct {
	parent  *QueryBuilder
	must    []map[string]interface{}
	should  []map[string]interface{}
	filter  []map[string]interface{}
	mustNot []map[string]interface{}
	minShouldMatch interface{}
}

// Must adds a must clause.
func (bqb *BoolQueryBuilder) Must(query map[string]interface{}) *BoolQueryBuilder {
	bqb.must = append(bqb.must, query)
	return bqb
}

// Should adds a should clause.
func (bqb *BoolQueryBuilder) Should(query map[string]interface{}) *BoolQueryBuilder {
	bqb.should = append(bqb.should, query)
	return bqb
}

// Filter adds a filter clause.
func (bqb *BoolQueryBuilder) Filter(query map[string]interface{}) *BoolQueryBuilder {
	bqb.filter = append(bqb.filter, query)
	return bqb
}

// MustNot adds a must_not clause.
func (bqb *BoolQueryBuilder) MustNot(query map[string]interface{}) *BoolQueryBuilder {
	bqb.mustNot = append(bqb.mustNot, query)
	return bqb
}

// MinShouldMatch sets minimum_should_match.
func (bqb *BoolQueryBuilder) MinShouldMatch(value interface{}) *BoolQueryBuilder {
	bqb.minShouldMatch = value
	return bqb
}

// Build returns the parent query builder with the bool query added.
func (bqb *BoolQueryBuilder) Build() *QueryBuilder {
	boolQ := make(map[string]interface{})
	if len(bqb.must) > 0 {
		boolQ["must"] = bqb.must
	}
	if len(bqb.should) > 0 {
		boolQ["should"] = bqb.should
	}
	if len(bqb.filter) > 0 {
		boolQ["filter"] = bqb.filter
	}
	if len(bqb.mustNot) > 0 {
		boolQ["must_not"] = bqb.mustNot
	}
	if bqb.minShouldMatch != nil {
		boolQ["minimum_should_match"] = bqb.minShouldMatch
	}
	bqb.parent.query["bool"] = boolQ
	return bqb.parent
}

// Query executes a search query.
func (c *Client) Query(ctx context.Context, req *connector.QueryRequest) (*connector.QueryResult, error) {
	startTime := time.Now()

	// Build search body
	searchBody := c.buildSearchBody(req)

	// Determine index
	index := c.config.Index.DefaultIndex
	if req.Parameters != nil {
		if idx, ok := req.Parameters["index"].(string); ok {
			index = idx
		}
	}

	// Execute search
	searchURL := fmt.Sprintf("%s/%s/_search", c.baseURL, url.PathEscape(index))
	if c.config.Query.TrackTotalHits {
		searchURL += "?track_total_hits=true"
	}

	resp, err := c.doJSONRequest(ctx, "POST", searchURL, searchBody)
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed: %s - %s", resp.Status, string(body))
	}

	var searchResp SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	// Convert hits to results
	results := make([]map[string]interface{}, len(searchResp.Hits.Hits))
	for i, hit := range searchResp.Hits.Hits {
		result := hit.Source
		if result == nil {
			result = make(map[string]interface{})
		}
		result["_id"] = hit.ID
		result["_index"] = hit.Index
		if hit.Score != nil {
			result["_score"] = *hit.Score
		}
		results[i] = result
	}

	return &connector.QueryResult{
		ID:        req.ID,
		Status:    connector.QueryStatusCompleted,
		Language:  connector.QueryLanguageDSL,
		Results:   results,
		StartTime: startTime,
		EndTime:   time.Now(),
		Metadata: connector.QueryMetadata{
			TotalResults:    searchResp.Hits.Total.Value,
			ReturnedResults: len(results),
			ExecutionTime:   time.Duration(searchResp.Took) * time.Millisecond,
			SIEM:            connector.SIEMElastic,
		},
	}, nil
}

// buildSearchBody builds the search request body.
func (c *Client) buildSearchBody(req *connector.QueryRequest) map[string]interface{} {
	body := make(map[string]interface{})

	// Parse query based on language
	if req.Language == connector.QueryLanguageDSL || req.Language == "" {
		// Parse DSL query
		var query map[string]interface{}
		if err := json.Unmarshal([]byte(req.Query), &query); err == nil {
			// Check if query is already wrapped
			if _, ok := query["query"]; ok {
				body = query
			} else {
				body["query"] = query
			}
		} else {
			// Treat as query string
			body["query"] = map[string]interface{}{
				"query_string": map[string]interface{}{
					"query": req.Query,
				},
			}
		}
	} else if req.Language == connector.QueryLanguageEQL {
		body["query"] = req.Query
	}

	// Add time range filter
	if !req.TimeRange.Start.IsZero() || !req.TimeRange.End.IsZero() {
		timeFilter := make(map[string]interface{})
		if !req.TimeRange.Start.IsZero() {
			timeFilter["gte"] = req.TimeRange.Start.Format(time.RFC3339)
		}
		if !req.TimeRange.End.IsZero() {
			timeFilter["lte"] = req.TimeRange.End.Format(time.RFC3339)
		}

		// Wrap existing query in bool filter
		if existingQuery, ok := body["query"]; ok {
			body["query"] = map[string]interface{}{
				"bool": map[string]interface{}{
					"must": existingQuery,
					"filter": []map[string]interface{}{
						{"range": map[string]interface{}{"@timestamp": timeFilter}},
					},
				},
			}
		} else {
			body["query"] = map[string]interface{}{
				"range": map[string]interface{}{"@timestamp": timeFilter},
			}
		}
	}

	// Set size
	size := req.MaxResults
	if size == 0 {
		size = c.config.Query.DefaultSize
	}
	body["size"] = size

	// Set fields
	if len(req.Fields) > 0 {
		body["_source"] = req.Fields
	}

	// Set sort
	if len(req.SortBy) > 0 {
		sort := make([]map[string]interface{}, len(req.SortBy))
		for i, s := range req.SortBy {
			order := "desc"
			if s.Ascending {
				order = "asc"
			}
			sort[i] = map[string]interface{}{
				s.Field: map[string]interface{}{"order": order},
			}
		}
		body["sort"] = sort
	}

	return body
}

// AsyncQuery starts an asynchronous search (using async search API).
func (c *Client) AsyncQuery(ctx context.Context, req *connector.QueryRequest) (string, error) {
	// Build search body
	searchBody := c.buildSearchBody(req)

	// Determine index
	index := c.config.Index.DefaultIndex
	if req.Parameters != nil {
		if idx, ok := req.Parameters["index"].(string); ok {
			index = idx
		}
	}

	// Execute async search
	asyncURL := fmt.Sprintf("%s/%s/_async_search", c.baseURL, url.PathEscape(index))

	// Set wait time (return early if results ready)
	asyncURL += "?wait_for_completion_timeout=100ms"

	resp, err := c.doJSONRequest(ctx, "POST", asyncURL, searchBody)
	if err != nil {
		return "", fmt.Errorf("async search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("async search failed: %s - %s", resp.Status, string(body))
	}

	var asyncResp struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&asyncResp); err != nil {
		return "", fmt.Errorf("failed to parse async search response: %w", err)
	}

	return asyncResp.ID, nil
}

// GetQueryStatus gets the status of an async query.
func (c *Client) GetQueryStatus(ctx context.Context, queryID string) (*connector.QueryResult, error) {
	statusURL := fmt.Sprintf("%s/_async_search/%s", c.baseURL, url.PathEscape(queryID))

	resp, err := c.doRequest(ctx, "GET", statusURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("async search %s not found", queryID)
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get async search status: %s - %s", resp.Status, string(body))
	}

	var asyncResp struct {
		ID                 string         `json:"id"`
		IsRunning          bool           `json:"is_running"`
		IsPartial          bool           `json:"is_partial"`
		ExpirationTimeMs   int64          `json:"expiration_time_in_millis"`
		CompletionTimeMs   *int64         `json:"completion_time_in_millis"`
		Response           SearchResponse `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&asyncResp); err != nil {
		return nil, fmt.Errorf("failed to parse async search status: %w", err)
	}

	result := &connector.QueryResult{
		ID:       queryID,
		Language: connector.QueryLanguageDSL,
		Metadata: connector.QueryMetadata{
			SIEM: connector.SIEMElastic,
		},
	}

	if asyncResp.IsRunning {
		result.Status = connector.QueryStatusRunning
	} else {
		result.Status = connector.QueryStatusCompleted
		result.Metadata.TotalResults = asyncResp.Response.Hits.Total.Value
		result.Metadata.ExecutionTime = time.Duration(asyncResp.Response.Took) * time.Millisecond
		result.Metadata.ReturnedResults = len(asyncResp.Response.Hits.Hits)

		// Convert hits to results
		results := make([]map[string]interface{}, len(asyncResp.Response.Hits.Hits))
		for i, hit := range asyncResp.Response.Hits.Hits {
			result := hit.Source
			if result == nil {
				result = make(map[string]interface{})
			}
			result["_id"] = hit.ID
			result["_index"] = hit.Index
			results[i] = result
		}
		result.Results = results
	}

	return result, nil
}

// CancelQuery cancels a running async query.
func (c *Client) CancelQuery(ctx context.Context, queryID string) error {
	deleteURL := fmt.Sprintf("%s/_async_search/%s", c.baseURL, url.PathEscape(queryID))

	resp, err := c.doRequest(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cancel async search: %s - %s", resp.Status, string(body))
	}

	return nil
}

// Scroll performs a scroll search for large result sets.
func (c *Client) Scroll(ctx context.Context, index string, query map[string]interface{}, size int, handler func(hits []Hit) error) error {
	// Initial search with scroll
	searchURL := fmt.Sprintf("%s/%s/_search?scroll=%s",
		c.baseURL,
		url.PathEscape(index),
		c.config.Query.ScrollTimeout.String(),
	)

	body := map[string]interface{}{
		"size":  size,
		"query": query,
	}

	resp, err := c.doJSONRequest(ctx, "POST", searchURL, body)
	if err != nil {
		return err
	}

	var searchResp SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	scrollID := searchResp.ScrollID
	defer c.clearScroll(ctx, scrollID)

	// Process initial results
	if err := handler(searchResp.Hits.Hits); err != nil {
		return err
	}

	// Continue scrolling
	for len(searchResp.Hits.Hits) > 0 {
		scrollURL := fmt.Sprintf("%s/_search/scroll", c.baseURL)
		scrollBody := map[string]interface{}{
			"scroll":    c.config.Query.ScrollTimeout.String(),
			"scroll_id": scrollID,
		}

		resp, err := c.doJSONRequest(ctx, "POST", scrollURL, scrollBody)
		if err != nil {
			return err
		}

		if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		if len(searchResp.Hits.Hits) == 0 {
			break
		}

		if err := handler(searchResp.Hits.Hits); err != nil {
			return err
		}

		scrollID = searchResp.ScrollID
	}

	return nil
}

// clearScroll clears a scroll context.
func (c *Client) clearScroll(ctx context.Context, scrollID string) error {
	scrollURL := fmt.Sprintf("%s/_search/scroll", c.baseURL)

	body := map[string]interface{}{
		"scroll_id": scrollID,
	}

	data, _ := json.Marshal(body)
	resp, err := c.doRequest(ctx, "DELETE", scrollURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// EQLSearch performs an EQL (Event Query Language) search.
func (c *Client) EQLSearch(ctx context.Context, index, query string, size int) (*EQLResponse, error) {
	eqlURL := fmt.Sprintf("%s/%s/_eql/search", c.baseURL, url.PathEscape(index))

	body := map[string]interface{}{
		"query": query,
		"size":  size,
	}

	resp, err := c.doJSONRequest(ctx, "POST", eqlURL, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("EQL search failed: %s - %s", resp.Status, string(body))
	}

	var eqlResp EQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&eqlResp); err != nil {
		return nil, err
	}

	return &eqlResp, nil
}

// EQLResponse represents an EQL search response.
type EQLResponse struct {
	Took   int      `json:"took"`
	Hits   EQLHits  `json:"hits"`
}

// EQLHits holds EQL hits.
type EQLHits struct {
	Total    TotalHits       `json:"total"`
	Events   []EQLEvent      `json:"events,omitempty"`
	Sequences []EQLSequence  `json:"sequences,omitempty"`
}

// EQLEvent represents an EQL event.
type EQLEvent struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Source map[string]interface{} `json:"_source"`
}

// EQLSequence represents an EQL sequence.
type EQLSequence struct {
	JoinKeys []interface{} `json:"join_keys"`
	Events   []EQLEvent    `json:"events"`
}
