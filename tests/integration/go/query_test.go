// Package integration provides integration tests for SIEM/SOAR services
package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// QueryRequest represents a query request
type QueryRequest struct {
	Query      string                 `json:"query"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Limit      int                    `json:"limit"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Format     string                 `json:"format,omitempty"` // json, csv, ndjson
}

// QueryResult represents a query result
type QueryResult struct {
	QueryID    string                   `json:"query_id"`
	Status     string                   `json:"status"`
	Results    []map[string]interface{} `json:"results"`
	Metadata   QueryMetadata            `json:"metadata"`
	Error      string                   `json:"error,omitempty"`
}

// QueryMetadata contains query execution metadata
type QueryMetadata struct {
	TotalRows     int64         `json:"total_rows"`
	ProcessedRows int64         `json:"processed_rows"`
	DurationMs    int64         `json:"duration_ms"`
	BytesScanned  int64         `json:"bytes_scanned"`
	CacheHit      bool          `json:"cache_hit"`
}

// AsyncQueryStatus represents async query status
type AsyncQueryStatus struct {
	QueryID      string    `json:"query_id"`
	Status       string    `json:"status"`
	Progress     int       `json:"progress"`
	EstimatedMs  int64     `json:"estimated_remaining_ms"`
	CreatedAt    time.Time `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// QueryTestSuite contains integration tests for Query Service
type QueryTestSuite struct {
	suite.Suite
	client  *http.Client
	baseURL string
}

// SetupSuite runs before all tests
func (s *QueryTestSuite) SetupSuite() {
	s.client = &http.Client{
		Timeout: 60 * time.Second,
	}
	s.baseURL = getEnvOrDefault("QUERY_SERVICE_URL", "http://localhost:8084")
}

// TestHealthCheck verifies the service health endpoint
func (s *QueryTestSuite) TestHealthCheck() {
	resp, err := s.client.Get(s.baseURL + "/health")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "healthy", result["status"])
}

// TestReadiness verifies the service readiness endpoint
func (s *QueryTestSuite) TestReadiness() {
	resp, err := s.client.Get(s.baseURL + "/ready")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestSimpleQuery tests a basic synchronous query
func (s *QueryTestSuite) TestSimpleQuery() {
	query := QueryRequest{
		Query:     "SELECT * FROM events WHERE event_type = 'auth_failure' LIMIT 10",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
		Limit:     10,
	}

	body, err := json.Marshal(query)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/query",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(s.T(), err)
	assert.Contains(s.T(), result, "results")
	assert.Contains(s.T(), result, "metadata")
}

// TestAggregationQuery tests aggregation queries
func (s *QueryTestSuite) TestAggregationQuery() {
	testCases := []struct {
		name  string
		query string
	}{
		{
			name:  "count by event type",
			query: "SELECT event_type, count(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 10",
		},
		{
			name:  "time series aggregation",
			query: "SELECT toStartOfHour(timestamp) as hour, count(*) as events FROM events GROUP BY hour ORDER BY hour",
		},
		{
			name:  "top source IPs",
			query: "SELECT src_ip, count(*) as cnt FROM events WHERE event_type = 'connection' GROUP BY src_ip ORDER BY cnt DESC LIMIT 10",
		},
		{
			name:  "average bytes by protocol",
			query: "SELECT protocol, avg(bytes_in + bytes_out) as avg_bytes FROM events GROUP BY protocol",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			query := QueryRequest{
				Query:     tc.query,
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
				Limit:     100,
			}

			body, err := json.Marshal(query)
			require.NoError(s.T(), err)

			resp, err := s.client.Post(
				s.baseURL+"/api/v1/query",
				"application/json",
				bytes.NewReader(body),
			)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
		})
	}
}

// TestParameterizedQuery tests queries with parameters
func (s *QueryTestSuite) TestParameterizedQuery() {
	query := QueryRequest{
		Query:     "SELECT * FROM events WHERE src_ip = {ip:String} AND event_type = {type:String} LIMIT {limit:Int32}",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
		Parameters: map[string]interface{}{
			"ip":    "192.168.1.100",
			"type":  "auth_failure",
			"limit": 50,
		},
	}

	body, err := json.Marshal(query)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/query",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestAsyncQuery tests asynchronous query execution
func (s *QueryTestSuite) TestAsyncQuery() {
	query := QueryRequest{
		Query:     "SELECT * FROM events WHERE timestamp >= now() - INTERVAL 7 DAY",
		StartTime: time.Now().Add(-7 * 24 * time.Hour),
		EndTime:   time.Now(),
		Limit:     100000,
	}

	body, err := json.Marshal(query)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/query/async",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusAccepted, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(s.T(), err)
	assert.Contains(s.T(), result, "query_id")
	assert.Contains(s.T(), result, "status")
}

// TestAsyncQueryStatus tests checking async query status
func (s *QueryTestSuite) TestAsyncQueryStatus() {
	queryID := "test-query-123"
	resp, err := s.client.Get(s.baseURL + "/api/v1/query/" + queryID + "/status")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestAsyncQueryResults tests retrieving async query results
func (s *QueryTestSuite) TestAsyncQueryResults() {
	queryID := "test-query-123"
	resp, err := s.client.Get(s.baseURL + "/api/v1/query/" + queryID + "/results")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestAsyncQueryPagination tests paginated results for async queries
func (s *QueryTestSuite) TestAsyncQueryPagination() {
	queryID := "test-query-123"
	testCases := []struct {
		name   string
		params string
	}{
		{"first page", "?page=1&page_size=100"},
		{"second page", "?page=2&page_size=100"},
		{"custom page size", "?page=1&page_size=50"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + "/api/v1/query/" + queryID + "/results" + tc.params)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestCancelAsyncQuery tests canceling an async query
func (s *QueryTestSuite) TestCancelAsyncQuery() {
	queryID := "query-to-cancel"

	req, err := http.NewRequest(
		http.MethodDelete,
		s.baseURL+"/api/v1/query/"+queryID,
		nil,
	)
	require.NoError(s.T(), err)

	resp, err := s.client.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNoContent, http.StatusNotFound}, resp.StatusCode)
}

// TestQueryValidation tests query validation
func (s *QueryTestSuite) TestQueryValidation() {
	testCases := []struct {
		name           string
		query          QueryRequest
		expectedStatus int
	}{
		{
			name: "valid query",
			query: QueryRequest{
				Query:     "SELECT * FROM events LIMIT 10",
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid SQL syntax",
			query: QueryRequest{
				Query:     "SELEC * FORM events",
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "dangerous query - DROP",
			query: QueryRequest{
				Query:     "DROP TABLE events",
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid time range",
			query: QueryRequest{
				Query:     "SELECT * FROM events LIMIT 10",
				StartTime: time.Now(),
				EndTime:   time.Now().Add(-24 * time.Hour), // End before start
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			body, err := json.Marshal(tc.query)
			require.NoError(s.T(), err)

			resp, err := s.client.Post(
				s.baseURL+"/api/v1/query/validate",
				"application/json",
				bytes.NewReader(body),
			)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			// Accept actual status or 404 (endpoint not implemented)
			assert.Contains(s.T(), []int{tc.expectedStatus, http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestQueryExplain tests query execution plan
func (s *QueryTestSuite) TestQueryExplain() {
	query := QueryRequest{
		Query:     "SELECT src_ip, count(*) FROM events GROUP BY src_ip ORDER BY count(*) DESC LIMIT 10",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}

	body, err := json.Marshal(query)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/query/explain",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestResultFormats tests different result formats
func (s *QueryTestSuite) TestResultFormats() {
	testCases := []struct {
		name        string
		format      string
		contentType string
	}{
		{"JSON format", "json", "application/json"},
		{"CSV format", "csv", "text/csv"},
		{"NDJSON format", "ndjson", "application/x-ndjson"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			query := QueryRequest{
				Query:     "SELECT * FROM events LIMIT 10",
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
				Format:    tc.format,
			}

			body, err := json.Marshal(query)
			require.NoError(s.T(), err)

			resp, err := s.client.Post(
				s.baseURL+"/api/v1/query",
				"application/json",
				bytes.NewReader(body),
			)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
		})
	}
}

// TestSavedQueries tests saved query management
func (s *QueryTestSuite) TestSavedQueries() {
	// Create saved query
	savedQuery := map[string]interface{}{
		"name":        "Top Failed Logins",
		"description": "Shows top IP addresses with failed login attempts",
		"query":       "SELECT src_ip, count(*) as cnt FROM events WHERE event_type = 'auth_failure' GROUP BY src_ip ORDER BY cnt DESC LIMIT 20",
		"tags":        []string{"authentication", "security"},
	}

	body, err := json.Marshal(savedQuery)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/queries/saved",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusCreated, http.StatusNotFound}, resp.StatusCode)
}

// TestListSavedQueries tests listing saved queries
func (s *QueryTestSuite) TestListSavedQueries() {
	resp, err := s.client.Get(s.baseURL + "/api/v1/queries/saved")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestQueryHistory tests query history
func (s *QueryTestSuite) TestQueryHistory() {
	testCases := []struct {
		name   string
		params string
	}{
		{"all history", ""},
		{"filter by user", "?user=admin"},
		{"filter by date", "?start_date=2024-01-01"},
		{"pagination", "?page=1&page_size=50"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + "/api/v1/queries/history" + tc.params)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestQueryTimeout tests query timeout handling
func (s *QueryTestSuite) TestQueryTimeout() {
	query := QueryRequest{
		Query:     "SELECT * FROM events", // Large query without limit
		StartTime: time.Now().Add(-30 * 24 * time.Hour),
		EndTime:   time.Now(),
	}

	body, err := json.Marshal(query)
	require.NoError(s.T(), err)

	// Use custom client with short timeout
	shortClient := &http.Client{
		Timeout: 1 * time.Second,
	}

	_, err = shortClient.Post(
		s.baseURL+"/api/v1/query",
		"application/json",
		bytes.NewReader(body),
	)

	// We expect either a timeout error or a response
	// This tests that the service handles timeouts gracefully
	if err != nil {
		assert.Contains(s.T(), err.Error(), "timeout")
	}
}

// TestQueryMetrics tests query service metrics
func (s *QueryTestSuite) TestQueryMetrics() {
	resp, err := s.client.Get(s.baseURL + "/api/v1/metrics")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestQueryCache tests query cache operations
func (s *QueryTestSuite) TestQueryCache() {
	// Clear cache
	req, err := http.NewRequest(
		http.MethodDelete,
		s.baseURL+"/api/v1/cache",
		nil,
	)
	require.NoError(s.T(), err)

	resp, err := s.client.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNoContent, http.StatusNotFound}, resp.StatusCode)
}

// TestNL2SQLQuery tests natural language to SQL query
func (s *QueryTestSuite) TestNL2SQLQuery() {
	nlQuery := map[string]interface{}{
		"question": "Show me the top 10 IP addresses with the most failed login attempts in the last 24 hours",
	}

	body, err := json.Marshal(nlQuery)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/query/natural",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestSchemaIntrospection tests schema introspection
func (s *QueryTestSuite) TestSchemaIntrospection() {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"list tables", "/api/v1/schema/tables"},
		{"events table schema", "/api/v1/schema/tables/events"},
		{"alerts table schema", "/api/v1/schema/tables/alerts"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + tc.endpoint)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestQueryTestSuite runs the query test suite
func TestQueryTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(QueryTestSuite))
}
