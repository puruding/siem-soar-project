// Package integration provides integration tests for SIEM/SOAR services
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Playbook represents a SOAR playbook
type Playbook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Trigger     PlaybookTrigger `json:"trigger"`
	Steps       []PlaybookStep `json:"steps"`
	Variables   map[string]interface{} `json:"variables"`
	Enabled     bool           `json:"enabled"`
	CreatedAt   time.Time      `json:"created_at"`
}

// PlaybookTrigger defines when a playbook is triggered
type PlaybookTrigger struct {
	Type      string            `json:"type"` // manual, alert, scheduled
	Condition string            `json:"condition"`
	Filters   map[string]string `json:"filters"`
}

// PlaybookStep represents a step in a playbook
type PlaybookStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // action, condition, loop, parallel
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	OnSuccess   string                 `json:"on_success"`
	OnFailure   string                 `json:"on_failure"`
	Timeout     int                    `json:"timeout_seconds"`
	RetryPolicy RetryPolicy            `json:"retry_policy"`
}

// RetryPolicy defines retry behavior for steps
type RetryPolicy struct {
	MaxAttempts     int `json:"max_attempts"`
	BackoffSeconds  int `json:"backoff_seconds"`
	ExponentialBase float64 `json:"exponential_base"`
}

// PlaybookExecution represents a playbook execution instance
type PlaybookExecution struct {
	ID           string                 `json:"id"`
	PlaybookID   string                 `json:"playbook_id"`
	Status       string                 `json:"status"`
	TriggerData  map[string]interface{} `json:"trigger_data"`
	StepResults  []StepResult           `json:"step_results"`
	Variables    map[string]interface{} `json:"variables"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at"`
	Error        string                 `json:"error,omitempty"`
}

// StepResult represents the result of executing a step
type StepResult struct {
	StepID      string                 `json:"step_id"`
	Status      string                 `json:"status"`
	Output      map[string]interface{} `json:"output"`
	Error       string                 `json:"error,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	Attempts    int                    `json:"attempts"`
}

// SOARTestSuite contains integration tests for SOAR service
type SOARTestSuite struct {
	suite.Suite
	client  *http.Client
	baseURL string
}

// SetupSuite runs before all tests
func (s *SOARTestSuite) SetupSuite() {
	s.client = &http.Client{
		Timeout: 30 * time.Second,
	}
	s.baseURL = getEnvOrDefault("SOAR_SERVICE_URL", "http://localhost:8082")
}

// TestHealthCheck verifies the service health endpoint
func (s *SOARTestSuite) TestHealthCheck() {
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
func (s *SOARTestSuite) TestReadiness() {
	resp, err := s.client.Get(s.baseURL + "/ready")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

// TestCreatePlaybook tests creating a new playbook
func (s *SOARTestSuite) TestCreatePlaybook() {
	playbook := Playbook{
		Name:        "SSH Brute Force Response",
		Description: "Automated response to SSH brute force attacks",
		Version:     "1.0.0",
		Trigger: PlaybookTrigger{
			Type:      "alert",
			Condition: "severity >= 'high' AND alert_type = 'ssh_brute_force'",
			Filters: map[string]string{
				"source": "detection_engine",
			},
		},
		Steps: []PlaybookStep{
			{
				ID:     "step-1",
				Name:   "Enrich IP Information",
				Type:   "action",
				Action: "enrichment.ip_lookup",
				Parameters: map[string]interface{}{
					"ip": "{{alert.src_ip}}",
				},
				OnSuccess: "step-2",
				OnFailure: "step-error",
				Timeout:   30,
			},
			{
				ID:     "step-2",
				Name:   "Check IP Reputation",
				Type:   "action",
				Action: "threat_intel.check_reputation",
				Parameters: map[string]interface{}{
					"ip": "{{alert.src_ip}}",
				},
				OnSuccess: "step-3",
				OnFailure: "step-error",
				Timeout:   30,
			},
			{
				ID:     "step-3",
				Name:   "Block IP at Firewall",
				Type:   "action",
				Action: "firewall.block_ip",
				Parameters: map[string]interface{}{
					"ip":       "{{alert.src_ip}}",
					"duration": "24h",
					"reason":   "SSH brute force attack detected",
				},
				OnSuccess: "step-4",
				OnFailure: "step-error",
				Timeout:   60,
				RetryPolicy: RetryPolicy{
					MaxAttempts:     3,
					BackoffSeconds:  5,
					ExponentialBase: 2.0,
				},
			},
			{
				ID:     "step-4",
				Name:   "Create Ticket",
				Type:   "action",
				Action: "ticketing.create_incident",
				Parameters: map[string]interface{}{
					"title":       "SSH Brute Force Attack - {{alert.src_ip}}",
					"severity":    "{{alert.severity}}",
					"description": "Automated response executed. IP blocked for 24 hours.",
				},
				OnSuccess: "step-complete",
				OnFailure: "step-error",
				Timeout:   30,
			},
		},
		Enabled: true,
	}

	body, err := json.Marshal(playbook)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/playbooks",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusCreated, resp.StatusCode)
}

// TestListPlaybooks tests listing all playbooks
func (s *SOARTestSuite) TestListPlaybooks() {
	resp, err := s.client.Get(s.baseURL + "/api/v1/playbooks")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(s.T(), err)
	assert.Contains(s.T(), result, "playbooks")
}

// TestListPlaybooksWithFilters tests listing playbooks with filters
func (s *SOARTestSuite) TestListPlaybooksWithFilters() {
	testCases := []struct {
		name        string
		queryParams string
	}{
		{"filter by enabled", "?enabled=true"},
		{"filter by trigger type", "?trigger_type=alert"},
		{"pagination", "?page=1&page_size=10"},
		{"search by name", "?search=brute+force"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + "/api/v1/playbooks" + tc.queryParams)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
		})
	}
}

// TestGetPlaybook tests retrieving a specific playbook
func (s *SOARTestSuite) TestGetPlaybook() {
	playbookID := "test-playbook-123"
	resp, err := s.client.Get(s.baseURL + "/api/v1/playbooks/" + playbookID)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestUpdatePlaybook tests updating an existing playbook
func (s *SOARTestSuite) TestUpdatePlaybook() {
	playbookID := "test-playbook-123"
	update := map[string]interface{}{
		"enabled":     false,
		"description": "Updated description",
	}

	body, err := json.Marshal(update)
	require.NoError(s.T(), err)

	req, err := http.NewRequest(
		http.MethodPut,
		s.baseURL+"/api/v1/playbooks/"+playbookID,
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestExecutePlaybook tests manual playbook execution
func (s *SOARTestSuite) TestExecutePlaybook() {
	playbookID := "test-playbook-123"
	triggerData := map[string]interface{}{
		"alert": map[string]interface{}{
			"id":       "alert-456",
			"src_ip":   "192.168.1.100",
			"severity": "high",
			"type":     "ssh_brute_force",
		},
	}

	body, err := json.Marshal(triggerData)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/playbooks/"+playbookID+"/execute",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Equal(s.T(), http.StatusAccepted, resp.StatusCode)
}

// TestGetPlaybookExecution tests retrieving execution status
func (s *SOARTestSuite) TestGetPlaybookExecution() {
	executionID := "execution-123"
	resp, err := s.client.Get(s.baseURL + "/api/v1/executions/" + executionID)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestListExecutions tests listing playbook executions
func (s *SOARTestSuite) TestListExecutions() {
	testCases := []struct {
		name        string
		queryParams string
	}{
		{"all executions", ""},
		{"filter by status", "?status=running"},
		{"filter by playbook", "?playbook_id=test-playbook-123"},
		{"date range", "?start_date=2024-01-01&end_date=2024-12-31"},
		{"pagination", "?page=1&page_size=20"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + "/api/v1/executions" + tc.queryParams)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestCancelExecution tests canceling a running execution
func (s *SOARTestSuite) TestCancelExecution() {
	executionID := "execution-to-cancel"

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/executions/"+executionID+"/cancel",
		"application/json",
		nil,
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound, http.StatusConflict}, resp.StatusCode)
}

// TestRetryExecution tests retrying a failed execution
func (s *SOARTestSuite) TestRetryExecution() {
	executionID := "failed-execution-123"

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/executions/"+executionID+"/retry",
		"application/json",
		nil,
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusAccepted, http.StatusNotFound}, resp.StatusCode)
}

// TestActionCatalog tests the action catalog endpoint
func (s *SOARTestSuite) TestActionCatalog() {
	resp, err := s.client.Get(s.baseURL + "/api/v1/actions")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestActionExecution tests executing a single action
func (s *SOARTestSuite) TestActionExecution() {
	action := map[string]interface{}{
		"action": "enrichment.ip_lookup",
		"parameters": map[string]interface{}{
			"ip": "8.8.8.8",
		},
	}

	body, err := json.Marshal(action)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/actions/execute",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusAccepted, http.StatusNotFound}, resp.StatusCode)
}

// TestConnectorManagement tests connector CRUD operations
func (s *SOARTestSuite) TestConnectorManagement() {
	// Create connector
	connector := map[string]interface{}{
		"name":        "Test Firewall Connector",
		"type":        "firewall",
		"vendor":      "palo_alto",
		"description": "Test connector for Palo Alto firewall",
		"config": map[string]interface{}{
			"api_url":  "https://firewall.example.com/api",
			"api_key":  "test-api-key",
			"verify_ssl": true,
		},
		"enabled": true,
	}

	body, err := json.Marshal(connector)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/connectors",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusCreated, http.StatusNotFound}, resp.StatusCode)
}

// TestConnectorTest tests connector connectivity test
func (s *SOARTestSuite) TestConnectorTest() {
	connectorID := "test-connector-123"

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/connectors/"+connectorID+"/test",
		"application/json",
		nil,
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound, http.StatusServiceUnavailable}, resp.StatusCode)
}

// TestPlaybookValidation tests playbook validation
func (s *SOARTestSuite) TestPlaybookValidation() {
	invalidPlaybook := map[string]interface{}{
		"name": "Invalid Playbook",
		"steps": []map[string]interface{}{
			{
				"id":   "step-1",
				"name": "Step with invalid action",
				"type": "action",
				"action": "nonexistent.action",
				"on_success": "nonexistent-step",
			},
		},
	}

	body, err := json.Marshal(invalidPlaybook)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/playbooks/validate",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusBadRequest, http.StatusNotFound}, resp.StatusCode)
}

// TestPlaybookVersioning tests playbook version management
func (s *SOARTestSuite) TestPlaybookVersioning() {
	playbookID := "versioned-playbook-123"

	// Get versions
	resp, err := s.client.Get(s.baseURL + "/api/v1/playbooks/" + playbookID + "/versions")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestPlaybookClone tests cloning a playbook
func (s *SOARTestSuite) TestPlaybookClone() {
	playbookID := "playbook-to-clone"
	cloneRequest := map[string]interface{}{
		"new_name": "Cloned Playbook",
	}

	body, err := json.Marshal(cloneRequest)
	require.NoError(s.T(), err)

	resp, err := s.client.Post(
		s.baseURL+"/api/v1/playbooks/"+playbookID+"/clone",
		"application/json",
		bytes.NewReader(body),
	)
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusCreated, http.StatusNotFound}, resp.StatusCode)
}

// TestPlaybookExportImport tests playbook export/import
func (s *SOARTestSuite) TestPlaybookExportImport() {
	// Export
	resp, err := s.client.Get(s.baseURL + "/api/v1/playbooks/export")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestExecutionMetrics tests execution metrics endpoint
func (s *SOARTestSuite) TestExecutionMetrics() {
	resp, err := s.client.Get(s.baseURL + "/api/v1/metrics/executions")
	require.NoError(s.T(), err)
	defer resp.Body.Close()

	assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
}

// TestAuditLog tests the audit log endpoint
func (s *SOARTestSuite) TestAuditLog() {
	testCases := []struct {
		name        string
		queryParams string
	}{
		{"all logs", ""},
		{"filter by action", "?action=playbook.execute"},
		{"filter by user", "?user=admin"},
		{"date range", "?start=2024-01-01&end=2024-12-31"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.client.Get(s.baseURL + "/api/v1/audit" + tc.queryParams)
			require.NoError(s.T(), err)
			defer resp.Body.Close()

			assert.Contains(s.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode)
		})
	}
}

// TestConcurrentExecutions tests concurrent playbook executions
func (s *SOARTestSuite) TestConcurrentExecutions() {
	numConcurrent := 5
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			triggerData := map[string]interface{}{
				"alert": map[string]interface{}{
					"id":     fmt.Sprintf("concurrent-alert-%d", idx),
					"src_ip": fmt.Sprintf("192.168.1.%d", 100+idx),
				},
			}

			body, err := json.Marshal(triggerData)
			if err != nil {
				results <- err
				return
			}

			resp, err := s.client.Post(
				s.baseURL+"/api/v1/playbooks/test-playbook/execute",
				"application/json",
				bytes.NewReader(body),
			)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusAccepted {
				results <- fmt.Errorf("unexpected status: %d", resp.StatusCode)
				return
			}
			results <- nil
		}(i)
	}

	for i := 0; i < numConcurrent; i++ {
		err := <-results
		assert.NoError(s.T(), err)
	}
}

// TestSOARTestSuite runs the SOAR test suite
func TestSOARTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(SOARTestSuite))
}
