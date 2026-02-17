package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Playbook represents a simplified playbook for API
type Playbook struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`    // enrichment, containment, notification, remediation
	TriggerType string `json:"trigger_type"` // manual, automatic
	Enabled     bool   `json:"enabled"`
}

// PlaybookExecution represents a playbook execution instance
type PlaybookExecution struct {
	ID          string     `json:"id"`
	PlaybookID  string     `json:"playbook_id"`
	PlaybookName string    `json:"playbook_name"`
	AlertID     string     `json:"alert_id"`
	Status      string     `json:"status"` // pending, running, completed, failed
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Default playbooks
var defaultPlaybooks = []Playbook{
	{
		ID:          "PB-001",
		Name:        "IP Reputation Check",
		Description: "Check IP against threat intelligence sources (VirusTotal, AbuseIPDB, etc.)",
		Category:    "enrichment",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-002",
		Name:        "Block IP on Firewall",
		Description: "Block malicious IP address on perimeter firewall",
		Category:    "containment",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-003",
		Name:        "Isolate Endpoint",
		Description: "Isolate compromised endpoint from network via EDR",
		Category:    "containment",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-004",
		Name:        "Send Slack Alert",
		Description: "Notify security team via Slack channel",
		Category:    "notification",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-005",
		Name:        "Create Jira Ticket",
		Description: "Create incident ticket in Jira for tracking",
		Category:    "notification",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-006",
		Name:        "Disable User Account",
		Description: "Disable compromised user account in Active Directory",
		Category:    "remediation",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-007",
		Name:        "Hash Lookup",
		Description: "Check file hash against malware databases",
		Category:    "enrichment",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-008",
		Name:        "Domain Reputation Check",
		Description: "Analyze domain against threat intelligence",
		Category:    "enrichment",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-009",
		Name:        "Reset User Password",
		Description: "Force password reset for compromised account",
		Category:    "remediation",
		TriggerType: "manual",
		Enabled:     true,
	},
	{
		ID:          "PB-010",
		Name:        "Send Email Notification",
		Description: "Send alert notification via email to stakeholders",
		Category:    "notification",
		TriggerType: "manual",
		Enabled:     true,
	},
}

// In-memory execution store
var (
	executionStore   = make([]PlaybookExecution, 0)
	executionStoreMu sync.RWMutex
	executionCounter = 0
)

// ListPlaybooksHandler returns available playbooks
func ListPlaybooksHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Filter by category if specified
	category := r.URL.Query().Get("category")

	playbooks := make([]Playbook, 0)
	for _, pb := range defaultPlaybooks {
		if category == "" || pb.Category == category {
			if pb.Enabled {
				playbooks = append(playbooks, pb)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"playbooks": playbooks,
			"total":     len(playbooks),
		},
	})
}

// GetPlaybookHandler returns a single playbook by ID
func GetPlaybookHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract playbook ID from path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	playbookID := parts[4]

	for _, pb := range defaultPlaybooks {
		if pb.ID == playbookID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":  true,
				"playbook": pb,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Playbook not found",
	})
}

// ExecutePlaybookRequest represents the request body for playbook execution
type ExecutePlaybookRequest struct {
	AlertID string `json:"alert_id"`
}

// ExecutePlaybookHandler executes a playbook
func ExecutePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract playbook ID from path: /api/v1/playbooks/run/{id}
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	playbookID := parts[5]

	// Find playbook
	var playbook *Playbook
	for _, pb := range defaultPlaybooks {
		if pb.ID == playbookID {
			playbook = &pb
			break
		}
	}

	if playbook == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Playbook not found",
		})
		return
	}

	if !playbook.Enabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Playbook is disabled",
		})
		return
	}

	var req ExecutePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for testing
		req.AlertID = ""
	}

	executionStoreMu.Lock()
	executionCounter++
	executionID := fmt.Sprintf("EXEC-%d-%03d", time.Now().Unix(), executionCounter)

	now := time.Now()
	execution := PlaybookExecution{
		ID:           executionID,
		PlaybookID:   playbook.ID,
		PlaybookName: playbook.Name,
		AlertID:      req.AlertID,
		Status:       "running",
		StartedAt:    now,
	}

	// Prepend to store
	executionStore = append([]PlaybookExecution{execution}, executionStore...)

	// Keep max 1000 executions
	if len(executionStore) > 1000 {
		executionStore = executionStore[:1000]
	}
	executionStoreMu.Unlock()

	// Simulate async execution - in real implementation this would be sent to Temporal
	go func() {
		// Simulate execution time (1-3 seconds)
		time.Sleep(time.Duration(1+time.Now().UnixNano()%3) * time.Second)

		executionStoreMu.Lock()
		defer executionStoreMu.Unlock()

		for i := range executionStore {
			if executionStore[i].ID == executionID {
				completedAt := time.Now()
				executionStore[i].Status = "completed"
				executionStore[i].CompletedAt = &completedAt
				break
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"execution": execution,
	})
}

// GetExecutionStatusHandler returns playbook execution status
func GetExecutionStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract execution ID from path: /api/v1/executions/{id}
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	executionID := parts[4]

	executionStoreMu.RLock()
	defer executionStoreMu.RUnlock()

	for _, exec := range executionStore {
		if exec.ID == executionID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":   true,
				"execution": exec,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Execution not found",
	})
}

// ListExecutionsHandler returns list of recent executions
func ListExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	executionStoreMu.RLock()
	defer executionStoreMu.RUnlock()

	// Filter by alert_id if specified
	alertID := r.URL.Query().Get("alert_id")

	executions := make([]PlaybookExecution, 0)
	for _, exec := range executionStore {
		if alertID == "" || exec.AlertID == alertID {
			executions = append(executions, exec)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"executions": executions,
		"total":      len(executions),
	})
}
