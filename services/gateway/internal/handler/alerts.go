package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Alert represents a security alert
type Alert struct {
	ID              string                 `json:"id"`
	AlertID         string                 `json:"alert_id"`
	EventID         string                 `json:"event_id"`
	TenantID        string                 `json:"tenant_id"`
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	Status          string                 `json:"status"`
	Source          string                 `json:"source"`
	SourceType      string                 `json:"source_type"`
	Target          string                 `json:"target"`
	Timestamp       time.Time              `json:"timestamp"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Fields          map[string]interface{} `json:"fields"`
	MatchedFields   map[string]interface{} `json:"matched_fields"`
	RawLog          string                 `json:"raw_log"`
	MITRETactics    []string               `json:"mitre_tactics"`
	MITRETechniques []string               `json:"mitre_techniques"`
}

// In-memory alert store (for demo - in production use ClickHouse/PostgreSQL)
var (
	alertStore   = make([]Alert, 0)
	alertStoreMu sync.RWMutex
	alertCounter = 1000 // Start from ALERT-1001
)

// ValidAlertStatuses defines allowed status transitions
var ValidAlertStatuses = map[string]bool{
	"new":           true,
	"acknowledged":  true,
	"investigating": true,
	"resolved":      true,
	"closed":        true,
}

// AlertComment represents a comment on an alert
type AlertComment struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// In-memory comment store
var (
	commentStore   = make(map[string][]AlertComment) // alertID -> comments
	commentStoreMu sync.RWMutex
	commentCounter = 0
)

// ListAlertsHandler returns list of alerts
func ListAlertsHandler(w http.ResponseWriter, r *http.Request) {
	alertStoreMu.RLock()
	defer alertStoreMu.RUnlock()

	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alertStore,
		"total":  len(alertStore),
	})
}

// CreateAlertHandler receives alerts from detection service
func CreateAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var alert Alert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	alertStoreMu.Lock()
	// Auto-generate ID if not provided
	if alert.ID == "" && alert.AlertID == "" {
		alertCounter++
		alert.ID = fmt.Sprintf("ALERT-%d", alertCounter)
		alert.AlertID = alert.ID
	} else if alert.ID == "" {
		alert.ID = alert.AlertID
	}

	// Set defaults
	if alert.Status == "" {
		alert.Status = "new"
	}
	if alert.Title == "" {
		alert.Title = alert.RuleName
	}
	if alert.Source == "" {
		alert.Source = "Detection"
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}
	alert.UpdatedAt = time.Now()

	// Generate sample fields if not provided (for demo/testing)
	if alert.Fields == nil {
		alert.Fields = generateSampleFields(alert)
	}
	if alert.MatchedFields == nil {
		alert.MatchedFields = generateMatchedFields(alert)
	}
	if alert.RawLog == "" {
		alert.RawLog = generateSampleRawLog(alert)
	}
	// Generate MITRE ATT&CK mapping if not provided
	if len(alert.MITRETactics) == 0 || len(alert.MITRETechniques) == 0 {
		tactics, techniques := generateMITREMapping(alert)
		if len(alert.MITRETactics) == 0 {
			alert.MITRETactics = tactics
		}
		if len(alert.MITRETechniques) == 0 {
			alert.MITRETechniques = techniques
		}
	}

	alertStore = append([]Alert{alert}, alertStore...) // prepend (newest first)
	if len(alertStore) > 1000 {
		alertStore = alertStore[:1000] // keep last 1000
	}
	alertStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(alert)
}

// GetAlertHandler returns a single alert by ID
func GetAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	alertStoreMu.RLock()
	defer alertStoreMu.RUnlock()

	for _, alert := range alertStore {
		if alert.ID == alertID || alert.AlertID == alertID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"alert":   alert,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Alert not found",
	})
}

// UpdateAlertStatusRequest represents the request body for status update
type UpdateAlertStatusRequest struct {
	Status string `json:"status"`
}

// UpdateAlertStatusHandler updates an alert's status
func UpdateAlertStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/status
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	var req UpdateAlertStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate status
	if !ValidAlertStatuses[req.Status] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid status. Must be one of: new, acknowledged, investigating, resolved, closed",
		})
		return
	}

	alertStoreMu.Lock()
	defer alertStoreMu.Unlock()

	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			alertStore[i].Status = req.Status
			alertStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"alert":   alertStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Alert not found",
	})
}

// AcknowledgeAlertHandler marks an alert as acknowledged
func AcknowledgeAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/acknowledge
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	alertStoreMu.Lock()
	defer alertStoreMu.Unlock()

	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			alertStore[i].Status = "acknowledged"
			alertStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    alertStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   map[string]string{"message": "Alert not found"},
	})
}

// CloseAlertHandler marks an alert as closed
func CloseAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/close
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	// Optional: parse close reason from body
	var closeReq struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&closeReq)

	alertStoreMu.Lock()
	defer alertStoreMu.Unlock()

	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			alertStore[i].Status = "closed"
			alertStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    alertStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   map[string]string{"message": "Alert not found"},
	})
}

// CreateCaseFromAlertHandler creates a case from an alert
func CreateCaseFromAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/create-case
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	// Optional: parse case title from body
	var caseReq struct {
		Title string `json:"title"`
	}
	json.NewDecoder(r.Body).Decode(&caseReq)

	alertStoreMu.RLock()
	var sourceAlert *Alert
	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			sourceAlert = &alertStore[i]
			break
		}
	}
	alertStoreMu.RUnlock()

	if sourceAlert == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Alert not found",
		})
		return
	}

	// Create case from alert
	caseTitle := caseReq.Title
	if caseTitle == "" {
		caseTitle = "Case: " + sourceAlert.Title
	}

	newCase := Case{
		ID:          "case-" + alertID,
		Title:       caseTitle,
		Description: sourceAlert.Description,
		Status:      "open",
		Priority:    severityToPriority(sourceAlert.Severity),
		AlertIDs:    []string{alertID},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	caseStoreMu.Lock()
	caseStore = append([]Case{newCase}, caseStore...)
	caseStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"caseId": newCase.ID,
			"case":   newCase,
		},
	})
}

// RunPlaybookOnAlertHandler runs a playbook on an alert
func RunPlaybookOnAlertHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/run-playbook
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	// Parse playbook ID from body (accept both camelCase and snake_case)
	var req struct {
		PlaybookID  string `json:"playbookId"`
		PlaybookID2 string `json:"playbook_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	// Accept either camelCase or snake_case
	playbookID := req.PlaybookID
	if playbookID == "" {
		playbookID = req.PlaybookID2
	}
	if playbookID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "playbookId is required",
		})
		return
	}

	// Verify alert exists
	alertStoreMu.RLock()
	var alertFound bool
	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			alertFound = true
			break
		}
	}
	alertStoreMu.RUnlock()

	if !alertFound {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Alert not found",
		})
		return
	}

	// Create execution record
	executionID := "exec-" + alertID + "-" + playbookID
	execution := PlaybookExecution{
		ID:         executionID,
		PlaybookID: playbookID,
		AlertID:    alertID,
		Status:     "running",
		StartedAt:  time.Now(),
	}

	executionStoreMu.Lock()
	executionStore = append([]PlaybookExecution{execution}, executionStore...)
	executionStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"executionId": execution.ID,
			"execution":   execution,
		},
	})
}

// severityToPriority converts alert severity to case priority
func severityToPriority(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// GetRelatedAlertsHandler returns alerts related to the specified alert
func GetRelatedAlertsHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/related
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	alertStoreMu.RLock()
	defer alertStoreMu.RUnlock()

	// Find the source alert
	var sourceAlert *Alert
	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			sourceAlert = &alertStore[i]
			break
		}
	}

	if sourceAlert == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Alert not found",
		})
		return
	}

	// Find related alerts by:
	// 1. Same rule_id
	// 2. Same source_type
	// 3. Overlapping MITRE techniques
	// 4. Same target
	relatedAlerts := make([]map[string]interface{}, 0)
	maxRelated := 10

	for _, alert := range alertStore {
		// Skip the source alert itself
		if alert.ID == sourceAlert.ID || alert.AlertID == sourceAlert.AlertID {
			continue
		}

		isRelated := false

		// Check rule_id match
		if sourceAlert.RuleID != "" && alert.RuleID == sourceAlert.RuleID {
			isRelated = true
		}

		// Check source_type match
		if sourceAlert.SourceType != "" && alert.SourceType == sourceAlert.SourceType {
			isRelated = true
		}

		// Check overlapping MITRE techniques
		if len(sourceAlert.MITRETechniques) > 0 && len(alert.MITRETechniques) > 0 {
			for _, t1 := range sourceAlert.MITRETechniques {
				for _, t2 := range alert.MITRETechniques {
					if t1 == t2 {
						isRelated = true
						break
					}
				}
				if isRelated {
					break
				}
			}
		}

		// Check target match
		if sourceAlert.Target != "" && alert.Target == sourceAlert.Target {
			isRelated = true
		}

		if isRelated {
			relatedAlerts = append(relatedAlerts, map[string]interface{}{
				"id":        alert.ID,
				"title":     alert.Title,
				"severity":  alert.Severity,
				"status":    alert.Status,
				"timestamp": alert.Timestamp,
			})

			if len(relatedAlerts) >= maxRelated {
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"alerts": relatedAlerts,
			"total":  len(relatedAlerts),
		},
	})
}

// GetAlertCommentsHandler returns comments for an alert
func GetAlertCommentsHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/comments
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	commentStoreMu.RLock()
	comments, exists := commentStore[alertID]
	commentStoreMu.RUnlock()

	if !exists {
		comments = []AlertComment{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"comments": comments,
			"total":    len(comments),
		},
	})
}

// AddAlertCommentRequest represents the request body for adding a comment
type AddAlertCommentRequest struct {
	Author  string `json:"author"`
	Content string `json:"content"`
}

// AddAlertCommentHandler adds a comment to an alert
func AddAlertCommentHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/comments
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	// Verify alert exists
	alertStoreMu.RLock()
	var alertExists bool
	for _, alert := range alertStore {
		if alert.ID == alertID || alert.AlertID == alertID {
			alertExists = true
			break
		}
	}
	alertStoreMu.RUnlock()

	if !alertExists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Alert not found",
		})
		return
	}

	var req AddAlertCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	// Validate content
	if req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Comment content is required",
		})
		return
	}

	// Default author if not provided
	if req.Author == "" {
		req.Author = "SOC Analyst"
	}

	commentStoreMu.Lock()
	commentCounter++
	comment := AlertComment{
		ID:        fmt.Sprintf("CMT-%d", commentCounter),
		AlertID:   alertID,
		Author:    req.Author,
		Content:   req.Content,
		CreatedAt: time.Now(),
	}

	if _, exists := commentStore[alertID]; !exists {
		commentStore[alertID] = []AlertComment{}
	}
	commentStore[alertID] = append(commentStore[alertID], comment)
	commentStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"comment": comment,
		},
	})
}

// generateSampleFields creates sample extracted fields based on alert context
func generateSampleFields(alert Alert) map[string]interface{} {
	fields := make(map[string]interface{})

	// Base fields from alert data
	fields["alert_id"] = alert.ID
	fields["rule_id"] = alert.RuleID
	fields["timestamp"] = alert.Timestamp.Format(time.RFC3339)

	// Add target-related fields
	if alert.Target != "" {
		// Check if target looks like an IP address
		if strings.Contains(alert.Target, ".") && !strings.Contains(alert.Target, "@") {
			fields["source_ip"] = alert.Target
			fields["dest_ip"] = "10.0.0.1"
		} else {
			fields["user"] = alert.Target
			fields["source_ip"] = "192.168.1." + fmt.Sprintf("%d", 10+len(alert.Target)%240)
		}
	}

	// Add source-type specific fields
	switch strings.ToLower(alert.SourceType) {
	case "endpoint", "edr":
		fields["hostname"] = "ws-prod-" + fmt.Sprintf("%02d", 1+len(alert.ID)%10)
		fields["process_name"] = "suspicious_process.exe"
		fields["process_id"] = 4532 + len(alert.ID)%1000
		fields["parent_process"] = "explorer.exe"
		fields["file_path"] = "C:\\Users\\admin\\AppData\\Local\\Temp\\malware.exe"
		fields["file_hash"] = "a1b2c3d4e5f6" + fmt.Sprintf("%012d", len(alert.ID)*12345)
		fields["command_line"] = "cmd.exe /c powershell -enc SGVsbG8gV29ybGQ="
	case "network", "ndr", "ids":
		fields["src_port"] = 49152 + len(alert.ID)%1000
		fields["dst_port"] = 443
		fields["protocol"] = "TCP"
		fields["bytes_sent"] = 1024 + len(alert.ID)*100
		fields["bytes_received"] = 2048 + len(alert.ID)*200
		fields["connection_state"] = "established"
	case "firewall":
		fields["action"] = "blocked"
		fields["src_port"] = 55123
		fields["dst_port"] = 22
		fields["protocol"] = "TCP"
		fields["rule_name"] = alert.RuleName
	case "authentication", "iam":
		fields["auth_method"] = "password"
		fields["auth_result"] = "failure"
		fields["failure_reason"] = "invalid_credentials"
		fields["login_attempts"] = 5
		fields["account_locked"] = false
	default:
		fields["event_type"] = "security_alert"
		fields["category"] = alert.SourceType
	}

	// Add severity-based fields
	switch strings.ToLower(alert.Severity) {
	case "critical":
		fields["risk_score"] = 95
		fields["confidence"] = 0.98
	case "high":
		fields["risk_score"] = 75
		fields["confidence"] = 0.85
	case "medium":
		fields["risk_score"] = 50
		fields["confidence"] = 0.70
	default:
		fields["risk_score"] = 25
		fields["confidence"] = 0.60
	}

	return fields
}

// generateMatchedFields creates sample matched fields that triggered the alert
func generateMatchedFields(alert Alert) map[string]interface{} {
	matched := make(map[string]interface{})

	// Fields that matched the detection rule
	if alert.Target != "" {
		if strings.Contains(alert.Target, ".") {
			matched["ip_address"] = alert.Target
		} else {
			matched["username"] = alert.Target
		}
	}

	// Add rule-specific matched fields based on alert title/description
	titleLower := strings.ToLower(alert.Title)
	if strings.Contains(titleLower, "ransomware") {
		matched["file_extension"] = ".encrypted"
		matched["encryption_pattern"] = "detected"
		matched["shadow_copy_deleted"] = true
	} else if strings.Contains(titleLower, "brute") || strings.Contains(titleLower, "login") {
		matched["failed_attempts"] = 10
		matched["time_window"] = "5 minutes"
		matched["threshold_exceeded"] = true
	} else if strings.Contains(titleLower, "exfil") || strings.Contains(titleLower, "data") {
		matched["data_volume"] = "500MB"
		matched["external_destination"] = true
		matched["unusual_time"] = true
	} else if strings.Contains(titleLower, "c2") || strings.Contains(titleLower, "command") {
		matched["beacon_interval"] = "60s"
		matched["known_c2_domain"] = true
		matched["encrypted_traffic"] = true
	} else if strings.Contains(titleLower, "process") || strings.Contains(titleLower, "execution") {
		matched["suspicious_parent"] = true
		matched["encoded_command"] = true
		matched["known_technique"] = "T1059"
	}

	matched["rule_matched"] = alert.RuleID
	matched["detection_time"] = alert.Timestamp.Format(time.RFC3339)

	return matched
}

// generateSampleRawLog creates a sample raw log entry
func generateSampleRawLog(alert Alert) string {
	timestamp := alert.Timestamp.Format("2006-01-02T15:04:05.000Z")
	target := alert.Target
	if target == "" {
		target = "192.168.1.100"
	}

	switch strings.ToLower(alert.SourceType) {
	case "endpoint", "edr":
		return fmt.Sprintf(`{"timestamp":"%s","source":"EDR","host":"ws-prod-01","event_type":"process_create","process_name":"suspicious.exe","pid":4532,"parent_pid":1234,"user":"%s","command_line":"cmd.exe /c powershell -enc SGVsbG8=","file_hash":"a1b2c3d4e5f6","severity":"%s"}`, timestamp, target, alert.Severity)
	case "network", "ndr", "ids":
		return fmt.Sprintf(`{"timestamp":"%s","source":"NDR","src_ip":"%s","dst_ip":"185.45.67.89","src_port":49152,"dst_port":443,"protocol":"TCP","bytes":15234,"alert_type":"%s","signature":"%s"}`, timestamp, target, alert.Title, alert.RuleID)
	case "firewall":
		return fmt.Sprintf(`%s firewall-01 action=blocked src=%s dst=10.0.0.1 sport=55123 dport=22 proto=TCP rule="%s" msg="%s"`, timestamp, target, alert.RuleID, alert.Title)
	default:
		return fmt.Sprintf(`CEF:0|SIEM|Detection|1.0|%s|%s|%s|src=%s dst=10.0.0.1 msg=%s rt=%s`, alert.RuleID, alert.Title, alert.Severity, target, alert.Description, timestamp)
	}
}

// generateMITREMapping creates MITRE ATT&CK mapping based on alert context
func generateMITREMapping(alert Alert) ([]string, []string) {
	var tactics []string
	var techniques []string

	titleLower := strings.ToLower(alert.Title)
	descLower := strings.ToLower(alert.Description)
	combined := titleLower + " " + descLower

	// Map based on alert content
	if strings.Contains(combined, "ransomware") || strings.Contains(combined, "encrypt") {
		tactics = append(tactics, "TA0040") // Impact
		techniques = append(techniques, "T1486") // Data Encrypted for Impact
		techniques = append(techniques, "T1490") // Inhibit System Recovery
	}

	if strings.Contains(combined, "c2") || strings.Contains(combined, "command and control") || strings.Contains(combined, "beacon") {
		tactics = append(tactics, "TA0011") // Command and Control
		techniques = append(techniques, "T1071") // Application Layer Protocol
		techniques = append(techniques, "T1573") // Encrypted Channel
	}

	if strings.Contains(combined, "lateral") || strings.Contains(combined, "spread") {
		tactics = append(tactics, "TA0008") // Lateral Movement
		techniques = append(techniques, "T1021") // Remote Services
	}

	if strings.Contains(combined, "credential") || strings.Contains(combined, "password") || strings.Contains(combined, "brute") {
		tactics = append(tactics, "TA0006") // Credential Access
		techniques = append(techniques, "T1110") // Brute Force
		techniques = append(techniques, "T1003") // OS Credential Dumping
	}

	if strings.Contains(combined, "exfil") || strings.Contains(combined, "data theft") || strings.Contains(combined, "upload") {
		tactics = append(tactics, "TA0010") // Exfiltration
		techniques = append(techniques, "T1041") // Exfiltration Over C2 Channel
	}

	if strings.Contains(combined, "execution") || strings.Contains(combined, "process") || strings.Contains(combined, "powershell") || strings.Contains(combined, "script") {
		tactics = append(tactics, "TA0002") // Execution
		techniques = append(techniques, "T1059") // Command and Scripting Interpreter
		if strings.Contains(combined, "powershell") {
			techniques = append(techniques, "T1059.001") // PowerShell
		}
	}

	if strings.Contains(combined, "persistence") || strings.Contains(combined, "registry") || strings.Contains(combined, "scheduled") {
		tactics = append(tactics, "TA0003") // Persistence
		techniques = append(techniques, "T1547") // Boot or Logon Autostart Execution
	}

	if strings.Contains(combined, "privilege") || strings.Contains(combined, "escalat") {
		tactics = append(tactics, "TA0004") // Privilege Escalation
		techniques = append(techniques, "T1548") // Abuse Elevation Control Mechanism
	}

	if strings.Contains(combined, "evasion") || strings.Contains(combined, "disable") || strings.Contains(combined, "bypass") {
		tactics = append(tactics, "TA0005") // Defense Evasion
		techniques = append(techniques, "T1562") // Impair Defenses
	}

	if strings.Contains(combined, "discovery") || strings.Contains(combined, "scan") || strings.Contains(combined, "recon") {
		tactics = append(tactics, "TA0007") // Discovery
		techniques = append(techniques, "T1046") // Network Service Discovery
	}

	if strings.Contains(combined, "phish") || strings.Contains(combined, "spear") || strings.Contains(combined, "initial access") {
		tactics = append(tactics, "TA0001") // Initial Access
		techniques = append(techniques, "T1566") // Phishing
	}

	// Default mapping based on source type if no specific match
	if len(tactics) == 0 {
		switch strings.ToLower(alert.SourceType) {
		case "endpoint", "edr":
			tactics = append(tactics, "TA0002") // Execution
			techniques = append(techniques, "T1059") // Command and Scripting Interpreter
		case "network", "ndr", "ids":
			tactics = append(tactics, "TA0011") // Command and Control
			techniques = append(techniques, "T1071") // Application Layer Protocol
		case "firewall":
			tactics = append(tactics, "TA0011") // Command and Control
			techniques = append(techniques, "T1090") // Proxy
		case "authentication", "iam":
			tactics = append(tactics, "TA0006") // Credential Access
			techniques = append(techniques, "T1110") // Brute Force
		default:
			tactics = append(tactics, "TA0002") // Execution
			techniques = append(techniques, "T1204") // User Execution
		}
	}

	return tactics, techniques
}
