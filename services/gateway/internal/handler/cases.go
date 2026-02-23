package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Case represents a security case
type Case struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`   // open, investigating, resolved, closed
	Priority    string    `json:"priority"` // critical, high, medium, low
	Severity    string    `json:"severity"` // critical, high, medium, low
	AlertIDs    []string  `json:"alert_ids"`
	AlertCount  int       `json:"alertCount"`
	AssignedTo  string    `json:"assigned_to"`
	Assignee    *Assignee `json:"assignee,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

// Assignee represents a user assigned to a case
type Assignee struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Initials string `json:"initials"`
}

// CaseTimelineEntry represents a timeline entry
type CaseTimelineEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // created, updated, comment, status_change, assignment, alert_added
	Actor       string                 `json:"actor"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// In-memory case store
var (
	caseStore     = make([]Case, 0)
	caseStoreMu   sync.RWMutex
	caseCounter   = 100
	caseTimelines = make(map[string][]CaseTimelineEntry)
)

// Available assignees
var availableAssignees = map[string]*Assignee{
	"john.smith": {ID: "john.smith", Name: "John Smith", Email: "john.smith@company.com", Initials: "JS"},
	"jane.doe":   {ID: "jane.doe", Name: "Jane Doe", Email: "jane.doe@company.com", Initials: "JD"},
	"mike.johnson": {ID: "mike.johnson", Name: "Mike Johnson", Email: "mike.johnson@company.com", Initials: "MJ"},
	"sarah.wilson": {ID: "sarah.wilson", Name: "Sarah Wilson", Email: "sarah.wilson@company.com", Initials: "SW"},
}

// init initializes sample cases for demo
func init() {
	now := time.Now()

	johnSmith := availableAssignees["john.smith"]
	janeDoe := availableAssignees["jane.doe"]
	mikeJohnson := availableAssignees["mike.johnson"]
	sarahWilson := availableAssignees["sarah.wilson"]

	sampleCases := []Case{
		{
			ID:          "CASE-101",
			Title:       "Brute Force Attack Investigation",
			Description: "Investigation of multiple failed SSH login attempts from 192.168.1.100",
			Status:      "in_progress",
			Priority:    "high",
			Severity:    "high",
			AlertIDs:    []string{"ALERT-1001"},
			AlertCount:  1,
			AssignedTo:  "John Smith",
			Assignee:    johnSmith,
			Tags:        []string{"brute-force", "ssh"},
			CreatedAt:   now.Add(-2 * time.Hour),
			UpdatedAt:   now.Add(-30 * time.Minute),
		},
		{
			ID:          "CASE-102",
			Title:       "Malware C2 Communication",
			Description: "Investigating beacon activity to known malicious C2 server",
			Status:      "open",
			Priority:    "critical",
			Severity:    "critical",
			AlertIDs:    []string{"ALERT-1005"},
			AlertCount:  1,
			AssignedTo:  "Jane Doe",
			Assignee:    janeDoe,
			Tags:        []string{"malware", "c2"},
			CreatedAt:   now.Add(-1 * time.Hour),
			UpdatedAt:   now.Add(-15 * time.Minute),
		},
		{
			ID:          "CASE-103",
			Title:       "Data Exfiltration Attempt",
			Description: "Large data transfer to external IP detected and under investigation",
			Status:      "in_progress",
			Priority:    "high",
			Severity:    "high",
			AlertIDs:    []string{"ALERT-1003"},
			AlertCount:  1,
			AssignedTo:  "Mike Johnson",
			Assignee:    mikeJohnson,
			Tags:        []string{"data-exfil", "network"},
			CreatedAt:   now.Add(-4 * time.Hour),
			UpdatedAt:   now.Add(-1 * time.Hour),
		},
		{
			ID:          "CASE-104",
			Title:       "Suspicious PowerShell Activity",
			Description: "Encoded PowerShell commands detected on workstation",
			Status:      "resolved",
			Priority:    "medium",
			Severity:    "medium",
			AlertIDs:    []string{"ALERT-1002"},
			AlertCount:  1,
			AssignedTo:  "Sarah Wilson",
			Assignee:    sarahWilson,
			Tags:        []string{"powershell", "endpoint"},
			CreatedAt:   now.Add(-24 * time.Hour),
			UpdatedAt:   now.Add(-6 * time.Hour),
		},
	}

	caseStoreMu.Lock()
	caseStore = sampleCases

	// Initialize timelines
	for _, c := range sampleCases {
		caseTimelines[c.ID] = []CaseTimelineEntry{
			{
				ID:          fmt.Sprintf("%s-TL-001", c.ID),
				Timestamp:   c.CreatedAt,
				Type:        "created",
				Actor:       "system",
				Description: "Case created",
			},
		}
		if c.AssignedTo != "" {
			caseTimelines[c.ID] = append(caseTimelines[c.ID], CaseTimelineEntry{
				ID:          fmt.Sprintf("%s-TL-002", c.ID),
				Timestamp:   c.CreatedAt.Add(time.Minute),
				Type:        "assignment",
				Actor:       "system",
				Description: fmt.Sprintf("Case assigned to %s", c.AssignedTo),
			})
		}
	}
	caseStoreMu.Unlock()
}

// CreateCaseRequest represents the request body for creating a case
type CreateCaseRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Severity    string   `json:"severity"`
	AlertIDs    []string `json:"alertIds"`
	AssigneeID  string   `json:"assigneeId"`
	Tags        []string `json:"tags"`
}

// UpdateCaseRequest represents the request body for updating a case
type UpdateCaseRequest struct {
	Title              string   `json:"title,omitempty"`
	Description        string   `json:"description,omitempty"`
	Status             string   `json:"status,omitempty"`
	Priority           string   `json:"priority,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	ResolutionSummary  string   `json:"resolutionSummary,omitempty"`
}

// extractCaseID extracts case ID from URL path
func extractCaseID(path string) string {
	// Path format: /api/v1/cases/{id} or /api/v1/cases/{id}/...
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "cases" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ListCasesHandler returns list of cases
func ListCasesHandler(w http.ResponseWriter, r *http.Request) {
	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"cases":    caseStore,
		"total":    len(caseStore),
		"page":     1,
		"pageSize": len(caseStore),
	})
}

// CreateCaseHandler creates a new case
func CreateCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Title is required",
		})
		return
	}

	// Default values
	if req.Priority == "" {
		req.Priority = "medium"
	}
	if req.Severity == "" {
		req.Severity = req.Priority
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	caseCounter++
	caseID := fmt.Sprintf("CASE-%03d", caseCounter)

	now := time.Now()
	newCase := Case{
		ID:          caseID,
		Title:       req.Title,
		Description: req.Description,
		Status:      "open",
		Priority:    req.Priority,
		Severity:    req.Severity,
		AlertIDs:    req.AlertIDs,
		AlertCount:  len(req.AlertIDs),
		AssignedTo:  "",
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Set assignee if provided
	if req.AssigneeID != "" {
		for _, a := range availableAssignees {
			if a.ID == req.AssigneeID || a.Name == req.AssigneeID {
				newCase.AssignedTo = a.Name
				newCase.Assignee = a
				break
			}
		}
	}

	// Prepend (newest first)
	caseStore = append([]Case{newCase}, caseStore...)

	// Initialize timeline
	caseTimelines[caseID] = []CaseTimelineEntry{
		{
			ID:          fmt.Sprintf("%s-TL-001", caseID),
			Timestamp:   now,
			Type:        "created",
			Actor:       "user",
			Description: "Case created",
		},
	}

	// Keep max 500 cases
	if len(caseStore) > 500 {
		caseStore = caseStore[:500]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    newCase,
	})
}

// GetCaseHandler returns a single case by ID
func GetCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	for _, c := range caseStore {
		if c.ID == caseID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    c,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// UpdateCaseHandler updates a case
func UpdateCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	var req UpdateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			if req.Title != "" {
				caseStore[i].Title = req.Title
			}
			if req.Description != "" {
				caseStore[i].Description = req.Description
			}
			if req.Status != "" {
				caseStore[i].Status = req.Status
			}
			if req.Priority != "" {
				caseStore[i].Priority = req.Priority
			}
			if req.Severity != "" {
				caseStore[i].Severity = req.Severity
			}
			if len(req.Tags) > 0 {
				caseStore[i].Tags = req.Tags
			}
			caseStore[i].UpdatedAt = time.Now()

			// Add timeline entry
			caseTimelines[caseID] = append(caseTimelines[caseID], CaseTimelineEntry{
				ID:          fmt.Sprintf("%s-TL-%03d", caseID, len(caseTimelines[caseID])+1),
				Timestamp:   time.Now(),
				Type:        "updated",
				Actor:       "user",
				Description: "Case updated",
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    caseStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// DeleteCaseHandler deletes a case
func DeleteCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			caseStore = append(caseStore[:i], caseStore[i+1:]...)
			delete(caseTimelines, caseID)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// AssignCaseHandler assigns a case to a user
func AssignCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	var req struct {
		AssigneeID string `json:"assigneeId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			// Find assignee
			var assignee *Assignee
			for _, a := range availableAssignees {
				if a.ID == req.AssigneeID || a.Name == req.AssigneeID {
					assignee = a
					break
				}
			}

			if assignee != nil {
				caseStore[i].AssignedTo = assignee.Name
				caseStore[i].Assignee = assignee
			} else {
				caseStore[i].AssignedTo = req.AssigneeID
			}
			caseStore[i].UpdatedAt = time.Now()

			// Add timeline entry
			caseTimelines[caseID] = append(caseTimelines[caseID], CaseTimelineEntry{
				ID:          fmt.Sprintf("%s-TL-%03d", caseID, len(caseTimelines[caseID])+1),
				Timestamp:   time.Now(),
				Type:        "assignment",
				Actor:       "user",
				Description: fmt.Sprintf("Case assigned to %s", caseStore[i].AssignedTo),
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    caseStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// ChangeStatusHandler changes case status
func ChangeStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	var req struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	validStatuses := map[string]bool{
		"open": true, "in_progress": true, "pending": true,
		"resolved": true, "closed": true, "reopened": true,
	}
	if !validStatuses[req.Status] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid status",
		})
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			oldStatus := caseStore[i].Status
			caseStore[i].Status = req.Status
			caseStore[i].UpdatedAt = time.Now()

			if req.Status == "closed" || req.Status == "resolved" {
				now := time.Now()
				caseStore[i].ClosedAt = &now
			}

			// Add timeline entry
			desc := fmt.Sprintf("Status changed from %s to %s", oldStatus, req.Status)
			if req.Comment != "" {
				desc += ": " + req.Comment
			}
			caseTimelines[caseID] = append(caseTimelines[caseID], CaseTimelineEntry{
				ID:          fmt.Sprintf("%s-TL-%03d", caseID, len(caseTimelines[caseID])+1),
				Timestamp:   time.Now(),
				Type:        "status_change",
				Actor:       "user",
				Description: desc,
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    caseStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// AddAlertToCaseHandler adds an alert to a case
func AddAlertToCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	var req struct {
		AlertID string `json:"alertId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			// Check if alert already exists
			for _, aid := range caseStore[i].AlertIDs {
				if aid == req.AlertID {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"success": true,
						"data":    caseStore[i],
					})
					return
				}
			}

			caseStore[i].AlertIDs = append(caseStore[i].AlertIDs, req.AlertID)
			caseStore[i].AlertCount = len(caseStore[i].AlertIDs)
			caseStore[i].UpdatedAt = time.Now()

			// Add timeline entry
			caseTimelines[caseID] = append(caseTimelines[caseID], CaseTimelineEntry{
				ID:          fmt.Sprintf("%s-TL-%03d", caseID, len(caseTimelines[caseID])+1),
				Timestamp:   time.Now(),
				Type:        "alert_added",
				Actor:       "user",
				Description: fmt.Sprintf("Alert %s added to case", req.AlertID),
			})

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    caseStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// RemoveAlertFromCaseHandler removes an alert from a case
func RemoveAlertFromCaseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract case ID and alert ID from path: /api/v1/cases/{caseId}/alerts/{alertId}
	parts := strings.Split(r.URL.Path, "/")
	var caseID, alertID string
	for i, p := range parts {
		if p == "cases" && i+1 < len(parts) {
			caseID = parts[i+1]
		}
		if p == "alerts" && i+1 < len(parts) {
			alertID = parts[i+1]
		}
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	for i, c := range caseStore {
		if c.ID == caseID {
			// Remove alert
			newAlertIDs := make([]string, 0)
			for _, aid := range caseStore[i].AlertIDs {
				if aid != alertID {
					newAlertIDs = append(newAlertIDs, aid)
				}
			}
			caseStore[i].AlertIDs = newAlertIDs
			caseStore[i].AlertCount = len(newAlertIDs)
			caseStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    caseStore[i],
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Case not found",
	})
}

// GetCaseTimelineHandler returns the timeline for a case
func GetCaseTimelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	timeline, exists := caseTimelines[caseID]
	if !exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Case not found",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    timeline,
	})
}

// AddCommentHandler adds a comment to case timeline
func AddCommentHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := extractCaseID(r.URL.Path)

	var req struct {
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	// Check if case exists
	found := false
	for _, c := range caseStore {
		if c.ID == caseID {
			found = true
			break
		}
	}

	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Case not found",
		})
		return
	}

	entry := CaseTimelineEntry{
		ID:          fmt.Sprintf("%s-TL-%03d", caseID, len(caseTimelines[caseID])+1),
		Timestamp:   time.Now(),
		Type:        "comment",
		Actor:       "user",
		Description: req.Comment,
	}

	caseTimelines[caseID] = append(caseTimelines[caseID], entry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    entry,
	})
}

// GetCaseStatsHandler returns case statistics
func GetCaseStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	stats := map[string]interface{}{
		"total":      len(caseStore),
		"open":       0,
		"inProgress": 0,
		"resolved":   0,
		"bySeverity": map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0,
		},
		"byStatus": map[string]int{
			"open": 0, "in_progress": 0, "pending": 0,
			"resolved": 0, "closed": 0, "reopened": 0,
		},
		"averageTTD": 3.2,
		"averageTTR": 24.0,
	}

	bySeverity := stats["bySeverity"].(map[string]int)
	byStatus := stats["byStatus"].(map[string]int)

	for _, c := range caseStore {
		byStatus[c.Status]++
		bySeverity[c.Severity]++

		if c.Status == "open" {
			stats["open"] = stats["open"].(int) + 1
		} else if c.Status == "in_progress" {
			stats["inProgress"] = stats["inProgress"].(int) + 1
		} else if c.Status == "resolved" || c.Status == "closed" {
			stats["resolved"] = stats["resolved"].(int) + 1
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}
