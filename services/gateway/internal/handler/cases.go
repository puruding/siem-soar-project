package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	AlertIDs    []string  `json:"alert_ids"`
	AssignedTo  string    `json:"assigned_to"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// In-memory case store
var (
	caseStore   = make([]Case, 0)
	caseStoreMu sync.RWMutex
	caseCounter = 0
)

// CreateCaseRequest represents the request body for creating a case
type CreateCaseRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	AlertIDs    []string `json:"alert_ids"`
	AssignedTo  string   `json:"assigned_to"`
}

// ListCasesHandler returns list of cases
func ListCasesHandler(w http.ResponseWriter, r *http.Request) {
	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"cases":   caseStore,
		"total":   len(caseStore),
	})
}

// CreateCaseHandler creates a new case
func CreateCaseHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
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

	// Validate required fields
	if req.Title == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Title is required",
		})
		return
	}

	// Default priority
	if req.Priority == "" {
		req.Priority = "medium"
	}

	// Validate priority
	validPriorities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}
	if !validPriorities[req.Priority] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid priority. Must be one of: critical, high, medium, low",
		})
		return
	}

	caseStoreMu.Lock()
	defer caseStoreMu.Unlock()

	// Generate case ID
	caseCounter++
	year := time.Now().Year()
	caseID := fmt.Sprintf("CASE-%d-%03d", year, caseCounter)

	now := time.Now()
	newCase := Case{
		ID:          caseID,
		Title:       req.Title,
		Description: req.Description,
		Status:      "open",
		Priority:    req.Priority,
		AlertIDs:    req.AlertIDs,
		AssignedTo:  req.AssignedTo,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Prepend (newest first)
	caseStore = append([]Case{newCase}, caseStore...)

	// Keep max 500 cases
	if len(caseStore) > 500 {
		caseStore = caseStore[:500]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"case":    newCase,
	})
}

// GetCaseHandler returns a single case by ID
func GetCaseHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract case ID from path: /api/v1/cases/{id}
	path := r.URL.Path
	parts := make([]string, 0)
	for _, p := range r.URL.Path[1:] {
		if p == '/' {
			break
		}
	}
	_ = parts
	// Simple extraction: take last segment
	lastSlash := len(path) - 1
	for lastSlash >= 0 && path[lastSlash] != '/' {
		lastSlash--
	}
	caseID := path[lastSlash+1:]

	caseStoreMu.RLock()
	defer caseStoreMu.RUnlock()

	for _, c := range caseStore {
		if c.ID == caseID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"case":    c,
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
