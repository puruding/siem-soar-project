// Package repository provides data access layer for cases.
package repository

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/case/internal/model"
)

// MockCaseRepository provides an in-memory implementation for development/testing.
type MockCaseRepository struct {
	mu       sync.RWMutex
	cases    map[string]*model.Case
	history  map[string][]*model.CaseHistory
	sequence int
}

// NewMockCaseRepository creates a new mock case repository.
func NewMockCaseRepository() *MockCaseRepository {
	repo := &MockCaseRepository{
		cases:    make(map[string]*model.Case),
		history:  make(map[string][]*model.CaseHistory),
		sequence: 1000,
	}
	// Add sample data
	repo.addSampleData()
	return repo
}

func (r *MockCaseRepository) addSampleData() {
	now := time.Now()

	samples := []*model.Case{
		{
			ID:          "case-001",
			Number:      "CASE-1001",
			Title:       "Suspicious Login Activity Detected",
			Description: "Multiple failed login attempts followed by successful login from unusual location",
			Type:        model.TypeIncident,
			Severity:    model.SeverityHigh,
			Priority:    model.PriorityP1,
			Status:      model.StatusOpen,
			Assignee:    "analyst1@example.com",
			Team:        "SOC",
			Source:      "detection",
			CreatedAt:   now.Add(-24 * time.Hour),
			UpdatedAt:   now.Add(-1 * time.Hour),
			CreatedBy:   "system",
			Tags:        []string{"authentication", "brute-force"},
			Tactics:     []string{"TA0006"},
			Techniques:  []string{"T1110"},
		},
		{
			ID:          "case-002",
			Number:      "CASE-1002",
			Title:       "Malware Detection on Endpoint",
			Description: "Ransomware variant detected on user workstation",
			Type:        model.TypeIncident,
			Severity:    model.SeverityCritical,
			Priority:    model.PriorityP1,
			Status:      model.StatusInProgress,
			Assignee:    "analyst2@example.com",
			Team:        "IR",
			Source:      "edr",
			CreatedAt:   now.Add(-12 * time.Hour),
			UpdatedAt:   now.Add(-30 * time.Minute),
			CreatedBy:   "system",
			Tags:        []string{"malware", "ransomware"},
			Tactics:     []string{"TA0040"},
			Techniques:  []string{"T1486"},
		},
		{
			ID:          "case-003",
			Number:      "CASE-1003",
			Title:       "Data Exfiltration Alert",
			Description: "Large volume of data transferred to external IP",
			Type:        model.TypeInvestigation,
			Severity:    model.SeverityMedium,
			Priority:    model.PriorityP2,
			Status:      model.StatusPending,
			Assignee:    "analyst1@example.com",
			Team:        "SOC",
			Source:      "dlp",
			CreatedAt:   now.Add(-48 * time.Hour),
			UpdatedAt:   now.Add(-6 * time.Hour),
			CreatedBy:   "system",
			Tags:        []string{"data-loss", "exfiltration"},
			Tactics:     []string{"TA0010"},
			Techniques:  []string{"T1048"},
		},
		{
			ID:          "case-004",
			Number:      "CASE-1004",
			Title:       "Phishing Email Reported",
			Description: "Employee reported suspicious email with malicious attachment",
			Type:        model.TypeOther,
			Severity:    model.SeverityLow,
			Priority:    model.PriorityP4,
			Status:      model.StatusClosed,
			Assignee:    "analyst3@example.com",
			Team:        "SOC",
			Source:      "user-report",
			CreatedAt:   now.Add(-72 * time.Hour),
			UpdatedAt:   now.Add(-24 * time.Hour),
			CreatedBy:   "system",
			Resolution:  "false_positive",
			Tags:        []string{"phishing", "email"},
			Tactics:     []string{"TA0001"},
			Techniques:  []string{"T1566"},
		},
	}

	for _, c := range samples {
		r.cases[c.ID] = c
	}
}

// Create creates a new case.
func (r *MockCaseRepository) Create(ctx context.Context, caseObj *model.Case) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if caseObj.ID == "" {
		caseObj.ID = uuid.New().String()
	}
	if caseObj.Number == "" {
		r.sequence++
		caseObj.Number = fmt.Sprintf("CASE-%d", r.sequence)
	}
	if caseObj.CreatedAt.IsZero() {
		caseObj.CreatedAt = time.Now()
	}
	caseObj.UpdatedAt = time.Now()

	r.cases[caseObj.ID] = caseObj
	return nil
}

// Get retrieves a case by ID.
func (r *MockCaseRepository) Get(ctx context.Context, id string) (*model.Case, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	caseObj, ok := r.cases[id]
	if !ok {
		return nil, fmt.Errorf("case not found: %s", id)
	}
	return caseObj, nil
}

// Update updates an existing case.
func (r *MockCaseRepository) Update(ctx context.Context, caseObj *model.Case) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.cases[caseObj.ID]; !ok {
		return fmt.Errorf("case not found: %s", caseObj.ID)
	}

	caseObj.UpdatedAt = time.Now()
	r.cases[caseObj.ID] = caseObj
	return nil
}

// Delete deletes a case.
func (r *MockCaseRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.cases[id]; !ok {
		return fmt.Errorf("case not found: %s", id)
	}

	delete(r.cases, id)
	delete(r.history, id)
	return nil
}

// List retrieves cases based on filter criteria.
func (r *MockCaseRepository) List(ctx context.Context, filter *model.CaseFilter) (*model.CaseListResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*model.Case

	for _, c := range r.cases {
		// Apply filters
		if len(filter.Status) > 0 && !containsStatus(filter.Status, c.Status) {
			continue
		}
		if len(filter.Severity) > 0 && !containsSeverity(filter.Severity, c.Severity) {
			continue
		}
		if filter.Assignee != "" && c.Assignee != filter.Assignee {
			continue
		}
		if filter.Team != "" && c.Team != filter.Team {
			continue
		}
		filtered = append(filtered, c)
	}

	total := int64(len(filtered))

	// Apply pagination
	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	start := offset
	end := offset + limit
	if start > len(filtered) {
		start = len(filtered)
	}
	if end > len(filtered) {
		end = len(filtered)
	}

	return &model.CaseListResult{
		Cases:   filtered[start:end],
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: int64(offset+limit) < total,
	}, nil
}

// GetSummary retrieves case statistics.
func (r *MockCaseRepository) GetSummary(ctx context.Context, tenantID string) (*model.CaseSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	summary := &model.CaseSummary{
		ByStatus:   make(map[model.CaseStatus]int64),
		BySeverity: make(map[model.CaseSeverity]int64),
		ByAssignee: make(map[string]int64),
	}

	for _, c := range r.cases {
		summary.TotalCases++
		summary.ByStatus[c.Status]++
		summary.BySeverity[c.Severity]++
		if c.Assignee != "" {
			summary.ByAssignee[c.Assignee]++
		}

		if c.Status == model.StatusOpen || c.Status == model.StatusInProgress || c.Status == model.StatusPending {
			summary.OpenCases++
		}
		if c.Severity == model.SeverityCritical {
			summary.CriticalCases++
		}
		if c.Severity == model.SeverityHigh {
			summary.HighCases++
		}
		if c.SLABreached {
			summary.OverdueCases++
		}
	}

	return summary, nil
}

// AddHistory adds a history entry for a case.
func (r *MockCaseRepository) AddHistory(ctx context.Context, history *model.CaseHistory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if history.ID == "" {
		history.ID = uuid.New().String()
	}
	if history.Timestamp.IsZero() {
		history.Timestamp = time.Now()
	}

	r.history[history.CaseID] = append(r.history[history.CaseID], history)
	return nil
}

// GetHistory retrieves history for a case.
func (r *MockCaseRepository) GetHistory(ctx context.Context, caseID string, limit int) ([]*model.CaseHistory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	histories := r.history[caseID]
	if limit > 0 && len(histories) > limit {
		histories = histories[:limit]
	}
	return histories, nil
}

// Helper functions
func containsStatus(statuses []model.CaseStatus, status model.CaseStatus) bool {
	for _, s := range statuses {
		if s == status {
			return true
		}
	}
	return false
}

func containsSeverity(severities []model.CaseSeverity, severity model.CaseSeverity) bool {
	for _, s := range severities {
		if s == severity {
			return true
		}
	}
	return false
}
