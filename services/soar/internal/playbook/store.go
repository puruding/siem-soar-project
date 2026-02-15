// Package playbook provides playbook storage and retrieval.
package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Store defines the interface for playbook storage.
type Store interface {
	// Create creates a new playbook.
	Create(ctx context.Context, playbook *Playbook) error

	// Get retrieves a playbook by ID.
	Get(ctx context.Context, id string) (*Playbook, error)

	// GetByName retrieves a playbook by name.
	GetByName(ctx context.Context, name string) (*Playbook, error)

	// GetVersion retrieves a specific version of a playbook.
	GetVersion(ctx context.Context, id string, version int) (*Playbook, error)

	// Update updates an existing playbook, creating a new version.
	Update(ctx context.Context, playbook *Playbook) error

	// Delete soft-deletes a playbook.
	Delete(ctx context.Context, id string) error

	// List lists playbooks with optional filters.
	List(ctx context.Context, filter *ListFilter) (*ListResult, error)

	// ListVersions lists all versions of a playbook.
	ListVersions(ctx context.Context, id string) ([]*PlaybookVersion, error)

	// Enable enables a playbook.
	Enable(ctx context.Context, id string) error

	// Disable disables a playbook.
	Disable(ctx context.Context, id string) error

	// Import imports playbooks from YAML.
	Import(ctx context.Context, data []byte) ([]*Playbook, error)

	// Export exports playbooks to YAML.
	Export(ctx context.Context, ids []string) ([]byte, error)
}

// ListFilter defines filters for listing playbooks.
type ListFilter struct {
	Category  Category    `json:"category,omitempty"`
	Tags      []string    `json:"tags,omitempty"`
	Enabled   *bool       `json:"enabled,omitempty"`
	TenantID  string      `json:"tenant_id,omitempty"`
	Search    string      `json:"search,omitempty"`
	Trigger   TriggerType `json:"trigger,omitempty"`
	Limit     int         `json:"limit,omitempty"`
	Offset    int         `json:"offset,omitempty"`
	SortBy    string      `json:"sort_by,omitempty"`
	SortOrder string      `json:"sort_order,omitempty"` // "asc" or "desc"
}

// ListResult contains paginated playbook results.
type ListResult struct {
	Playbooks  []*Playbook `json:"playbooks"`
	Total      int64       `json:"total"`
	Limit      int         `json:"limit"`
	Offset     int         `json:"offset"`
	HasMore    bool        `json:"has_more"`
}

// PlaybookVersion represents a version of a playbook.
type PlaybookVersion struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Comment   string    `json:"comment,omitempty"`
	Diff      string    `json:"diff,omitempty"`
}

// MemoryStore implements an in-memory playbook store.
type MemoryStore struct {
	mu        sync.RWMutex
	playbooks map[string]*Playbook
	versions  map[string][]*Playbook
	byName    map[string]string // name -> id
	parser    *Parser
	validator *Validator
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		playbooks: make(map[string]*Playbook),
		versions:  make(map[string][]*Playbook),
		byName:    make(map[string]string),
		parser:    NewParser(),
		validator: NewValidator(),
	}
}

// Create creates a new playbook.
func (s *MemoryStore) Create(ctx context.Context, playbook *Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not provided
	if playbook.ID == "" {
		playbook.ID = uuid.New().String()
	}

	// Check for duplicate ID
	if _, exists := s.playbooks[playbook.ID]; exists {
		return fmt.Errorf("playbook with ID %s already exists", playbook.ID)
	}

	// Check for duplicate name
	if existingID, exists := s.byName[playbook.Name]; exists {
		return fmt.Errorf("playbook with name %s already exists (ID: %s)", playbook.Name, existingID)
	}

	// Validate playbook
	result := s.validator.Validate(playbook)
	if !result.Valid {
		return fmt.Errorf("validation failed: %s", result.Error())
	}

	// Set timestamps
	now := time.Now()
	playbook.CreatedAt = now
	playbook.UpdatedAt = now
	playbook.Version = 1

	// Store playbook
	s.playbooks[playbook.ID] = playbook
	s.byName[playbook.Name] = playbook.ID
	s.versions[playbook.ID] = []*Playbook{copyPlaybook(playbook)}

	return nil
}

// Get retrieves a playbook by ID.
func (s *MemoryStore) Get(ctx context.Context, id string) (*Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	playbook, exists := s.playbooks[id]
	if !exists {
		return nil, fmt.Errorf("playbook %s not found", id)
	}

	return copyPlaybook(playbook), nil
}

// GetByName retrieves a playbook by name.
func (s *MemoryStore) GetByName(ctx context.Context, name string) (*Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byName[name]
	if !exists {
		return nil, fmt.Errorf("playbook with name %s not found", name)
	}

	return copyPlaybook(s.playbooks[id]), nil
}

// GetVersion retrieves a specific version of a playbook.
func (s *MemoryStore) GetVersion(ctx context.Context, id string, version int) (*Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, exists := s.versions[id]
	if !exists {
		return nil, fmt.Errorf("playbook %s not found", id)
	}

	for _, pb := range versions {
		if pb.Version == version {
			return copyPlaybook(pb), nil
		}
	}

	return nil, fmt.Errorf("playbook %s version %d not found", id, version)
}

// Update updates an existing playbook, creating a new version.
func (s *MemoryStore) Update(ctx context.Context, playbook *Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.playbooks[playbook.ID]
	if !exists {
		return fmt.Errorf("playbook %s not found", playbook.ID)
	}

	// Validate playbook
	result := s.validator.Validate(playbook)
	if !result.Valid {
		return fmt.Errorf("validation failed: %s", result.Error())
	}

	// Update name mapping if changed
	if existing.Name != playbook.Name {
		// Check for name collision
		if existingID, nameExists := s.byName[playbook.Name]; nameExists && existingID != playbook.ID {
			return fmt.Errorf("playbook with name %s already exists", playbook.Name)
		}
		delete(s.byName, existing.Name)
		s.byName[playbook.Name] = playbook.ID
	}

	// Increment version
	playbook.Version = existing.Version + 1
	playbook.CreatedAt = existing.CreatedAt
	playbook.UpdatedAt = time.Now()

	// Store updated playbook
	s.playbooks[playbook.ID] = playbook
	s.versions[playbook.ID] = append(s.versions[playbook.ID], copyPlaybook(playbook))

	return nil
}

// Delete soft-deletes a playbook.
func (s *MemoryStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook, exists := s.playbooks[id]
	if !exists {
		return fmt.Errorf("playbook %s not found", id)
	}

	delete(s.playbooks, id)
	delete(s.byName, playbook.Name)
	// Keep versions for audit

	return nil
}

// List lists playbooks with optional filters.
func (s *MemoryStore) List(ctx context.Context, filter *ListFilter) (*ListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*Playbook

	for _, pb := range s.playbooks {
		if s.matchesFilter(pb, filter) {
			filtered = append(filtered, copyPlaybook(pb))
		}
	}

	// Apply pagination
	total := int64(len(filtered))
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset

	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return &ListResult{
		Playbooks: filtered[start:end],
		Total:     total,
		Limit:     limit,
		Offset:    offset,
		HasMore:   end < len(filtered),
	}, nil
}

// matchesFilter checks if a playbook matches the filter criteria.
func (s *MemoryStore) matchesFilter(pb *Playbook, filter *ListFilter) bool {
	if filter == nil {
		return true
	}

	if filter.Category != "" && pb.Category != filter.Category {
		return false
	}

	if filter.TenantID != "" && pb.TenantID != filter.TenantID {
		return false
	}

	if filter.Enabled != nil && pb.Enabled != *filter.Enabled {
		return false
	}

	if filter.Trigger != "" && pb.Trigger.Type != filter.Trigger {
		return false
	}

	if len(filter.Tags) > 0 {
		hasTag := false
		for _, ft := range filter.Tags {
			for _, pt := range pb.Tags {
				if ft == pt {
					hasTag = true
					break
				}
			}
		}
		if !hasTag {
			return false
		}
	}

	if filter.Search != "" {
		// Simple search in name and description
		searchLower := filter.Search
		if !containsIgnoreCase(pb.Name, searchLower) &&
			!containsIgnoreCase(pb.Description, searchLower) {
			return false
		}
	}

	return true
}

// containsIgnoreCase checks if s contains substr (case insensitive).
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(substr) == 0 ||
			(len(s) > 0 && len(substr) > 0 &&
				(s[0] == substr[0] || s[0]+32 == substr[0] || s[0] == substr[0]+32)))
}

// ListVersions lists all versions of a playbook.
func (s *MemoryStore) ListVersions(ctx context.Context, id string) ([]*PlaybookVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, exists := s.versions[id]
	if !exists {
		return nil, fmt.Errorf("playbook %s not found", id)
	}

	result := make([]*PlaybookVersion, len(versions))
	for i, pb := range versions {
		result[i] = &PlaybookVersion{
			ID:        pb.ID,
			Version:   pb.Version,
			CreatedAt: pb.UpdatedAt,
			CreatedBy: pb.Author,
		}
	}

	return result, nil
}

// Enable enables a playbook.
func (s *MemoryStore) Enable(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook, exists := s.playbooks[id]
	if !exists {
		return fmt.Errorf("playbook %s not found", id)
	}

	playbook.Enabled = true
	playbook.UpdatedAt = time.Now()
	return nil
}

// Disable disables a playbook.
func (s *MemoryStore) Disable(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook, exists := s.playbooks[id]
	if !exists {
		return fmt.Errorf("playbook %s not found", id)
	}

	playbook.Enabled = false
	playbook.UpdatedAt = time.Now()
	return nil
}

// Import imports playbooks from YAML.
func (s *MemoryStore) Import(ctx context.Context, data []byte) ([]*Playbook, error) {
	multiParser := NewMultiDocParser()
	playbooks, err := multiParser.Parse(bytesReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse playbooks: %w", err)
	}

	var imported []*Playbook
	for _, pb := range playbooks {
		if err := s.Create(ctx, pb); err != nil {
			return imported, fmt.Errorf("failed to import playbook %s: %w", pb.Name, err)
		}
		imported = append(imported, pb)
	}

	return imported, nil
}

// Export exports playbooks to YAML.
func (s *MemoryStore) Export(ctx context.Context, ids []string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var playbooks []*Playbook
	for _, id := range ids {
		if pb, exists := s.playbooks[id]; exists {
			playbooks = append(playbooks, copyPlaybook(pb))
		}
	}

	if len(playbooks) == 0 {
		return nil, fmt.Errorf("no playbooks found")
	}

	// Serialize to YAML
	var result []byte
	for i, pb := range playbooks {
		data, err := Serialize(pb)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize playbook %s: %w", pb.ID, err)
		}
		if i > 0 {
			result = append(result, []byte("\n---\n")...)
		}
		result = append(result, data...)
	}

	return result, nil
}

// copyPlaybook creates a deep copy of a playbook.
func copyPlaybook(pb *Playbook) *Playbook {
	if pb == nil {
		return nil
	}

	data, err := json.Marshal(pb)
	if err != nil {
		return nil
	}

	var copy Playbook
	if err := json.Unmarshal(data, &copy); err != nil {
		return nil
	}

	return &copy
}

// bytesReader creates a reader from bytes.
type bytesReaderWrapper struct {
	data   []byte
	offset int
}

func bytesReader(data []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: data}
}

func (r *bytesReaderWrapper) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// ExecutionStore defines the interface for execution storage.
type ExecutionStore interface {
	// Create creates a new execution record.
	Create(ctx context.Context, execution *Execution) error

	// Get retrieves an execution by ID.
	Get(ctx context.Context, id string) (*Execution, error)

	// Update updates an execution.
	Update(ctx context.Context, execution *Execution) error

	// List lists executions with optional filters.
	List(ctx context.Context, filter *ExecutionFilter) (*ExecutionListResult, error)

	// GetByWorkflowID retrieves an execution by Temporal workflow ID.
	GetByWorkflowID(ctx context.Context, workflowID string) (*Execution, error)

	// AddStepResult adds a step result to an execution.
	AddStepResult(ctx context.Context, executionID string, result *StepResult) error

	// UpdateStatus updates the execution status.
	UpdateStatus(ctx context.Context, id string, status ExecutionStatus, err string) error
}

// ExecutionFilter defines filters for listing executions.
type ExecutionFilter struct {
	PlaybookID string            `json:"playbook_id,omitempty"`
	Status     []ExecutionStatus `json:"status,omitempty"`
	AlertID    string            `json:"alert_id,omitempty"`
	CaseID     string            `json:"case_id,omitempty"`
	TenantID   string            `json:"tenant_id,omitempty"`
	StartTime  time.Time         `json:"start_time,omitempty"`
	EndTime    time.Time         `json:"end_time,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Offset     int               `json:"offset,omitempty"`
}

// ExecutionListResult contains paginated execution results.
type ExecutionListResult struct {
	Executions []*Execution `json:"executions"`
	Total      int64        `json:"total"`
	Limit      int          `json:"limit"`
	Offset     int          `json:"offset"`
	HasMore    bool         `json:"has_more"`
}

// MemoryExecutionStore implements an in-memory execution store.
type MemoryExecutionStore struct {
	mu         sync.RWMutex
	executions map[string]*Execution
	byWorkflow map[string]string // workflowID -> executionID
}

// NewMemoryExecutionStore creates a new in-memory execution store.
func NewMemoryExecutionStore() *MemoryExecutionStore {
	return &MemoryExecutionStore{
		executions: make(map[string]*Execution),
		byWorkflow: make(map[string]string),
	}
}

// Create creates a new execution record.
func (s *MemoryExecutionStore) Create(ctx context.Context, execution *Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if execution.ID == "" {
		execution.ID = uuid.New().String()
	}

	if _, exists := s.executions[execution.ID]; exists {
		return fmt.Errorf("execution %s already exists", execution.ID)
	}

	s.executions[execution.ID] = execution
	if execution.WorkflowID != "" {
		s.byWorkflow[execution.WorkflowID] = execution.ID
	}

	return nil
}

// Get retrieves an execution by ID.
func (s *MemoryExecutionStore) Get(ctx context.Context, id string) (*Execution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	execution, exists := s.executions[id]
	if !exists {
		return nil, fmt.Errorf("execution %s not found", id)
	}

	return execution, nil
}

// Update updates an execution.
func (s *MemoryExecutionStore) Update(ctx context.Context, execution *Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.executions[execution.ID]; !exists {
		return fmt.Errorf("execution %s not found", execution.ID)
	}

	s.executions[execution.ID] = execution
	return nil
}

// List lists executions with optional filters.
func (s *MemoryExecutionStore) List(ctx context.Context, filter *ExecutionFilter) (*ExecutionListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*Execution

	for _, exec := range s.executions {
		if s.matchesExecutionFilter(exec, filter) {
			filtered = append(filtered, exec)
		}
	}

	total := int64(len(filtered))
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset

	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return &ExecutionListResult{
		Executions: filtered[start:end],
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		HasMore:    end < len(filtered),
	}, nil
}

func (s *MemoryExecutionStore) matchesExecutionFilter(exec *Execution, filter *ExecutionFilter) bool {
	if filter == nil {
		return true
	}

	if filter.PlaybookID != "" && exec.PlaybookID != filter.PlaybookID {
		return false
	}

	if filter.AlertID != "" && exec.AlertID != filter.AlertID {
		return false
	}

	if filter.CaseID != "" && exec.CaseID != filter.CaseID {
		return false
	}

	if filter.TenantID != "" && exec.TenantID != filter.TenantID {
		return false
	}

	if len(filter.Status) > 0 {
		found := false
		for _, s := range filter.Status {
			if exec.Status == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// GetByWorkflowID retrieves an execution by Temporal workflow ID.
func (s *MemoryExecutionStore) GetByWorkflowID(ctx context.Context, workflowID string) (*Execution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	execID, exists := s.byWorkflow[workflowID]
	if !exists {
		return nil, fmt.Errorf("execution with workflow ID %s not found", workflowID)
	}

	return s.executions[execID], nil
}

// AddStepResult adds a step result to an execution.
func (s *MemoryExecutionStore) AddStepResult(ctx context.Context, executionID string, result *StepResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	exec, exists := s.executions[executionID]
	if !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	exec.StepResults = append(exec.StepResults, *result)
	exec.CurrentStep = result.StepID
	return nil
}

// UpdateStatus updates the execution status.
func (s *MemoryExecutionStore) UpdateStatus(ctx context.Context, id string, status ExecutionStatus, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	exec, exists := s.executions[id]
	if !exists {
		return fmt.Errorf("execution %s not found", id)
	}

	exec.Status = status
	exec.Error = errMsg

	if status == StatusCompleted || status == StatusFailed || status == StatusCancelled {
		now := time.Now()
		exec.CompletedAt = &now
	}

	return nil
}
