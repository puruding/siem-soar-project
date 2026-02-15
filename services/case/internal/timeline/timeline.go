// Package timeline provides timeline management for cases.
package timeline

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of timeline event.
type EventType string

const (
	// Case events
	EventCaseCreated        EventType = "case_created"
	EventCaseUpdated        EventType = "case_updated"
	EventCaseAssigned       EventType = "case_assigned"
	EventCaseStatusChanged  EventType = "case_status_changed"
	EventCaseSeverityChanged EventType = "case_severity_changed"
	EventCaseClosed         EventType = "case_closed"
	EventCaseReopened       EventType = "case_reopened"
	EventCaseMerged         EventType = "case_merged"

	// Evidence events
	EventEvidenceAdded      EventType = "evidence_added"
	EventEvidenceRemoved    EventType = "evidence_removed"

	// Task events
	EventTaskCreated        EventType = "task_created"
	EventTaskCompleted      EventType = "task_completed"
	EventTaskAssigned       EventType = "task_assigned"

	// Comment events
	EventCommentAdded       EventType = "comment_added"

	// Playbook events
	EventPlaybookTriggered  EventType = "playbook_triggered"
	EventPlaybookCompleted  EventType = "playbook_completed"
	EventPlaybookFailed     EventType = "playbook_failed"

	// Alert events
	EventAlertLinked        EventType = "alert_linked"
	EventAlertUnlinked      EventType = "alert_unlinked"

	// External events
	EventTicketCreated      EventType = "ticket_created"
	EventTicketUpdated      EventType = "ticket_updated"
	EventNotificationSent   EventType = "notification_sent"

	// Security events (from alerts/logs)
	EventSecurityDetection  EventType = "security_detection"
	EventSecurityActivity   EventType = "security_activity"
	EventNetworkConnection  EventType = "network_connection"
	EventProcessExecution   EventType = "process_execution"
	EventFileActivity       EventType = "file_activity"
	EventUserActivity       EventType = "user_activity"

	// Custom events
	EventCustom             EventType = "custom"
)

// EventSource represents where the event originated.
type EventSource string

const (
	SourceSystem       EventSource = "system"
	SourceUser         EventSource = "user"
	SourcePlaybook     EventSource = "playbook"
	SourceAlert        EventSource = "alert"
	SourceSIEM         EventSource = "siem"
	SourceEDR          EventSource = "edr"
	SourceExternal     EventSource = "external"
)

// Event represents a timeline event.
type Event struct {
	ID          string                 `json:"id"`
	CaseID      string                 `json:"case_id"`
	Type        EventType              `json:"type"`
	Source      EventSource            `json:"source"`
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Actor       string                 `json:"actor,omitempty"`
	ActorName   string                 `json:"actor_name,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Severity    string                 `json:"severity,omitempty"` // info, warning, error, critical
	EntityType  string                 `json:"entity_type,omitempty"` // ip, user, host, file, etc.
	EntityValue string                 `json:"entity_value,omitempty"`
	LinkedID    string                 `json:"linked_id,omitempty"` // ID of related object (evidence, task, etc.)
	LinkedType  string                 `json:"linked_type,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	TenantID    string                 `json:"tenant_id,omitempty"`
}

// CreateEventRequest represents a request to create an event.
type CreateEventRequest struct {
	Type        EventType              `json:"type" validate:"required"`
	Source      EventSource            `json:"source" validate:"required"`
	Title       string                 `json:"title" validate:"required"`
	Description string                 `json:"description,omitempty"`
	Timestamp   *time.Time             `json:"timestamp,omitempty"` // Defaults to now if not provided
	Data        map[string]interface{} `json:"data,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	EntityType  string                 `json:"entity_type,omitempty"`
	EntityValue string                 `json:"entity_value,omitempty"`
	LinkedID    string                 `json:"linked_id,omitempty"`
	LinkedType  string                 `json:"linked_type,omitempty"`
}

// EventFilter defines filters for listing events.
type EventFilter struct {
	CaseID      string      `json:"case_id,omitempty"`
	Types       []EventType `json:"types,omitempty"`
	Sources     []EventSource `json:"sources,omitempty"`
	StartTime   *time.Time  `json:"start_time,omitempty"`
	EndTime     *time.Time  `json:"end_time,omitempty"`
	Actor       string      `json:"actor,omitempty"`
	EntityType  string      `json:"entity_type,omitempty"`
	EntityValue string      `json:"entity_value,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Search      string      `json:"search,omitempty"`
	Limit       int         `json:"limit,omitempty"`
	Offset      int         `json:"offset,omitempty"`
	SortOrder   string      `json:"sort_order,omitempty"` // asc, desc
}

// EventListResult contains paginated event results.
type EventListResult struct {
	Events  []*Event `json:"events"`
	Total   int64    `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
	HasMore bool     `json:"has_more"`
}

// Timeline represents the full timeline for a case.
type Timeline struct {
	CaseID     string    `json:"case_id"`
	Events     []*Event  `json:"events"`
	FirstEvent time.Time `json:"first_event"`
	LastEvent  time.Time `json:"last_event"`
	TotalCount int       `json:"total_count"`
}

// TimelineService manages timeline operations.
type TimelineService struct {
	store Store
}

// Store defines the interface for timeline storage.
type Store interface {
	Create(ctx context.Context, event *Event) error
	Get(ctx context.Context, id string) (*Event, error)
	List(ctx context.Context, filter *EventFilter) (*EventListResult, error)
	Delete(ctx context.Context, id string) error
	GetTimeline(ctx context.Context, caseID string, filter *EventFilter) (*Timeline, error)
}

// NewTimelineService creates a new timeline service.
func NewTimelineService(store Store) *TimelineService {
	return &TimelineService{store: store}
}

// AddEvent adds an event to the timeline.
func (s *TimelineService) AddEvent(ctx context.Context, caseID string, req *CreateEventRequest, actor string) (*Event, error) {
	event := &Event{
		ID:          uuid.New().String(),
		CaseID:      caseID,
		Type:        req.Type,
		Source:      req.Source,
		Title:       req.Title,
		Description: req.Description,
		Timestamp:   time.Now(),
		Actor:       actor,
		Data:        req.Data,
		Tags:        req.Tags,
		Severity:    req.Severity,
		EntityType:  req.EntityType,
		EntityValue: req.EntityValue,
		LinkedID:    req.LinkedID,
		LinkedType:  req.LinkedType,
		CreatedAt:   time.Now(),
	}

	if req.Timestamp != nil {
		event.Timestamp = *req.Timestamp
	}

	if err := s.store.Create(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to create event: %w", err)
	}

	return event, nil
}

// GetEvent retrieves an event by ID.
func (s *TimelineService) GetEvent(ctx context.Context, id string) (*Event, error) {
	return s.store.Get(ctx, id)
}

// ListEvents lists events with filters.
func (s *TimelineService) ListEvents(ctx context.Context, filter *EventFilter) (*EventListResult, error) {
	return s.store.List(ctx, filter)
}

// GetTimeline retrieves the full timeline for a case.
func (s *TimelineService) GetTimeline(ctx context.Context, caseID string, filter *EventFilter) (*Timeline, error) {
	if filter == nil {
		filter = &EventFilter{}
	}
	filter.CaseID = caseID
	return s.store.GetTimeline(ctx, caseID, filter)
}

// DeleteEvent deletes an event.
func (s *TimelineService) DeleteEvent(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// MemoryStore implements an in-memory timeline store.
type MemoryStore struct {
	mu     sync.RWMutex
	events map[string]*Event
	byCase map[string][]string // caseID -> event IDs
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		events: make(map[string]*Event),
		byCase: make(map[string][]string),
	}
}

// Create creates a new event.
func (s *MemoryStore) Create(ctx context.Context, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events[event.ID] = event
	s.byCase[event.CaseID] = append(s.byCase[event.CaseID], event.ID)

	return nil
}

// Get retrieves an event by ID.
func (s *MemoryStore) Get(ctx context.Context, id string) (*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	event, exists := s.events[id]
	if !exists {
		return nil, fmt.Errorf("event %s not found", id)
	}

	return event, nil
}

// List lists events with filters.
func (s *MemoryStore) List(ctx context.Context, filter *EventFilter) (*EventListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*Event

	for _, event := range s.events {
		if s.matchesFilter(event, filter) {
			filtered = append(filtered, event)
		}
	}

	// Sort by timestamp
	sortOrder := "desc"
	if filter != nil && filter.SortOrder != "" {
		sortOrder = filter.SortOrder
	}

	sort.Slice(filtered, func(i, j int) bool {
		if sortOrder == "asc" {
			return filtered[i].Timestamp.Before(filtered[j].Timestamp)
		}
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	// Apply pagination
	total := int64(len(filtered))
	limit := 100
	offset := 0

	if filter != nil {
		if filter.Limit > 0 {
			limit = filter.Limit
		}
		offset = filter.Offset
	}

	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return &EventListResult{
		Events:  filtered[start:end],
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: end < len(filtered),
	}, nil
}

// matchesFilter checks if an event matches the filter criteria.
func (s *MemoryStore) matchesFilter(event *Event, filter *EventFilter) bool {
	if filter == nil {
		return true
	}

	if filter.CaseID != "" && event.CaseID != filter.CaseID {
		return false
	}

	if len(filter.Types) > 0 {
		found := false
		for _, t := range filter.Types {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.Sources) > 0 {
		found := false
		for _, src := range filter.Sources {
			if event.Source == src {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	if filter.Actor != "" && event.Actor != filter.Actor {
		return false
	}

	if filter.EntityType != "" && event.EntityType != filter.EntityType {
		return false
	}

	if filter.EntityValue != "" && event.EntityValue != filter.EntityValue {
		return false
	}

	return true
}

// Delete deletes an event.
func (s *MemoryStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	event, exists := s.events[id]
	if !exists {
		return fmt.Errorf("event %s not found", id)
	}

	delete(s.events, id)

	// Remove from case index
	caseEvents := s.byCase[event.CaseID]
	for i, eid := range caseEvents {
		if eid == id {
			s.byCase[event.CaseID] = append(caseEvents[:i], caseEvents[i+1:]...)
			break
		}
	}

	return nil
}

// GetTimeline retrieves the full timeline for a case.
func (s *MemoryStore) GetTimeline(ctx context.Context, caseID string, filter *EventFilter) (*Timeline, error) {
	result, err := s.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	timeline := &Timeline{
		CaseID:     caseID,
		Events:     result.Events,
		TotalCount: int(result.Total),
	}

	if len(result.Events) > 0 {
		timeline.FirstEvent = result.Events[len(result.Events)-1].Timestamp
		timeline.LastEvent = result.Events[0].Timestamp
	}

	return timeline, nil
}

// Builder helps build timeline events programmatically.
type Builder struct {
	service *TimelineService
	caseID  string
	actor   string
}

// NewBuilder creates a new timeline builder.
func NewBuilder(service *TimelineService, caseID, actor string) *Builder {
	return &Builder{
		service: service,
		caseID:  caseID,
		actor:   actor,
	}
}

// AddCaseCreated adds a case created event.
func (b *Builder) AddCaseCreated(ctx context.Context, title, severity string) (*Event, error) {
	return b.service.AddEvent(ctx, b.caseID, &CreateEventRequest{
		Type:     EventCaseCreated,
		Source:   SourceSystem,
		Title:    fmt.Sprintf("Case created: %s", title),
		Severity: severity,
		Data: map[string]interface{}{
			"title": title,
		},
	}, b.actor)
}

// AddStatusChange adds a status change event.
func (b *Builder) AddStatusChange(ctx context.Context, oldStatus, newStatus string) (*Event, error) {
	return b.service.AddEvent(ctx, b.caseID, &CreateEventRequest{
		Type:     EventCaseStatusChanged,
		Source:   SourceUser,
		Title:    fmt.Sprintf("Status changed from %s to %s", oldStatus, newStatus),
		Severity: "info",
		Data: map[string]interface{}{
			"old_status": oldStatus,
			"new_status": newStatus,
		},
	}, b.actor)
}

// AddEvidenceAdded adds an evidence added event.
func (b *Builder) AddEvidenceAdded(ctx context.Context, evidenceName, evidenceID, evidenceType string) (*Event, error) {
	return b.service.AddEvent(ctx, b.caseID, &CreateEventRequest{
		Type:       EventEvidenceAdded,
		Source:     SourceUser,
		Title:      fmt.Sprintf("Evidence added: %s", evidenceName),
		Severity:   "info",
		LinkedID:   evidenceID,
		LinkedType: "evidence",
		Data: map[string]interface{}{
			"evidence_type": evidenceType,
		},
	}, b.actor)
}

// AddPlaybookTriggered adds a playbook triggered event.
func (b *Builder) AddPlaybookTriggered(ctx context.Context, playbookName, executionID string) (*Event, error) {
	return b.service.AddEvent(ctx, b.caseID, &CreateEventRequest{
		Type:       EventPlaybookTriggered,
		Source:     SourcePlaybook,
		Title:      fmt.Sprintf("Playbook triggered: %s", playbookName),
		Severity:   "info",
		LinkedID:   executionID,
		LinkedType: "playbook_execution",
		Data: map[string]interface{}{
			"playbook_name": playbookName,
		},
	}, b.actor)
}

// AddSecurityEvent adds a security detection event.
func (b *Builder) AddSecurityEvent(ctx context.Context, title, entityType, entityValue string, timestamp time.Time, data map[string]interface{}) (*Event, error) {
	return b.service.AddEvent(ctx, b.caseID, &CreateEventRequest{
		Type:        EventSecurityDetection,
		Source:      SourceSIEM,
		Title:       title,
		Timestamp:   &timestamp,
		Severity:    "warning",
		EntityType:  entityType,
		EntityValue: entityValue,
		Data:        data,
	}, b.actor)
}
