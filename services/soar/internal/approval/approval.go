// Package approval provides approval workflow management.
package approval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RequestStatus represents the status of an approval request.
type RequestStatus string

const (
	StatusPending   RequestStatus = "pending"
	StatusApproved  RequestStatus = "approved"
	StatusRejected  RequestStatus = "rejected"
	StatusExpired   RequestStatus = "expired"
	StatusCancelled RequestStatus = "cancelled"
	StatusEscalated RequestStatus = "escalated"
)

// ApprovalType represents the type of approval required.
type ApprovalType string

const (
	TypeSingleApprover   ApprovalType = "single"
	TypeAnyApprover      ApprovalType = "any"
	TypeAllApprovers     ApprovalType = "all"
	TypeMajorityApprovers ApprovalType = "majority"
	TypeQuorum           ApprovalType = "quorum"
)

// Request represents an approval request.
type Request struct {
	ID             string        `json:"id"`
	WorkflowID     string        `json:"workflow_id"` // Temporal workflow ID
	RunID          string        `json:"run_id"`
	StepID         string        `json:"step_id"`
	ExecutionID    string        `json:"execution_id"` // Playbook execution ID
	Type           ApprovalType  `json:"type"`
	Status         RequestStatus `json:"status"`
	Title          string        `json:"title"`
	Description    string        `json:"description"`

	// Approvers
	Approvers        []string `json:"approvers"`
	ApproverGroups   []string `json:"approver_groups,omitempty"`
	RequiredCount    int      `json:"required_count"`

	// Responses
	Responses        []Response `json:"responses"`
	ApprovedCount    int        `json:"approved_count"`
	RejectedCount    int        `json:"rejected_count"`

	// Context
	Context          map[string]interface{} `json:"context,omitempty"`
	AlertID          string                 `json:"alert_id,omitempty"`
	CaseID           string                 `json:"case_id,omitempty"`
	PlaybookName     string                 `json:"playbook_name,omitempty"`

	// Actions
	AvailableActions []Action `json:"available_actions"`

	// Timing
	Timeout          time.Duration `json:"timeout"`
	CreatedAt        time.Time     `json:"created_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	CompletedAt      *time.Time    `json:"completed_at,omitempty"`

	// Escalation
	EscalationLevel  int           `json:"escalation_level"`
	EscalatedAt      *time.Time    `json:"escalated_at,omitempty"`
	EscalatedTo      []string      `json:"escalated_to,omitempty"`

	// Metadata
	TenantID         string `json:"tenant_id,omitempty"`
	CreatedBy        string `json:"created_by"`
	Priority         string `json:"priority,omitempty"` // low, medium, high, critical
}

// Response represents an approver's response.
type Response struct {
	ID           string    `json:"id"`
	RequestID    string    `json:"request_id"`
	Approver     string    `json:"approver"`
	ApproverName string    `json:"approver_name,omitempty"`
	ApproverEmail string   `json:"approver_email,omitempty"`
	Action       string    `json:"action"` // approve, reject, or custom action name
	Approved     bool      `json:"approved"`
	Comment      string    `json:"comment,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// Action represents a possible approval action.
type Action struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Style       string `json:"style,omitempty"` // primary, danger, warning, secondary
	IsApproval  bool   `json:"is_approval"`     // true for approve-like actions, false for reject-like
	RequiresComment bool `json:"requires_comment,omitempty"`
}

// DefaultActions returns the default approval actions.
func DefaultActions() []Action {
	return []Action{
		{
			Name:       "approve",
			Label:      "Approve",
			Style:      "primary",
			IsApproval: true,
		},
		{
			Name:       "reject",
			Label:      "Reject",
			Style:      "danger",
			IsApproval: false,
		},
	}
}

// CreateRequestInput represents input for creating an approval request.
type CreateRequestInput struct {
	WorkflowID       string                 `json:"workflow_id" validate:"required"`
	RunID            string                 `json:"run_id"`
	StepID           string                 `json:"step_id" validate:"required"`
	ExecutionID      string                 `json:"execution_id"`
	Type             ApprovalType           `json:"type" validate:"required"`
	Title            string                 `json:"title" validate:"required"`
	Description      string                 `json:"description"`
	Approvers        []string               `json:"approvers" validate:"required,min=1"`
	ApproverGroups   []string               `json:"approver_groups,omitempty"`
	RequiredCount    int                    `json:"required_count,omitempty"`
	Context          map[string]interface{} `json:"context,omitempty"`
	AlertID          string                 `json:"alert_id,omitempty"`
	CaseID           string                 `json:"case_id,omitempty"`
	PlaybookName     string                 `json:"playbook_name,omitempty"`
	Timeout          time.Duration          `json:"timeout" validate:"required"`
	Actions          []Action               `json:"actions,omitempty"`
	Priority         string                 `json:"priority,omitempty"`
	EscalationConfig *EscalationConfig      `json:"escalation_config,omitempty"`
}

// EscalationConfig defines escalation rules.
type EscalationConfig struct {
	Enabled         bool          `json:"enabled"`
	Timeout         time.Duration `json:"timeout"`
	Escalators      []string      `json:"escalators"`
	MaxLevels       int           `json:"max_levels"`
	NotifyOriginal  bool          `json:"notify_original"` // Notify original approvers on escalation
}

// RespondInput represents input for responding to an approval request.
type RespondInput struct {
	RequestID string `json:"request_id" validate:"required"`
	Approver  string `json:"approver" validate:"required"`
	Action    string `json:"action" validate:"required"`
	Comment   string `json:"comment,omitempty"`
}

// RequestFilter defines filters for listing requests.
type RequestFilter struct {
	Status         []RequestStatus `json:"status,omitempty"`
	Approver       string          `json:"approver,omitempty"`
	WorkflowID     string          `json:"workflow_id,omitempty"`
	ExecutionID    string          `json:"execution_id,omitempty"`
	AlertID        string          `json:"alert_id,omitempty"`
	CaseID         string          `json:"case_id,omitempty"`
	Priority       string          `json:"priority,omitempty"`
	TenantID       string          `json:"tenant_id,omitempty"`
	IncludeExpired bool            `json:"include_expired,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Offset         int             `json:"offset,omitempty"`
}

// RequestListResult contains paginated request results.
type RequestListResult struct {
	Requests []*Request `json:"requests"`
	Total    int64      `json:"total"`
	Limit    int        `json:"limit"`
	Offset   int        `json:"offset"`
	HasMore  bool       `json:"has_more"`
}

// Service manages approval workflows.
type Service struct {
	store        Store
	notifier     Notifier
	signalSender SignalSender
	mu           sync.RWMutex
}

// Store defines the interface for approval storage.
type Store interface {
	Create(ctx context.Context, request *Request) error
	Get(ctx context.Context, id string) (*Request, error)
	Update(ctx context.Context, request *Request) error
	List(ctx context.Context, filter *RequestFilter) (*RequestListResult, error)
	GetByWorkflow(ctx context.Context, workflowID, stepID string) (*Request, error)
	AddResponse(ctx context.Context, requestID string, response *Response) error
}

// Notifier sends approval notifications.
type Notifier interface {
	SendApprovalRequest(ctx context.Context, approver string, request *Request) error
	SendApprovalReminder(ctx context.Context, approver string, request *Request) error
	SendApprovalResult(ctx context.Context, request *Request) error
	SendEscalationNotice(ctx context.Context, escalators []string, request *Request) error
}

// SignalSender sends signals to Temporal workflows.
type SignalSender interface {
	SendApprovalSignal(ctx context.Context, workflowID, runID string, response *Response) error
}

// NewService creates a new approval service.
func NewService(store Store, notifier Notifier, signalSender SignalSender) *Service {
	return &Service{
		store:        store,
		notifier:     notifier,
		signalSender: signalSender,
	}
}

// CreateRequest creates a new approval request.
func (s *Service) CreateRequest(ctx context.Context, input *CreateRequestInput, createdBy string) (*Request, error) {
	// Validate required count
	requiredCount := input.RequiredCount
	if requiredCount <= 0 {
		switch input.Type {
		case TypeSingleApprover, TypeAnyApprover:
			requiredCount = 1
		case TypeAllApprovers:
			requiredCount = len(input.Approvers)
		case TypeMajorityApprovers:
			requiredCount = len(input.Approvers)/2 + 1
		case TypeQuorum:
			requiredCount = len(input.Approvers) / 2
		}
	}

	actions := input.Actions
	if len(actions) == 0 {
		actions = DefaultActions()
	}

	now := time.Now()
	request := &Request{
		ID:               uuid.New().String(),
		WorkflowID:       input.WorkflowID,
		RunID:            input.RunID,
		StepID:           input.StepID,
		ExecutionID:      input.ExecutionID,
		Type:             input.Type,
		Status:           StatusPending,
		Title:            input.Title,
		Description:      input.Description,
		Approvers:        input.Approvers,
		ApproverGroups:   input.ApproverGroups,
		RequiredCount:    requiredCount,
		Responses:        make([]Response, 0),
		Context:          input.Context,
		AlertID:          input.AlertID,
		CaseID:           input.CaseID,
		PlaybookName:     input.PlaybookName,
		AvailableActions: actions,
		Timeout:          input.Timeout,
		CreatedAt:        now,
		ExpiresAt:        now.Add(input.Timeout),
		Priority:         input.Priority,
		CreatedBy:        createdBy,
	}

	if err := s.store.Create(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	// Send notifications to approvers
	for _, approver := range input.Approvers {
		if err := s.notifier.SendApprovalRequest(ctx, approver, request); err != nil {
			// Log error but don't fail
			fmt.Printf("Failed to send notification to %s: %v\n", approver, err)
		}
	}

	return request, nil
}

// Respond processes an approver's response.
func (s *Service) Respond(ctx context.Context, input *RespondInput) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, err := s.store.Get(ctx, input.RequestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get approval request: %w", err)
	}

	// Check if request is still pending
	if request.Status != StatusPending && request.Status != StatusEscalated {
		return nil, fmt.Errorf("approval request is no longer pending (status: %s)", request.Status)
	}

	// Check if request has expired
	if time.Now().After(request.ExpiresAt) {
		request.Status = StatusExpired
		if err := s.store.Update(ctx, request); err != nil {
			return nil, fmt.Errorf("failed to update expired request: %w", err)
		}
		return nil, fmt.Errorf("approval request has expired")
	}

	// Check if approver is authorized
	authorized := false
	for _, approver := range request.Approvers {
		if approver == input.Approver {
			authorized = true
			break
		}
	}
	if !authorized {
		for _, approver := range request.EscalatedTo {
			if approver == input.Approver {
				authorized = true
				break
			}
		}
	}
	if !authorized {
		return nil, fmt.Errorf("user %s is not authorized to respond to this request", input.Approver)
	}

	// Check if approver has already responded
	for _, resp := range request.Responses {
		if resp.Approver == input.Approver {
			return nil, fmt.Errorf("approver %s has already responded", input.Approver)
		}
	}

	// Find the action
	var action *Action
	for _, a := range request.AvailableActions {
		if a.Name == input.Action {
			action = &a
			break
		}
	}
	if action == nil {
		return nil, fmt.Errorf("invalid action: %s", input.Action)
	}

	// Create response
	response := &Response{
		ID:        uuid.New().String(),
		RequestID: input.RequestID,
		Approver:  input.Approver,
		Action:    input.Action,
		Approved:  action.IsApproval,
		Comment:   input.Comment,
		Timestamp: time.Now(),
	}

	// Add response
	if err := s.store.AddResponse(ctx, input.RequestID, response); err != nil {
		return nil, fmt.Errorf("failed to add response: %w", err)
	}

	// Update counts
	request.Responses = append(request.Responses, *response)
	if action.IsApproval {
		request.ApprovedCount++
	} else {
		request.RejectedCount++
	}

	// Check if approval is complete
	completed := false
	var finalStatus RequestStatus

	switch request.Type {
	case TypeSingleApprover, TypeAnyApprover:
		if request.ApprovedCount >= 1 {
			completed = true
			finalStatus = StatusApproved
		} else if request.RejectedCount >= 1 {
			completed = true
			finalStatus = StatusRejected
		}

	case TypeAllApprovers:
		if request.RejectedCount >= 1 {
			completed = true
			finalStatus = StatusRejected
		} else if request.ApprovedCount >= len(request.Approvers) {
			completed = true
			finalStatus = StatusApproved
		}

	case TypeMajorityApprovers, TypeQuorum:
		if request.ApprovedCount >= request.RequiredCount {
			completed = true
			finalStatus = StatusApproved
		} else {
			remaining := len(request.Approvers) - len(request.Responses)
			if request.ApprovedCount+remaining < request.RequiredCount {
				completed = true
				finalStatus = StatusRejected
			}
		}
	}

	if completed {
		now := time.Now()
		request.Status = finalStatus
		request.CompletedAt = &now

		// Send signal to workflow
		if err := s.signalSender.SendApprovalSignal(ctx, request.WorkflowID, request.RunID, response); err != nil {
			return nil, fmt.Errorf("failed to send approval signal: %w", err)
		}

		// Send completion notification
		if err := s.notifier.SendApprovalResult(ctx, request); err != nil {
			fmt.Printf("Failed to send result notification: %v\n", err)
		}
	}

	if err := s.store.Update(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to update request: %w", err)
	}

	return request, nil
}

// GetRequest retrieves an approval request by ID.
func (s *Service) GetRequest(ctx context.Context, id string) (*Request, error) {
	return s.store.Get(ctx, id)
}

// ListRequests lists approval requests with filters.
func (s *Service) ListRequests(ctx context.Context, filter *RequestFilter) (*RequestListResult, error) {
	return s.store.List(ctx, filter)
}

// GetPendingForApprover gets pending requests for an approver.
func (s *Service) GetPendingForApprover(ctx context.Context, approver string) (*RequestListResult, error) {
	return s.store.List(ctx, &RequestFilter{
		Status:   []RequestStatus{StatusPending, StatusEscalated},
		Approver: approver,
	})
}

// CancelRequest cancels an approval request.
func (s *Service) CancelRequest(ctx context.Context, id string, cancelledBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if request.Status != StatusPending && request.Status != StatusEscalated {
		return fmt.Errorf("cannot cancel request with status %s", request.Status)
	}

	now := time.Now()
	request.Status = StatusCancelled
	request.CompletedAt = &now

	if err := s.store.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update request: %w", err)
	}

	// Send cancellation signal to workflow
	response := &Response{
		ID:        uuid.New().String(),
		RequestID: id,
		Approver:  cancelledBy,
		Action:    "cancel",
		Approved:  false,
		Comment:   "Request cancelled",
		Timestamp: now,
	}

	return s.signalSender.SendApprovalSignal(ctx, request.WorkflowID, request.RunID, response)
}

// Escalate escalates an approval request.
func (s *Service) Escalate(ctx context.Context, id string, escalators []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if request.Status != StatusPending {
		return fmt.Errorf("cannot escalate request with status %s", request.Status)
	}

	now := time.Now()
	request.Status = StatusEscalated
	request.EscalationLevel++
	request.EscalatedAt = &now
	request.EscalatedTo = escalators

	if err := s.store.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update request: %w", err)
	}

	// Send escalation notifications
	if err := s.notifier.SendEscalationNotice(ctx, escalators, request); err != nil {
		fmt.Printf("Failed to send escalation notice: %v\n", err)
	}

	return nil
}

// CheckExpired checks for and marks expired requests.
func (s *Service) CheckExpired(ctx context.Context) (int, error) {
	result, err := s.store.List(ctx, &RequestFilter{
		Status: []RequestStatus{StatusPending, StatusEscalated},
	})
	if err != nil {
		return 0, err
	}

	expiredCount := 0
	now := time.Now()

	for _, request := range result.Requests {
		if now.After(request.ExpiresAt) {
			request.Status = StatusExpired
			request.CompletedAt = &now

			if err := s.store.Update(ctx, request); err != nil {
				fmt.Printf("Failed to mark request %s as expired: %v\n", request.ID, err)
				continue
			}

			// Send timeout signal to workflow
			response := &Response{
				ID:        uuid.New().String(),
				RequestID: request.ID,
				Approver:  "system",
				Action:    "timeout",
				Approved:  false,
				Comment:   "Request expired",
				Timestamp: now,
			}

			if err := s.signalSender.SendApprovalSignal(ctx, request.WorkflowID, request.RunID, response); err != nil {
				fmt.Printf("Failed to send timeout signal for request %s: %v\n", request.ID, err)
			}

			expiredCount++
		}
	}

	return expiredCount, nil
}
