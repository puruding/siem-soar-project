// Package service provides business logic for case management.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/case/internal/model"
	"github.com/siem-soar-platform/services/case/internal/repository"
	"github.com/siem-soar-platform/services/case/internal/timeline"
)

// CaseService provides case management operations.
type CaseService struct {
	repo            *repository.CaseRepository
	timelineService *timeline.TimelineService
}

// NewCaseService creates a new case service.
func NewCaseService(repo *repository.CaseRepository, timelineService *timeline.TimelineService) *CaseService {
	return &CaseService{
		repo:            repo,
		timelineService: timelineService,
	}
}

// CreateCase creates a new security case.
func (s *CaseService) CreateCase(ctx context.Context, req *model.CreateCaseRequest, createdBy string) (*model.Case, error) {
	// Validate request
	if req.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("type is required")
	}
	if req.Severity == "" {
		return nil, fmt.Errorf("severity is required")
	}

	// Generate case ID and number
	caseID := uuid.New().String()
	caseNumber := s.generateCaseNumber()

	// Set default priority if not provided
	priority := req.Priority
	if priority == "" {
		priority = s.calculatePriority(req.Severity)
	}

	// Calculate SLA deadline if not provided
	slaDeadline := req.SLADeadline
	if slaDeadline == nil {
		deadline := s.calculateSLADeadline(req.Severity)
		slaDeadline = &deadline
	}

	now := time.Now()

	caseObj := &model.Case{
		ID:             caseID,
		Number:         caseNumber,
		Title:          req.Title,
		Description:    req.Description,
		Type:           req.Type,
		Severity:       req.Severity,
		Priority:       priority,
		Status:         model.StatusNew,
		Assignee:       req.Assignee,
		Team:           req.Team,
		AlertIDs:       req.AlertIDs,
		Tags:           req.Tags,
		Labels:         req.Labels,
		Tactics:        req.Tactics,
		Techniques:     req.Techniques,
		AffectedAssets: req.AffectedAssets,
		AffectedUsers:  req.AffectedUsers,
		SLADeadline:    slaDeadline,
		CustomFields:   req.CustomFields,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      createdBy,
	}

	// Create case in database
	err := s.repo.Create(ctx, caseObj)
	if err != nil {
		return nil, fmt.Errorf("failed to create case: %w", err)
	}

	// Add creation history
	history := &model.CaseHistory{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Action:    "created",
		Actor:     createdBy,
		Timestamp: now,
		Metadata: map[string]interface{}{
			"severity": req.Severity,
			"type":     req.Type,
		},
	}
	_ = s.repo.AddHistory(ctx, history)

	return caseObj, nil
}

// GetCase retrieves a case by ID.
func (s *CaseService) GetCase(ctx context.Context, id string) (*model.Case, error) {
	return s.repo.Get(ctx, id)
}

// UpdateCase updates an existing case.
func (s *CaseService) UpdateCase(ctx context.Context, id string, req *model.UpdateCaseRequest, updatedBy string) (*model.Case, error) {
	// Get existing case
	caseObj, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Title != nil {
		caseObj.Title = *req.Title
	}
	if req.Description != nil {
		caseObj.Description = *req.Description
	}
	if req.Severity != nil {
		caseObj.Severity = *req.Severity
		// Recalculate priority and SLA
		caseObj.Priority = s.calculatePriority(*req.Severity)
		deadline := s.calculateSLADeadline(*req.Severity)
		caseObj.SLADeadline = &deadline
	}
	if req.Priority != nil {
		caseObj.Priority = *req.Priority
	}
	if req.Status != nil {
		oldStatus := caseObj.Status
		caseObj.Status = *req.Status

		// Handle status transitions
		if *req.Status == model.StatusResolved {
			now := time.Now()
			caseObj.ResolvedAt = &now
			caseObj.ResolvedBy = updatedBy
			// Calculate resolution time
			caseObj.ResolutionTime = int64(now.Sub(caseObj.CreatedAt).Minutes())
		}
		if *req.Status == model.StatusClosed {
			now := time.Now()
			caseObj.ClosedAt = &now
			caseObj.ClosedBy = updatedBy
		}
		if *req.Status == model.StatusReopened && oldStatus == model.StatusClosed {
			caseObj.ClosedAt = nil
			caseObj.ClosedBy = ""
		}
	}
	if req.Assignee != nil {
		oldAssignee := caseObj.Assignee
		caseObj.Assignee = *req.Assignee
		if oldAssignee != *req.Assignee {
			s.recordHistory(ctx, id, "assigned", "assignee", oldAssignee, *req.Assignee, updatedBy)
		}
	}
	if req.Team != nil {
		caseObj.Team = *req.Team
	}
	if req.Classification != nil {
		caseObj.Classification = *req.Classification
	}
	if req.ClassificationReason != nil {
		caseObj.ClassificationReason = *req.ClassificationReason
	}
	if req.Tags != nil {
		caseObj.Tags = req.Tags
	}
	if req.Labels != nil {
		caseObj.Labels = req.Labels
	}
	if req.Tactics != nil {
		caseObj.Tactics = req.Tactics
	}
	if req.Techniques != nil {
		caseObj.Techniques = req.Techniques
	}
	if req.Resolution != nil {
		caseObj.Resolution = *req.Resolution
	}
	if req.ResolutionNotes != nil {
		caseObj.ResolutionNotes = *req.ResolutionNotes
	}
	if req.RootCause != nil {
		caseObj.RootCause = *req.RootCause
	}
	if req.LessonsLearned != nil {
		caseObj.LessonsLearned = *req.LessonsLearned
	}
	if req.CustomFields != nil {
		caseObj.CustomFields = req.CustomFields
	}

	// Check SLA breach
	if caseObj.SLADeadline != nil && time.Now().After(*caseObj.SLADeadline) {
		if !caseObj.SLABreached {
			caseObj.SLABreached = true
			s.recordHistory(ctx, id, "sla_breached", "", "", "", updatedBy)
		}
	}

	caseObj.UpdatedAt = time.Now()
	caseObj.UpdatedBy = updatedBy

	// Update in database
	err = s.repo.Update(ctx, caseObj)
	if err != nil {
		return nil, fmt.Errorf("failed to update case: %w", err)
	}

	// Record update history
	s.recordHistory(ctx, id, "updated", "", "", "", updatedBy)

	return caseObj, nil
}

// DeleteCase deletes a case.
func (s *CaseService) DeleteCase(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// ListCases retrieves cases based on filter criteria.
func (s *CaseService) ListCases(ctx context.Context, filter *model.CaseFilter) (*model.CaseListResult, error) {
	return s.repo.List(ctx, filter)
}

// GetSummary retrieves case statistics.
func (s *CaseService) GetSummary(ctx context.Context, tenantID string) (*model.CaseSummary, error) {
	return s.repo.GetSummary(ctx, tenantID)
}

// AssignCase assigns a case to a user.
func (s *CaseService) AssignCase(ctx context.Context, caseID, assignee, assignedBy string) error {
	caseObj, err := s.repo.Get(ctx, caseID)
	if err != nil {
		return err
	}

	oldAssignee := caseObj.Assignee
	caseObj.Assignee = assignee
	caseObj.UpdatedAt = time.Now()
	caseObj.UpdatedBy = assignedBy

	// If case is new, move to open
	if caseObj.Status == model.StatusNew {
		caseObj.Status = model.StatusOpen
	}

	err = s.repo.Update(ctx, caseObj)
	if err != nil {
		return err
	}

	s.recordHistory(ctx, caseID, "assigned", "assignee", oldAssignee, assignee, assignedBy)

	return nil
}

// EscalateCase escalates a case severity.
func (s *CaseService) EscalateCase(ctx context.Context, caseID, reason, escalatedBy string) error {
	caseObj, err := s.repo.Get(ctx, caseID)
	if err != nil {
		return err
	}

	oldSeverity := caseObj.Severity

	// Escalate severity
	switch caseObj.Severity {
	case model.SeverityInformational:
		caseObj.Severity = model.SeverityLow
	case model.SeverityLow:
		caseObj.Severity = model.SeverityMedium
	case model.SeverityMedium:
		caseObj.Severity = model.SeverityHigh
	case model.SeverityHigh:
		caseObj.Severity = model.SeverityCritical
	default:
		return fmt.Errorf("case is already at critical severity")
	}

	// Recalculate priority and SLA
	caseObj.Priority = s.calculatePriority(caseObj.Severity)
	deadline := s.calculateSLADeadline(caseObj.Severity)
	caseObj.SLADeadline = &deadline

	caseObj.UpdatedAt = time.Now()
	caseObj.UpdatedBy = escalatedBy

	err = s.repo.Update(ctx, caseObj)
	if err != nil {
		return err
	}

	history := &model.CaseHistory{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Action:    "escalated",
		Field:     "severity",
		Actor:     escalatedBy,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"old_severity": oldSeverity,
			"new_severity": caseObj.Severity,
			"reason":       reason,
		},
	}
	_ = s.repo.AddHistory(ctx, history)

	return nil
}

// GetHistory retrieves case history.
func (s *CaseService) GetHistory(ctx context.Context, caseID string, limit int) ([]*model.CaseHistory, error) {
	return s.repo.GetHistory(ctx, caseID, limit)
}

// BuildTimeline builds a timeline for a case.
func (s *CaseService) BuildTimeline(ctx context.Context, caseID string) (*timeline.Timeline, error) {
	return s.timelineService.GetTimeline(ctx, caseID, nil)
}

// Helper methods

func (s *CaseService) generateCaseNumber() string {
	// In production, this should use a sequence or counter
	timestamp := time.Now().Format("20060102")
	random := uuid.New().String()[:8]
	return fmt.Sprintf("CASE-%s-%s", timestamp, random)
}

func (s *CaseService) calculatePriority(severity model.CaseSeverity) model.CasePriority {
	switch severity {
	case model.SeverityCritical:
		return model.PriorityP1
	case model.SeverityHigh:
		return model.PriorityP2
	case model.SeverityMedium:
		return model.PriorityP3
	default:
		return model.PriorityP4
	}
}

func (s *CaseService) calculateSLADeadline(severity model.CaseSeverity) time.Time {
	now := time.Now()
	switch severity {
	case model.SeverityCritical:
		return now.Add(1 * time.Hour) // 1 hour for critical
	case model.SeverityHigh:
		return now.Add(4 * time.Hour) // 4 hours for high
	case model.SeverityMedium:
		return now.Add(24 * time.Hour) // 24 hours for medium
	case model.SeverityLow:
		return now.Add(72 * time.Hour) // 3 days for low
	default:
		return now.Add(7 * 24 * time.Hour) // 1 week for informational
	}
}

func (s *CaseService) recordHistory(ctx context.Context, caseID, action, field, oldValue, newValue, actor string) {
	history := &model.CaseHistory{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Action:    action,
		Field:     field,
		Actor:     actor,
		Timestamp: time.Now(),
	}

	if oldValue != "" {
		history.OldValue = []byte(fmt.Sprintf(`"%s"`, oldValue))
	}
	if newValue != "" {
		history.NewValue = []byte(fmt.Sprintf(`"%s"`, newValue))
	}

	_ = s.repo.AddHistory(ctx, history)
}
