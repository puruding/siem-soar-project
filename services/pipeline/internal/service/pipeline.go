// Package service provides business logic for the pipeline service.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/siem-soar-platform/services/pipeline/config"
	"github.com/siem-soar-platform/services/pipeline/internal/model"
	"github.com/siem-soar-platform/services/pipeline/internal/repository"
)

// PipelineService handles pipeline business logic.
type PipelineService struct {
	repo   *repository.PipelineRepository
	config *config.Config
	logger *slog.Logger

	// In-memory stats for quick access
	mu    sync.RWMutex
	stats model.PipelineStats
}

// NewPipelineService creates a new pipeline service.
func NewPipelineService(repo *repository.PipelineRepository, cfg *config.Config, logger *slog.Logger) *PipelineService {
	return &PipelineService{
		repo:   repo,
		config: cfg,
		logger: logger,
	}
}

// ProcessEvent processes a pipeline event through all stages.
func (s *PipelineService) ProcessEvent(ctx context.Context, event *model.PipelineEvent) error {
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	event.Stage = model.StageEventReceive

	s.logger.Info("processing event",
		"event_id", event.ID,
		"tenant_id", event.TenantID,
		"source", event.Source,
	)

	// Stage 1: Event Receive
	if err := s.handleEventReceive(ctx, event); err != nil {
		return fmt.Errorf("event receive failed: %w", err)
	}

	// Stage 2: Classification
	if err := s.handleClassification(ctx, event); err != nil {
		s.logger.Warn("classification failed, continuing",
			"event_id", event.ID,
			"error", err,
		)
	}

	// Stage 3: Playbook Selection
	if err := s.handlePlaybookSelection(ctx, event); err != nil {
		s.logger.Warn("playbook selection failed, continuing",
			"event_id", event.ID,
			"error", err,
		)
	}

	// Stage 4: Flow Execution (if auto-response enabled and playbook matched)
	if s.config.Pipeline.EnableAutoResponse && event.PlaybookMatch != nil {
		if err := s.handleFlowExecution(ctx, event); err != nil {
			s.logger.Warn("flow execution failed",
				"event_id", event.ID,
				"error", err,
			)
		}
	}

	// Persist final state
	if s.repo != nil {
		if err := s.repo.SaveEvent(ctx, event); err != nil {
			s.logger.Error("failed to save event",
				"event_id", event.ID,
				"error", err,
			)
		}
	}

	// Update stats
	s.updateStats(event)

	return nil
}

// handleEventReceive handles the event receive stage.
func (s *PipelineService) handleEventReceive(ctx context.Context, event *model.PipelineEvent) error {
	event.Stage = model.StageEventReceive

	// Validate event data
	if event.RawLog == "" && event.Source == "" {
		return fmt.Errorf("event must have raw_log or source")
	}

	// Log audit entry
	s.logAudit(ctx, event, "EVENT_RECEIVED", model.ActorSystem,
		fmt.Sprintf("Event received from source: %s", event.Source))

	return nil
}

// handleClassification handles the classification stage.
func (s *PipelineService) handleClassification(ctx context.Context, event *model.PipelineEvent) error {
	event.Stage = model.StageClassification

	startTime := time.Now()

	// TODO: Integrate with AI classification service
	// For now, create a placeholder classification based on severity
	classification := &model.Classification{
		Method:           model.MethodHYBRID,
		MatchedRules:     make([]string, 0),
		MatchedIOCs:      make([]string, 0),
		MITRETactics:     make([]string, 0),
		MITRETechniques:  make([]string, 0),
		ProcessingTimeMs: int(time.Since(startTime).Milliseconds()),
	}

	// Simple severity-based classification
	switch event.Severity {
	case "critical", "high":
		classification.Label = "malicious"
		classification.Confidence = 0.85
	case "medium":
		classification.Label = "suspicious"
		classification.Confidence = 0.65
	default:
		classification.Label = "benign"
		classification.Confidence = 0.90
	}

	event.Classification = classification

	s.logAudit(ctx, event, "EVENT_CLASSIFIED", model.ActorAI,
		fmt.Sprintf("Classified as %s with confidence %.2f", classification.Label, classification.Confidence))

	return nil
}

// handlePlaybookSelection handles the playbook selection stage.
func (s *PipelineService) handlePlaybookSelection(ctx context.Context, event *model.PipelineEvent) error {
	event.Stage = model.StagePlaybookSelect

	// Skip if no classification or benign
	if event.Classification == nil || event.Classification.Label == "benign" {
		return nil
	}

	// TODO: Integrate with playbook matching service
	// For now, create a placeholder match for non-benign events
	if event.Classification.Label == "malicious" {
		event.PlaybookMatch = &model.PlaybookMatch{
			PlaybookID:   "pb-auto-response-001",
			PlaybookName: "Automated Threat Response",
			MatchScore:   0.75,
			TriggerTags:  []string{"threat", "auto-response"},
			StepCount:    5,
		}

		s.logAudit(ctx, event, "PLAYBOOK_MATCHED", model.ActorSOAR,
			fmt.Sprintf("Matched playbook: %s (score: %.2f)", event.PlaybookMatch.PlaybookName, event.PlaybookMatch.MatchScore))
	}

	return nil
}

// handleFlowExecution handles the flow execution stage.
func (s *PipelineService) handleFlowExecution(ctx context.Context, event *model.PipelineEvent) error {
	event.Stage = model.StageFlowExecution

	if event.PlaybookMatch == nil {
		return nil
	}

	// Create execution status
	event.Execution = &model.ExecutionStatus{
		ExecutionID: fmt.Sprintf("exec-%s-%d", event.ID, time.Now().UnixMilli()),
		Status:      model.StatusPending,
		CurrentStep: 0,
		TotalSteps:  event.PlaybookMatch.StepCount,
		StartedAt:   time.Now(),
	}

	// TODO: Integrate with SOAR execution engine (Temporal)
	// For now, just log the intent

	s.logAudit(ctx, event, "EXECUTION_STARTED", model.ActorSOAR,
		fmt.Sprintf("Started execution %s for playbook %s", event.Execution.ExecutionID, event.PlaybookMatch.PlaybookID))

	return nil
}

// logAudit creates an audit log entry.
func (s *PipelineService) logAudit(ctx context.Context, event *model.PipelineEvent, eventType, actorType, message string) {
	auditLog := &model.AuditLog{
		ID:             generateAuditID(),
		TenantID:       event.TenantID,
		EventType:      eventType,
		ActorType:      actorType,
		ActorID:        "pipeline-service",
		Message:        message,
		RelatedEventID: event.ID,
		CreatedAt:      time.Now(),
	}

	if s.repo != nil {
		if err := s.repo.SaveAuditLog(ctx, auditLog); err != nil {
			s.logger.Warn("failed to save audit log",
				"event_id", event.ID,
				"error", err,
			)
		}
	}

	s.logger.Debug("audit log",
		"event_type", eventType,
		"actor_type", actorType,
		"message", message,
		"related_event_id", event.ID,
	)
}

// updateStats updates in-memory statistics.
func (s *PipelineService) updateStats(event *model.PipelineEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.TotalEvents++
	if event.Stage != model.StageEventReceive {
		s.stats.ProcessedEvents++
	}
	if event.Classification != nil {
		s.stats.AutoClassified++
	}

	// Update automation rate
	if s.stats.TotalEvents > 0 {
		s.stats.AutomationRate = float32(s.stats.AutoClassified) / float32(s.stats.TotalEvents)
	}
}

// GetEvent retrieves a pipeline event by ID.
func (s *PipelineService) GetEvent(ctx context.Context, id string) (*model.PipelineEvent, error) {
	if s.repo == nil {
		return nil, fmt.Errorf("repository not available")
	}
	return s.repo.GetEventByID(ctx, id)
}

// ListEvents retrieves pipeline events based on filter criteria.
func (s *PipelineService) ListEvents(ctx context.Context, filter model.PipelineEventFilter) ([]*model.PipelineEvent, int, error) {
	if s.repo == nil {
		return make([]*model.PipelineEvent, 0), 0, nil
	}
	return s.repo.ListEvents(ctx, filter)
}

// GetStats retrieves pipeline statistics.
func (s *PipelineService) GetStats(ctx context.Context, tenantID string) (*model.PipelineStats, error) {
	// Return in-memory stats for quick access
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &model.PipelineStats{
		TotalEvents:     s.stats.TotalEvents,
		ProcessedEvents: s.stats.ProcessedEvents,
		AutoClassified:  s.stats.AutoClassified,
		AutomationRate:  s.stats.AutomationRate,
		AvgProcessingMs: s.stats.AvgProcessingMs,
	}, nil
}

// GetStatsWithTimeRange retrieves pipeline statistics for a specific time range.
func (s *PipelineService) GetStatsWithTimeRange(ctx context.Context, tenantID string, from, to time.Time) (*model.PipelineStats, error) {
	if s.repo == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()

		stats := &model.PipelineStats{
			TotalEvents:     s.stats.TotalEvents,
			ProcessedEvents: s.stats.ProcessedEvents,
			AutoClassified:  s.stats.AutoClassified,
			AutomationRate:  s.stats.AutomationRate,
			AvgProcessingMs: s.stats.AvgProcessingMs,
		}
		stats.TimeRange.From = from
		stats.TimeRange.To = to
		return stats, nil
	}

	return s.repo.GetStatsWithTimeRange(ctx, tenantID, from, to)
}

// GetStatus retrieves the current pipeline status.
func (s *PipelineService) GetStatus(ctx context.Context, tenantID string) (*model.PipelineStatus, error) {
	if s.repo == nil {
		// Return default status when no repository
		return &model.PipelineStatus{
			Status:       "healthy",
			IsProcessing: false,
			LastEventAt:  time.Time{},
			Stages: []model.StageStatus{
				{Name: string(model.StageEventReceive), Status: "idle", CurrentCount: 0, ProcessedLast5Min: 0},
				{Name: string(model.StageClassification), Status: "idle", CurrentCount: 0, ProcessedLast5Min: 0},
				{Name: string(model.StagePlaybookSelect), Status: "idle", CurrentCount: 0, ProcessedLast5Min: 0},
				{Name: string(model.StageFlowExecution), Status: "idle", CurrentCount: 0, ProcessedLast5Min: 0},
			},
		}, nil
	}

	return s.repo.GetPipelineStatus(ctx, tenantID)
}

// GetStageDetails retrieves detailed information about all pipeline stages.
func (s *PipelineService) GetStageDetails(ctx context.Context, tenantID string) ([]model.StageDetail, error) {
	if s.repo == nil {
		// Return default stage details when no repository
		stages := []model.PipelineStage{
			model.StageEventReceive,
			model.StageClassification,
			model.StagePlaybookSelect,
			model.StageFlowExecution,
		}

		details := make([]model.StageDetail, 0, len(stages))
		for _, stage := range stages {
			displayInfo := model.StageDisplayInfo[stage]
			details = append(details, model.StageDetail{
				Name:         string(stage),
				DisplayName:  displayInfo.DisplayName,
				Description:  displayInfo.Description,
				Status:       "idle",
				RecentEvents: []model.EventSummary{},
				Stats:        model.StageStat{},
			})
		}
		return details, nil
	}

	return s.repo.GetStageDetails(ctx, tenantID)
}

// UpdateEventClassification updates the classification of an event.
func (s *PipelineService) UpdateEventClassification(ctx context.Context, eventID string, classification *model.Classification) error {
	event, err := s.GetEvent(ctx, eventID)
	if err != nil {
		return err
	}

	event.Classification = classification
	event.UpdatedAt = time.Now()

	if s.repo != nil {
		return s.repo.SaveEvent(ctx, event)
	}
	return nil
}

// UpdateEventExecution updates the execution status of an event.
func (s *PipelineService) UpdateEventExecution(ctx context.Context, eventID string, execution *model.ExecutionStatus) error {
	event, err := s.GetEvent(ctx, eventID)
	if err != nil {
		return err
	}

	event.Execution = execution
	event.UpdatedAt = time.Now()

	if s.repo != nil {
		return s.repo.SaveEvent(ctx, event)
	}
	return nil
}

// ApproveExecution approves a pending approval gate.
func (s *PipelineService) ApproveExecution(ctx context.Context, eventID, approver string) error {
	event, err := s.GetEvent(ctx, eventID)
	if err != nil {
		return err
	}

	if event.Execution == nil || event.Execution.ApprovalInfo == nil {
		return fmt.Errorf("no pending approval for event: %s", eventID)
	}

	if event.Execution.ApprovalInfo.Status != model.ApprovalPending {
		return fmt.Errorf("approval already resolved: %s", event.Execution.ApprovalInfo.Status)
	}

	event.Execution.ApprovalInfo.Status = model.ApprovalApproved
	event.Execution.ApprovalInfo.Approver = approver
	event.Execution.ApprovalInfo.ResolvedAt = time.Now()
	event.Execution.Status = model.StatusRunning

	s.logAudit(ctx, event, "APPROVAL_GRANTED", model.ActorUser,
		fmt.Sprintf("Approval granted by %s for step: %s", approver, event.Execution.ApprovalInfo.StepName))

	if s.repo != nil {
		return s.repo.SaveEvent(ctx, event)
	}
	return nil
}

// RejectExecution rejects a pending approval gate.
func (s *PipelineService) RejectExecution(ctx context.Context, eventID, approver, reason string) error {
	event, err := s.GetEvent(ctx, eventID)
	if err != nil {
		return err
	}

	if event.Execution == nil || event.Execution.ApprovalInfo == nil {
		return fmt.Errorf("no pending approval for event: %s", eventID)
	}

	if event.Execution.ApprovalInfo.Status != model.ApprovalPending {
		return fmt.Errorf("approval already resolved: %s", event.Execution.ApprovalInfo.Status)
	}

	event.Execution.ApprovalInfo.Status = model.ApprovalRejected
	event.Execution.ApprovalInfo.Approver = approver
	event.Execution.ApprovalInfo.ResolvedAt = time.Now()
	event.Execution.Status = model.StatusFailed

	s.logAudit(ctx, event, "APPROVAL_REJECTED", model.ActorUser,
		fmt.Sprintf("Approval rejected by %s for step: %s. Reason: %s", approver, event.Execution.ApprovalInfo.StepName, reason))

	if s.repo != nil {
		return s.repo.SaveEvent(ctx, event)
	}
	return nil
}

// Helper functions

func generateEventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

func generateAuditID() string {
	return fmt.Sprintf("audit-%d", time.Now().UnixNano())
}
