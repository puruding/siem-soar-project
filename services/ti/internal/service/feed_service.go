// Package service provides the feed service layer.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/siem-soar-platform/services/ti/internal/feed"
)

// FeedService provides business logic for feed management.
type FeedService struct {
	manager    *feed.Manager
	iocService *IOCService
	logger     *slog.Logger
}

// NewFeedService creates a new feed service.
func NewFeedService(manager *feed.Manager, iocService *IOCService, logger *slog.Logger) *FeedService {
	return &FeedService{
		manager:    manager,
		iocService: iocService,
		logger:     logger.With("component", "feed-service"),
	}
}

// CreateFeedRequest represents a request to create a feed.
type CreateFeedRequest struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Type           string            `json:"type"` // stix, taxii, misp, csv, json, otx
	URL            string            `json:"url"`
	APIKey         string            `json:"api_key,omitempty"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	CollectionID   string            `json:"collection_id,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Enabled        bool              `json:"enabled"`
	Schedule       string            `json:"schedule,omitempty"`
	SyncInterval   string            `json:"sync_interval,omitempty"` // e.g., "1h", "30m"
	IOCTypes       []string          `json:"ioc_types,omitempty"`
	MinConfidence  int               `json:"min_confidence,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
}

// CreateFeed creates a new feed.
func (s *FeedService) CreateFeed(ctx context.Context, req *CreateFeedRequest) (*feed.Feed, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.URL == "" {
		return nil, fmt.Errorf("url is required")
	}

	// Parse sync interval
	var syncInterval time.Duration
	if req.SyncInterval != "" {
		var err error
		syncInterval, err = time.ParseDuration(req.SyncInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid sync_interval: %w", err)
		}
	} else {
		syncInterval = time.Hour // Default to 1 hour
	}

	newFeed := &feed.Feed{
		ID:            uuid.New().String(),
		Name:          req.Name,
		Description:   req.Description,
		Type:          feed.FeedType(req.Type),
		URL:           req.URL,
		APIKey:        req.APIKey,
		Username:      req.Username,
		Password:      req.Password,
		CollectionID:  req.CollectionID,
		Headers:       req.Headers,
		Enabled:       req.Enabled,
		Schedule:      req.Schedule,
		SyncInterval:  syncInterval,
		IOCTypes:      req.IOCTypes,
		MinConfidence: req.MinConfidence,
		Tags:          req.Tags,
		Status:        feed.StatusActive,
	}

	// Register with manager
	if err := s.manager.RegisterFeed(newFeed); err != nil {
		return nil, fmt.Errorf("failed to register feed: %w", err)
	}

	s.logger.Info("created feed", "id", newFeed.ID, "name", newFeed.Name)

	return newFeed, nil
}

// GetFeed retrieves a feed by ID.
func (s *FeedService) GetFeed(ctx context.Context, id string) (*feed.Feed, error) {
	f := s.manager.GetFeed(id)
	if f == nil {
		return nil, fmt.Errorf("feed not found")
	}
	return f, nil
}

// ListFeeds retrieves all feeds.
func (s *FeedService) ListFeeds(ctx context.Context) ([]*feed.Feed, error) {
	return s.manager.ListFeeds(), nil
}

// UpdateFeedRequest represents a request to update a feed.
type UpdateFeedRequest struct {
	Name           *string            `json:"name,omitempty"`
	Description    *string            `json:"description,omitempty"`
	URL            *string            `json:"url,omitempty"`
	APIKey         *string            `json:"api_key,omitempty"`
	Username       *string            `json:"username,omitempty"`
	Password       *string            `json:"password,omitempty"`
	CollectionID   *string            `json:"collection_id,omitempty"`
	Headers        map[string]string  `json:"headers,omitempty"`
	Enabled        *bool              `json:"enabled,omitempty"`
	Schedule       *string            `json:"schedule,omitempty"`
	SyncInterval   *string            `json:"sync_interval,omitempty"`
	IOCTypes       []string           `json:"ioc_types,omitempty"`
	MinConfidence  *int               `json:"min_confidence,omitempty"`
	Tags           []string           `json:"tags,omitempty"`
}

// UpdateFeed updates an existing feed.
func (s *FeedService) UpdateFeed(ctx context.Context, id string, req *UpdateFeedRequest) (*feed.Feed, error) {
	f := s.manager.GetFeed(id)
	if f == nil {
		return nil, fmt.Errorf("feed not found")
	}

	// Apply updates
	if req.Name != nil {
		f.Name = *req.Name
	}
	if req.Description != nil {
		f.Description = *req.Description
	}
	if req.URL != nil {
		f.URL = *req.URL
	}
	if req.APIKey != nil {
		f.APIKey = *req.APIKey
	}
	if req.Username != nil {
		f.Username = *req.Username
	}
	if req.Password != nil {
		f.Password = *req.Password
	}
	if req.CollectionID != nil {
		f.CollectionID = *req.CollectionID
	}
	if req.Headers != nil {
		f.Headers = req.Headers
	}
	if req.Enabled != nil {
		f.Enabled = *req.Enabled
	}
	if req.Schedule != nil {
		f.Schedule = *req.Schedule
	}
	if req.SyncInterval != nil {
		interval, err := time.ParseDuration(*req.SyncInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid sync_interval: %w", err)
		}
		f.SyncInterval = interval
	}
	if req.IOCTypes != nil {
		f.IOCTypes = req.IOCTypes
	}
	if req.MinConfidence != nil {
		f.MinConfidence = *req.MinConfidence
	}
	if req.Tags != nil {
		f.Tags = req.Tags
	}

	s.logger.Info("updated feed", "id", id, "name", f.Name)

	return f, nil
}

// DeleteFeed removes a feed.
func (s *FeedService) DeleteFeed(ctx context.Context, id string) error {
	f := s.manager.GetFeed(id)
	if f == nil {
		return fmt.Errorf("feed not found")
	}

	s.manager.UnregisterFeed(id)
	s.logger.Info("deleted feed", "id", id)

	return nil
}

// SyncFeed triggers a sync for a specific feed.
func (s *FeedService) SyncFeed(ctx context.Context, id string) (*feed.FeedResult, error) {
	result, err := s.manager.SyncFeed(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to sync feed: %w", err)
	}

	return result, nil
}

// SyncAllFeeds triggers sync for all enabled feeds.
func (s *FeedService) SyncAllFeeds(ctx context.Context) ([]*feed.FeedResult, error) {
	return s.manager.SyncAll(ctx), nil
}

// TestFeed tests connectivity to a feed.
func (s *FeedService) TestFeed(ctx context.Context, req *CreateFeedRequest) error {
	testFeed := &feed.Feed{
		Type:         feed.FeedType(req.Type),
		URL:          req.URL,
		APIKey:       req.APIKey,
		Username:     req.Username,
		Password:     req.Password,
		CollectionID: req.CollectionID,
		Headers:      req.Headers,
	}

	return s.manager.TestFeed(ctx, testFeed)
}

// FeedStats returns statistics for feeds.
func (s *FeedService) FeedStats(ctx context.Context) map[string]interface{} {
	return s.manager.Stats()
}

// FeedIOCHandler implements feed.FeedHandler for processing IOCs.
type FeedIOCHandler struct {
	service *IOCService
	logger  *slog.Logger
	batch   []*CreateIOCRequest
}

// NewFeedIOCHandler creates a new feed IOC handler.
func NewFeedIOCHandler(service *IOCService, logger *slog.Logger) *FeedIOCHandler {
	return &FeedIOCHandler{
		service: service,
		logger:  logger.With("component", "feed-ioc-handler"),
		batch:   make([]*CreateIOCRequest, 0, 1000),
	}
}

// HandleIOC processes a single IOC from a feed.
func (h *FeedIOCHandler) HandleIOC(ctx context.Context, feedIOC *feed.IOC) error {
	// Convert feed IOC to create request
	req := &CreateIOCRequest{
		Type:        string(feedIOC.Type),
		Value:       feedIOC.Value,
		ThreatType:  feedIOC.ThreatType,
		Confidence:  feedIOC.Confidence,
		Source:      feedIOC.Source,
		Tags:        feedIOC.Tags,
		Description: feedIOC.Description,
		Severity:    feedIOC.Severity,
		MITREAttack: feedIOC.Mitre,
	}

	h.batch = append(h.batch, req)

	// Flush if batch is full
	if len(h.batch) >= 1000 {
		return h.flush(ctx)
	}

	return nil
}

// HandleBatch processes multiple IOCs from a feed.
func (h *FeedIOCHandler) HandleBatch(ctx context.Context, feedIOCs []*feed.IOC) error {
	for _, feedIOC := range feedIOCs {
		if err := h.HandleIOC(ctx, feedIOC); err != nil {
			return err
		}
	}
	return nil
}

// Commit flushes any remaining IOCs.
func (h *FeedIOCHandler) Commit(ctx context.Context) error {
	return h.flush(ctx)
}

func (h *FeedIOCHandler) flush(ctx context.Context) error {
	if len(h.batch) == 0 {
		return nil
	}

	// Create IOCs through service
	for _, req := range h.batch {
		if _, err := h.service.Create(ctx, req); err != nil {
			h.logger.Warn("failed to create IOC from feed", "value", req.Value, "error", err)
		}
	}

	h.logger.Debug("flushed IOC batch", "count", len(h.batch))
	h.batch = h.batch[:0]

	return nil
}
