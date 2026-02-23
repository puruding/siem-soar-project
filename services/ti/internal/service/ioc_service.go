// Package service provides the IOC service layer.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/siem-soar-platform/services/ti/internal/cache"
	"github.com/siem-soar-platform/services/ti/internal/ioc"
	"github.com/siem-soar-platform/services/ti/internal/matcher"
	"github.com/siem-soar-platform/services/ti/internal/repository"
)

// IOCService provides business logic for IOC management.
type IOCService struct {
	repo    *repository.PostgresIOCRepository
	cache   *cache.IOCCache
	matcher *matcher.Matcher
	store   *ioc.Store
	logger  *slog.Logger
}

// NewIOCService creates a new IOC service.
func NewIOCService(
	repo *repository.PostgresIOCRepository,
	cache *cache.IOCCache,
	matcher *matcher.Matcher,
	store *ioc.Store,
	logger *slog.Logger,
) *IOCService {
	return &IOCService{
		repo:    repo,
		cache:   cache,
		matcher: matcher,
		store:   store,
		logger:  logger.With("component", "ioc-service"),
	}
}

// CreateIOCRequest represents a request to create an IOC.
type CreateIOCRequest struct {
	Type            string            `json:"type"`
	Value           string            `json:"value"`
	ThreatType      string            `json:"threat_type"`
	Confidence      int               `json:"confidence"`
	Source          string            `json:"source"`
	Tags            []string          `json:"tags,omitempty"`
	Description     string            `json:"description,omitempty"`
	Name            string            `json:"name,omitempty"`
	Severity        string            `json:"severity,omitempty"`
	TLP             string            `json:"tlp,omitempty"`
	MITREAttack     []string          `json:"mitre_attack,omitempty"`
	MalwareFamilies []string          `json:"malware_families,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

// Create creates a new IOC.
func (s *IOCService) Create(ctx context.Context, req *CreateIOCRequest) (*ioc.IOC, error) {
	// Validate request
	if req.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	if req.Source == "" {
		return nil, fmt.Errorf("source is required")
	}

	// Auto-detect type if not provided
	iocType := ioc.IOCType(req.Type)
	if iocType == "" {
		iocType = ioc.DetectIOCType(req.Value)
	}

	// Validate confidence
	if req.Confidence < 0 || req.Confidence > 100 {
		return nil, fmt.Errorf("confidence must be between 0 and 100")
	}

	now := time.Now()
	newIOC := &ioc.IOC{
		ID:              uuid.New().String(),
		TenantID:        "default", // TODO: Get from context
		Type:            iocType,
		Value:           req.Value,
		Name:            req.Name,
		Description:     req.Description,
		Source:          req.Source,
		ThreatType:      ioc.ThreatType(req.ThreatType),
		Severity:        ioc.Severity(req.Severity),
		Confidence:      req.Confidence,
		TLP:             ioc.TLP(req.TLP),
		MITREAttack:     req.MITREAttack,
		MalwareFamilies: req.MalwareFamilies,
		Labels:          req.Tags,
		Attributes:      req.Attributes,
		ValidFrom:       now,
		FirstSeen:       now,
		LastSeen:        now,
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Set defaults
	if newIOC.ThreatType == "" {
		newIOC.ThreatType = ioc.ThreatUnknown
	}
	if newIOC.Severity == "" {
		newIOC.Severity = ioc.SeverityMedium
	}
	if newIOC.TLP == "" {
		newIOC.TLP = ioc.TLPAmber
	}
	if newIOC.Confidence == 0 {
		newIOC.Confidence = 50
	}
	if req.ExpiresAt != nil {
		newIOC.ExpiresAt = *req.ExpiresAt
	}
	if newIOC.Attributes == nil {
		newIOC.Attributes = make(map[string]string)
	}

	// Save to database
	if err := s.repo.Save(ctx, newIOC); err != nil {
		return nil, fmt.Errorf("failed to save IOC: %w", err)
	}

	// Add to in-memory store
	if s.store != nil {
		if err := s.store.Add(newIOC); err != nil {
			s.logger.Warn("failed to add IOC to store", "id", newIOC.ID, "error", err)
		}
	}

	// Add to cache
	if s.cache != nil {
		if err := s.cache.Set(ctx, newIOC); err != nil {
			s.logger.Warn("failed to cache IOC", "id", newIOC.ID, "error", err)
		}
	}

	// Add to matcher indices
	if s.matcher != nil {
		s.matcher.AddIOC(newIOC)
	}

	s.logger.Info("created IOC", "id", newIOC.ID, "type", newIOC.Type, "value", newIOC.Value)

	return newIOC, nil
}

// GetByID retrieves an IOC by ID.
func (s *IOCService) GetByID(ctx context.Context, id string) (*ioc.IOC, error) {
	// Try cache first
	if s.cache != nil {
		if cached, err := s.cache.Get(ctx, id); err == nil && cached != nil {
			return cached, nil
		}
	}

	// Try in-memory store
	if s.store != nil {
		if stored := s.store.GetByID(id); stored != nil {
			// Cache for next time
			if s.cache != nil {
				s.cache.Set(ctx, stored)
			}
			return stored, nil
		}
	}

	// Fallback to database
	result, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get IOC: %w", err)
	}

	if result != nil && s.cache != nil {
		s.cache.Set(ctx, result)
	}

	return result, nil
}

// UpdateIOCRequest represents a request to update an IOC.
type UpdateIOCRequest struct {
	Name            *string            `json:"name,omitempty"`
	Description     *string            `json:"description,omitempty"`
	ThreatType      *string            `json:"threat_type,omitempty"`
	Severity        *string            `json:"severity,omitempty"`
	Confidence      *int               `json:"confidence,omitempty"`
	TLP             *string            `json:"tlp,omitempty"`
	Tags            []string           `json:"tags,omitempty"`
	MITREAttack     []string           `json:"mitre_attack,omitempty"`
	MalwareFamilies []string           `json:"malware_families,omitempty"`
	IsActive        *bool              `json:"is_active,omitempty"`
	IsWhitelisted   *bool              `json:"is_whitelisted,omitempty"`
	ExpiresAt       *time.Time         `json:"expires_at,omitempty"`
	Attributes      map[string]string  `json:"attributes,omitempty"`
}

// Update updates an existing IOC.
func (s *IOCService) Update(ctx context.Context, id string, req *UpdateIOCRequest) (*ioc.IOC, error) {
	// Get existing IOC
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get IOC: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("IOC not found")
	}

	// Apply updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.ThreatType != nil {
		existing.ThreatType = ioc.ThreatType(*req.ThreatType)
	}
	if req.Severity != nil {
		existing.Severity = ioc.Severity(*req.Severity)
	}
	if req.Confidence != nil {
		if *req.Confidence < 0 || *req.Confidence > 100 {
			return nil, fmt.Errorf("confidence must be between 0 and 100")
		}
		existing.Confidence = *req.Confidence
	}
	if req.TLP != nil {
		existing.TLP = ioc.TLP(*req.TLP)
	}
	if req.Tags != nil {
		existing.Labels = req.Tags
	}
	if req.MITREAttack != nil {
		existing.MITREAttack = req.MITREAttack
	}
	if req.MalwareFamilies != nil {
		existing.MalwareFamilies = req.MalwareFamilies
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}
	if req.IsWhitelisted != nil {
		existing.IsWhitelisted = *req.IsWhitelisted
	}
	if req.ExpiresAt != nil {
		existing.ExpiresAt = *req.ExpiresAt
	}
	if req.Attributes != nil {
		for k, v := range req.Attributes {
			existing.Attributes[k] = v
		}
	}

	existing.UpdatedAt = time.Now()

	// Save to database
	if err := s.repo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update IOC: %w", err)
	}

	// Update in-memory store
	if s.store != nil {
		s.store.Add(existing) // Add handles update via merge
	}

	// Invalidate and update cache
	if s.cache != nil {
		s.cache.Delete(ctx, id)
		s.cache.Set(ctx, existing)
	}

	s.logger.Info("updated IOC", "id", id)

	return existing, nil
}

// Delete removes an IOC.
func (s *IOCService) Delete(ctx context.Context, id string) error {
	// Get IOC first for cleanup
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get IOC: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("IOC not found")
	}

	// Delete from database
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete IOC: %w", err)
	}

	// Remove from in-memory store
	if s.store != nil {
		s.store.DeleteByID(id)
	}

	// Remove from cache
	if s.cache != nil {
		s.cache.Delete(ctx, id)
	}

	// Remove from matcher
	if s.matcher != nil {
		s.matcher.RemoveIOC(existing)
	}

	s.logger.Info("deleted IOC", "id", id)

	return nil
}

// ListRequest represents a request to list IOCs.
type ListRequest struct {
	Types         []string  `json:"types,omitempty"`
	ThreatTypes   []string  `json:"threat_types,omitempty"`
	Severities    []string  `json:"severities,omitempty"`
	Sources       []string  `json:"sources,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	MinConfidence int       `json:"min_confidence,omitempty"`
	IsActive      *bool     `json:"is_active,omitempty"`
	Search        string    `json:"search,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}

// ListResponse represents a response from listing IOCs.
type ListResponse struct {
	IOCs   []*ioc.IOC `json:"iocs"`
	Total  int64      `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

// List retrieves IOCs matching the filter.
func (s *IOCService) List(ctx context.Context, req *ListRequest) (*ListResponse, error) {
	// Build filter
	filter := ioc.IOCFilter{
		MinConfidence: req.MinConfidence,
		IsActive:      req.IsActive,
		SearchQuery:   req.Search,
	}

	// Convert string types to IOC types
	for _, t := range req.Types {
		filter.Types = append(filter.Types, ioc.IOCType(t))
	}
	for _, t := range req.ThreatTypes {
		filter.ThreatTypes = append(filter.ThreatTypes, ioc.ThreatType(t))
	}
	for _, s := range req.Severities {
		filter.Severities = append(filter.Severities, ioc.Severity(s))
	}
	filter.Sources = req.Sources
	filter.Labels = req.Tags

	// Set defaults
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	// Query database
	iocs, total, err := s.repo.List(ctx, filter, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list IOCs: %w", err)
	}

	return &ListResponse{
		IOCs:   iocs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// LookupRequest represents a request to lookup an IOC.
type LookupRequest struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// LookupResponse represents a response from IOC lookup.
type LookupResponse struct {
	Found       bool                   `json:"found"`
	IOC         *ioc.IOC               `json:"ioc,omitempty"`
	CacheHit    bool                   `json:"cache_hit"`
	BloomHit    bool                   `json:"bloom_hit"`
	LookupTime  time.Duration          `json:"lookup_time"`
	MatchType   string                 `json:"match_type,omitempty"`
	Reputation  map[string]interface{} `json:"reputation,omitempty"`
}

// Lookup performs a fast IOC lookup.
func (s *IOCService) Lookup(ctx context.Context, req *LookupRequest) (*LookupResponse, error) {
	start := time.Now()

	if req.Value == "" {
		return nil, fmt.Errorf("value is required")
	}

	// Auto-detect type if not provided
	iocType := ioc.IOCType(req.Type)
	if iocType == "" {
		iocType = ioc.DetectIOCType(req.Value)
	}

	response := &LookupResponse{
		Reputation: make(map[string]interface{}),
	}

	// Try cache first with bloom filter
	if s.cache != nil {
		result, err := s.cache.CachedLookup(ctx, iocType, req.Value)
		if err == nil && result != nil {
			response.CacheHit = result.CacheHit
			response.BloomHit = result.BloomHit
			if result.Found {
				response.Found = true
				response.IOC = result.IOC
				response.MatchType = "exact"
				s.buildReputation(response)
				// Record hit asynchronously
				go s.recordHit(ctx, result.IOC.ID)
			}
			response.LookupTime = time.Since(start)
			return response, nil
		}
	}

	// Try matcher for advanced matching (CIDR, subdomain, etc.)
	if s.matcher != nil {
		result := s.matcher.MatchSingle(ctx, iocType, req.Value)
		if result != nil {
			response.Found = true
			response.IOC = result.IOC
			response.MatchType = result.MatchType
			s.buildReputation(response)
			// Cache the result
			if s.cache != nil {
				s.cache.Set(ctx, result.IOC)
			}
			// Record hit
			go s.recordHit(ctx, result.IOC.ID)
			response.LookupTime = time.Since(start)
			return response, nil
		}
	}

	// Fallback to database
	found, err := s.repo.GetByTypeAndValue(ctx, iocType, req.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IOC: %w", err)
	}

	if found != nil {
		response.Found = true
		response.IOC = found
		response.MatchType = "exact"
		s.buildReputation(response)
		// Cache for next time
		if s.cache != nil {
			s.cache.Set(ctx, found)
		}
		// Record hit
		go s.recordHit(ctx, found.ID)
	}

	response.LookupTime = time.Since(start)
	return response, nil
}

// BatchLookupRequest represents a batch lookup request.
type BatchLookupRequest struct {
	Indicators []LookupRequest `json:"indicators"`
}

// BatchLookupResponse represents a batch lookup response.
type BatchLookupResponse struct {
	Results     map[string]*LookupResponse `json:"results"`
	TotalFound  int                        `json:"total_found"`
	LookupTime  time.Duration              `json:"lookup_time"`
}

// BatchLookup performs multiple IOC lookups.
func (s *IOCService) BatchLookup(ctx context.Context, req *BatchLookupRequest) (*BatchLookupResponse, error) {
	start := time.Now()

	if len(req.Indicators) == 0 {
		return nil, fmt.Errorf("at least one indicator is required")
	}

	if len(req.Indicators) > 1000 {
		return nil, fmt.Errorf("maximum 1000 indicators per batch")
	}

	results := make(map[string]*LookupResponse)
	totalFound := 0

	for _, ind := range req.Indicators {
		key := ind.Type + ":" + ind.Value
		if ind.Type == "" {
			detectedType := ioc.DetectIOCType(ind.Value)
			key = string(detectedType) + ":" + ind.Value
		}

		result, err := s.Lookup(ctx, &ind)
		if err != nil {
			s.logger.Warn("batch lookup failed", "value", ind.Value, "error", err)
			results[key] = &LookupResponse{Found: false}
			continue
		}

		results[key] = result
		if result.Found {
			totalFound++
		}
	}

	return &BatchLookupResponse{
		Results:    results,
		TotalFound: totalFound,
		LookupTime: time.Since(start),
	}, nil
}

// GetStats retrieves IOC statistics.
func (s *IOCService) GetStats(ctx context.Context, tenantID string) (*ioc.IOCStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}

// buildReputation adds reputation information to the response.
func (s *IOCService) buildReputation(response *LookupResponse) {
	if response.IOC == nil {
		return
	}

	i := response.IOC
	response.Reputation["threat_type"] = string(i.ThreatType)
	response.Reputation["severity"] = string(i.Severity)
	response.Reputation["confidence"] = i.Confidence
	response.Reputation["source"] = i.Source
	response.Reputation["first_seen"] = i.FirstSeen
	response.Reputation["last_seen"] = i.LastSeen
	response.Reputation["hit_count"] = i.HitCount
	response.Reputation["is_active"] = i.IsActive

	if len(i.MITREAttack) > 0 {
		response.Reputation["mitre_attack"] = i.MITREAttack
	}
	if len(i.MalwareFamilies) > 0 {
		response.Reputation["malware_families"] = i.MalwareFamilies
	}
	if len(i.Labels) > 0 {
		response.Reputation["tags"] = i.Labels
	}
}

// recordHit records a hit for an IOC.
func (s *IOCService) recordHit(ctx context.Context, id string) {
	if s.repo != nil {
		if err := s.repo.IncrementHitCount(ctx, id); err != nil {
			s.logger.Warn("failed to record hit", "id", id, "error", err)
		}
	}
	if s.cache != nil {
		if err := s.cache.RecordHit(ctx, id); err != nil {
			s.logger.Warn("failed to record hit in cache", "id", id, "error", err)
		}
	}
}

// WarmupCache loads IOCs into cache.
func (s *IOCService) WarmupCache(ctx context.Context) error {
	s.logger.Info("starting cache warmup")

	// Load all active IOCs
	filter := ioc.IOCFilter{}
	active := true
	filter.IsActive = &active

	iocs, _, err := s.repo.List(ctx, filter, 0, 0) // No limit
	if err != nil {
		return fmt.Errorf("failed to load IOCs: %w", err)
	}

	if s.cache != nil {
		if err := s.cache.Warmup(ctx, iocs); err != nil {
			return fmt.Errorf("failed to warm up cache: %w", err)
		}
	}

	if s.store != nil {
		for _, i := range iocs {
			s.store.Add(i)
		}
	}

	if s.matcher != nil {
		s.matcher.Rebuild()
	}

	s.logger.Info("cache warmup complete", "ioc_count", len(iocs))
	return nil
}
