// Package service provides business logic for asset management.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/siem-soar-platform/services/asset-registry/internal/model"
	"github.com/siem-soar-platform/services/asset-registry/internal/repository"
)

// AssetService provides business logic for asset management.
type AssetService struct {
	repo   repository.AssetRepository
	logger *slog.Logger
}

// NewAssetService creates a new asset service.
func NewAssetService(repo repository.AssetRepository, logger *slog.Logger) *AssetService {
	return &AssetService{
		repo:   repo,
		logger: logger,
	}
}

// CreateAsset creates a new asset.
func (s *AssetService) CreateAsset(ctx context.Context, req *model.CreateAssetRequest, createdBy string) (*model.Asset, error) {
	// Validate request
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.Type == "" {
		return nil, errors.New("type is required")
	}

	// Build asset
	asset := &model.Asset{
		Name:            req.Name,
		Hostname:        req.Hostname,
		Description:     req.Description,
		Type:            req.Type,
		Status:          req.Status,
		Criticality:     req.Criticality,
		IPAddresses:     req.IPAddresses,
		MACAddresses:    req.MACAddresses,
		FQDN:            req.FQDN,
		OS:              req.OS,
		OSVersion:       req.OSVersion,
		Vendor:          req.Vendor,
		Model:           req.Model,
		SerialNumber:    req.SerialNumber,
		AssetTag:        req.AssetTag,
		Location:        req.Location,
		DataCenter:      req.DataCenter,
		Environment:     req.Environment,
		CloudProvider:   req.CloudProvider,
		CloudRegion:     req.CloudRegion,
		CloudAccountID:  req.CloudAccountID,
		CloudInstanceID: req.CloudInstanceID,
		Owner:           req.Owner,
		OwnerEmail:      req.OwnerEmail,
		Team:            req.Team,
		Department:      req.Department,
		GroupIDs:        req.GroupIDs,
		Tags:            req.Tags,
		Labels:          req.Labels,
		AgentID:         req.AgentID,
		CustomFields:    req.CustomFields,
		Metadata:        req.Metadata,
		CreatedBy:       createdBy,
		DiscoverySource: "api",
	}

	// Set defaults
	if asset.Status == "" {
		asset.Status = model.AssetStatusActive
	}
	if asset.Criticality == "" {
		asset.Criticality = model.CriticalityMedium
	}

	// Create asset
	if err := s.repo.Create(ctx, asset); err != nil {
		s.logger.Error("failed to create asset", "error", err)
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}

	// Record history
	s.recordHistory(ctx, asset.ID, "created", "", nil, asset, createdBy)

	s.logger.Info("asset created",
		"asset_id", asset.ID,
		"name", asset.Name,
		"type", asset.Type,
		"created_by", createdBy,
	)

	return asset, nil
}

// GetAsset retrieves an asset by ID.
func (s *AssetService) GetAsset(ctx context.Context, id string) (*model.Asset, error) {
	asset, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	if asset == nil {
		return nil, errors.New("asset not found")
	}

	// Get identifiers
	identifiers, _ := s.repo.GetIdentifiers(ctx, id)
	if len(identifiers) > 0 {
		// Ensure IP addresses are current
		ips := make([]string, 0)
		macs := make([]string, 0)
		for _, ident := range identifiers {
			switch ident.Type {
			case "ip":
				ips = append(ips, ident.Value)
			case "mac":
				macs = append(macs, ident.Value)
			}
		}
		if len(ips) > 0 {
			asset.IPAddresses = ips
		}
		if len(macs) > 0 {
			asset.MACAddresses = macs
		}
	}

	return asset, nil
}

// UpdateAsset updates an existing asset.
func (s *AssetService) UpdateAsset(ctx context.Context, id string, req *model.UpdateAssetRequest, updatedBy string) (*model.Asset, error) {
	// Get existing asset
	asset, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	if asset == nil {
		return nil, errors.New("asset not found")
	}

	oldAsset := *asset

	// Apply updates
	if req.Name != nil {
		asset.Name = *req.Name
	}
	if req.Hostname != nil {
		asset.Hostname = *req.Hostname
	}
	if req.Description != nil {
		asset.Description = *req.Description
	}
	if req.Type != nil {
		asset.Type = *req.Type
	}
	if req.Status != nil {
		asset.Status = *req.Status
	}
	if req.Criticality != nil {
		asset.Criticality = *req.Criticality
	}
	if req.IPAddresses != nil {
		asset.IPAddresses = req.IPAddresses
	}
	if req.MACAddresses != nil {
		asset.MACAddresses = req.MACAddresses
	}
	if req.FQDN != nil {
		asset.FQDN = *req.FQDN
	}
	if req.OS != nil {
		asset.OS = *req.OS
	}
	if req.OSVersion != nil {
		asset.OSVersion = *req.OSVersion
	}
	if req.Vendor != nil {
		asset.Vendor = *req.Vendor
	}
	if req.Model != nil {
		asset.Model = *req.Model
	}
	if req.Location != nil {
		asset.Location = *req.Location
	}
	if req.Environment != nil {
		asset.Environment = *req.Environment
	}
	if req.Owner != nil {
		asset.Owner = *req.Owner
	}
	if req.OwnerEmail != nil {
		asset.OwnerEmail = *req.OwnerEmail
	}
	if req.Team != nil {
		asset.Team = *req.Team
	}
	if req.GroupIDs != nil {
		asset.GroupIDs = req.GroupIDs
	}
	if req.Tags != nil {
		asset.Tags = req.Tags
	}
	if req.Labels != nil {
		asset.Labels = req.Labels
	}
	if req.CustomFields != nil {
		asset.CustomFields = req.CustomFields
	}
	if req.Metadata != nil {
		asset.Metadata = req.Metadata
	}

	asset.UpdatedBy = updatedBy

	// Update asset
	if err := s.repo.Update(ctx, asset); err != nil {
		s.logger.Error("failed to update asset", "error", err, "asset_id", id)
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// Record history
	s.recordHistory(ctx, asset.ID, "updated", "", &oldAsset, asset, updatedBy)

	s.logger.Info("asset updated",
		"asset_id", asset.ID,
		"updated_by", updatedBy,
	)

	return asset, nil
}

// DeleteAsset deletes an asset.
func (s *AssetService) DeleteAsset(ctx context.Context, id string, deletedBy string) error {
	asset, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get asset: %w", err)
	}
	if asset == nil {
		return errors.New("asset not found")
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		s.logger.Error("failed to delete asset", "error", err, "asset_id", id)
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	// Record history
	s.recordHistory(ctx, id, "deleted", "", asset, nil, deletedBy)

	s.logger.Info("asset deleted",
		"asset_id", id,
		"deleted_by", deletedBy,
	)

	return nil
}

// ListAssets retrieves assets with filtering.
func (s *AssetService) ListAssets(ctx context.Context, filter *model.AssetFilter) (*model.AssetListResult, error) {
	result, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	return result, nil
}

// AddIdentifier adds an identifier to an asset.
func (s *AssetService) AddIdentifier(ctx context.Context, assetID string, req *model.AddIdentifierRequest, addedBy string) (*model.AssetIdentifier, error) {
	// Validate request
	if req.Type == "" || req.Value == "" {
		return nil, errors.New("type and value are required")
	}

	// Check asset exists
	asset, err := s.repo.GetByID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	if asset == nil {
		return nil, errors.New("asset not found")
	}

	// Check if identifier already exists for another asset
	existing, err := s.repo.LookupByIdentifier(ctx, req.Type, req.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup identifier: %w", err)
	}
	if existing != nil && existing.ID != assetID {
		return nil, fmt.Errorf("identifier already assigned to asset %s", existing.ID)
	}

	// Build identifier
	identifier := &model.AssetIdentifier{
		AssetID:    assetID,
		Type:       req.Type,
		Value:      req.Value,
		IsPrimary:  req.IsPrimary,
		Confidence: req.Confidence,
		Source:     req.Source,
		ValidFrom:  time.Now(),
		LastSeenAt: time.Now(),
	}

	if identifier.Confidence == 0 {
		identifier.Confidence = 1.0
	}
	if identifier.Source == "" {
		identifier.Source = "manual"
	}

	// Add identifier
	if err := s.repo.AddIdentifier(ctx, assetID, identifier); err != nil {
		return nil, fmt.Errorf("failed to add identifier: %w", err)
	}

	s.logger.Info("identifier added",
		"asset_id", assetID,
		"type", req.Type,
		"value", req.Value,
		"added_by", addedBy,
	)

	return identifier, nil
}

// LookupAsset looks up an asset by identifier.
func (s *AssetService) LookupAsset(ctx context.Context, identType, value string) (*model.Asset, error) {
	asset, err := s.repo.LookupByIdentifier(ctx, identType, value)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup asset: %w", err)
	}
	return asset, nil
}

// RegisterUnknownIP registers an unknown IP as a new asset.
func (s *AssetService) RegisterUnknownIP(ctx context.Context, req *model.UnknownIPRequest) (*model.Asset, error) {
	if req.IPAddress == "" {
		return nil, errors.New("ip_address is required")
	}

	if req.DiscoverySource == "" {
		req.DiscoverySource = "network_discovery"
	}

	asset, err := s.repo.RegisterUnknownIP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to register unknown IP: %w", err)
	}

	s.logger.Info("unknown IP registered",
		"asset_id", asset.ID,
		"ip_address", req.IPAddress,
		"source", req.DiscoverySource,
	)

	return asset, nil
}

// GetAssetHistory retrieves change history for an asset.
func (s *AssetService) GetAssetHistory(ctx context.Context, assetID string, limit int) ([]*model.AssetHistory, error) {
	// Check asset exists
	asset, err := s.repo.GetByID(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	if asset == nil {
		return nil, errors.New("asset not found")
	}

	history, err := s.repo.GetHistory(ctx, assetID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}

	return history, nil
}

// CreateAssetGroup creates a new asset group.
func (s *AssetService) CreateAssetGroup(ctx context.Context, req *model.CreateAssetGroupRequest, createdBy string) (*model.AssetGroup, error) {
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.Type == "" {
		return nil, errors.New("type is required")
	}

	group := &model.AssetGroup{
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Query:       req.Query,
		AssetIDs:    req.AssetIDs,
		ParentID:    req.ParentID,
		Tags:        req.Tags,
		Labels:      req.Labels,
		AssetCount:  len(req.AssetIDs),
		CreatedBy:   createdBy,
	}

	if err := s.repo.CreateGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	s.logger.Info("asset group created",
		"group_id", group.ID,
		"name", group.Name,
		"type", group.Type,
		"created_by", createdBy,
	)

	return group, nil
}

// ListAssetGroups retrieves asset groups for a tenant.
func (s *AssetService) ListAssetGroups(ctx context.Context, tenantID string, limit, offset int) ([]*model.AssetGroup, int, error) {
	return s.repo.ListGroups(ctx, tenantID, limit, offset)
}

// recordHistory records a history entry.
func (s *AssetService) recordHistory(ctx context.Context, assetID, action, field string, oldValue, newValue interface{}, actor string) {
	history := &model.AssetHistory{
		AssetID: assetID,
		Action:  action,
		Field:   field,
		Actor:   actor,
	}

	if oldValue != nil {
		data, _ := json.Marshal(oldValue)
		history.OldValue = data
	}
	if newValue != nil {
		data, _ := json.Marshal(newValue)
		history.NewValue = data
	}

	if err := s.repo.RecordHistory(ctx, history); err != nil {
		s.logger.Error("failed to record history",
			"error", err,
			"asset_id", assetID,
			"action", action,
		)
	}
}

// GetCacheStats returns cache statistics (if using cached repository).
func (s *AssetService) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	if cached, ok := s.repo.(*repository.CachedAssetRepository); ok {
		return cached.CacheStats(ctx)
	}
	return map[string]interface{}{"cached": false}, nil
}

// IdentifyAsset identifies an asset by various identifiers.
func (s *AssetService) IdentifyAsset(ctx context.Context, req *model.IdentifyAssetRequest) (*model.IdentifyAssetResponse, error) {
	response := &model.IdentifyAssetResponse{
		Found: false,
	}

	// Try identifiers in order of reliability
	identifiers := []struct {
		Type       string
		Value      string
		Confidence float64
	}{}

	if req.AgentID != "" {
		identifiers = append(identifiers, struct {
			Type       string
			Value      string
			Confidence float64
		}{"agent_id", req.AgentID, 0.99})
	}
	if req.MAC != "" {
		identifiers = append(identifiers, struct {
			Type       string
			Value      string
			Confidence float64
		}{"mac", req.MAC, 0.95})
	}
	if req.FQDN != "" {
		identifiers = append(identifiers, struct {
			Type       string
			Value      string
			Confidence float64
		}{"fqdn", req.FQDN, 0.90})
	}
	if req.Hostname != "" {
		identifiers = append(identifiers, struct {
			Type       string
			Value      string
			Confidence float64
		}{"hostname", req.Hostname, 0.85})
	}
	if req.IP != "" {
		identifiers = append(identifiers, struct {
			Type       string
			Value      string
			Confidence float64
		}{"ip", req.IP, 0.75})
	}

	for _, ident := range identifiers {
		asset, err := s.repo.LookupByIdentifier(ctx, ident.Type, ident.Value)
		if err != nil {
			continue
		}
		if asset != nil {
			response.Found = true
			response.Asset = asset
			response.MatchedBy = ident.Type
			response.Confidence = ident.Confidence
			return response, nil
		}
	}

	return response, nil
}

// SearchAssets searches assets with full-text search.
func (s *AssetService) SearchAssets(ctx context.Context, req *model.AssetSearchRequest) (*model.AssetSearchResult, error) {
	startTime := time.Now()

	filter := &model.AssetFilter{
		Search: req.Query,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	if filter.Limit == 0 {
		filter.Limit = 20
	}

	if len(req.Types) > 0 {
		filter.Types = make([]model.AssetType, len(req.Types))
		for i, t := range req.Types {
			filter.Types[i] = model.AssetType(t)
		}
	}

	if len(req.Statuses) > 0 {
		filter.Statuses = make([]model.AssetStatus, len(req.Statuses))
		for i, s := range req.Statuses {
			filter.Statuses[i] = model.AssetStatus(s)
		}
	}

	result, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to search assets: %w", err)
	}

	return &model.AssetSearchResult{
		Query:    req.Query,
		Assets:   result.Assets,
		Total:    result.Total,
		Duration: time.Since(startTime).String(),
	}, nil
}

// UpdateAssetGroup updates an existing asset group.
func (s *AssetService) UpdateAssetGroup(ctx context.Context, id string, req *model.UpdateAssetGroupRequest, updatedBy string) (*model.AssetGroup, error) {
	group, err := s.repo.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return nil, errors.New("group not found")
	}

	// Apply updates
	if req.Name != nil {
		group.Name = *req.Name
	}
	if req.Description != nil {
		group.Description = *req.Description
	}
	if req.Query != nil {
		group.Query = *req.Query
	}
	if req.AssetIDs != nil {
		group.AssetIDs = req.AssetIDs
		group.AssetCount = len(req.AssetIDs)
	}
	if req.ParentID != nil {
		group.ParentID = *req.ParentID
	}
	if req.Tags != nil {
		group.Tags = req.Tags
	}
	if req.Labels != nil {
		group.Labels = req.Labels
	}

	group.UpdatedBy = updatedBy

	if err := s.repo.UpdateGroup(ctx, group); err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	s.logger.Info("asset group updated",
		"group_id", id,
		"updated_by", updatedBy,
	)

	return group, nil
}

// DeleteAssetGroup deletes an asset group.
func (s *AssetService) DeleteAssetGroup(ctx context.Context, id string, deletedBy string) error {
	group, err := s.repo.GetGroup(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return errors.New("group not found")
	}

	if err := s.repo.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	s.logger.Info("asset group deleted",
		"group_id", id,
		"deleted_by", deletedBy,
	)

	return nil
}

// GetAssetGroup retrieves an asset group by ID.
func (s *AssetService) GetAssetGroup(ctx context.Context, id string) (*model.AssetGroup, error) {
	group, err := s.repo.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return nil, errors.New("group not found")
	}
	return group, nil
}

// AddGroupMembers adds assets to a group.
func (s *AssetService) AddGroupMembers(ctx context.Context, groupID string, assetIDs []string, addedBy string) error {
	group, err := s.repo.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return errors.New("group not found")
	}

	for _, assetID := range assetIDs {
		if err := s.repo.AddToGroup(ctx, assetID, groupID); err != nil {
			s.logger.Error("failed to add asset to group",
				"asset_id", assetID,
				"group_id", groupID,
				"error", err,
			)
		}
	}

	s.logger.Info("members added to group",
		"group_id", groupID,
		"count", len(assetIDs),
		"added_by", addedBy,
	)

	return nil
}

// RemoveGroupMembers removes assets from a group.
func (s *AssetService) RemoveGroupMembers(ctx context.Context, groupID string, assetIDs []string, removedBy string) error {
	group, err := s.repo.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return errors.New("group not found")
	}

	for _, assetID := range assetIDs {
		if err := s.repo.RemoveFromGroup(ctx, assetID, groupID); err != nil {
			s.logger.Error("failed to remove asset from group",
				"asset_id", assetID,
				"group_id", groupID,
				"error", err,
			)
		}
	}

	s.logger.Info("members removed from group",
		"group_id", groupID,
		"count", len(assetIDs),
		"removed_by", removedBy,
	)

	return nil
}

// GetGroupMembers retrieves the members of a group.
func (s *AssetService) GetGroupMembers(ctx context.Context, groupID string, limit, offset int) (*model.GroupMembersResponse, error) {
	group, err := s.repo.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return nil, errors.New("group not found")
	}

	if limit == 0 {
		limit = 20
	}

	// Get asset details for each member
	members := make([]model.GroupMember, 0)
	for i, assetID := range group.AssetIDs {
		if i < offset {
			continue
		}
		if len(members) >= limit {
			break
		}

		asset, err := s.repo.GetByID(ctx, assetID)
		if err != nil || asset == nil {
			continue
		}

		members = append(members, model.GroupMember{
			AssetID:   asset.ID,
			AssetName: asset.Name,
			AssetType: asset.Type,
			JoinedAt:  asset.CreatedAt,
		})
	}

	return &model.GroupMembersResponse{
		GroupID:   group.ID,
		GroupName: group.Name,
		Members:   members,
		Total:     len(group.AssetIDs),
		Limit:     limit,
		Offset:    offset,
	}, nil
}
