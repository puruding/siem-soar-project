// Package service provides business logic for parser management.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/siem-soar-platform/services/parser-manager/internal/hotreload"
	"github.com/siem-soar-platform/services/parser-manager/internal/model"
	"github.com/siem-soar-platform/services/parser-manager/internal/repository"
)

// ParserService provides business logic for parser management.
type ParserService struct {
	repo      repository.ParserRepository
	hotreload *hotreload.Manager
	logger    *slog.Logger
}

// NewParserService creates a new parser service.
func NewParserService(repo repository.ParserRepository, hotreload *hotreload.Manager, logger *slog.Logger) *ParserService {
	return &ParserService{
		repo:      repo,
		hotreload: hotreload,
		logger:    logger,
	}
}

// CreateProduct creates a new product.
func (s *ParserService) CreateProduct(ctx context.Context, req *model.CreateProductRequest, createdBy string) (*model.Product, error) {
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.Vendor == "" {
		return nil, errors.New("vendor is required")
	}

	product := &model.Product{
		Name:        req.Name,
		Vendor:      req.Vendor,
		Version:     req.Version,
		Description: req.Description,
		Category:    req.Category,
		LogFormats:  req.LogFormats,
		SampleLogs:  req.SampleLogs,
		Tags:        req.Tags,
		Labels:      req.Labels,
		CreatedBy:   createdBy,
	}

	if err := s.repo.CreateProduct(ctx, product); err != nil {
		return nil, fmt.Errorf("failed to create product: %w", err)
	}

	s.logger.Info("product created",
		"product_id", product.ID,
		"name", product.Name,
		"vendor", product.Vendor,
		"created_by", createdBy,
	)

	return product, nil
}

// GetProduct retrieves a product by ID.
func (s *ParserService) GetProduct(ctx context.Context, id string) (*model.Product, error) {
	product, err := s.repo.GetProduct(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get product: %w", err)
	}
	if product == nil {
		return nil, errors.New("product not found")
	}
	return product, nil
}

// UpdateProduct updates a product.
func (s *ParserService) UpdateProduct(ctx context.Context, id string, req *model.UpdateProductRequest, updatedBy string) (*model.Product, error) {
	product, err := s.repo.GetProduct(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get product: %w", err)
	}
	if product == nil {
		return nil, errors.New("product not found")
	}

	if req.Name != nil {
		product.Name = *req.Name
	}
	if req.Vendor != nil {
		product.Vendor = *req.Vendor
	}
	if req.Version != nil {
		product.Version = *req.Version
	}
	if req.Description != nil {
		product.Description = *req.Description
	}
	if req.Category != nil {
		product.Category = *req.Category
	}
	if req.LogFormats != nil {
		product.LogFormats = req.LogFormats
	}
	if req.SampleLogs != nil {
		product.SampleLogs = req.SampleLogs
	}
	if req.Tags != nil {
		product.Tags = req.Tags
	}
	if req.Labels != nil {
		product.Labels = req.Labels
	}

	product.UpdatedBy = updatedBy

	if err := s.repo.UpdateProduct(ctx, product); err != nil {
		return nil, fmt.Errorf("failed to update product: %w", err)
	}

	s.logger.Info("product updated",
		"product_id", id,
		"updated_by", updatedBy,
	)

	return product, nil
}

// DeleteProduct deletes a product.
func (s *ParserService) DeleteProduct(ctx context.Context, id string, deletedBy string) error {
	product, err := s.repo.GetProduct(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get product: %w", err)
	}
	if product == nil {
		return errors.New("product not found")
	}

	// Check if product has parsers
	if product.ParserCount > 0 {
		return fmt.Errorf("cannot delete product with %d parsers, delete parsers first", product.ParserCount)
	}

	if err := s.repo.DeleteProduct(ctx, id); err != nil {
		return fmt.Errorf("failed to delete product: %w", err)
	}

	s.logger.Info("product deleted",
		"product_id", id,
		"deleted_by", deletedBy,
	)

	return nil
}

// ListProducts lists products.
func (s *ParserService) ListProducts(ctx context.Context, filter *model.ProductFilter) (*model.ProductListResult, error) {
	return s.repo.ListProducts(ctx, filter)
}

// CreateParser creates a new parser.
func (s *ParserService) CreateParser(ctx context.Context, req *model.CreateParserRequest, createdBy string) (*model.Parser, error) {
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.ProductID == "" {
		return nil, errors.New("product_id is required")
	}
	if req.Type == "" {
		return nil, errors.New("type is required")
	}

	// Verify product exists
	product, err := s.repo.GetProduct(ctx, req.ProductID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify product: %w", err)
	}
	if product == nil {
		return nil, errors.New("product not found")
	}

	// Validate pattern
	if req.Pattern != "" {
		if err := s.validatePattern(req.Type, req.Pattern); err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
	}

	parser := &model.Parser{
		TenantID:         product.TenantID,
		ProductID:        req.ProductID,
		Name:             req.Name,
		Description:      req.Description,
		Type:             req.Type,
		Status:           model.ParserStatusInactive,
		Priority:         req.Priority,
		Pattern:          req.Pattern,
		GrokPatterns:     req.GrokPatterns,
		FieldMapping:     req.FieldMapping,
		Transforms:       req.Transforms,
		Filters:          req.Filters,
		Config:           req.Config,
		NormalizeToUDM:   req.NormalizeToUDM,
		UDMMapping:       req.UDMMapping,
		DetectionPattern: req.DetectionPattern,
		Tags:             req.Tags,
		Labels:           req.Labels,
		CreatedBy:        createdBy,
	}

	if err := s.repo.CreateParser(ctx, parser); err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	s.logger.Info("parser created",
		"parser_id", parser.ID,
		"name", parser.Name,
		"product_id", parser.ProductID,
		"type", parser.Type,
		"created_by", createdBy,
	)

	return parser, nil
}

// GetParser retrieves a parser by ID.
func (s *ParserService) GetParser(ctx context.Context, id string) (*model.Parser, error) {
	parser, err := s.repo.GetParser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get parser: %w", err)
	}
	if parser == nil {
		return nil, errors.New("parser not found")
	}
	return parser, nil
}

// UpdateParser updates a parser.
func (s *ParserService) UpdateParser(ctx context.Context, id string, req *model.UpdateParserRequest, updatedBy string) (*model.Parser, error) {
	parser, err := s.repo.GetParser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get parser: %w", err)
	}
	if parser == nil {
		return nil, errors.New("parser not found")
	}

	if req.Name != nil {
		parser.Name = *req.Name
	}
	if req.Description != nil {
		parser.Description = *req.Description
	}
	if req.Status != nil {
		parser.Status = *req.Status
	}
	if req.Priority != nil {
		parser.Priority = *req.Priority
	}
	if req.Pattern != nil {
		if err := s.validatePattern(parser.Type, *req.Pattern); err != nil {
			return nil, fmt.Errorf("invalid pattern: %w", err)
		}
		parser.Pattern = *req.Pattern
	}
	if req.GrokPatterns != nil {
		parser.GrokPatterns = req.GrokPatterns
	}
	if req.FieldMapping != nil {
		parser.FieldMapping = req.FieldMapping
	}
	if req.Transforms != nil {
		parser.Transforms = req.Transforms
	}
	if req.Filters != nil {
		parser.Filters = req.Filters
	}
	if req.Config != nil {
		parser.Config = req.Config
	}
	if req.NormalizeToUDM != nil {
		parser.NormalizeToUDM = *req.NormalizeToUDM
	}
	if req.UDMMapping != nil {
		parser.UDMMapping = req.UDMMapping
	}
	if req.DetectionPattern != nil {
		parser.DetectionPattern = *req.DetectionPattern
	}
	if req.Tags != nil {
		parser.Tags = req.Tags
	}
	if req.Labels != nil {
		parser.Labels = req.Labels
	}

	parser.UpdatedBy = updatedBy

	if err := s.repo.UpdateParser(ctx, parser); err != nil {
		return nil, fmt.Errorf("failed to update parser: %w", err)
	}

	s.logger.Info("parser updated",
		"parser_id", id,
		"updated_by", updatedBy,
	)

	return parser, nil
}

// DeleteParser deletes a parser.
func (s *ParserService) DeleteParser(ctx context.Context, id string, deletedBy string) error {
	parser, err := s.repo.GetParser(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get parser: %w", err)
	}
	if parser == nil {
		return errors.New("parser not found")
	}

	// Undeploy if active
	if parser.Status == model.ParserStatusActive {
		if err := s.hotreload.UndeployParser(ctx, id); err != nil {
			s.logger.Warn("failed to undeploy parser before delete", "error", err)
		}
	}

	if err := s.repo.DeleteParser(ctx, id); err != nil {
		return fmt.Errorf("failed to delete parser: %w", err)
	}

	s.logger.Info("parser deleted",
		"parser_id", id,
		"deleted_by", deletedBy,
	)

	return nil
}

// GetParsersByProduct retrieves parsers for a product.
func (s *ParserService) GetParsersByProduct(ctx context.Context, productID string, limit, offset int) ([]*model.Parser, int, error) {
	return s.repo.GetParsersByProduct(ctx, productID, limit, offset)
}

// ListParsers lists parsers.
func (s *ParserService) ListParsers(ctx context.Context, filter *model.ParserFilter2) (*model.ParserListResult, error) {
	return s.repo.ListParsers(ctx, filter)
}

// TestParser tests a parser with sample data.
func (s *ParserService) TestParser(ctx context.Context, req *model.ParserTestRequest) ([]*model.ParserTestResult, error) {
	if len(req.Samples) == 0 {
		return nil, errors.New("at least one sample is required")
	}

	var parser *model.Parser
	var err error

	if req.ParserID != "" {
		parser, err = s.repo.GetParser(ctx, req.ParserID)
		if err != nil {
			return nil, err
		}
		if parser == nil {
			return nil, errors.New("parser not found")
		}
	} else if req.Config != nil {
		parser = req.Config
	} else {
		return nil, errors.New("parser_id or config is required")
	}

	results := make([]*model.ParserTestResult, len(req.Samples))

	for i, sample := range req.Samples {
		startTime := time.Now()

		result := &model.ParserTestResult{
			Sample: sample,
		}

		// Parse the sample
		parsedFields, err := s.parseWithParser(parser, sample)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Success = true
			result.ParsedFields = parsedFields

			// Apply UDM mapping if enabled
			if parser.NormalizeToUDM && len(parser.UDMMapping) > 0 {
				result.UDMEvent = s.applyUDMMapping(parsedFields, parser.UDMMapping)
			}
		}

		result.DurationMs = float64(time.Since(startTime).Microseconds()) / 1000
		results[i] = result
	}

	return results, nil
}

// DeployParser deploys a parser via hot reload.
func (s *ParserService) DeployParser(ctx context.Context, req *model.ParserDeployRequest, deployedBy string) (*model.ParserDeployResult, error) {
	parser, err := s.repo.GetParser(ctx, req.ParserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parser: %w", err)
	}
	if parser == nil {
		return nil, errors.New("parser not found")
	}

	// Validate parser before deployment
	if parser.Pattern == "" && parser.Type != model.ParserTypeJSON && parser.Type != model.ParserTypeCEF && parser.Type != model.ParserTypeLEEF {
		if !req.Force {
			return nil, errors.New("parser has no pattern defined")
		}
	}

	return s.hotreload.DeployParser(ctx, parser, deployedBy)
}

// GetReloadStatus returns the current reload status.
func (s *ParserService) GetReloadStatus() *model.ReloadStatus {
	return s.hotreload.GetReloadStatus()
}

// ReloadAll triggers a reload of all parsers.
func (s *ParserService) ReloadAll(ctx context.Context) error {
	return s.hotreload.ReloadAll(ctx)
}

// GetHotReloadStats returns hot reload statistics.
func (s *ParserService) GetHotReloadStats() map[string]interface{} {
	return s.hotreload.Stats()
}

func (s *ParserService) validatePattern(parserType model.ParserType, pattern string) error {
	switch parserType {
	case model.ParserTypeRegex:
		_, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	case model.ParserTypeGrok:
		// Basic grok pattern validation
		if pattern == "" {
			return errors.New("grok pattern cannot be empty")
		}
	}
	return nil
}

func (s *ParserService) parseWithParser(parser *model.Parser, sample string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	switch parser.Type {
	case model.ParserTypeJSON:
		return s.parseJSON(sample)
	case model.ParserTypeRegex:
		return s.parseRegex(parser.Pattern, sample)
	case model.ParserTypeCEF:
		return s.parseCEF(sample)
	case model.ParserTypeLEEF:
		return s.parseLEEF(sample)
	case model.ParserTypeGrok:
		return s.parseGrok(parser.Pattern, parser.GrokPatterns, sample)
	default:
		return result, fmt.Errorf("unsupported parser type: %s", parser.Type)
	}
}

func (s *ParserService) parseJSON(sample string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	if err := json.Unmarshal([]byte(sample), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return result, nil
}

func (s *ParserService) parseRegex(pattern, sample string) (map[string]interface{}, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	matches := re.FindStringSubmatch(sample)
	if matches == nil {
		return nil, errors.New("pattern did not match")
	}

	result := make(map[string]interface{})
	names := re.SubexpNames()
	for i, name := range names {
		if i > 0 && name != "" && i < len(matches) {
			result[name] = matches[i]
		}
	}

	return result, nil
}

func (s *ParserService) parseCEF(sample string) (map[string]interface{}, error) {
	// Basic CEF parsing
	result := make(map[string]interface{})
	result["raw"] = sample
	result["format"] = "cef"
	// Full CEF parsing would be implemented here
	return result, nil
}

func (s *ParserService) parseLEEF(sample string) (map[string]interface{}, error) {
	// Basic LEEF parsing
	result := make(map[string]interface{})
	result["raw"] = sample
	result["format"] = "leef"
	// Full LEEF parsing would be implemented here
	return result, nil
}

func (s *ParserService) parseGrok(pattern string, customPatterns map[string]string, sample string) (map[string]interface{}, error) {
	// Basic grok pattern extraction (simplified)
	result := make(map[string]interface{})
	result["raw"] = sample
	result["pattern"] = pattern
	// Full grok parsing would use a grok library
	return result, nil
}

func (s *ParserService) applyUDMMapping(fields map[string]interface{}, mapping map[string]string) map[string]interface{} {
	udm := make(map[string]interface{})
	for sourceField, targetField := range mapping {
		if value, ok := fields[sourceField]; ok {
			udm[targetField] = value
		}
	}
	return udm
}
