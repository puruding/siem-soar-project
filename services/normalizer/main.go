package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/normalizer/internal/config"
	"github.com/siem-soar-platform/services/normalizer/internal/consumer"
	"github.com/siem-soar-platform/services/normalizer/internal/mapping"
	"github.com/siem-soar-platform/services/normalizer/internal/normalizer"
	"github.com/siem-soar-platform/services/normalizer/internal/udm"
)

const (
	serviceName = "normalizer"
)

// Server holds all service dependencies.
type Server struct {
	normalizer *normalizer.Normalizer
	mapper     *udm.Mapper
	consumer   *consumer.Consumer
	config     *config.Config
	stats      *Stats
	logger     *slog.Logger

	// Custom mappings storage (in-memory)
	customMappings   map[string]*udm.MappingConfig
	customMappingsMu sync.RWMutex

	// Kafka connectivity status
	kafkaConnected atomic.Bool
}

// Stats holds normalization statistics.
type Stats struct {
	EventsNormalized  atomic.Int64
	BatchesProcessed  atomic.Int64
	NormalizeErrors   atomic.Int64
	ValidationErrors  atomic.Int64
	TotalNormalizeMs  atomic.Int64
	mu                sync.RWMutex
}

// NormalizeRequest represents a single event normalization request.
type NormalizeRequest struct {
	SourceType  string                 `json:"source_type"`
	ParsedEvent map[string]interface{} `json:"parsed_event"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	EventID     string                 `json:"event_id,omitempty"`
}

// NormalizeResponse represents a single event normalization response.
type NormalizeResponse struct {
	Success        bool                    `json:"success"`
	UDMEvent       *normalizer.UDMEvent    `json:"udm_event,omitempty"`
	Error          string                  `json:"error,omitempty"`
	NormalizeTimeMs int64                  `json:"normalize_time_ms"`
}

// BatchNormalizeRequest represents a batch normalization request.
type BatchNormalizeRequest struct {
	Events []NormalizeRequest `json:"events"`
}

// BatchNormalizeResponse represents a batch normalization response.
type BatchNormalizeResponse struct {
	TotalCount    int                  `json:"total_count"`
	SuccessCount  int                  `json:"success_count"`
	FailedCount   int                  `json:"failed_count"`
	Results       []NormalizeResponse  `json:"results"`
	TotalTimeMs   int64                `json:"total_time_ms"`
}

// MappingInfo represents mapping information for API responses.
type MappingInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	SourceType      string `json:"source_type"`
	VendorName      string `json:"vendor_name"`
	ProductName     string `json:"product_name"`
	FieldMappings   int    `json:"field_mappings_count"`
	EventTypeMappings int  `json:"event_type_mappings_count"`
}

// CreateMappingRequest represents a request to create a custom mapping.
type CreateMappingRequest struct {
	Name              string                   `json:"name"`
	SourceType        string                   `json:"source_type"`
	VendorName        string                   `json:"vendor_name"`
	ProductName       string                   `json:"product_name"`
	DefaultEventType  string                   `json:"default_event_type"`
	EventTypeMappings map[string]string        `json:"event_type_mappings,omitempty"`
	FieldMappings     []udm.FieldMapping       `json:"field_mappings"`
}

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.Load()

	// Initialize normalizer engine
	norm := normalizer.NewNormalizer(logger)
	norm.SetPreserveUnmapped(cfg.PreserveUnmappedFields)
	norm.SetStrictValidation(cfg.StrictValidation)
	norm.SetRequiredFields(cfg.RequiredFields)

	// Initialize UDM mapper
	mapper := udm.NewMapper()

	// Create server
	server := &Server{
		normalizer:     norm,
		mapper:         mapper,
		config:         cfg,
		stats:          &Stats{},
		logger:         logger,
		customMappings: make(map[string]*udm.MappingConfig),
	}

	// Load all default mappings (17 total)
	server.loadDefaultMappings()

	// Initialize Kafka consumer (if Kafka is configured)
	if len(cfg.KafkaBrokers) > 0 && cfg.KafkaBrokers[0] != "" {
		cons, err := consumer.NewConsumer(cfg, norm, logger)
		if err != nil {
			logger.Warn("failed to create Kafka consumer, running in API-only mode", "error", err)
		} else {
			server.consumer = cons
			server.kafkaConnected.Store(true)
		}
	}

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.healthHandler)
	mux.HandleFunc("GET /ready", server.readyHandler)
	mux.HandleFunc("POST /api/v1/normalize", server.normalizeHandler)
	mux.HandleFunc("POST /api/v1/normalize/batch", server.batchNormalizeHandler)
	mux.HandleFunc("GET /api/v1/mappings", server.listMappingsHandler)
	mux.HandleFunc("POST /api/v1/mappings", server.createMappingHandler)
	mux.HandleFunc("GET /api/v1/mappings/{id}", server.getMappingHandler)
	mux.HandleFunc("PUT /api/v1/mappings/{id}", server.updateMappingHandler)
	mux.HandleFunc("DELETE /api/v1/mappings/{id}", server.deleteMappingHandler)
	mux.HandleFunc("GET /api/v1/schema", server.schemaHandler)
	mux.HandleFunc("GET /api/v1/stats", server.statsHandler)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start Kafka consumer in background
	if server.consumer != nil {
		server.consumer.Start()
		logger.Info("kafka consumer started")
	}

	// Start HTTP server
	go func() {
		slog.Info("starting server", "service", serviceName, "port", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop Kafka consumer first
	if server.consumer != nil {
		server.consumer.Stop()
		logger.Info("kafka consumer stopped")
	}

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
}

// loadDefaultMappings loads all 17 default mappings.
func (s *Server) loadDefaultMappings() {
	// Windows mappings (2)
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.WindowsEventMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.WindowsSysmonMapping()))
	s.mapper.RegisterConfig(mapping.WindowsEventMapping())
	s.mapper.RegisterConfig(mapping.WindowsSysmonMapping())

	// Linux mappings (4)
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.LinuxAuthMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.LinuxAuditdMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.LinuxSyslogMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.LinuxSystemdMapping()))
	s.mapper.RegisterConfig(mapping.LinuxAuthMapping())
	s.mapper.RegisterConfig(mapping.LinuxAuditdMapping())
	s.mapper.RegisterConfig(mapping.LinuxSyslogMapping())
	s.mapper.RegisterConfig(mapping.LinuxSystemdMapping())

	// Network mappings (6)
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.FirewallMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.IPSIDSMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.VPNMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.ProxyMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.DNSMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.DHCPMapping()))
	s.mapper.RegisterConfig(mapping.FirewallMapping())
	s.mapper.RegisterConfig(mapping.IPSIDSMapping())
	s.mapper.RegisterConfig(mapping.VPNMapping())
	s.mapper.RegisterConfig(mapping.ProxyMapping())
	s.mapper.RegisterConfig(mapping.DNSMapping())
	s.mapper.RegisterConfig(mapping.DHCPMapping())

	// Cloud mappings (5)
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.AWSCloudTrailMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.GCPAuditMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.AzureActivityMapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.Office365Mapping()))
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(mapping.KubernetesAuditMapping()))
	s.mapper.RegisterConfig(mapping.AWSCloudTrailMapping())
	s.mapper.RegisterConfig(mapping.GCPAuditMapping())
	s.mapper.RegisterConfig(mapping.AzureActivityMapping())
	s.mapper.RegisterConfig(mapping.Office365Mapping())
	s.mapper.RegisterConfig(mapping.KubernetesAuditMapping())

	s.logger.Info("loaded default mappings", "count", 17)
}

// convertUDMToNormalizerMapping converts udm.MappingConfig to normalizer.MappingConfig.
func convertUDMToNormalizerMapping(src *udm.MappingConfig) *normalizer.MappingConfig {
	dst := &normalizer.MappingConfig{
		Name:             src.Name,
		SourceType:       src.SourceType,
		VendorName:       src.VendorName,
		ProductName:      src.ProductName,
		DefaultEventType: normalizer.EventType(src.DefaultEventType),
		EventTypeMappings: make(map[string]normalizer.EventType),
		FieldMappings:    make([]normalizer.FieldMapping, 0, len(src.FieldMappings)),
	}

	// Convert event type mappings
	for k, v := range src.EventTypeMappings {
		dst.EventTypeMappings[k] = normalizer.EventType(v)
	}

	// Convert field mappings
	for _, fm := range src.FieldMappings {
		dst.FieldMappings = append(dst.FieldMappings, normalizer.FieldMapping{
			SourceField:  fm.SourceField,
			TargetField:  fm.TargetField,
			Transform:    fm.Transform,
			Condition:    fm.Condition,
			DefaultValue: fm.DefaultValue,
			Required:     fm.Required,
			Multiple:     fm.Multiple,
			Parameters:   fm.Parameters,
		})
	}

	return dst
}

// healthHandler returns service health status.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": serviceName,
	})
}

// readyHandler returns service readiness status.
func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "ready"
	httpStatus := http.StatusOK

	// Check Kafka connectivity if configured
	dependencies := map[string]string{}
	if s.consumer != nil {
		if s.kafkaConnected.Load() {
			dependencies["kafka"] = "connected"
		} else {
			dependencies["kafka"] = "disconnected"
			// Don't fail readiness for Kafka - API mode still works
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       status,
		"service":      serviceName,
		"dependencies": dependencies,
	})
	w.WriteHeader(httpStatus)
}

// normalizeHandler normalizes a single event.
func (s *Server) normalizeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req NormalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(NormalizeResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	start := time.Now()

	// Set defaults
	if req.EventID == "" {
		req.EventID = uuid.New().String()
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	// Get timestamp from parsed event or use current time
	timestamp := time.Now().UTC()
	if ts, ok := req.ParsedEvent["timestamp"]; ok {
		if tsStr, ok := ts.(string); ok {
			if parsed, err := time.Parse(time.RFC3339, tsStr); err == nil {
				timestamp = parsed
			}
		}
	}

	// Create input event
	input := &normalizer.InputEvent{
		EventID:    req.EventID,
		TenantID:   req.TenantID,
		SourceType: req.SourceType,
		Timestamp:  timestamp,
		Fields:     req.ParsedEvent,
	}

	// Normalize
	udmEvent, err := s.normalizer.Normalize(input)
	elapsed := time.Since(start).Milliseconds()

	// Update stats
	s.stats.TotalNormalizeMs.Add(elapsed)
	if err != nil {
		s.stats.NormalizeErrors.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(NormalizeResponse{
			Success:        false,
			Error:          err.Error(),
			NormalizeTimeMs: elapsed,
		})
		return
	}

	s.stats.EventsNormalized.Add(1)

	// Validate if strict mode enabled
	if s.config.StrictValidation {
		if validErr := s.normalizer.Validate(udmEvent); validErr != nil {
			s.stats.ValidationErrors.Add(1)
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(NormalizeResponse{
				Success:        false,
				Error:          fmt.Sprintf("validation failed: %v", validErr),
				NormalizeTimeMs: elapsed,
			})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(NormalizeResponse{
		Success:        true,
		UDMEvent:       udmEvent,
		NormalizeTimeMs: elapsed,
	})
}

// batchNormalizeHandler normalizes a batch of events.
func (s *Server) batchNormalizeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchNormalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	start := time.Now()
	results := make([]NormalizeResponse, 0, len(req.Events))
	successCount := 0
	failedCount := 0

	for _, event := range req.Events {
		eventStart := time.Now()

		// Set defaults
		if event.EventID == "" {
			event.EventID = uuid.New().String()
		}
		if event.TenantID == "" {
			event.TenantID = "default"
		}

		// Get timestamp
		timestamp := time.Now().UTC()
		if ts, ok := event.ParsedEvent["timestamp"]; ok {
			if tsStr, ok := ts.(string); ok {
				if parsed, err := time.Parse(time.RFC3339, tsStr); err == nil {
					timestamp = parsed
				}
			}
		}

		// Create input
		input := &normalizer.InputEvent{
			EventID:    event.EventID,
			TenantID:   event.TenantID,
			SourceType: event.SourceType,
			Timestamp:  timestamp,
			Fields:     event.ParsedEvent,
		}

		// Normalize
		udmEvent, err := s.normalizer.Normalize(input)
		elapsed := time.Since(eventStart).Milliseconds()

		if err != nil {
			s.stats.NormalizeErrors.Add(1)
			failedCount++
			results = append(results, NormalizeResponse{
				Success:        false,
				Error:          err.Error(),
				NormalizeTimeMs: elapsed,
			})
			continue
		}

		// Validate if strict mode
		if s.config.StrictValidation {
			if validErr := s.normalizer.Validate(udmEvent); validErr != nil {
				s.stats.ValidationErrors.Add(1)
				failedCount++
				results = append(results, NormalizeResponse{
					Success:        false,
					Error:          fmt.Sprintf("validation failed: %v", validErr),
					NormalizeTimeMs: elapsed,
				})
				continue
			}
		}

		s.stats.EventsNormalized.Add(1)
		successCount++
		results = append(results, NormalizeResponse{
			Success:        true,
			UDMEvent:       udmEvent,
			NormalizeTimeMs: elapsed,
		})
	}

	s.stats.BatchesProcessed.Add(1)
	totalElapsed := time.Since(start).Milliseconds()
	s.stats.TotalNormalizeMs.Add(totalElapsed)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(BatchNormalizeResponse{
		TotalCount:   len(req.Events),
		SuccessCount: successCount,
		FailedCount:  failedCount,
		Results:      results,
		TotalTimeMs:  totalElapsed,
	})
}

// listMappingsHandler lists all loaded mappings.
func (s *Server) listMappingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	mappings := s.normalizer.GetMappings()
	result := make([]MappingInfo, 0, len(mappings))

	for _, m := range mappings {
		result = append(result, MappingInfo{
			ID:                m.SourceType,
			Name:              m.Name,
			SourceType:        m.SourceType,
			VendorName:        m.VendorName,
			ProductName:       m.ProductName,
			FieldMappings:     len(m.FieldMappings),
			EventTypeMappings: len(m.EventTypeMappings),
		})
	}

	// Add custom mappings
	s.customMappingsMu.RLock()
	for _, m := range s.customMappings {
		result = append(result, MappingInfo{
			ID:                m.SourceType,
			Name:              m.Name,
			SourceType:        m.SourceType,
			VendorName:        m.VendorName,
			ProductName:       m.ProductName,
			FieldMappings:     len(m.FieldMappings),
			EventTypeMappings: len(m.EventTypeMappings),
		})
	}
	s.customMappingsMu.RUnlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mappings": result,
		"count":    len(result),
	})
}

// createMappingHandler creates a new custom mapping.
func (s *Server) createMappingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CreateMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	// Validate required fields
	if req.SourceType == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "source_type is required"})
		return
	}

	// Check if mapping already exists
	s.customMappingsMu.RLock()
	_, exists := s.customMappings[req.SourceType]
	s.customMappingsMu.RUnlock()

	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "mapping with this source_type already exists"})
		return
	}

	// Also check built-in mappings
	builtInMappings := s.normalizer.GetMappings()
	if _, exists := builtInMappings[req.SourceType]; exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "cannot override built-in mapping"})
		return
	}

	// Convert event type mappings
	eventTypeMappings := make(map[string]udm.EventType)
	for k, v := range req.EventTypeMappings {
		eventTypeMappings[k] = udm.EventType(v)
	}

	// Create mapping config
	cfg := &udm.MappingConfig{
		Name:              req.Name,
		SourceType:        req.SourceType,
		VendorName:        req.VendorName,
		ProductName:       req.ProductName,
		DefaultEventType:  udm.EventType(req.DefaultEventType),
		EventTypeMappings: eventTypeMappings,
		FieldMappings:     req.FieldMappings,
	}

	// Store custom mapping
	s.customMappingsMu.Lock()
	s.customMappings[req.SourceType] = cfg
	s.customMappingsMu.Unlock()

	// Register with normalizer and mapper
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(cfg))
	s.mapper.RegisterConfig(cfg)

	s.logger.Info("custom mapping created", "source_type", req.SourceType)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "mapping created",
		"id":      req.SourceType,
	})
}

// getMappingHandler gets a mapping by source type.
func (s *Server) getMappingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "mapping id is required"})
		return
	}

	// Check custom mappings first
	s.customMappingsMu.RLock()
	customCfg, customExists := s.customMappings[id]
	s.customMappingsMu.RUnlock()

	if customExists {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":                   customCfg.SourceType,
			"name":                 customCfg.Name,
			"source_type":          customCfg.SourceType,
			"vendor_name":          customCfg.VendorName,
			"product_name":         customCfg.ProductName,
			"default_event_type":   customCfg.DefaultEventType,
			"event_type_mappings":  customCfg.EventTypeMappings,
			"field_mappings":       customCfg.FieldMappings,
			"custom":               true,
		})
		return
	}

	// Check built-in mappings
	builtInMappings := s.normalizer.GetMappings()
	if cfg, exists := builtInMappings[id]; exists {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":                   cfg.SourceType,
			"name":                 cfg.Name,
			"source_type":          cfg.SourceType,
			"vendor_name":          cfg.VendorName,
			"product_name":         cfg.ProductName,
			"default_event_type":   cfg.DefaultEventType,
			"event_type_mappings":  cfg.EventTypeMappings,
			"field_mappings":       cfg.FieldMappings,
			"custom":               false,
		})
		return
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "mapping not found"})
}

// updateMappingHandler updates an existing custom mapping.
func (s *Server) updateMappingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "mapping id is required"})
		return
	}

	// Check if it's a built-in mapping
	builtInMappings := s.normalizer.GetMappings()
	if _, exists := builtInMappings[id]; exists {
		// Check if it's NOT a custom mapping
		s.customMappingsMu.RLock()
		_, isCustom := s.customMappings[id]
		s.customMappingsMu.RUnlock()

		if !isCustom {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "cannot update built-in mapping"})
			return
		}
	}

	var req CreateMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	// Convert event type mappings
	eventTypeMappings := make(map[string]udm.EventType)
	for k, v := range req.EventTypeMappings {
		eventTypeMappings[k] = udm.EventType(v)
	}

	// Create updated config
	cfg := &udm.MappingConfig{
		Name:              req.Name,
		SourceType:        id, // Use path id, not body
		VendorName:        req.VendorName,
		ProductName:       req.ProductName,
		DefaultEventType:  udm.EventType(req.DefaultEventType),
		EventTypeMappings: eventTypeMappings,
		FieldMappings:     req.FieldMappings,
	}

	// Update custom mapping
	s.customMappingsMu.Lock()
	s.customMappings[id] = cfg
	s.customMappingsMu.Unlock()

	// Re-register with normalizer and mapper
	s.normalizer.RegisterMapping(convertUDMToNormalizerMapping(cfg))
	s.mapper.RegisterConfig(cfg)

	s.logger.Info("custom mapping updated", "source_type", id)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "mapping updated"})
}

// deleteMappingHandler deletes a custom mapping.
func (s *Server) deleteMappingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "mapping id is required"})
		return
	}

	// Check if it's a custom mapping
	s.customMappingsMu.Lock()
	_, exists := s.customMappings[id]
	if exists {
		delete(s.customMappings, id)
	}
	s.customMappingsMu.Unlock()

	if !exists {
		// Check if it's a built-in mapping
		builtInMappings := s.normalizer.GetMappings()
		if _, builtInExists := builtInMappings[id]; builtInExists {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "cannot delete built-in mapping"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "mapping not found"})
		return
	}

	s.logger.Info("custom mapping deleted", "source_type", id)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "mapping deleted"})
}

// schemaHandler returns UDM schema documentation.
func (s *Server) schemaHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	schema := map[string]interface{}{
		"schema":  "udm",
		"version": "1.0",
		"description": "Google Chronicle Unified Data Model (UDM) schema for security event normalization",
		"entities": []string{
			"metadata",
			"principal",
			"target",
			"src",
			"observer",
			"intermediary",
			"network",
			"security_result",
			"extensions",
			"about",
		},
		"event_types": []string{
			"GENERIC_EVENT",
			"USER_LOGIN",
			"USER_LOGOUT",
			"USER_CREATION",
			"USER_DELETION",
			"USER_PASSWORD_CHANGE",
			"USER_PRIVILEGE_CHANGE",
			"GROUP_CREATION",
			"GROUP_DELETION",
			"GROUP_MODIFICATION",
			"NETWORK_CONNECTION",
			"NETWORK_FLOW",
			"NETWORK_DNS",
			"NETWORK_DHCP",
			"NETWORK_HTTP",
			"FILE_CREATION",
			"FILE_DELETION",
			"FILE_MODIFICATION",
			"FILE_READ",
			"FILE_COPY",
			"FILE_MOVE",
			"PROCESS_LAUNCH",
			"PROCESS_TERMINATION",
			"PROCESS_INJECTION",
			"REGISTRY_CREATION",
			"REGISTRY_DELETION",
			"REGISTRY_MODIFICATION",
			"SERVICE_CREATION",
			"SERVICE_DELETION",
			"SERVICE_START",
			"SERVICE_STOP",
			"SCHEDULED_TASK",
			"SCAN",
			"RESOURCE_ACCESS",
			"RESOURCE_CREATION",
			"RESOURCE_DELETION",
			"STATUS_UPDATE",
			"SYSTEM_AUDIT_LOG_EVENT",
		},
		"transforms": []string{
			"to_int",
			"to_timestamp",
			"uppercase",
			"lowercase",
			"trim",
			"split",
			"regex_extract",
			"map_value",
		},
		"supported_sources": map[string][]string{
			"windows": {"windows", "sysmon"},
			"linux":   {"linux_auth", "auditd", "syslog", "journald"},
			"network": {"firewall", "ips", "vpn", "proxy", "dns", "dhcp"},
			"cloud":   {"cloudtrail", "gcp_audit", "azure_activity", "office365", "kubernetes"},
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(schema)
}

// statsHandler returns normalization statistics.
func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	eventsNormalized := s.stats.EventsNormalized.Load()
	totalMs := s.stats.TotalNormalizeMs.Load()

	var avgMs float64
	if eventsNormalized > 0 {
		avgMs = float64(totalMs) / float64(eventsNormalized)
	}

	// Get normalizer stats
	normStats := s.normalizer.Stats()

	// Get consumer stats if available
	var consumerStats map[string]interface{}
	if s.consumer != nil {
		consumerStats = s.consumer.Stats()
	}

	stats := map[string]interface{}{
		"service": serviceName,
		"api": map[string]interface{}{
			"events_normalized":    eventsNormalized,
			"batches_processed":    s.stats.BatchesProcessed.Load(),
			"normalize_errors":     s.stats.NormalizeErrors.Load(),
			"validation_errors":    s.stats.ValidationErrors.Load(),
			"total_normalize_ms":   totalMs,
			"avg_normalize_time_ms": avgMs,
		},
		"normalizer": normStats,
		"mappings": map[string]interface{}{
			"built_in_count": len(s.normalizer.GetMappings()),
			"custom_count":   len(s.customMappings),
		},
	}

	if consumerStats != nil {
		stats["kafka_consumer"] = consumerStats
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
