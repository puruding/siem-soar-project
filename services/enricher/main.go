package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/siem-soar-platform/services/enricher/internal/config"
	"github.com/siem-soar-platform/services/enricher/internal/consumer"
	"github.com/siem-soar-platform/services/enricher/internal/enrichment"
)

const (
	serviceName = "enricher"
)

// Server holds all service dependencies.
type Server struct {
	config   *config.Config
	engine   *enrichment.Engine
	geoip    *enrichment.GeoIPEnricher
	asset    *enrichment.AssetEnricher
	user     *enrichment.UserEnricher
	threat   *enrichment.ThreatEnricher
	consumer *consumer.Consumer
	logger   *slog.Logger

	// Status flags
	kafkaConnected atomic.Bool
	ready          atomic.Bool
}

// EnrichRequest represents a single event enrichment request.
type EnrichRequest struct {
	UDMEvent        *enrichment.UDMEvent `json:"udm_event"`
	EnrichmentTypes []string             `json:"enrichment_types,omitempty"` // geoip, asset, user, threat
}

// EnrichResponse represents a single event enrichment response.
type EnrichResponse struct {
	Success       bool                      `json:"success"`
	EnrichedEvent *enrichment.UDMEvent      `json:"enriched_event,omitempty"`
	Enrichments   *EnrichmentDetails        `json:"enrichments,omitempty"`
	EnrichTimeMs  int64                     `json:"enrich_time_ms"`
	Error         string                    `json:"error,omitempty"`
}

// EnrichmentDetails contains detailed enrichment results.
type EnrichmentDetails struct {
	GeoIP   map[string]*enrichment.GeoIPResult  `json:"geoip,omitempty"`
	Assets  map[string]*enrichment.AssetInfo    `json:"assets,omitempty"`
	Users   map[string]*enrichment.UserInfo     `json:"users,omitempty"`
	Threats map[string]*enrichment.ThreatInfo   `json:"threats,omitempty"`
}

// BatchEnrichRequest represents a batch enrichment request.
type BatchEnrichRequest struct {
	Events []EnrichRequest `json:"events"`
}

// BatchEnrichResponse represents a batch enrichment response.
type BatchEnrichResponse struct {
	TotalCount   int               `json:"total_count"`
	SuccessCount int               `json:"success_count"`
	FailedCount  int               `json:"failed_count"`
	Results      []EnrichResponse  `json:"results"`
	TotalTimeMs  int64             `json:"total_time_ms"`
}

// CacheInvalidateRequest represents a cache invalidation request.
type CacheInvalidateRequest struct {
	Type   string   `json:"type,omitempty"`   // geoip, asset, user, threat, or empty for all
	Keys   []string `json:"keys,omitempty"`   // specific keys to invalidate
}

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.Load()

	// Create server
	server := &Server{
		config: cfg,
		logger: logger,
	}

	// Initialize enrichers
	if err := server.initEnrichers(); err != nil {
		logger.Error("failed to initialize enrichers", "error", err)
		os.Exit(1)
	}

	// Initialize Kafka consumer (if configured)
	if len(cfg.KafkaBrokers) > 0 && cfg.KafkaBrokers[0] != "" {
		cons, err := consumer.NewConsumer(cfg, server.engine, logger)
		if err != nil {
			logger.Warn("failed to create Kafka consumer, running in API-only mode", "error", err)
		} else {
			server.consumer = cons
			server.kafkaConnected.Store(true)
		}
	}

	// Load sample data for development
	server.loadDevData()

	server.ready.Store(true)

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.healthHandler)
	mux.HandleFunc("GET /ready", server.readyHandler)
	mux.HandleFunc("POST /api/v1/enrich", server.enrichHandler)
	mux.HandleFunc("POST /api/v1/enrich/batch", server.batchEnrichHandler)
	mux.HandleFunc("GET /api/v1/geoip/{ip}", server.geoipLookupHandler)
	mux.HandleFunc("GET /api/v1/asset/{identifier}", server.assetLookupHandler)
	mux.HandleFunc("GET /api/v1/user/{identifier}", server.userLookupHandler)
	mux.HandleFunc("GET /api/v1/threat/{ioc}", server.threatLookupHandler)
	mux.HandleFunc("GET /api/v1/cache/stats", server.cacheStatsHandler)
	mux.HandleFunc("POST /api/v1/cache/invalidate", server.cacheInvalidateHandler)
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

	// Close enrichers
	server.closeEnrichers()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
}

// initEnrichers initializes all enrichers based on configuration.
func (s *Server) initEnrichers() error {
	cfg := s.config

	// Initialize GeoIP enricher
	if cfg.EnableGeoIP && (cfg.GeoIPCityDB != "" || cfg.GeoIPASNDB != "") {
		geoipCfg := enrichment.GeoIPConfig{
			CityDBPath:      cfg.GeoIPCityDB,
			ASNDBPath:       cfg.GeoIPASNDB,
			AnonymousDBPath: cfg.GeoIPAnonDB,
			CacheSize:       cfg.GeoIPCacheSize,
			CacheTTL:        cfg.GeoIPCacheTTL,
		}
		geoip, err := enrichment.NewGeoIPEnricher(geoipCfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to initialize GeoIP enricher", "error", err)
		} else {
			s.geoip = geoip
			s.logger.Info("GeoIP enricher initialized")
		}
	}

	// Initialize Asset enricher
	if cfg.EnableAsset {
		assetCfg := enrichment.AssetEnricherConfig{
			CMDBEndpoint:   cfg.CMDBEndpoint,
			CMDBAPIKey:     cfg.CMDBAPIKey,
			CacheSize:      cfg.AssetCacheSize,
			CacheTTL:       cfg.AssetCacheTTL,
			RequestTimeout: cfg.RequestTimeout,
		}
		s.asset = enrichment.NewAssetEnricher(assetCfg, s.logger)
		s.logger.Info("Asset enricher initialized")
	}

	// Initialize User enricher
	if cfg.EnableUser {
		userCfg := enrichment.UserEnricherConfig{
			LDAPEndpoint:     cfg.LDAPEndpoint,
			LDAPBaseDN:       cfg.LDAPBaseDN,
			LDAPBindDN:       cfg.LDAPBindDN,
			LDAPBindPassword: cfg.LDAPBindPassword,
			LDAPUseTLS:       cfg.LDAPUseTLS,
			CacheSize:        cfg.UserCacheSize,
			CacheTTL:         cfg.UserCacheTTL,
			RequestTimeout:   cfg.RequestTimeout,
		}
		s.user = enrichment.NewUserEnricher(userCfg, s.logger)
		s.logger.Info("User enricher initialized")
	}

	// Initialize Threat enricher
	if cfg.EnableThreat {
		threatCfg := enrichment.ThreatEnricherConfig{
			MISPEndpoint:   cfg.MISPEndpoint,
			MISPAPIKey:     cfg.MISPAPIKey,
			OTXEndpoint:    cfg.OTXEndpoint,
			OTXAPIKey:      cfg.OTXAPIKey,
			VirusTotalKey:  cfg.VirusTotalKey,
			AbuseIPDBKey:   cfg.AbuseIPDBKey,
			CacheSize:      cfg.ThreatCacheSize,
			CacheTTL:       cfg.ThreatCacheTTL,
			RequestTimeout: cfg.RequestTimeout,
		}
		s.threat = enrichment.NewThreatEnricher(threatCfg, s.logger)
		s.logger.Info("Threat enricher initialized")
	}

	// Create enrichment engine
	engineCfg := enrichment.EngineConfig{
		EnableGeoIP:    cfg.EnableGeoIP,
		EnableAsset:    cfg.EnableAsset,
		EnableUser:     cfg.EnableUser,
		EnableThreat:   cfg.EnableThreat,
		SkipPrivateIPs: cfg.SkipPrivateIPs,
	}
	s.engine = enrichment.NewEngine(s.geoip, s.asset, s.user, s.threat, engineCfg, s.logger)
	s.logger.Info("Enrichment engine initialized")

	return nil
}

// closeEnrichers closes all enrichers.
func (s *Server) closeEnrichers() {
	if s.geoip != nil {
		if err := s.geoip.Close(); err != nil {
			s.logger.Error("failed to close GeoIP enricher", "error", err)
		}
	}
	if s.user != nil {
		if err := s.user.Close(); err != nil {
			s.logger.Error("failed to close User enricher", "error", err)
		}
	}
}

// loadDevData loads sample data for development/testing.
func (s *Server) loadDevData() {
	// Register sample assets
	if s.asset != nil {
		s.asset.RegisterLocalAsset(&enrichment.AssetInfo{
			AssetID:      "ASSET-001",
			Hostname:     "ws-admin-001",
			FQDN:         "ws-admin-001.corp.local",
			IPAddresses:  []string{"192.168.1.100"},
			AssetType:    "workstation",
			OS:           "Windows 11",
			OSVersion:    "22H2",
			Owner:        "admin",
			OwnerEmail:   "admin@corp.local",
			Department:   "IT",
			BusinessUnit: "Security",
			Location:     "HQ Floor 5",
			Criticality:  "high",
			Environment:  "production",
		})
		s.asset.RegisterLocalAsset(&enrichment.AssetInfo{
			AssetID:      "ASSET-002",
			Hostname:     "srv-db-001",
			FQDN:         "srv-db-001.corp.local",
			IPAddresses:  []string{"192.168.1.50"},
			AssetType:    "server",
			OS:           "Ubuntu",
			OSVersion:    "22.04 LTS",
			Owner:        "dba-team",
			OwnerEmail:   "dba@corp.local",
			Department:   "IT",
			BusinessUnit: "Infrastructure",
			Criticality:  "critical",
			Environment:  "production",
		})
		s.logger.Info("loaded sample assets", "count", 2)
	}

	// Register sample users
	if s.user != nil {
		s.user.RegisterLocalUser(&enrichment.UserInfo{
			UserID:       "EMP001",
			Username:     "admin",
			Email:        "admin@corp.local",
			DisplayName:  "System Administrator",
			FirstName:    "Admin",
			LastName:     "User",
			Department:   "IT",
			Title:        "Senior System Administrator",
			Manager:      "IT Director",
			Groups:       []string{"Domain Admins", "IT Staff", "VPN Users"},
			Location:     "Headquarters",
			EmployeeType: "employee",
			AccountStatus: "active",
		})
		s.user.RegisterLocalUser(&enrichment.UserInfo{
			UserID:       "EMP002",
			Username:     "jsmith",
			Email:        "jsmith@corp.local",
			DisplayName:  "John Smith",
			FirstName:    "John",
			LastName:     "Smith",
			Department:   "Engineering",
			Title:        "Software Engineer",
			Manager:      "Engineering Manager",
			Groups:       []string{"Developers", "VPN Users"},
			Location:     "Remote",
			EmployeeType: "employee",
			AccountStatus: "active",
		})
		s.logger.Info("loaded sample users", "count", 2)
	}

	// Register sample threat indicators
	if s.threat != nil {
		s.threat.RegisterLocalIOC(&enrichment.ThreatInfo{
			IOC:        "malware-c2.evil",
			IOCType:    "domain",
			ThreatType: "c2",
			ThreatName: "Cobalt Strike C2",
			Confidence: 95,
			Severity:   "critical",
			Sources: []enrichment.ThreatSource{{
				Name:       "Internal TI",
				Confidence: 95,
				LastSeen:   time.Now(),
			}},
			Tags:      []string{"apt", "c2", "cobalt-strike"},
			LastSeen:  time.Now(),
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		})
		s.threat.RegisterLocalIOC(&enrichment.ThreatInfo{
			IOC:        "185.234.72.100",
			IOCType:    "ip",
			ThreatType: "malicious_ip",
			ThreatName: "Known Malicious IP",
			Confidence: 80,
			Severity:   "high",
			Sources: []enrichment.ThreatSource{{
				Name:       "Internal TI",
				Confidence: 80,
				LastSeen:   time.Now(),
			}},
			Tags:      []string{"scanner", "bruteforce"},
			LastSeen:  time.Now(),
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		})
		s.logger.Info("loaded sample threat indicators", "count", 2)
	}
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

	if !s.ready.Load() {
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	}

	// Check enricher status
	enrichers := map[string]string{}
	if s.geoip != nil {
		enrichers["geoip"] = "enabled"
	} else {
		enrichers["geoip"] = "disabled"
	}
	if s.asset != nil {
		enrichers["asset"] = "enabled"
	} else {
		enrichers["asset"] = "disabled"
	}
	if s.user != nil {
		enrichers["user"] = "enabled"
	} else {
		enrichers["user"] = "disabled"
	}
	if s.threat != nil {
		enrichers["threat"] = "enabled"
	} else {
		enrichers["threat"] = "disabled"
	}

	// Check Kafka
	dependencies := map[string]string{}
	if s.consumer != nil {
		if s.kafkaConnected.Load() {
			dependencies["kafka"] = "connected"
		} else {
			dependencies["kafka"] = "disconnected"
		}
	}

	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       status,
		"service":      serviceName,
		"enrichers":    enrichers,
		"dependencies": dependencies,
	})
}

// enrichHandler enriches a single event.
func (s *Server) enrichHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req EnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(EnrichResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if req.UDMEvent == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(EnrichResponse{
			Success: false,
			Error:   "udm_event is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	result, err := s.engine.Enrich(ctx, req.UDMEvent)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(EnrichResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(EnrichResponse{
		Success:       true,
		EnrichedEvent: result.EnrichedEvent,
		Enrichments: &EnrichmentDetails{
			GeoIP:   result.GeoIP,
			Assets:  result.Assets,
			Users:   result.Users,
			Threats: result.Threats,
		},
		EnrichTimeMs: result.EnrichTimeMs,
	})
}

// batchEnrichHandler enriches a batch of events.
func (s *Server) batchEnrichHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchEnrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	start := time.Now()
	results := make([]EnrichResponse, 0, len(req.Events))
	successCount := 0
	failedCount := 0

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	for _, event := range req.Events {
		if event.UDMEvent == nil {
			failedCount++
			results = append(results, EnrichResponse{
				Success: false,
				Error:   "udm_event is required",
			})
			continue
		}

		result, err := s.engine.Enrich(ctx, event.UDMEvent)
		if err != nil {
			failedCount++
			results = append(results, EnrichResponse{
				Success: false,
				Error:   err.Error(),
			})
			continue
		}

		successCount++
		results = append(results, EnrichResponse{
			Success:       true,
			EnrichedEvent: result.EnrichedEvent,
			Enrichments: &EnrichmentDetails{
				GeoIP:   result.GeoIP,
				Assets:  result.Assets,
				Users:   result.Users,
				Threats: result.Threats,
			},
			EnrichTimeMs: result.EnrichTimeMs,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(BatchEnrichResponse{
		TotalCount:   len(req.Events),
		SuccessCount: successCount,
		FailedCount:  failedCount,
		Results:      results,
		TotalTimeMs:  time.Since(start).Milliseconds(),
	})
}

// geoipLookupHandler performs direct GeoIP lookup.
func (s *Server) geoipLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ip := r.PathValue("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ip is required"})
		return
	}

	if s.geoip == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "GeoIP enricher not available"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	result, err := s.geoip.Lookup(ctx, ip)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// assetLookupHandler performs direct asset lookup.
func (s *Server) assetLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	identifier := r.PathValue("identifier")
	if identifier == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "identifier is required"})
		return
	}

	if s.asset == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Asset enricher not available"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	// Try lookup by hostname, IP, or asset ID
	lookupType := r.URL.Query().Get("type")
	var result *enrichment.AssetInfo
	var err error

	switch lookupType {
	case "ip":
		result, err = s.asset.LookupByIP(ctx, identifier)
	case "mac":
		result, err = s.asset.LookupByMAC(ctx, identifier)
	case "asset_id":
		result, err = s.asset.LookupByAssetID(ctx, identifier)
	default:
		result, err = s.asset.LookupByHostname(ctx, identifier)
	}

	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// userLookupHandler performs direct user lookup.
func (s *Server) userLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	identifier := r.PathValue("identifier")
	if identifier == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "identifier is required"})
		return
	}

	if s.user == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "User enricher not available"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	// Try lookup by username, email, or user ID
	lookupType := r.URL.Query().Get("type")
	var result *enrichment.UserInfo
	var err error

	switch lookupType {
	case "email":
		result, err = s.user.LookupByEmail(ctx, identifier)
	case "userid":
		result, err = s.user.LookupByUserID(ctx, identifier)
	default:
		result, err = s.user.LookupByUsername(ctx, identifier)
	}

	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// threatLookupHandler performs direct threat lookup.
func (s *Server) threatLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ioc := r.PathValue("ioc")
	if ioc == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ioc is required"})
		return
	}

	if s.threat == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Threat enricher not available"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	// Determine IOC type
	iocType := r.URL.Query().Get("type")
	var result *enrichment.ThreatInfo
	var err error

	switch iocType {
	case "ip":
		result, err = s.threat.LookupIP(ctx, ioc)
	case "domain":
		result, err = s.threat.LookupDomain(ctx, ioc)
	case "url":
		result, err = s.threat.LookupURL(ctx, ioc)
	case "email":
		result, err = s.threat.LookupEmail(ctx, ioc)
	case "hash", "md5", "sha1", "sha256":
		result, err = s.threat.LookupHash(ctx, ioc)
	default:
		// Auto-detect type
		result, err = s.autoDetectAndLookup(ctx, ioc)
	}

	if err != nil || result == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "threat indicator not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (s *Server) autoDetectAndLookup(ctx context.Context, ioc string) (*enrichment.ThreatInfo, error) {
	// Try IP first
	if result, err := s.threat.LookupIP(ctx, ioc); err == nil && result != nil {
		return result, nil
	}

	// Try domain
	if result, err := s.threat.LookupDomain(ctx, ioc); err == nil && result != nil {
		return result, nil
	}

	// Try hash
	if result, err := s.threat.LookupHash(ctx, ioc); err == nil && result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("no threat data found")
}

// cacheStatsHandler returns cache statistics.
func (s *Server) cacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{}

	if s.geoip != nil {
		stats["geoip"] = s.geoip.Stats()
	}
	if s.asset != nil {
		stats["asset"] = s.asset.Stats()
	}
	if s.user != nil {
		stats["user"] = s.user.Stats()
	}
	if s.threat != nil {
		stats["threat"] = s.threat.Stats()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// cacheInvalidateHandler invalidates caches.
func (s *Server) cacheInvalidateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// For now, we don't support selective invalidation
	// A full implementation would require adding Clear() methods to caches

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "cache invalidation not yet implemented",
	})
}

// statsHandler returns combined statistics.
func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{
		"service": serviceName,
	}

	// Engine stats
	if s.engine != nil {
		stats["engine"] = s.engine.Stats()
	}

	// Consumer stats
	if s.consumer != nil {
		stats["kafka_consumer"] = s.consumer.Stats()
	}

	// Enricher status
	stats["enrichers"] = map[string]bool{
		"geoip":  s.geoip != nil,
		"asset":  s.asset != nil,
		"user":   s.user != nil,
		"threat": s.threat != nil,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
