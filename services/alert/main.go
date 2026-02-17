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
	"syscall"
	"time"

	"github.com/siem-soar-platform/services/alert/internal/config"
	"github.com/siem-soar-platform/services/alert/internal/consumer"
	"github.com/siem-soar-platform/services/alert/internal/dedup"
	"github.com/siem-soar-platform/services/alert/internal/enricher"
	"github.com/siem-soar-platform/services/alert/internal/generator"
	"github.com/siem-soar-platform/services/alert/internal/publisher"
)

const (
	serviceName = "alert"
)

// AlertStore provides in-memory storage for alerts.
type AlertStore struct {
	alerts map[string]*generator.Alert
	mu     sync.RWMutex
	maxSize int
}

// NewAlertStore creates a new alert store.
func NewAlertStore(maxSize int) *AlertStore {
	return &AlertStore{
		alerts:  make(map[string]*generator.Alert),
		maxSize: maxSize,
	}
}

// Store stores an alert.
func (s *AlertStore) Store(alert *generator.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict oldest if at capacity (simple strategy)
	if len(s.alerts) >= s.maxSize {
		// Remove first item found (not ideal, but simple)
		for id := range s.alerts {
			delete(s.alerts, id)
			break
		}
	}

	s.alerts[alert.ID] = alert
}

// Get retrieves an alert by ID.
func (s *AlertStore) Get(id string) (*generator.Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert, ok := s.alerts[id]
	return alert, ok
}

// List returns recent alerts.
func (s *AlertStore) List(limit int) []*generator.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alerts := make([]*generator.Alert, 0, limit)
	count := 0
	for _, alert := range s.alerts {
		if count >= limit {
			break
		}
		alerts = append(alerts, alert)
		count++
	}
	return alerts
}

// Update updates an alert.
func (s *AlertStore) Update(id string, updateFn func(*generator.Alert)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[id]
	if !ok {
		return false
	}
	updateFn(alert)
	return true
}

// AlertWrapper wraps generator.Alert to implement dedup.Alert and publisher.Alert interfaces.
type AlertWrapper struct {
	*generator.Alert
}

// GetID returns the alert ID.
func (a *AlertWrapper) GetID() string {
	return a.ID
}

// GetDedupKey returns the dedup key.
func (a *AlertWrapper) GetDedupKey() string {
	return a.DedupKey
}

// GetFingerprint returns the fingerprint.
func (a *AlertWrapper) GetFingerprint() string {
	return a.Fingerprint
}

// GetTenantID returns the tenant ID.
func (a *AlertWrapper) GetTenantID() string {
	return a.TenantID
}

// GetRuleID returns the rule ID.
func (a *AlertWrapper) GetRuleID() string {
	return a.RuleID
}

// GetCreatedAt returns the creation time.
func (a *AlertWrapper) GetCreatedAt() time.Time {
	return a.CreatedAt
}

// GetEventCount returns the event count.
func (a *AlertWrapper) GetEventCount() int {
	return a.EventCount
}

// SetGroupID sets the group ID.
func (a *AlertWrapper) SetGroupID(groupID string) {
	a.GroupID = groupID
}

// IncrementEventCount increments the event count.
func (a *AlertWrapper) IncrementEventCount(count int) {
	a.EventCount += count
}

// SetUpdatedAt sets the updated time.
func (a *AlertWrapper) SetUpdatedAt(t time.Time) {
	a.UpdatedAt = t
}

// GetAggregationConfig returns the aggregation config (implements dedup.Alert).
func (a *AlertWrapper) GetAggregationConfig() *dedup.AlertAggregationConfig {
	return nil // Use default dedup strategy
}

// GetSeverity returns the severity.
func (a *AlertWrapper) GetSeverity() string {
	return string(a.Severity)
}

// GetTitle returns the title.
func (a *AlertWrapper) GetTitle() string {
	return a.Title
}

// GetStatus returns the status.
func (a *AlertWrapper) GetStatus() string {
	return string(a.Status)
}

// ToJSON serializes the alert to JSON.
func (a *AlertWrapper) ToJSON() ([]byte, error) {
	return json.Marshal(a.Alert)
}

// EnricherAlertWrapper wraps generator.Alert to implement enricher.Alert interface.
type EnricherAlertWrapper struct {
	*generator.Alert
}

// GetID returns the alert ID.
func (a *EnricherAlertWrapper) GetID() string {
	return a.ID
}

// GetEntities returns entities.
func (a *EnricherAlertWrapper) GetEntities() []enricher.Entity {
	entities := make([]enricher.Entity, len(a.Entities))
	for i, e := range a.Entities {
		entities[i] = enricher.Entity{
			Type:  e.Type,
			Value: e.Value,
			Role:  e.Role,
		}
	}
	return entities
}

// AddContext adds context.
func (a *EnricherAlertWrapper) AddContext(key string, value interface{}) {
	if a.Context == nil {
		a.Context = make(map[string]interface{})
	}
	a.Context[key] = value
}

// AddTag adds a tag.
func (a *EnricherAlertWrapper) AddTag(tag string) {
	// Check if tag already exists
	for _, t := range a.Tags {
		if t == tag {
			return
		}
	}
	a.Tags = append(a.Tags, tag)
}

// SetAssets sets assets.
func (a *EnricherAlertWrapper) SetAssets(assets []enricher.Asset) {
	a.Assets = make([]generator.Asset, len(assets))
	for i, asset := range assets {
		a.Assets[i] = generator.Asset{
			ID:       asset.ID,
			Type:     asset.Type,
			Name:     asset.Name,
			Hostname: asset.Hostname,
			IP:       asset.IP,
			OS:       asset.OS,
			Owner:    asset.Owner,
			Labels:   asset.Labels,
		}
	}
}

func main() {
	// Initialize structured logger
	logLevel := slog.LevelInfo
	if lvl := os.Getenv("LOG_LEVEL"); lvl == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.LoadFromEnv()

	// Create alert store
	alertStore := NewAlertStore(10000)

	// Initialize generator
	gen := generator.NewGenerator(cfg.Generator, logger)

	// Initialize deduplicator
	deduplicator := dedup.NewDeduplicator(cfg.Dedup, logger)

	// Initialize enricher with default (no-op) provider
	// In production, replace with actual providers
	enricherProvider := &enricher.DefaultProvider{}
	alertEnricher := enricher.NewEnricher(cfg.Enricher, enricherProvider, logger)

	// Initialize publisher manager
	pubManager := publisher.NewPublisherManager(logger)

	// Register publishers based on configuration
	if cfg.Publisher.Webhook.Enabled {
		for i, endpoint := range cfg.Publisher.Webhook.Endpoints {
			webhookPub := publisher.NewWebhookPublisher(publisher.PublisherConfig{
				Enabled:    true,
				Type:       publisher.PublisherTypeWebhook,
				Name:       fmt.Sprintf("webhook-%d", i),
				Endpoint:   endpoint,
				Headers:    cfg.Publisher.Webhook.Headers,
				Timeout:    cfg.Publisher.Webhook.Timeout,
				RetryCount: cfg.Publisher.Webhook.RetryCount,
				RetryDelay: cfg.Publisher.Webhook.RetryDelay,
			}, logger)
			pubManager.RegisterPublisher(webhookPub)
		}
	}

	if cfg.Publisher.Slack.Enabled && cfg.Publisher.Slack.WebhookURL != "" {
		slackPub := publisher.NewSlackPublisher(publisher.PublisherConfig{
			Enabled:  true,
			Type:     publisher.PublisherTypeSlack,
			Name:     "slack",
			Endpoint: cfg.Publisher.Slack.WebhookURL,
			Timeout:  cfg.Publisher.Slack.Timeout,
		}, logger)
		pubManager.RegisterPublisher(slackPub)
	}

	if cfg.Publisher.PagerDuty.Enabled && cfg.Publisher.PagerDuty.RoutingKey != "" {
		pdPub := publisher.NewPagerDutyPublisher(publisher.PublisherConfig{
			Enabled: true,
			Type:    publisher.PublisherTypePagerDuty,
			Name:    "pagerduty",
			APIKey:  cfg.Publisher.PagerDuty.RoutingKey,
			Timeout: cfg.Publisher.PagerDuty.Timeout,
		}, logger)
		pubManager.RegisterPublisher(pdPub)
	}

	// Initialize Kafka consumer
	kafkaConsumer, err := consumer.NewConsumer(cfg.Kafka, gen, logger)
	if err != nil {
		logger.Error("failed to create kafka consumer", "error", err)
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start components
	if err := gen.Start(); err != nil {
		logger.Error("failed to start generator", "error", err)
		os.Exit(1)
	}

	if err := pubManager.Start(); err != nil {
		logger.Error("failed to start publisher manager", "error", err)
		os.Exit(1)
	}

	if err := kafkaConsumer.Start(); err != nil {
		logger.Error("failed to start kafka consumer", "error", err)
		os.Exit(1)
	}

	// Start alert processing pipeline
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case alert, ok := <-gen.Alerts():
				if !ok {
					return
				}

				// Wrap alert for interface compatibility
				wrapper := &AlertWrapper{Alert: alert}

				// Check for duplicates
				dedupResult := deduplicator.Check(wrapper)
				if dedupResult.IsDuplicate {
					if dedupResult.Action == dedup.ActionDrop {
						logger.Debug("dropping duplicate alert",
							"alert_id", alert.ID,
							"existing_id", dedupResult.ExistingID)
						continue
					}
					// For merge/group actions, we could update the existing alert
					// but for simplicity, we'll just log it
					logger.Debug("duplicate alert detected",
						"alert_id", alert.ID,
						"action", dedupResult.Action,
						"existing_id", dedupResult.ExistingID)
				}

				// Enrich alert
				enricherWrapper := &EnricherAlertWrapper{Alert: alert}
				if err := alertEnricher.Enrich(ctx, enricherWrapper); err != nil {
					logger.Warn("enrichment failed", "alert_id", alert.ID, "error", err)
				}

				// Store alert
				alertStore.Store(alert)

				// Publish alert
				pubManager.Publish(wrapper)

				logger.Info("alert processed",
					"alert_id", alert.ID,
					"rule_id", alert.RuleID,
					"severity", alert.Severity)
			}
		}
	}()

	// Setup HTTP server
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		readyHandler(w, r, kafkaConsumer)
	})

	// Alert endpoints
	mux.HandleFunc("GET /alerts", func(w http.ResponseWriter, r *http.Request) {
		listAlertsHandler(w, r, alertStore)
	})
	mux.HandleFunc("GET /alerts/{id}", func(w http.ResponseWriter, r *http.Request) {
		getAlertHandler(w, r, alertStore)
	})
	mux.HandleFunc("POST /alerts/{id}/acknowledge", func(w http.ResponseWriter, r *http.Request) {
		acknowledgeAlertHandler(w, r, alertStore)
	})
	mux.HandleFunc("POST /alerts/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		closeAlertHandler(w, r, alertStore)
	})

	// Metrics endpoint
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		metricsHandler(w, r, gen, deduplicator, alertEnricher, pubManager, kafkaConsumer)
	})

	server := &http.Server{
		Addr:         ":" + cfg.Service.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server
	go func() {
		logger.Info("starting server", "service", serviceName, "port", cfg.Service.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server")

	// Cancel context to stop alert processing
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop components in reverse order
	if err := kafkaConsumer.Stop(); err != nil {
		logger.Error("failed to stop kafka consumer", "error", err)
	}

	if err := gen.Stop(); err != nil {
		logger.Error("failed to stop generator", "error", err)
	}

	if err := pubManager.Stop(); err != nil {
		logger.Error("failed to stop publisher manager", "error", err)
	}

	deduplicator.Stop()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
	}

	logger.Info("server exited")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"alert"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request, c *consumer.Consumer) {
	w.Header().Set("Content-Type", "application/json")
	if c.Health() {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ready","service":"alert"}`)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"status":"not_ready","service":"alert"}`)
	}
}

func listAlertsHandler(w http.ResponseWriter, r *http.Request, store *AlertStore) {
	w.Header().Set("Content-Type", "application/json")

	alerts := store.List(100)
	response := map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}
}

func getAlertHandler(w http.ResponseWriter, r *http.Request, store *AlertStore) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	alert, ok := store.Get(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"alert not found","id":"%s"}`, id)
		return
	}

	if err := json.NewEncoder(w).Encode(alert); err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}
}

func acknowledgeAlertHandler(w http.ResponseWriter, r *http.Request, store *AlertStore) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	now := time.Now()

	ok := store.Update(id, func(alert *generator.Alert) {
		alert.Status = generator.StatusAcknowledged
		alert.AcknowledgedAt = &now
		alert.UpdatedAt = now
	})

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"alert not found","id":"%s"}`, id)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"acknowledged","id":"%s"}`, id)
}

func closeAlertHandler(w http.ResponseWriter, r *http.Request, store *AlertStore) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	now := time.Now()

	ok := store.Update(id, func(alert *generator.Alert) {
		alert.Status = generator.StatusClosed
		alert.ResolvedAt = &now
		alert.UpdatedAt = now
	})

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"alert not found","id":"%s"}`, id)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"closed","id":"%s"}`, id)
}

func metricsHandler(w http.ResponseWriter, r *http.Request,
	gen *generator.Generator,
	deduplicator *dedup.Deduplicator,
	enricher *enricher.Enricher,
	pubManager *publisher.PublisherManager,
	kafkaConsumer *consumer.Consumer) {

	w.Header().Set("Content-Type", "application/json")

	metrics := map[string]interface{}{
		"generator":    gen.Stats(),
		"deduplicator": deduplicator.Stats(),
		"enricher":     enricher.Stats(),
		"publisher":    pubManager.Stats(),
		"consumer":     kafkaConsumer.Stats(),
	}

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
	}
}
