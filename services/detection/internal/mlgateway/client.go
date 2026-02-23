// Package mlgateway provides HTTP client for ML Gateway service.
package mlgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// MLAnalysis represents the ML Gateway response for alert analysis.
type MLAnalysis struct {
	Classification     *Classification `json:"classification,omitempty"`
	RiskScore          float64         `json:"risk_score"`
	Priority           string          `json:"priority"` // critical, high, medium, low
	IsFalsePositive    bool            `json:"is_false_positive"`
	FPConfidence       float64         `json:"fp_confidence"`
	MITRETactics       []string        `json:"mitre_tactics,omitempty"`
	MITRETechniques    []string        `json:"mitre_techniques,omitempty"`
	RecommendedActions []string        `json:"recommended_actions,omitempty"`
	ProcessedAt        time.Time       `json:"processed_at"`
	TraceID            string          `json:"trace_id,omitempty"`
	ModelID            string          `json:"model_id,omitempty"`
	ModelVersion       string          `json:"model_version,omitempty"`
	CacheHit           bool            `json:"cache_hit"`
}

// Classification represents alert classification from ML.
type Classification struct {
	Category           string  `json:"category"`
	Severity           string  `json:"severity"`
	CategoryConfidence float64 `json:"category_confidence"`
	SeverityConfidence float64 `json:"severity_confidence"`
}

// RiskFactor represents a factor contributing to risk score.
type RiskFactor struct {
	Factor    string  `json:"factor"`
	Weight    float64 `json:"weight"`
	Triggered bool    `json:"triggered"`
}

// AlertRequest represents the request payload for ML Gateway.
type AlertRequest struct {
	AlertID       string                 `json:"alert_id"`
	AlertType     string                 `json:"alert_type"`
	Severity      string                 `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	RuleID        string                 `json:"rule_id"`
	RuleName      string                 `json:"rule_name"`
	Events        []map[string]any       `json:"events"`
	MatchedFields map[string]interface{} `json:"matched_fields,omitempty"`
	TraceID       string                 `json:"trace_id"`
}

// BatchAlertRequest represents a batch request payload.
type BatchAlertRequest struct {
	Alerts  []AlertRequest `json:"alerts"`
	TraceID string         `json:"trace_id"`
}

// BatchAlertResponse represents a batch response.
type BatchAlertResponse struct {
	Results []MLAnalysis `json:"results"`
	Errors  []string     `json:"errors,omitempty"`
}

// Config holds ML Gateway client configuration.
type Config struct {
	BaseURL              string        `json:"base_url"`
	Timeout              time.Duration `json:"timeout"`
	Enabled              bool          `json:"enabled"`
	CacheEnabled         bool          `json:"cache_enabled"`
	CacheTTL             time.Duration `json:"cache_ttl"`
	RedisAddr            string        `json:"redis_addr"`
	RedisPassword        string        `json:"redis_password"`
	RedisDB              int           `json:"redis_db"`
	CircuitBreakerConfig CBConfig      `json:"circuit_breaker"`
}

// CBConfig holds circuit breaker configuration.
type CBConfig struct {
	MaxRequests  uint32        `json:"max_requests"`
	Interval     time.Duration `json:"interval"`
	Timeout      time.Duration `json:"timeout"`
	FailureRatio float64       `json:"failure_ratio"`
}

// DefaultConfig returns default ML Gateway configuration.
func DefaultConfig() Config {
	return Config{
		BaseURL:      "http://ml-gateway:8000",
		Timeout:      5 * time.Second,
		Enabled:      true,
		CacheEnabled: true,
		CacheTTL:     5 * time.Minute,
		CircuitBreakerConfig: CBConfig{
			MaxRequests:  5,
			Interval:     10 * time.Second,
			Timeout:      30 * time.Second,
			FailureRatio: 0.5,
		},
	}
}

// Client is the ML Gateway HTTP client with circuit breaker and caching.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	breaker     *gobreaker.CircuitBreaker
	cache       *redis.Client
	tracer      trace.Tracer
	propagator  propagation.TextMapPropagator
	featureFlag func() bool
	logger      *slog.Logger
	cacheTTL    time.Duration
	metrics     *Metrics
}

// NewClient creates a new ML Gateway client.
func NewClient(cfg Config, featureFlag func() bool, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "mlgateway-client")

	// HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
	}

	// Circuit breaker settings
	breakerSettings := gobreaker.Settings{
		Name:        "ml-gateway",
		MaxRequests: cfg.CircuitBreakerConfig.MaxRequests,
		Interval:    cfg.CircuitBreakerConfig.Interval,
		Timeout:     cfg.CircuitBreakerConfig.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 5 && failureRatio >= cfg.CircuitBreakerConfig.FailureRatio
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("circuit breaker state changed",
				"name", name,
				"from", from.String(),
				"to", to.String(),
			)
			// Update Prometheus metric
			circuitState.WithLabelValues(name).Set(stateToFloat(to))
		},
	}

	breaker := gobreaker.NewCircuitBreaker(breakerSettings)

	// Redis client for caching (optional)
	var redisClient *redis.Client
	if cfg.CacheEnabled && cfg.RedisAddr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		})

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := redisClient.Ping(ctx).Err(); err != nil {
			logger.Warn("redis connection failed, caching disabled", "error", err)
			redisClient = nil
		} else {
			logger.Info("redis cache enabled", "addr", cfg.RedisAddr)
		}
	}

	// OpenTelemetry tracer
	tracer := otel.Tracer("mlgateway-client")
	propagator := otel.GetTextMapPropagator()

	// Default feature flag (always enabled)
	if featureFlag == nil {
		featureFlag = func() bool { return cfg.Enabled }
	}

	// Initialize metrics
	metrics := NewMetrics()

	return &Client{
		baseURL:     cfg.BaseURL,
		httpClient:  httpClient,
		breaker:     breaker,
		cache:       redisClient,
		tracer:      tracer,
		propagator:  propagator,
		featureFlag: featureFlag,
		logger:      logger,
		cacheTTL:    cfg.CacheTTL,
		metrics:     metrics,
	}, nil
}

// TriageAlert calls ML Gateway to analyze an alert.
// Returns MLAnalysis or nil if circuit is open or feature is disabled.
func (c *Client) TriageAlert(ctx context.Context, alertReq *AlertRequest) (*MLAnalysis, error) {
	// Check feature flag
	if !c.featureFlag() {
		c.logger.Debug("ml enrichment disabled by feature flag")
		return nil, nil
	}

	// Start span
	ctx, span := c.tracer.Start(ctx, "mlgateway.triage_alert",
		trace.WithAttributes(
			attribute.String("alert_id", alertReq.AlertID),
			attribute.String("rule_id", alertReq.RuleID),
		),
	)
	defer span.End()

	// Set trace ID on request
	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	alertReq.TraceID = spanCtx.TraceID().String()

	// Check cache first
	cacheKey := c.buildCacheKey(alertReq)
	if cached, ok := c.getFromCache(ctx, cacheKey); ok {
		span.SetAttributes(attribute.Bool("cache_hit", true))
		c.metrics.cacheHits.Inc()
		cached.CacheHit = true
		cached.TraceID = alertReq.TraceID
		return cached, nil
	}
	span.SetAttributes(attribute.Bool("cache_hit", false))
	c.metrics.cacheMisses.Inc()

	// Execute via circuit breaker
	start := time.Now()
	result, err := c.breaker.Execute(func() (interface{}, error) {
		return c.doTriageRequest(ctx, alertReq)
	})

	duration := time.Since(start)
	c.metrics.triageDuration.WithLabelValues("triage").Observe(duration.Seconds())

	if err != nil {
		// Check if circuit is open
		if err == gobreaker.ErrOpenState || err == gobreaker.ErrTooManyRequests {
			span.SetAttributes(attribute.Bool("circuit_open", true))
			c.metrics.triageRequests.WithLabelValues("circuit_open").Inc()
			c.logger.Warn("circuit breaker open, skipping ML call", "alert_id", alertReq.AlertID)
			return nil, nil // Graceful degradation
		}

		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		c.metrics.triageRequests.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("ml gateway call failed: %w", err)
	}

	analysis := result.(*MLAnalysis)
	analysis.ProcessedAt = time.Now()
	analysis.TraceID = alertReq.TraceID

	// Store in cache
	c.setInCache(ctx, cacheKey, analysis)

	span.SetAttributes(
		attribute.Float64("risk_score", analysis.RiskScore),
		attribute.String("priority", analysis.Priority),
		attribute.Bool("is_false_positive", analysis.IsFalsePositive),
	)
	c.metrics.triageRequests.WithLabelValues("success").Inc()

	return analysis, nil
}

// BatchTriageAlerts handles multiple alerts in a single request.
func (c *Client) BatchTriageAlerts(ctx context.Context, alerts []*AlertRequest) ([]*MLAnalysis, error) {
	if !c.featureFlag() {
		c.logger.Debug("ml enrichment disabled by feature flag")
		return nil, nil
	}

	if len(alerts) == 0 {
		return nil, nil
	}

	ctx, span := c.tracer.Start(ctx, "mlgateway.batch_triage_alerts",
		trace.WithAttributes(attribute.Int("batch_size", len(alerts))),
	)
	defer span.End()

	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	traceID := spanCtx.TraceID().String()

	// Check cache for each alert
	results := make([]*MLAnalysis, len(alerts))
	uncachedAlerts := make([]*AlertRequest, 0)
	uncachedIndices := make([]int, 0)

	for i, alert := range alerts {
		alert.TraceID = traceID
		cacheKey := c.buildCacheKey(alert)
		if cached, ok := c.getFromCache(ctx, cacheKey); ok {
			cached.CacheHit = true
			cached.TraceID = traceID
			results[i] = cached
			c.metrics.cacheHits.Inc()
		} else {
			uncachedAlerts = append(uncachedAlerts, alert)
			uncachedIndices = append(uncachedIndices, i)
			c.metrics.cacheMisses.Inc()
		}
	}

	// If all cached, return early
	if len(uncachedAlerts) == 0 {
		span.SetAttributes(attribute.Bool("all_cached", true))
		return results, nil
	}

	// Batch request for uncached alerts
	start := time.Now()
	batchResult, err := c.breaker.Execute(func() (interface{}, error) {
		return c.doBatchTriageRequest(ctx, uncachedAlerts, traceID)
	})

	duration := time.Since(start)
	c.metrics.triageDuration.WithLabelValues("batch_triage").Observe(duration.Seconds())

	if err != nil {
		if err == gobreaker.ErrOpenState || err == gobreaker.ErrTooManyRequests {
			span.SetAttributes(attribute.Bool("circuit_open", true))
			c.metrics.triageRequests.WithLabelValues("circuit_open").Inc()
			c.logger.Warn("circuit breaker open, returning cached results only")
			return results, nil
		}

		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		c.metrics.triageRequests.WithLabelValues("error").Inc()
		return results, fmt.Errorf("batch ml gateway call failed: %w", err)
	}

	// Merge results
	batchAnalyses := batchResult.([]*MLAnalysis)
	for i, analysis := range batchAnalyses {
		if analysis != nil {
			analysis.ProcessedAt = time.Now()
			analysis.TraceID = traceID
			results[uncachedIndices[i]] = analysis

			// Cache each result
			cacheKey := c.buildCacheKey(uncachedAlerts[i])
			c.setInCache(ctx, cacheKey, analysis)
		}
	}

	c.metrics.triageRequests.WithLabelValues("success").Inc()
	return results, nil
}

// IsAvailable checks if ML Gateway is accessible.
func (c *Client) IsAvailable() bool {
	// Check circuit breaker state
	state := c.breaker.State()
	if state == gobreaker.StateOpen {
		return false
	}

	// Quick health check
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetCircuitState returns the current circuit breaker state.
func (c *Client) GetCircuitState() string {
	return c.breaker.State().String()
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	if c.cache != nil {
		return c.cache.Close()
	}
	return nil
}

// doTriageRequest performs the actual HTTP request to ML Gateway.
func (c *Client) doTriageRequest(ctx context.Context, alertReq *AlertRequest) (*MLAnalysis, error) {
	body, err := json.Marshal(alertReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/triage", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Inject trace context
	c.propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var analysis MLAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &analysis, nil
}

// doBatchTriageRequest performs batch request to ML Gateway.
func (c *Client) doBatchTriageRequest(ctx context.Context, alerts []*AlertRequest, traceID string) ([]*MLAnalysis, error) {
	alertReqs := make([]AlertRequest, len(alerts))
	for i, a := range alerts {
		alertReqs[i] = *a
	}

	batchReq := BatchAlertRequest{
		Alerts:  alertReqs,
		TraceID: traceID,
	}

	body, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("marshal batch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/triage/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http batch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected batch status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var batchResp BatchAlertResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}

	results := make([]*MLAnalysis, len(batchResp.Results))
	for i := range batchResp.Results {
		results[i] = &batchResp.Results[i]
	}

	return results, nil
}

// buildCacheKey builds a cache key for an alert request.
func (c *Client) buildCacheKey(req *AlertRequest) string {
	// Use content hash for cache key
	data := fmt.Sprintf("%s:%s:%s", req.AlertID, req.RuleID, req.AlertType)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("ml:triage:%s", hex.EncodeToString(hash[:8]))
}

// getFromCache retrieves analysis from cache.
func (c *Client) getFromCache(ctx context.Context, key string) (*MLAnalysis, bool) {
	if c.cache == nil {
		return nil, false
	}

	data, err := c.cache.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			c.logger.Debug("cache get error", "key", key, "error", err)
		}
		return nil, false
	}

	var analysis MLAnalysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		c.logger.Debug("cache unmarshal error", "key", key, "error", err)
		return nil, false
	}

	return &analysis, true
}

// setInCache stores analysis in cache.
func (c *Client) setInCache(ctx context.Context, key string, analysis *MLAnalysis) {
	if c.cache == nil {
		return
	}

	data, err := json.Marshal(analysis)
	if err != nil {
		c.logger.Debug("cache marshal error", "key", key, "error", err)
		return
	}

	if err := c.cache.Set(ctx, key, data, c.cacheTTL).Err(); err != nil {
		c.logger.Debug("cache set error", "key", key, "error", err)
	}
}

// stateToFloat converts circuit breaker state to float for Prometheus.
func stateToFloat(state gobreaker.State) float64 {
	switch state {
	case gobreaker.StateClosed:
		return 0
	case gobreaker.StateHalfOpen:
		return 1
	case gobreaker.StateOpen:
		return 2
	default:
		return -1
	}
}
