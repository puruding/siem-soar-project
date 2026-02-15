// Package publisher provides alert publishing capabilities.
package publisher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// PublisherType represents the type of publisher.
type PublisherType string

const (
	PublisherTypeKafka      PublisherType = "kafka"
	PublisherTypeWebhook    PublisherType = "webhook"
	PublisherTypeSNS        PublisherType = "sns"
	PublisherTypePubSub     PublisherType = "pubsub"
	PublisherTypeSlack      PublisherType = "slack"
	PublisherTypePagerDuty  PublisherType = "pagerduty"
	PublisherTypeEmail      PublisherType = "email"
	PublisherTypeSIEM       PublisherType = "siem"
	PublisherTypeSOAR       PublisherType = "soar"
)

// Alert interface for publishing.
type Alert interface {
	GetID() string
	GetTenantID() string
	GetSeverity() string
	GetTitle() string
	GetStatus() string
	ToJSON() ([]byte, error)
}

// PublisherConfig holds publisher configuration.
type PublisherConfig struct {
	Enabled         bool              `json:"enabled"`
	Type            PublisherType     `json:"type"`
	Name            string            `json:"name"`
	Endpoint        string            `json:"endpoint,omitempty"`
	Topic           string            `json:"topic,omitempty"`
	APIKey          string            `json:"api_key,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Timeout         time.Duration     `json:"timeout"`
	RetryCount      int               `json:"retry_count"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	BatchSize       int               `json:"batch_size"`
	FlushInterval   time.Duration     `json:"flush_interval"`
	Filters         PublisherFilters  `json:"filters,omitempty"`
	RateLimitPerSec int               `json:"rate_limit_per_sec"`
}

// PublisherFilters defines filters for publishing.
type PublisherFilters struct {
	Severities []string `json:"severities,omitempty"` // Only publish these severities
	Types      []string `json:"types,omitempty"`      // Only publish these types
	Tags       []string `json:"tags,omitempty"`       // Only publish alerts with these tags
	TenantIDs  []string `json:"tenant_ids,omitempty"` // Only publish for these tenants
}

// PublishResult represents the result of publishing.
type PublishResult struct {
	Success   bool          `json:"success"`
	AlertID   string        `json:"alert_id"`
	Publisher string        `json:"publisher"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration_ms"`
	Retries   int           `json:"retries"`
}

// Publisher publishes alerts to external systems.
type Publisher interface {
	Publish(ctx context.Context, alert Alert) (*PublishResult, error)
	PublishBatch(ctx context.Context, alerts []Alert) ([]*PublishResult, error)
	Name() string
	Type() PublisherType
	Close() error
}

// PublisherManager manages multiple publishers.
type PublisherManager struct {
	publishers []Publisher
	alertCh    chan Alert
	batchCh    chan []Alert
	resultCh   chan *PublishResult
	logger     *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Batch settings
	batchSize     int
	flushInterval time.Duration
	batchBuffer   []Alert
	batchMu       sync.Mutex

	// Metrics
	totalPublished atomic.Uint64
	totalFailed    atomic.Uint64
}

// NewPublisherManager creates a new publisher manager.
func NewPublisherManager(logger *slog.Logger) *PublisherManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &PublisherManager{
		publishers:    make([]Publisher, 0),
		alertCh:       make(chan Alert, 10000),
		batchCh:       make(chan []Alert, 100),
		resultCh:      make(chan *PublishResult, 10000),
		logger:        logger.With("component", "alert-publisher"),
		ctx:           ctx,
		cancel:        cancel,
		batchSize:     100,
		flushInterval: 5 * time.Second,
		batchBuffer:   make([]Alert, 0, 100),
	}
}

// RegisterPublisher registers a publisher.
func (m *PublisherManager) RegisterPublisher(pub Publisher) {
	m.publishers = append(m.publishers, pub)
	m.logger.Info("registered publisher", "name", pub.Name(), "type", pub.Type())
}

// Start starts the publisher manager.
func (m *PublisherManager) Start() error {
	// Start batch collector
	m.wg.Add(1)
	go m.batchCollector()

	// Start batch publisher
	m.wg.Add(1)
	go m.batchPublisher()

	m.logger.Info("publisher manager started", "publishers", len(m.publishers))
	return nil
}

// Stop stops the publisher manager.
func (m *PublisherManager) Stop() error {
	m.cancel()

	// Flush remaining alerts
	m.flushBatch()

	close(m.alertCh)
	close(m.batchCh)
	m.wg.Wait()
	close(m.resultCh)

	// Close publishers
	for _, pub := range m.publishers {
		if err := pub.Close(); err != nil {
			m.logger.Error("failed to close publisher", "name", pub.Name(), "error", err)
		}
	}

	m.logger.Info("publisher manager stopped")
	return nil
}

// Publish publishes an alert.
func (m *PublisherManager) Publish(alert Alert) {
	select {
	case m.alertCh <- alert:
	default:
		m.logger.Warn("publisher queue full, dropping alert")
		m.totalFailed.Add(1)
	}
}

// PublishSync publishes an alert synchronously.
func (m *PublisherManager) PublishSync(ctx context.Context, alert Alert) []*PublishResult {
	results := make([]*PublishResult, 0, len(m.publishers))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, pub := range m.publishers {
		wg.Add(1)
		go func(p Publisher) {
			defer wg.Done()

			result, err := p.Publish(ctx, alert)
			if err != nil {
				result = &PublishResult{
					Success:   false,
					AlertID:   alert.GetID(),
					Publisher: p.Name(),
					Error:     err.Error(),
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(pub)
	}

	wg.Wait()
	return results
}

// Results returns the results channel.
func (m *PublisherManager) Results() <-chan *PublishResult {
	return m.resultCh
}

// Stats returns publisher statistics.
func (m *PublisherManager) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_published": m.totalPublished.Load(),
		"total_failed":    m.totalFailed.Load(),
		"queue_size":      len(m.alertCh),
		"publishers":      len(m.publishers),
	}
}

// batchCollector collects alerts into batches.
func (m *PublisherManager) batchCollector() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case alert, ok := <-m.alertCh:
			if !ok {
				return
			}

			m.batchMu.Lock()
			m.batchBuffer = append(m.batchBuffer, alert)

			if len(m.batchBuffer) >= m.batchSize {
				batch := m.batchBuffer
				m.batchBuffer = make([]Alert, 0, m.batchSize)
				m.batchMu.Unlock()

				m.batchCh <- batch
			} else {
				m.batchMu.Unlock()
			}

		case <-ticker.C:
			m.flushBatch()
		}
	}
}

// flushBatch flushes the current batch.
func (m *PublisherManager) flushBatch() {
	m.batchMu.Lock()
	if len(m.batchBuffer) > 0 {
		batch := m.batchBuffer
		m.batchBuffer = make([]Alert, 0, m.batchSize)
		m.batchMu.Unlock()

		select {
		case m.batchCh <- batch:
		default:
			m.logger.Warn("batch channel full")
		}
	} else {
		m.batchMu.Unlock()
	}
}

// batchPublisher publishes batches to all publishers.
func (m *PublisherManager) batchPublisher() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case batch, ok := <-m.batchCh:
			if !ok {
				return
			}

			m.publishBatch(batch)
		}
	}
}

// publishBatch publishes a batch to all publishers.
func (m *PublisherManager) publishBatch(batch []Alert) {
	var wg sync.WaitGroup

	for _, pub := range m.publishers {
		wg.Add(1)
		go func(p Publisher) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
			defer cancel()

			results, err := p.PublishBatch(ctx, batch)
			if err != nil {
				m.logger.Error("batch publish failed",
					"publisher", p.Name(),
					"batch_size", len(batch),
					"error", err)
				m.totalFailed.Add(uint64(len(batch)))
				return
			}

			for _, result := range results {
				if result.Success {
					m.totalPublished.Add(1)
				} else {
					m.totalFailed.Add(1)
				}

				// Send result to channel
				select {
				case m.resultCh <- result:
				default:
				}
			}
		}(pub)
	}

	wg.Wait()
}

// WebhookPublisher publishes alerts via HTTP webhooks.
type WebhookPublisher struct {
	config PublisherConfig
	client *http.Client
	logger *slog.Logger
}

// NewWebhookPublisher creates a new webhook publisher.
func NewWebhookPublisher(cfg PublisherConfig, logger *slog.Logger) *WebhookPublisher {
	return &WebhookPublisher{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger.With("component", "webhook-publisher", "name", cfg.Name),
	}
}

// Publish publishes an alert via webhook.
func (w *WebhookPublisher) Publish(ctx context.Context, alert Alert) (*PublishResult, error) {
	startTime := time.Now()

	result := &PublishResult{
		AlertID:   alert.GetID(),
		Publisher: w.config.Name,
	}

	// Check filters
	if !w.matchesFilters(alert) {
		result.Success = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Serialize alert
	data, err := alert.ToJSON()
	if err != nil {
		result.Error = fmt.Sprintf("failed to serialize alert: %s", err.Error())
		return result, err
	}

	// Retry loop
	var lastErr error
	for i := 0; i <= w.config.RetryCount; i++ {
		result.Retries = i

		req, err := http.NewRequestWithContext(ctx, "POST", w.config.Endpoint, bytes.NewReader(data))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		for k, v := range w.config.Headers {
			req.Header.Set(k, v)
		}
		if w.config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+w.config.APIKey)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(w.config.RetryDelay)
			continue
		}

		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Success = true
			result.Duration = time.Since(startTime)
			return result, nil
		}

		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
		time.Sleep(w.config.RetryDelay)
	}

	result.Error = lastErr.Error()
	result.Duration = time.Since(startTime)
	return result, lastErr
}

// PublishBatch publishes a batch of alerts.
func (w *WebhookPublisher) PublishBatch(ctx context.Context, alerts []Alert) ([]*PublishResult, error) {
	results := make([]*PublishResult, len(alerts))

	for i, alert := range alerts {
		result, _ := w.Publish(ctx, alert)
		results[i] = result
	}

	return results, nil
}

// Name returns the publisher name.
func (w *WebhookPublisher) Name() string {
	return w.config.Name
}

// Type returns the publisher type.
func (w *WebhookPublisher) Type() PublisherType {
	return PublisherTypeWebhook
}

// Close closes the publisher.
func (w *WebhookPublisher) Close() error {
	return nil
}

// matchesFilters checks if an alert matches the configured filters.
func (w *WebhookPublisher) matchesFilters(alert Alert) bool {
	filters := w.config.Filters

	// Check severity filter
	if len(filters.Severities) > 0 {
		matched := false
		severity := alert.GetSeverity()
		for _, s := range filters.Severities {
			if s == severity {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check tenant filter
	if len(filters.TenantIDs) > 0 {
		matched := false
		tenantID := alert.GetTenantID()
		for _, t := range filters.TenantIDs {
			if t == tenantID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// SlackPublisher publishes alerts to Slack.
type SlackPublisher struct {
	config PublisherConfig
	client *http.Client
	logger *slog.Logger
}

// NewSlackPublisher creates a new Slack publisher.
func NewSlackPublisher(cfg PublisherConfig, logger *slog.Logger) *SlackPublisher {
	return &SlackPublisher{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger.With("component", "slack-publisher", "name", cfg.Name),
	}
}

// Publish publishes an alert to Slack.
func (s *SlackPublisher) Publish(ctx context.Context, alert Alert) (*PublishResult, error) {
	startTime := time.Now()

	result := &PublishResult{
		AlertID:   alert.GetID(),
		Publisher: s.config.Name,
	}

	// Format Slack message
	message := s.formatSlackMessage(alert)

	data, err := json.Marshal(message)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("Slack returned %d", resp.StatusCode)
		return result, fmt.Errorf(result.Error)
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	return result, nil
}

// formatSlackMessage formats an alert as a Slack message.
func (s *SlackPublisher) formatSlackMessage(alert Alert) map[string]interface{} {
	severity := alert.GetSeverity()

	// Map severity to color
	colors := map[string]string{
		"critical": "#FF0000",
		"high":     "#FF6B6B",
		"medium":   "#FFA500",
		"low":      "#FFFF00",
		"info":     "#0000FF",
	}

	color, ok := colors[severity]
	if !ok {
		color = "#808080"
	}

	// Map severity to emoji
	emojis := map[string]string{
		"critical": ":red_circle:",
		"high":     ":orange_circle:",
		"medium":   ":yellow_circle:",
		"low":      ":blue_circle:",
		"info":     ":white_circle:",
	}

	emoji, ok := emojis[severity]
	if !ok {
		emoji = ":grey_question:"
	}

	return map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"blocks": []map[string]interface{}{
					{
						"type": "section",
						"text": map[string]interface{}{
							"type": "mrkdwn",
							"text": fmt.Sprintf("%s *%s Alert*\n*%s*", emoji, severity, alert.GetTitle()),
						},
					},
					{
						"type": "context",
						"elements": []map[string]interface{}{
							{
								"type": "mrkdwn",
								"text": fmt.Sprintf("Alert ID: `%s` | Status: `%s`", alert.GetID(), alert.GetStatus()),
							},
						},
					},
				},
			},
		},
	}
}

// PublishBatch publishes a batch of alerts.
func (s *SlackPublisher) PublishBatch(ctx context.Context, alerts []Alert) ([]*PublishResult, error) {
	results := make([]*PublishResult, len(alerts))

	for i, alert := range alerts {
		result, _ := s.Publish(ctx, alert)
		results[i] = result
	}

	return results, nil
}

// Name returns the publisher name.
func (s *SlackPublisher) Name() string {
	return s.config.Name
}

// Type returns the publisher type.
func (s *SlackPublisher) Type() PublisherType {
	return PublisherTypeSlack
}

// Close closes the publisher.
func (s *SlackPublisher) Close() error {
	return nil
}

// PagerDutyPublisher publishes alerts to PagerDuty.
type PagerDutyPublisher struct {
	config PublisherConfig
	client *http.Client
	logger *slog.Logger
}

// NewPagerDutyPublisher creates a new PagerDuty publisher.
func NewPagerDutyPublisher(cfg PublisherConfig, logger *slog.Logger) *PagerDutyPublisher {
	return &PagerDutyPublisher{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		logger: logger.With("component", "pagerduty-publisher", "name", cfg.Name),
	}
}

// Publish publishes an alert to PagerDuty.
func (p *PagerDutyPublisher) Publish(ctx context.Context, alert Alert) (*PublishResult, error) {
	startTime := time.Now()

	result := &PublishResult{
		AlertID:   alert.GetID(),
		Publisher: p.config.Name,
	}

	// Map severity to PagerDuty severity
	pdSeverity := map[string]string{
		"critical": "critical",
		"high":     "error",
		"medium":   "warning",
		"low":      "info",
		"info":     "info",
	}

	severity, ok := pdSeverity[alert.GetSeverity()]
	if !ok {
		severity = "info"
	}

	// Create PagerDuty event
	event := map[string]interface{}{
		"routing_key":  p.config.APIKey,
		"event_action": "trigger",
		"dedup_key":    alert.GetID(),
		"payload": map[string]interface{}{
			"summary":  alert.GetTitle(),
			"severity": severity,
			"source":   "siem-soar-platform",
			"custom_details": map[string]interface{}{
				"alert_id":  alert.GetID(),
				"tenant_id": alert.GetTenantID(),
				"status":    alert.GetStatus(),
			},
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(data))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("PagerDuty returned %d", resp.StatusCode)
		return result, fmt.Errorf(result.Error)
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	return result, nil
}

// PublishBatch publishes a batch of alerts.
func (p *PagerDutyPublisher) PublishBatch(ctx context.Context, alerts []Alert) ([]*PublishResult, error) {
	results := make([]*PublishResult, len(alerts))

	for i, alert := range alerts {
		result, _ := p.Publish(ctx, alert)
		results[i] = result
	}

	return results, nil
}

// Name returns the publisher name.
func (p *PagerDutyPublisher) Name() string {
	return p.config.Name
}

// Type returns the publisher type.
func (p *PagerDutyPublisher) Type() PublisherType {
	return PublisherTypePagerDuty
}

// Close closes the publisher.
func (p *PagerDutyPublisher) Close() error {
	return nil
}
