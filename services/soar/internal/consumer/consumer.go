// Package consumer provides Kafka consumer for ML-enriched alerts.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/siem-soar-platform/services/soar/internal/engine"
)

// AlertConsumer consumes ML-enriched alerts from Kafka.
type AlertConsumer struct {
	client      *kgo.Client
	engine      *engine.SOAREngine
	handler     *Handler
	idempotency *IdempotencyChecker
	dlq         *DLQProducer
	logger      *slog.Logger
	config      Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds the Kafka consumer configuration.
type Config struct {
	Brokers        []string      `json:"brokers"`
	Topic          string        `json:"topic"`           // alerts.ml_enriched
	ConsumerGroup  string        `json:"consumer_group"`  // soar-consumer
	DLQTopic       string        `json:"dlq_topic"`       // alerts.ml_enriched.dlq
	MaxRetries     int           `json:"max_retries"`     // default 3
	RetryBackoff   time.Duration `json:"retry_backoff"`   // default 1s
	CommitInterval time.Duration `json:"commit_interval"` // default 5s
	BatchSize      int           `json:"batch_size"`      // default 100
	Enabled        bool          `json:"enabled"`         // Feature flag
}

// DefaultConfig returns default consumer configuration.
func DefaultConfig() Config {
	return Config{
		Brokers:        []string{"localhost:9092"},
		Topic:          "alerts.ml_enriched",
		ConsumerGroup:  "soar-consumer",
		DLQTopic:       "alerts.ml_enriched.dlq",
		MaxRetries:     3,
		RetryBackoff:   time.Second,
		CommitInterval: 5 * time.Second,
		BatchSize:      100,
		Enabled:        true,
	}
}

// NewAlertConsumer creates a new AlertConsumer instance.
func NewAlertConsumer(
	cfg Config,
	soarEngine *engine.SOAREngine,
	ruleStore *PlaybookRuleStore,
	idempotency *IdempotencyChecker,
	logger *slog.Logger,
) (*AlertConsumer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("kafka consumer is disabled")
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Set default values
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = time.Second
	}
	if cfg.CommitInterval == 0 {
		cfg.CommitInterval = 5 * time.Second
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}

	// Create Kafka client
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ConsumerGroup(cfg.ConsumerGroup),
		kgo.ConsumeTopics(cfg.Topic),
		kgo.DisableAutoCommit(),
		kgo.FetchMaxBytes(10 * 1024 * 1024), // 10MB max fetch
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka client: %w", err)
	}

	// Create DLQ producer
	dlq, err := NewDLQProducer(cfg.Brokers, cfg.DLQTopic, logger)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create DLQ producer: %w", err)
	}

	// Create handler
	handler := NewHandler(soarEngine, ruleStore, idempotency, logger)

	return &AlertConsumer{
		client:      client,
		engine:      soarEngine,
		handler:     handler,
		idempotency: idempotency,
		dlq:         dlq,
		logger:      logger,
		config:      cfg,
	}, nil
}

// Start starts the consumer.
func (c *AlertConsumer) Start() error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.logger.Info("Starting Kafka alert consumer",
		"topic", c.config.Topic,
		"consumer_group", c.config.ConsumerGroup,
		"brokers", c.config.Brokers,
	)

	c.wg.Add(1)
	go c.consumeLoop()

	return nil
}

// Stop gracefully stops the consumer.
func (c *AlertConsumer) Stop() error {
	c.logger.Info("Stopping Kafka alert consumer")

	if c.cancel != nil {
		c.cancel()
	}

	// Wait for consume loop to finish
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		c.logger.Info("Consumer stopped gracefully")
	case <-time.After(30 * time.Second):
		c.logger.Warn("Consumer stop timed out after 30s")
	}

	// Close Kafka client
	if c.client != nil {
		c.client.Close()
	}

	// Close DLQ producer
	if c.dlq != nil {
		c.dlq.Close()
	}

	return nil
}

// consumeLoop is the main consume loop.
func (c *AlertConsumer) consumeLoop() {
	defer c.wg.Done()

	commitTicker := time.NewTicker(c.config.CommitInterval)
	defer commitTicker.Stop()

	uncommitted := make(map[string]map[int32]kgo.Offset) // topic -> partition -> offset

	for {
		select {
		case <-c.ctx.Done():
			// Final commit before exit
			c.commitOffsets(uncommitted)
			return
		case <-commitTicker.C:
			c.commitOffsets(uncommitted)
			uncommitted = make(map[string]map[int32]kgo.Offset)
		default:
			fetches := c.client.PollFetches(c.ctx)
			if fetches.IsClientClosed() {
				return
			}

			if errs := fetches.Errors(); len(errs) > 0 {
				for _, err := range errs {
					c.logger.Error("Fetch error",
						"topic", err.Topic,
						"partition", err.Partition,
						"error", err.Err,
					)
				}
				continue
			}

			fetches.EachRecord(func(record *kgo.Record) {
				c.processMessage(c.ctx, record, uncommitted)
			})
		}
	}
}

// processMessage processes a single Kafka message.
func (c *AlertConsumer) processMessage(ctx context.Context, record *kgo.Record, uncommitted map[string]map[int32]kgo.Offset) {
	startTime := time.Now()

	c.logger.Debug("Processing message",
		"topic", record.Topic,
		"partition", record.Partition,
		"offset", record.Offset,
		"key", string(record.Key),
	)

	// Parse the alert
	var alert MLEnrichedAlert
	if err := json.Unmarshal(record.Value, &alert); err != nil {
		c.logger.Error("Failed to unmarshal alert",
			"error", err,
			"offset", record.Offset,
		)
		c.sendToDLQ(ctx, record, err, 0)
		c.trackOffset(uncommitted, record)
		return
	}

	// Process with retries
	var lastErr error
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debug("Retrying message",
				"alert_id", alert.AlertID,
				"attempt", attempt,
			)
			time.Sleep(c.config.RetryBackoff * time.Duration(attempt))
		}

		lastErr = c.handler.HandleAlert(ctx, &alert)
		if lastErr == nil {
			// Success
			duration := time.Since(startTime)
			c.logger.Info("Successfully processed alert",
				"alert_id", alert.AlertID,
				"duration_ms", duration.Milliseconds(),
			)
			c.trackOffset(uncommitted, record)
			return
		}

		// Check if error is retryable
		if !isRetryableError(lastErr) {
			break
		}
	}

	// All retries exhausted, send to DLQ
	c.logger.Error("Failed to process alert after retries",
		"alert_id", alert.AlertID,
		"error", lastErr,
		"retries", c.config.MaxRetries,
	)
	c.sendToDLQ(ctx, record, lastErr, c.config.MaxRetries)
	c.trackOffset(uncommitted, record)
}

// trackOffset tracks the offset for later commit.
func (c *AlertConsumer) trackOffset(uncommitted map[string]map[int32]kgo.Offset, record *kgo.Record) {
	if uncommitted[record.Topic] == nil {
		uncommitted[record.Topic] = make(map[int32]kgo.Offset)
	}

	// Track the next offset to commit (current + 1)
	uncommitted[record.Topic][record.Partition] = kgo.NewOffset().At(record.Offset + 1)
}

// commitOffsets commits the tracked offsets.
func (c *AlertConsumer) commitOffsets(uncommitted map[string]map[int32]kgo.Offset) {
	if len(uncommitted) == 0 {
		return
	}

	offsets := make(map[string]map[int32]kgo.EpochOffset)
	for topic, partitions := range uncommitted {
		offsets[topic] = make(map[int32]kgo.EpochOffset)
		for partition, offset := range partitions {
			offsets[topic][partition] = kgo.EpochOffset{
				Epoch:  -1,
				Offset: offset.At(0).EpochOffset().Offset,
			}
		}
	}

	// Use async commit with callback
	var commitErr error
	done := make(chan struct{})
	c.client.CommitOffsets(c.ctx, offsets, func(_ *kgo.Client, _ *kmsg.OffsetCommitRequest, _ *kmsg.OffsetCommitResponse, err error) {
		commitErr = err
		close(done)
	})

	// Wait for commit with timeout
	select {
	case <-done:
		if commitErr != nil {
			c.logger.Error("Failed to commit offsets", "error", commitErr)
		} else {
			c.logger.Debug("Committed offsets", "topic_count", len(offsets))
		}
	case <-time.After(10 * time.Second):
		c.logger.Warn("Commit offsets timed out")
	}
}

// sendToDLQ sends a failed message to the Dead Letter Queue.
func (c *AlertConsumer) sendToDLQ(ctx context.Context, record *kgo.Record, err error, retryCount int) {
	if c.dlq == nil {
		return
	}

	if dlqErr := c.dlq.Publish(ctx, record.Value, err, retryCount); dlqErr != nil {
		c.logger.Error("Failed to send to DLQ",
			"original_error", err,
			"dlq_error", dlqErr,
		)
	}
}

// isRetryableError determines if an error is retryable.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Add specific error types that are retryable
	// For now, treat all errors as retryable except specific non-retryable ones
	errStr := err.Error()

	// Non-retryable errors
	nonRetryable := []string{
		"invalid JSON",
		"validation failed",
		"playbook not found",
		"already processed",
	}

	for _, s := range nonRetryable {
		if contains(errStr, s) {
			return false
		}
	}

	return true
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr) != -1)
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
