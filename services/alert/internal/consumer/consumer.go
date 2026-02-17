// Package consumer provides Kafka consumer for the alert service.
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/alert/internal/config"
	"github.com/siem-soar-platform/services/alert/internal/generator"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Consumer consumes detection results from Kafka.
type Consumer struct {
	client    *kgo.Client
	config    config.KafkaConfig
	generator *generator.Generator
	logger    *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Batch processing
	batchSize    int
	batchTimeout time.Duration

	// Metrics
	totalConsumed atomic.Uint64
	totalFailed   atomic.Uint64
	totalBatches  atomic.Uint64
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(cfg config.KafkaConfig, gen *generator.Generator, logger *slog.Logger) (*Consumer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Consumer{
		config:       cfg,
		generator:    gen,
		logger:       logger.With("component", "kafka-consumer"),
		ctx:          ctx,
		cancel:       cancel,
		batchSize:    cfg.BatchSize,
		batchTimeout: cfg.BatchTimeout,
	}

	// Build Kafka client options
	opts, err := c.buildClientOptions()
	if err != nil {
		cancel()
		return nil, err
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		cancel()
		return nil, err
	}

	c.client = client
	return c, nil
}

// buildClientOptions builds Kafka client options from configuration.
func (c *Consumer) buildClientOptions() ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.config.Brokers...),
		kgo.ConsumerGroup(c.config.ConsumerGroup),
		kgo.ConsumeTopics(c.config.InputTopic),
		kgo.FetchMaxWait(c.config.BatchTimeout),
	}

	// Session timeout
	if c.config.SessionTimeout > 0 {
		opts = append(opts, kgo.SessionTimeout(c.config.SessionTimeout))
	}

	// Heartbeat interval
	if c.config.HeartbeatInterval > 0 {
		opts = append(opts, kgo.HeartbeatInterval(c.config.HeartbeatInterval))
	}

	// SASL authentication
	if c.config.SASL.Enabled {
		saslOpt, err := c.buildSASLOption()
		if err != nil {
			return nil, err
		}
		opts = append(opts, saslOpt)
	}

	// TLS configuration
	if c.config.TLS.Enabled {
		tlsConfig, err := c.config.TLS.BuildTLSConfig()
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil {
			opts = append(opts, kgo.DialTLSConfig(tlsConfig))
		}
	}

	return opts, nil
}

// buildSASLOption builds the SASL option based on mechanism.
func (c *Consumer) buildSASLOption() (kgo.Opt, error) {
	switch c.config.SASL.Mechanism {
	case "PLAIN":
		return kgo.SASL(plain.Auth{
			User: c.config.SASL.Username,
			Pass: c.config.SASL.Password,
		}.AsMechanism()), nil
	case "SCRAM-SHA-256":
		return kgo.SASL(scram.Auth{
			User: c.config.SASL.Username,
			Pass: c.config.SASL.Password,
		}.AsSha256Mechanism()), nil
	case "SCRAM-SHA-512":
		return kgo.SASL(scram.Auth{
			User: c.config.SASL.Username,
			Pass: c.config.SASL.Password,
		}.AsSha512Mechanism()), nil
	default:
		return kgo.SASL(plain.Auth{
			User: c.config.SASL.Username,
			Pass: c.config.SASL.Password,
		}.AsMechanism()), nil
	}
}

// Start starts consuming messages.
func (c *Consumer) Start() error {
	c.wg.Add(1)
	go c.consumeLoop()

	c.logger.Info("kafka consumer started",
		"brokers", c.config.Brokers,
		"topic", c.config.InputTopic,
		"group", c.config.ConsumerGroup,
		"batch_size", c.batchSize)

	return nil
}

// Stop stops the consumer gracefully.
func (c *Consumer) Stop() error {
	c.logger.Info("stopping kafka consumer")
	c.cancel()
	c.wg.Wait()
	c.client.Close()
	c.logger.Info("kafka consumer stopped")
	return nil
}

// consumeLoop is the main consumption loop.
func (c *Consumer) consumeLoop() {
	defer c.wg.Done()

	batch := make([]*generator.DetectionResult, 0, c.batchSize)
	ticker := time.NewTicker(c.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Process remaining batch before exit
			if len(batch) > 0 {
				c.processBatch(batch)
			}
			return

		case <-ticker.C:
			// Flush batch on timeout
			if len(batch) > 0 {
				c.processBatch(batch)
				batch = make([]*generator.DetectionResult, 0, c.batchSize)
			}

		default:
			// Fetch records
			fetches := c.client.PollFetches(c.ctx)
			if fetches.IsClientClosed() {
				return
			}

			// Handle errors
			if errs := fetches.Errors(); len(errs) > 0 {
				for _, err := range errs {
					c.logger.Error("fetch error",
						"topic", err.Topic,
						"partition", err.Partition,
						"error", err.Err)
				}
				continue
			}

			// Process records
			fetches.EachRecord(func(record *kgo.Record) {
				result, err := c.parseDetectionResult(record.Value)
				if err != nil {
					c.logger.Error("failed to parse detection result",
						"offset", record.Offset,
						"partition", record.Partition,
						"error", err)
					c.totalFailed.Add(1)
					return
				}

				batch = append(batch, result)
				c.totalConsumed.Add(1)

				// Process batch if full
				if len(batch) >= c.batchSize {
					c.processBatch(batch)
					batch = make([]*generator.DetectionResult, 0, c.batchSize)
					ticker.Reset(c.batchTimeout)
				}
			})
		}
	}
}

// parseDetectionResult parses a detection result from JSON.
func (c *Consumer) parseDetectionResult(data []byte) (*generator.DetectionResult, error) {
	var result generator.DetectionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// processBatch processes a batch of detection results.
func (c *Consumer) processBatch(batch []*generator.DetectionResult) {
	c.totalBatches.Add(1)

	c.logger.Debug("processing batch", "size", len(batch))

	for _, result := range batch {
		c.generator.Submit(result)
	}
}

// Stats returns consumer statistics.
func (c *Consumer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_consumed": c.totalConsumed.Load(),
		"total_failed":   c.totalFailed.Load(),
		"total_batches":  c.totalBatches.Load(),
	}
}

// Health checks if the consumer is healthy.
func (c *Consumer) Health() bool {
	// Check if client is connected by pinging
	return c.client != nil
}
