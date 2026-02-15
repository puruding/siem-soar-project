// Package consumer provides Kafka consumer functionality for the parser service.
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/parser/internal/config"
	"github.com/siem-soar-platform/services/parser/internal/engine"
	"github.com/twmb/franz-go/pkg/kgo"
)

// RawLogEvent represents an incoming raw log event from Kafka.
type RawLogEvent struct {
	EventID    string            `json:"event_id"`
	TenantID   string            `json:"tenant_id"`
	SourceType string            `json:"source_type"`
	Timestamp  time.Time         `json:"timestamp"`
	Data       string            `json:"data"`
	Metadata   map[string]string `json:"metadata"`
}

// Consumer handles Kafka consumption and parsing.
type Consumer struct {
	cfg      *config.Config
	client   *kgo.Client
	engine   *engine.Engine
	producer *kgo.Client
	logger   *slog.Logger

	// Batching
	batchCh   chan *kgo.Record
	batchSize int
	batchWait time.Duration

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	messagesConsumed atomic.Uint64
	messagesProduced atomic.Uint64
	messagesDLQ      atomic.Uint64
	parseErrors      atomic.Uint64
	batchesProcessed atomic.Uint64
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(cfg *config.Config, eng *engine.Engine, logger *slog.Logger) (*Consumer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Consumer client
	consumerOpts := []kgo.Opt{
		kgo.SeedBrokers(cfg.KafkaBrokers...),
		kgo.ConsumerGroup(cfg.KafkaConsumerGroup),
		kgo.ConsumeTopics(cfg.KafkaInputTopic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxWait(100 * time.Millisecond),
		kgo.FetchMaxBytes(10 * 1024 * 1024), // 10MB
	}

	consumer, err := kgo.NewClient(consumerOpts...)
	if err != nil {
		cancel()
		return nil, err
	}

	// Producer client
	producerOpts := []kgo.Opt{
		kgo.SeedBrokers(cfg.KafkaBrokers...),
		kgo.ProducerBatchMaxBytes(16 * 1024 * 1024), // 16MB
		kgo.ProducerLinger(10 * time.Millisecond),
		kgo.RequiredAcks(kgo.AllISRAcks()),
	}

	producer, err := kgo.NewClient(producerOpts...)
	if err != nil {
		consumer.Close()
		cancel()
		return nil, err
	}

	return &Consumer{
		cfg:       cfg,
		client:    consumer,
		engine:    eng,
		producer:  producer,
		logger:    logger.With("component", "kafka-consumer"),
		batchCh:   make(chan *kgo.Record, cfg.BatchSize*2),
		batchSize: cfg.BatchSize,
		batchWait: cfg.BatchTimeout,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start starts the consumer.
func (c *Consumer) Start() {
	c.logger.Info("starting parser consumer",
		"input_topic", c.cfg.KafkaInputTopic,
		"output_topic", c.cfg.KafkaOutputTopic,
		"workers", c.cfg.Workers,
	)

	// Start batch processor workers
	for i := 0; i < c.cfg.Workers; i++ {
		c.wg.Add(1)
		go c.batchWorker(i)
	}

	// Start consumer loop
	c.wg.Add(1)
	go c.consumeLoop()
}

// Stop stops the consumer.
func (c *Consumer) Stop() {
	c.logger.Info("stopping parser consumer")
	c.cancel()
	close(c.batchCh)
	c.wg.Wait()
	c.client.Close()
	c.producer.Close()
	c.logger.Info("parser consumer stopped")
}

// Stats returns consumer statistics.
func (c *Consumer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"messages_consumed":  c.messagesConsumed.Load(),
		"messages_produced":  c.messagesProduced.Load(),
		"messages_dlq":       c.messagesDLQ.Load(),
		"parse_errors":       c.parseErrors.Load(),
		"batches_processed":  c.batchesProcessed.Load(),
	}
}

func (c *Consumer) consumeLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		fetches := c.client.PollFetches(c.ctx)
		if fetches.IsClientClosed() {
			return
		}

		if errs := fetches.Errors(); len(errs) > 0 {
			for _, err := range errs {
				c.logger.Error("fetch error",
					"topic", err.Topic,
					"partition", err.Partition,
					"error", err.Err,
				)
			}
			continue
		}

		fetches.EachRecord(func(r *kgo.Record) {
			select {
			case c.batchCh <- r:
				c.messagesConsumed.Add(1)
			case <-c.ctx.Done():
				return
			}
		})
	}
}

func (c *Consumer) batchWorker(id int) {
	defer c.wg.Done()

	batch := make([]*kgo.Record, 0, c.batchSize)
	ticker := time.NewTicker(c.batchWait)
	defer ticker.Stop()

	processBatch := func() {
		if len(batch) == 0 {
			return
		}

		c.processBatch(batch)
		c.batchesProcessed.Add(1)
		batch = batch[:0]
	}

	for {
		select {
		case <-c.ctx.Done():
			processBatch()
			return

		case record, ok := <-c.batchCh:
			if !ok {
				processBatch()
				return
			}
			batch = append(batch, record)
			if len(batch) >= c.batchSize {
				processBatch()
			}

		case <-ticker.C:
			processBatch()
		}
	}
}

func (c *Consumer) processBatch(records []*kgo.Record) {
	if len(records) == 0 {
		return
	}

	// Convert Kafka records to raw events
	rawEvents := make([]*engine.RawEvent, 0, len(records))
	recordMap := make(map[string]*kgo.Record) // Map event ID to record for commit tracking

	for _, record := range records {
		var rawLog RawLogEvent
		if err := json.Unmarshal(record.Value, &rawLog); err != nil {
			// Try to handle as plain text
			rawLog = RawLogEvent{
				EventID:    uuid.New().String(),
				TenantID:   "default",
				SourceType: "unknown",
				Timestamp:  time.Now(),
				Data:       string(record.Value),
				Metadata:   make(map[string]string),
			}

			// Extract metadata from Kafka headers
			for _, h := range record.Headers {
				rawLog.Metadata[h.Key] = string(h.Value)
			}
		}

		if rawLog.EventID == "" {
			rawLog.EventID = uuid.New().String()
		}

		rawEvent := &engine.RawEvent{
			EventID:    rawLog.EventID,
			TenantID:   rawLog.TenantID,
			SourceType: rawLog.SourceType,
			Timestamp:  rawLog.Timestamp,
			Data:       []byte(rawLog.Data),
			Metadata:   rawLog.Metadata,
		}

		rawEvents = append(rawEvents, rawEvent)
		recordMap[rawLog.EventID] = record
	}

	// Parse batch
	parsedEvents := c.engine.ParseBatch(c.ctx, rawEvents)

	// Produce parsed events
	var produceRecords []*kgo.Record
	var dlqRecords []*kgo.Record

	for _, parsed := range parsedEvents {
		if parsed == nil {
			continue
		}

		data, err := json.Marshal(parsed)
		if err != nil {
			c.logger.Error("failed to marshal parsed event",
				"event_id", parsed.EventID,
				"error", err,
			)
			continue
		}

		record := &kgo.Record{
			Key:   []byte(parsed.TenantID),
			Value: data,
			Headers: []kgo.RecordHeader{
				{Key: "event_id", Value: []byte(parsed.EventID)},
				{Key: "source_type", Value: []byte(parsed.SourceType)},
				{Key: "format", Value: []byte(parsed.Format)},
			},
		}

		if parsed.ParseSuccess {
			record.Topic = c.cfg.KafkaOutputTopic
			produceRecords = append(produceRecords, record)
		} else {
			record.Topic = c.cfg.KafkaDLQTopic
			dlqRecords = append(dlqRecords, record)
			c.parseErrors.Add(1)
		}
	}

	// Produce to output topic
	if len(produceRecords) > 0 {
		results := c.producer.ProduceSync(c.ctx, produceRecords...)
		for _, r := range results {
			if r.Err != nil {
				c.logger.Error("failed to produce parsed event",
					"topic", r.Record.Topic,
					"error", r.Err,
				)
			} else {
				c.messagesProduced.Add(1)
			}
		}
	}

	// Produce to DLQ
	if len(dlqRecords) > 0 {
		results := c.producer.ProduceSync(c.ctx, dlqRecords...)
		for _, r := range results {
			if r.Err != nil {
				c.logger.Error("failed to produce to DLQ",
					"topic", r.Record.Topic,
					"error", r.Err,
				)
			} else {
				c.messagesDLQ.Add(1)
			}
		}
	}

	// Commit offsets
	if err := c.client.CommitRecords(c.ctx, records...); err != nil {
		c.logger.Error("failed to commit offsets", "error", err)
	}
}
