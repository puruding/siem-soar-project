// Package consumer provides Kafka consumer functionality for the normalizer service.
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/normalizer/internal/config"
	"github.com/siem-soar-platform/services/normalizer/internal/normalizer"
	"github.com/twmb/franz-go/pkg/kgo"
)

// ParsedEvent represents an incoming parsed event from Kafka.
type ParsedEvent struct {
	EventID      string                 `json:"event_id"`
	TenantID     string                 `json:"tenant_id"`
	SourceType   string                 `json:"source_type"`
	Format       string                 `json:"format"`
	Timestamp    time.Time              `json:"timestamp"`
	Fields       map[string]interface{} `json:"fields"`
	RawLog       string                 `json:"raw_log"`
	ParseSuccess bool                   `json:"parse_success"`
}

// Consumer handles Kafka consumption and normalization.
type Consumer struct {
	cfg        *config.Config
	client     *kgo.Client
	normalizer *normalizer.Normalizer
	producer   *kgo.Client
	logger     *slog.Logger

	// Batching
	batchCh   chan *kgo.Record
	batchSize int
	batchWait time.Duration

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	messagesConsumed  atomic.Uint64
	messagesProduced  atomic.Uint64
	messagesDLQ       atomic.Uint64
	normalizeErrors   atomic.Uint64
	validationErrors  atomic.Uint64
	batchesProcessed  atomic.Uint64
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(cfg *config.Config, norm *normalizer.Normalizer, logger *slog.Logger) (*Consumer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Consumer client
	consumerOpts := []kgo.Opt{
		kgo.SeedBrokers(cfg.KafkaBrokers...),
		kgo.ConsumerGroup(cfg.KafkaConsumerGroup),
		kgo.ConsumeTopics(cfg.KafkaInputTopic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxWait(100 * time.Millisecond),
		kgo.FetchMaxBytes(10 * 1024 * 1024),
	}

	consumer, err := kgo.NewClient(consumerOpts...)
	if err != nil {
		cancel()
		return nil, err
	}

	// Producer client
	producerOpts := []kgo.Opt{
		kgo.SeedBrokers(cfg.KafkaBrokers...),
		kgo.ProducerBatchMaxBytes(16 * 1024 * 1024),
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
		cfg:        cfg,
		client:     consumer,
		normalizer: norm,
		producer:   producer,
		logger:     logger.With("component", "kafka-consumer"),
		batchCh:    make(chan *kgo.Record, cfg.BatchSize*2),
		batchSize:  cfg.BatchSize,
		batchWait:  cfg.BatchTimeout,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start starts the consumer.
func (c *Consumer) Start() {
	c.logger.Info("starting normalizer consumer",
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
	c.logger.Info("stopping normalizer consumer")
	c.cancel()
	close(c.batchCh)
	c.wg.Wait()
	c.client.Close()
	c.producer.Close()
	c.logger.Info("normalizer consumer stopped")
}

// Stats returns consumer statistics.
func (c *Consumer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"messages_consumed":  c.messagesConsumed.Load(),
		"messages_produced":  c.messagesProduced.Load(),
		"messages_dlq":       c.messagesDLQ.Load(),
		"normalize_errors":   c.normalizeErrors.Load(),
		"validation_errors":  c.validationErrors.Load(),
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

	var produceRecords []*kgo.Record
	var dlqRecords []*kgo.Record

	for _, record := range records {
		var parsed ParsedEvent
		if err := json.Unmarshal(record.Value, &parsed); err != nil {
			c.logger.Warn("failed to unmarshal parsed event", "error", err)
			c.normalizeErrors.Add(1)
			continue
		}

		// Normalize
		udmEvent, err := c.normalizer.Normalize(&normalizer.InputEvent{
			EventID:    parsed.EventID,
			TenantID:   parsed.TenantID,
			SourceType: parsed.SourceType,
			Format:     parsed.Format,
			Timestamp:  parsed.Timestamp,
			Fields:     parsed.Fields,
			RawLog:     parsed.RawLog,
		})

		if err != nil {
			c.normalizeErrors.Add(1)

			if c.cfg.DropInvalidEvents {
				continue
			}

			// Send to DLQ
			dlqRecord := &kgo.Record{
				Topic: c.cfg.KafkaDLQTopic,
				Key:   record.Key,
				Value: record.Value,
				Headers: []kgo.RecordHeader{
					{Key: "error", Value: []byte(err.Error())},
					{Key: "source_topic", Value: []byte(c.cfg.KafkaInputTopic)},
				},
			}
			dlqRecords = append(dlqRecords, dlqRecord)
			continue
		}

		// Validate
		if c.cfg.StrictValidation {
			if validErr := c.normalizer.Validate(udmEvent); validErr != nil {
				c.validationErrors.Add(1)
				if c.cfg.DropInvalidEvents {
					continue
				}
			}
		}

		// Marshal UDM event
		data, err := json.Marshal(udmEvent)
		if err != nil {
			c.logger.Error("failed to marshal UDM event", "error", err)
			continue
		}

		outputRecord := &kgo.Record{
			Topic: c.cfg.KafkaOutputTopic,
			Key:   []byte(parsed.TenantID),
			Value: data,
			Headers: []kgo.RecordHeader{
				{Key: "event_id", Value: []byte(parsed.EventID)},
				{Key: "event_type", Value: []byte(string(udmEvent.Metadata.EventType))},
				{Key: "source_type", Value: []byte(parsed.SourceType)},
			},
		}
		produceRecords = append(produceRecords, outputRecord)
	}

	// Produce to output topic
	if len(produceRecords) > 0 {
		results := c.producer.ProduceSync(c.ctx, produceRecords...)
		for _, r := range results {
			if r.Err != nil {
				c.logger.Error("failed to produce normalized event",
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
				c.logger.Error("failed to produce to DLQ", "error", r.Err)
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
