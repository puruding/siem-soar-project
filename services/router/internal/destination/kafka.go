// Package destination provides routing destination implementations.
package destination

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"github.com/siem-soar-platform/services/router/internal/routing"
)

// KafkaConfig holds Kafka destination configuration.
type KafkaConfig struct {
	Name            string
	Brokers         []string
	Topic           string
	RequiredAcks    int
	Compression     string
	BatchSize       int
	BatchTimeout    time.Duration
	MaxMessageBytes int
	Retries         int
	RetryBackoff    time.Duration
	TLSEnabled      bool
	TLSCertPath     string
	TLSKeyPath      string
	TLSCAPath       string
	SASLEnabled     bool
	SASLMechanism   string
	SASLUsername    string
	SASLPassword    string
}

// KafkaDestination sends events to Kafka.
type KafkaDestination struct {
	config    KafkaConfig
	producer  sarama.AsyncProducer
	logger    *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// Health
	healthy   atomic.Bool
	lastError atomic.Value

	// Metrics
	messagesSent    atomic.Uint64
	messagesAcked   atomic.Uint64
	errors          atomic.Uint64
}

// NewKafkaDestination creates a new Kafka destination.
func NewKafkaDestination(cfg KafkaConfig, logger *slog.Logger) (*KafkaDestination, error) {
	ctx, cancel := context.WithCancel(context.Background())

	d := &KafkaDestination{
		config: cfg,
		logger: logger.With("component", "kafka-dest", "name", cfg.Name),
		ctx:    ctx,
		cancel: cancel,
	}

	// Set defaults
	if d.config.RequiredAcks == 0 {
		d.config.RequiredAcks = -1 // Wait for all
	}
	if d.config.BatchSize == 0 {
		d.config.BatchSize = 1000
	}
	if d.config.BatchTimeout == 0 {
		d.config.BatchTimeout = 10 * time.Millisecond
	}
	if d.config.MaxMessageBytes == 0 {
		d.config.MaxMessageBytes = 10 * 1024 * 1024 // 10MB
	}
	if d.config.Retries == 0 {
		d.config.Retries = 3
	}
	if d.config.RetryBackoff == 0 {
		d.config.RetryBackoff = 100 * time.Millisecond
	}

	// Create producer
	if err := d.createProducer(); err != nil {
		cancel()
		return nil, err
	}

	// Start handlers
	d.wg.Add(2)
	go d.handleSuccesses()
	go d.handleErrors()

	return d, nil
}

func (d *KafkaDestination) createProducer() error {
	config := sarama.NewConfig()
	config.Version = sarama.V3_5_0_0

	// Required acks
	switch d.config.RequiredAcks {
	case 0:
		config.Producer.RequiredAcks = sarama.NoResponse
	case 1:
		config.Producer.RequiredAcks = sarama.WaitForLocal
	default:
		config.Producer.RequiredAcks = sarama.WaitForAll
	}

	// Compression
	switch d.config.Compression {
	case "gzip":
		config.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		config.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		config.Producer.Compression = sarama.CompressionLZ4
	case "zstd":
		config.Producer.Compression = sarama.CompressionZSTD
	}

	// Batching
	config.Producer.Flush.Messages = d.config.BatchSize
	config.Producer.Flush.Frequency = d.config.BatchTimeout
	config.Producer.MaxMessageBytes = d.config.MaxMessageBytes

	// Retries
	config.Producer.Retry.Max = d.config.Retries
	config.Producer.Retry.Backoff = d.config.RetryBackoff

	// Return successes and errors
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true

	// TLS
	if d.config.TLSEnabled {
		config.Net.TLS.Enable = true
		// TLS config setup would go here
	}

	// SASL
	if d.config.SASLEnabled {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLMechanism(d.config.SASLMechanism)
		config.Net.SASL.User = d.config.SASLUsername
		config.Net.SASL.Password = d.config.SASLPassword
	}

	producer, err := sarama.NewAsyncProducer(d.config.Brokers, config)
	if err != nil {
		return fmt.Errorf("failed to create producer: %w", err)
	}

	d.producer = producer
	d.healthy.Store(true)

	d.logger.Info("connected to Kafka",
		"brokers", d.config.Brokers,
		"topic", d.config.Topic)

	return nil
}

// Name returns the destination name.
func (d *KafkaDestination) Name() string {
	return d.config.Name
}

// Type returns the destination type.
func (d *KafkaDestination) Type() string {
	return "kafka"
}

// Send sends events to Kafka.
func (d *KafkaDestination) Send(ctx context.Context, events []*routing.Event) error {
	if len(events) == 0 {
		return nil
	}

	for _, event := range events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.ctx.Done():
			return d.ctx.Err()
		default:
		}

		// Serialize event
		value, err := json.Marshal(event)
		if err != nil {
			d.logger.Warn("failed to serialize event", "event_id", event.ID, "error", err)
			continue
		}

		// Create message
		msg := &sarama.ProducerMessage{
			Topic: d.config.Topic,
			Key:   sarama.StringEncoder(event.TenantID),
			Value: sarama.ByteEncoder(value),
			Headers: []sarama.RecordHeader{
				{Key: []byte("event_id"), Value: []byte(event.ID)},
				{Key: []byte("event_type"), Value: []byte(event.EventType)},
				{Key: []byte("source_type"), Value: []byte(event.SourceType)},
			},
			Timestamp: event.Timestamp,
		}

		// Send asynchronously
		select {
		case d.producer.Input() <- msg:
			d.messagesSent.Add(1)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// IsHealthy returns true if the destination is healthy.
func (d *KafkaDestination) IsHealthy() bool {
	return d.healthy.Load()
}

// Close closes the destination.
func (d *KafkaDestination) Close() error {
	d.cancel()

	if d.producer != nil {
		d.producer.AsyncClose()
	}

	d.wg.Wait()
	return nil
}

// Stats returns destination statistics.
func (d *KafkaDestination) Stats() map[string]interface{} {
	return map[string]interface{}{
		"messages_sent":  d.messagesSent.Load(),
		"messages_acked": d.messagesAcked.Load(),
		"errors":         d.errors.Load(),
		"healthy":        d.healthy.Load(),
	}
}

func (d *KafkaDestination) handleSuccesses() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		case msg, ok := <-d.producer.Successes():
			if !ok {
				return
			}
			d.messagesAcked.Add(1)
			d.healthy.Store(true)
			_ = msg // Can log partition/offset if needed
		}
	}
}

func (d *KafkaDestination) handleErrors() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		case err, ok := <-d.producer.Errors():
			if !ok {
				return
			}
			d.errors.Add(1)
			d.lastError.Store(err)
			d.logger.Error("produce error",
				"topic", err.Msg.Topic,
				"error", err.Err)
		}
	}
}
