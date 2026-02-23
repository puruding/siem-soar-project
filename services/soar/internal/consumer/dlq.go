// Package consumer provides Kafka consumer for ML-enriched alerts.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// DLQProducer publishes failed messages to DLQ topic.
type DLQProducer struct {
	client *kgo.Client
	topic  string
	logger *slog.Logger
}

// DLQMessage represents a message in the Dead Letter Queue.
type DLQMessage struct {
	OriginalMessage []byte    `json:"original_message"`
	Error           string    `json:"error"`
	ErrorType       string    `json:"error_type,omitempty"`
	RetryCount      int       `json:"retry_count"`
	FirstFailedAt   time.Time `json:"first_failed_at"`
	LastFailedAt    time.Time `json:"last_failed_at"`
	StackTrace      string    `json:"stack_trace,omitempty"`
	ConsumerGroup   string    `json:"consumer_group,omitempty"`
	SourceTopic     string    `json:"source_topic,omitempty"`
	SourcePartition int32     `json:"source_partition,omitempty"`
	SourceOffset    int64     `json:"source_offset,omitempty"`
}

// NewDLQProducer creates a new DLQProducer instance.
func NewDLQProducer(brokers []string, topic string, logger *slog.Logger) (*DLQProducer, error) {
	if logger == nil {
		logger = slog.Default()
	}

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.AllowAutoTopicCreation(),
		kgo.ProducerBatchMaxBytes(10 * 1024 * 1024), // 10MB max batch
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer for DLQ: %w", err)
	}

	return &DLQProducer{
		client: client,
		topic:  topic,
		logger: logger,
	}, nil
}

// Publish publishes a failed message to the DLQ topic.
func (p *DLQProducer) Publish(ctx context.Context, original []byte, err error, retryCount int) error {
	now := time.Now().UTC()

	dlqMsg := DLQMessage{
		OriginalMessage: original,
		Error:           err.Error(),
		ErrorType:       categorizeError(err),
		RetryCount:      retryCount,
		FirstFailedAt:   now,
		LastFailedAt:    now,
		StackTrace:      getStackTrace(),
		ConsumerGroup:   "soar-consumer",
		SourceTopic:     "alerts.ml_enriched",
	}

	// Serialize DLQ message
	msgBytes, marshalErr := json.Marshal(dlqMsg)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal DLQ message: %w", marshalErr)
	}

	// Build Kafka record
	record := &kgo.Record{
		Topic: p.topic,
		Value: msgBytes,
		Headers: []kgo.RecordHeader{
			{Key: "error_type", Value: []byte(dlqMsg.ErrorType)},
			{Key: "retry_count", Value: []byte(fmt.Sprintf("%d", retryCount))},
			{Key: "failed_at", Value: []byte(now.Format(time.RFC3339))},
		},
	}

	// Try to extract alert_id for key
	alertID := extractAlertID(original)
	if alertID != "" {
		record.Key = []byte(alertID)
		record.Headers = append(record.Headers, kgo.RecordHeader{
			Key:   "alert_id",
			Value: []byte(alertID),
		})
	}

	// Produce to DLQ with sync
	results := p.client.ProduceSync(ctx, record)
	if len(results) > 0 && results[0].Err != nil {
		return fmt.Errorf("failed to produce to DLQ: %w", results[0].Err)
	}

	p.logger.Info("Published message to DLQ",
		"topic", p.topic,
		"alert_id", alertID,
		"error_type", dlqMsg.ErrorType,
		"retry_count", retryCount,
	)

	return nil
}

// PublishWithMetadata publishes a failed message to the DLQ with source metadata.
func (p *DLQProducer) PublishWithMetadata(
	ctx context.Context,
	original []byte,
	err error,
	retryCount int,
	sourceTopic string,
	sourcePartition int32,
	sourceOffset int64,
) error {
	now := time.Now().UTC()

	dlqMsg := DLQMessage{
		OriginalMessage: original,
		Error:           err.Error(),
		ErrorType:       categorizeError(err),
		RetryCount:      retryCount,
		FirstFailedAt:   now,
		LastFailedAt:    now,
		StackTrace:      getStackTrace(),
		ConsumerGroup:   "soar-consumer",
		SourceTopic:     sourceTopic,
		SourcePartition: sourcePartition,
		SourceOffset:    sourceOffset,
	}

	msgBytes, marshalErr := json.Marshal(dlqMsg)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal DLQ message: %w", marshalErr)
	}

	record := &kgo.Record{
		Topic: p.topic,
		Value: msgBytes,
		Headers: []kgo.RecordHeader{
			{Key: "error_type", Value: []byte(dlqMsg.ErrorType)},
			{Key: "retry_count", Value: []byte(fmt.Sprintf("%d", retryCount))},
			{Key: "failed_at", Value: []byte(now.Format(time.RFC3339))},
			{Key: "source_topic", Value: []byte(sourceTopic)},
			{Key: "source_partition", Value: []byte(fmt.Sprintf("%d", sourcePartition))},
			{Key: "source_offset", Value: []byte(fmt.Sprintf("%d", sourceOffset))},
		},
	}

	alertID := extractAlertID(original)
	if alertID != "" {
		record.Key = []byte(alertID)
	}

	results := p.client.ProduceSync(ctx, record)
	if len(results) > 0 && results[0].Err != nil {
		return fmt.Errorf("failed to produce to DLQ: %w", results[0].Err)
	}

	return nil
}

// Close closes the DLQ producer.
func (p *DLQProducer) Close() {
	if p.client != nil {
		p.client.Close()
	}
}

// categorizeError categorizes an error for DLQ analysis.
func categorizeError(err error) string {
	if err == nil {
		return "unknown"
	}

	errStr := err.Error()

	// Parse/validation errors
	parseErrors := []string{"unmarshal", "parse", "invalid JSON", "syntax"}
	for _, s := range parseErrors {
		if containsIgnoreCase(errStr, s) {
			return "parse_error"
		}
	}

	// Not found errors
	notFoundErrors := []string{"not found", "does not exist", "no such"}
	for _, s := range notFoundErrors {
		if containsIgnoreCase(errStr, s) {
			return "not_found"
		}
	}

	// Connection/network errors
	connErrors := []string{"connection", "timeout", "refused", "network", "dial"}
	for _, s := range connErrors {
		if containsIgnoreCase(errStr, s) {
			return "connection_error"
		}
	}

	// Validation errors
	validationErrors := []string{"validation", "required", "invalid", "constraint"}
	for _, s := range validationErrors {
		if containsIgnoreCase(errStr, s) {
			return "validation_error"
		}
	}

	// Resource errors
	resourceErrors := []string{"exhausted", "limit", "quota", "rate"}
	for _, s := range resourceErrors {
		if containsIgnoreCase(errStr, s) {
			return "resource_error"
		}
	}

	// Execution errors
	execErrors := []string{"execution", "workflow", "playbook"}
	for _, s := range execErrors {
		if containsIgnoreCase(errStr, s) {
			return "execution_error"
		}
	}

	return "unknown_error"
}

// extractAlertID tries to extract alert_id from JSON message.
func extractAlertID(data []byte) string {
	var msg struct {
		ID      string `json:"id"`
		AlertID string `json:"alert_id"`
	}

	if err := json.Unmarshal(data, &msg); err != nil {
		return ""
	}

	if msg.ID != "" {
		return msg.ID
	}
	return msg.AlertID
}

// getStackTrace captures the current stack trace.
func getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// containsIgnoreCase checks if s contains substr (case insensitive).
func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)

	return findSubstringDLQ(sLower, substrLower) != -1
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func findSubstringDLQ(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// DLQStats represents DLQ statistics.
type DLQStats struct {
	TotalMessages   int64            `json:"total_messages"`
	ByErrorType     map[string]int64 `json:"by_error_type"`
	OldestMessage   time.Time        `json:"oldest_message,omitempty"`
	RecentMessages  int64            `json:"recent_messages_24h"`
	RequiresReview  int64            `json:"requires_review"`
}

// DLQReader reads messages from the DLQ for analysis.
type DLQReader struct {
	client *kgo.Client
	topic  string
	logger *slog.Logger
}

// NewDLQReader creates a new DLQReader instance.
func NewDLQReader(brokers []string, topic string, logger *slog.Logger) (*DLQReader, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create DLQ reader: %w", err)
	}

	return &DLQReader{
		client: client,
		topic:  topic,
		logger: logger,
	}, nil
}

// ReadMessages reads messages from the DLQ.
func (r *DLQReader) ReadMessages(ctx context.Context, limit int) ([]DLQMessage, error) {
	var messages []DLQMessage

	// Set a deadline for reading
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for len(messages) < limit {
		fetches := r.client.PollFetches(ctx)
		if fetches.IsClientClosed() {
			break
		}

		if ctx.Err() != nil {
			break
		}

		fetches.EachRecord(func(record *kgo.Record) {
			if len(messages) >= limit {
				return
			}

			var msg DLQMessage
			if err := json.Unmarshal(record.Value, &msg); err != nil {
				r.logger.Warn("Failed to unmarshal DLQ message",
					"offset", record.Offset,
					"error", err,
				)
				return
			}
			messages = append(messages, msg)
		})
	}

	return messages, nil
}

// Close closes the DLQ reader.
func (r *DLQReader) Close() {
	if r.client != nil {
		r.client.Close()
	}
}
