// Package receiver provides log reception from various sources.
package receiver

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
)

// KafkaMessage represents a message received from Kafka.
type KafkaMessage struct {
	Topic      string
	Partition  int32
	Offset     int64
	Key        []byte
	Value      []byte
	Headers    map[string]string
	Timestamp  time.Time
	ReceivedAt time.Time
}

// KafkaReceiverConfig holds Kafka consumer configuration.
type KafkaReceiverConfig struct {
	Brokers           []string
	Topics            []string
	GroupID           string
	ClientID          string
	AutoCommit        bool
	AutoCommitInterval time.Duration
	MaxPollRecords    int
	SessionTimeout    time.Duration
	HeartbeatInterval time.Duration
	RebalanceStrategy string
	OffsetReset       string // "earliest" or "latest"
	TLSEnabled        bool
	TLSCertPath       string
	TLSKeyPath        string
	TLSCAPath         string
	SASLEnabled       bool
	SASLMechanism     string
	SASLUsername      string
	SASLPassword      string
}

// KafkaReceiver consumes messages from Kafka topics.
type KafkaReceiver struct {
	config        KafkaReceiverConfig
	output        chan<- *KafkaMessage
	consumerGroup sarama.ConsumerGroup
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup

	// Metrics
	messagesReceived atomic.Uint64
	bytesReceived    atomic.Uint64
	errors           atomic.Uint64
	rebalances       atomic.Uint64
}

// NewKafkaReceiver creates a new Kafka receiver.
func NewKafkaReceiver(cfg KafkaReceiverConfig, output chan<- *KafkaMessage, logger *slog.Logger) (*KafkaReceiver, error) {
	ctx, cancel := context.WithCancel(context.Background())

	r := &KafkaReceiver{
		config: cfg,
		output: output,
		logger: logger.With("component", "kafka-receiver"),
		ctx:    ctx,
		cancel: cancel,
	}

	return r, nil
}

// Start begins consuming from Kafka.
func (r *KafkaReceiver) Start() error {
	config := sarama.NewConfig()
	config.Version = sarama.V3_5_0_0

	// Consumer group settings
	config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{
		sarama.NewBalanceStrategyRoundRobin(),
	}
	if r.config.RebalanceStrategy == "range" {
		config.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{
			sarama.NewBalanceStrategyRange(),
		}
	}

	config.Consumer.Group.Session.Timeout = r.config.SessionTimeout
	config.Consumer.Group.Heartbeat.Interval = r.config.HeartbeatInterval

	// Offset settings
	if r.config.OffsetReset == "earliest" {
		config.Consumer.Offsets.Initial = sarama.OffsetOldest
	} else {
		config.Consumer.Offsets.Initial = sarama.OffsetNewest
	}

	// Auto commit settings
	config.Consumer.Offsets.AutoCommit.Enable = r.config.AutoCommit
	config.Consumer.Offsets.AutoCommit.Interval = r.config.AutoCommitInterval

	// Fetch settings for high throughput
	config.Consumer.Fetch.Min = 1
	config.Consumer.Fetch.Max = 10 * 1024 * 1024 // 10MB
	config.Consumer.MaxWaitTime = 500 * time.Millisecond

	// Client ID
	if r.config.ClientID != "" {
		config.ClientID = r.config.ClientID
	}

	// TLS configuration
	if r.config.TLSEnabled {
		config.Net.TLS.Enable = true
		// TLS config setup would go here
	}

	// SASL configuration
	if r.config.SASLEnabled {
		config.Net.SASL.Enable = true
		config.Net.SASL.Mechanism = sarama.SASLMechanism(r.config.SASLMechanism)
		config.Net.SASL.User = r.config.SASLUsername
		config.Net.SASL.Password = r.config.SASLPassword
	}

	// Create consumer group
	consumerGroup, err := sarama.NewConsumerGroup(r.config.Brokers, r.config.GroupID, config)
	if err != nil {
		return err
	}
	r.consumerGroup = consumerGroup

	r.logger.Info("Kafka receiver started",
		"brokers", r.config.Brokers,
		"topics", r.config.Topics,
		"group_id", r.config.GroupID)

	// Start consumption loop
	r.wg.Add(1)
	go r.consumeLoop()

	return nil
}

// Stop stops the Kafka receiver.
func (r *KafkaReceiver) Stop() error {
	r.cancel()
	r.wg.Wait()

	if r.consumerGroup != nil {
		return r.consumerGroup.Close()
	}
	return nil
}

// Stats returns receiver statistics.
func (r *KafkaReceiver) Stats() map[string]uint64 {
	return map[string]uint64{
		"messages_received": r.messagesReceived.Load(),
		"bytes_received":    r.bytesReceived.Load(),
		"errors":            r.errors.Load(),
		"rebalances":        r.rebalances.Load(),
	}
}

func (r *KafkaReceiver) consumeLoop() {
	defer r.wg.Done()

	handler := &consumerGroupHandler{
		receiver: r,
	}

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		err := r.consumerGroup.Consume(r.ctx, r.config.Topics, handler)
		if err != nil {
			if r.ctx.Err() == nil {
				r.logger.Error("consumer group error", "error", err)
				r.errors.Add(1)
			}
		}

		// Check if context was cancelled
		if r.ctx.Err() != nil {
			return
		}
	}
}

// consumerGroupHandler implements sarama.ConsumerGroupHandler
type consumerGroupHandler struct {
	receiver *KafkaReceiver
}

func (h *consumerGroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	h.receiver.logger.Info("consumer group setup",
		"member_id", session.MemberID(),
		"generation_id", session.GenerationID())
	h.receiver.rebalances.Add(1)
	return nil
}

func (h *consumerGroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	h.receiver.logger.Info("consumer group cleanup",
		"member_id", session.MemberID())
	return nil
}

func (h *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-h.receiver.ctx.Done():
			return nil
		case <-session.Context().Done():
			return nil
		case msg, ok := <-claim.Messages():
			if !ok {
				return nil
			}

			kafkaMsg := &KafkaMessage{
				Topic:      msg.Topic,
				Partition:  msg.Partition,
				Offset:     msg.Offset,
				Key:        msg.Key,
				Value:      msg.Value,
				Headers:    extractKafkaHeaders(msg.Headers),
				Timestamp:  msg.Timestamp,
				ReceivedAt: time.Now(),
			}

			h.receiver.bytesReceived.Add(uint64(len(msg.Value)))

			select {
			case h.receiver.output <- kafkaMsg:
				h.receiver.messagesReceived.Add(1)
				if !h.receiver.config.AutoCommit {
					session.MarkMessage(msg, "")
				}
			case <-h.receiver.ctx.Done():
				return nil
			}
		}
	}
}

func extractKafkaHeaders(headers []*sarama.RecordHeader) map[string]string {
	result := make(map[string]string, len(headers))
	for _, h := range headers {
		result[string(h.Key)] = string(h.Value)
	}
	return result
}

// KafkaMessageToJSON converts a Kafka message to a JSON-serializable format.
func KafkaMessageToJSON(msg *KafkaMessage) ([]byte, error) {
	data := map[string]interface{}{
		"topic":       msg.Topic,
		"partition":   msg.Partition,
		"offset":      msg.Offset,
		"key":         string(msg.Key),
		"value":       string(msg.Value),
		"headers":     msg.Headers,
		"timestamp":   msg.Timestamp.Format(time.RFC3339Nano),
		"received_at": msg.ReceivedAt.Format(time.RFC3339Nano),
	}
	return json.Marshal(data)
}
