package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"github.com/siem-soar-platform/services/collector/internal/poller"
	"github.com/siem-soar-platform/services/collector/internal/receiver"
)

const serviceName = "collector"

// appConfig holds resolved runtime configuration.
type appConfig struct {
	managementPort   string
	httpReceiverPort string
	kafkaBrokers     []string
	kafkaTopic       string

	// Syslog receiver
	syslogUDPPort string
	syslogTCPPort string
	syslogTLSPort string
	syslogTLSCert string
	syslogTLSKey  string

	// Kafka consumer (inbound from external topics)
	kafkaConsumerTopics []string
	kafkaConsumerGroup  string
}

func loadAppConfig() appConfig {
	managementPort := os.Getenv("PORT")
	if managementPort == "" {
		managementPort = "8086"
	}

	httpReceiverPort := os.Getenv("HTTP_RECEIVER_PORT")
	if httpReceiverPort == "" {
		httpReceiverPort = "8087"
	}

	brokersEnv := os.Getenv("KAFKA_BROKERS")
	var brokers []string
	if brokersEnv != "" {
		for _, b := range strings.Split(brokersEnv, ",") {
			if trimmed := strings.TrimSpace(b); trimmed != "" {
				brokers = append(brokers, trimmed)
			}
		}
	}
	if len(brokers) == 0 {
		brokers = []string{"localhost:9092"}
	}

	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "logs.raw"
	}

	// Syslog ports
	syslogUDPPort := os.Getenv("SYSLOG_UDP_PORT")
	if syslogUDPPort == "" {
		syslogUDPPort = "514"
	}
	syslogTCPPort := os.Getenv("SYSLOG_TCP_PORT")
	if syslogTCPPort == "" {
		syslogTCPPort = "1514"
	}
	syslogTLSPort := os.Getenv("SYSLOG_TLS_PORT") // optional; empty means disabled
	syslogTLSCert := os.Getenv("SYSLOG_TLS_CERT")
	syslogTLSKey := os.Getenv("SYSLOG_TLS_KEY")

	// Kafka consumer
	var consumerTopics []string
	consumerTopicsEnv := os.Getenv("KAFKA_CONSUMER_TOPICS")
	if consumerTopicsEnv != "" {
		for _, t := range strings.Split(consumerTopicsEnv, ",") {
			if trimmed := strings.TrimSpace(t); trimmed != "" {
				consumerTopics = append(consumerTopics, trimmed)
			}
		}
	}
	consumerGroup := os.Getenv("KAFKA_CONSUMER_GROUP")
	if consumerGroup == "" {
		consumerGroup = "collector-consumer"
	}

	return appConfig{
		managementPort:      managementPort,
		httpReceiverPort:    httpReceiverPort,
		kafkaBrokers:        brokers,
		kafkaTopic:          topic,
		syslogUDPPort:       syslogUDPPort,
		syslogTCPPort:       syslogTCPPort,
		syslogTLSPort:       syslogTLSPort,
		syslogTLSCert:       syslogTLSCert,
		syslogTLSKey:        syslogTLSKey,
		kafkaConsumerTopics: consumerTopics,
		kafkaConsumerGroup:  consumerGroup,
	}
}

// kafkaStats tracks producer metrics.
type kafkaStats struct {
	messagesProduced atomic.Uint64
	bytesProduced    atomic.Uint64
	produceErrors    atomic.Uint64
}

func newSaramaProducer(brokers []string) (sarama.SyncProducer, error) {
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Retry.Max = 3
	cfg.Producer.Retry.Backoff = 100 * time.Millisecond
	cfg.Producer.Return.Successes = true
	cfg.Producer.Return.Errors = true
	cfg.Producer.Compression = sarama.CompressionLZ4
	cfg.Producer.MaxMessageBytes = 10 * 1024 * 1024 // 10MB
	cfg.Producer.Flush.Bytes = 1024 * 1024          // 1MB
	cfg.Producer.Flush.Messages = 500
	cfg.Producer.Flush.Frequency = 5 * time.Millisecond

	return sarama.NewSyncProducer(brokers, cfg)
}

// processMessages reads HTTPMessages from the channel and writes them to Kafka.
func processMessages(
	ctx context.Context,
	msgChan <-chan *receiver.HTTPMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) {
	logger.Info("HTTP message processor started", "topic", topic)

	for {
		select {
		case <-ctx.Done():
			logger.Info("HTTP message processor stopping")
			return

		case msg, ok := <-msgChan:
			if !ok {
				logger.Info("HTTP message channel closed, processor exiting")
				return
			}

			if err := sendToKafka(msg, producer, topic, stats, logger); err != nil {
				logger.Error("failed to send HTTP message to kafka",
					"error", err,
					"tenant_id", msg.TenantID,
					"source_type", msg.SourceType,
				)
				stats.produceErrors.Add(1)
			}
		}
	}
}

// sendToKafka converts an HTTPMessage to Kafka messages and produces them.
func sendToKafka(
	msg *receiver.HTTPMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) error {
	// Build envelope metadata
	type envelope struct {
		TenantID    string          `json:"tenant_id"`
		SourceType  string          `json:"source_type"`
		ContentType string          `json:"content_type"`
		RemoteAddr  string          `json:"remote_addr"`
		ReceivedAt  string          `json:"received_at"`
		Payload     json.RawMessage `json:"payload"`
	}

	sendOne := func(payload json.RawMessage) error {
		env := envelope{
			TenantID:    msg.TenantID,
			SourceType:  msg.SourceType,
			ContentType: msg.ContentType,
			RemoteAddr:  msg.RemoteAddr,
			ReceivedAt:  msg.ReceivedAt.UTC().Format(time.RFC3339Nano),
			Payload:     payload,
		}

		data, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshal envelope: %w", err)
		}

		kafkaMsg := &sarama.ProducerMessage{
			Topic: topic,
			Key:   sarama.StringEncoder(msg.TenantID),
			Value: sarama.ByteEncoder(data),
			Headers: []sarama.RecordHeader{
				{Key: []byte("tenant_id"), Value: []byte(msg.TenantID)},
				{Key: []byte("source_type"), Value: []byte(msg.SourceType)},
				{Key: []byte("content_type"), Value: []byte(msg.ContentType)},
			},
		}

		_, _, err = producer.SendMessage(kafkaMsg)
		if err != nil {
			return err
		}

		stats.messagesProduced.Add(1)
		stats.bytesProduced.Add(uint64(len(data)))
		return nil
	}

	// Send structured log entries individually for downstream granularity.
	if len(msg.Logs) > 0 {
		var lastErr error
		for _, logEntry := range msg.Logs {
			if err := sendOne(logEntry); err != nil {
				logger.Warn("failed to produce log entry", "error", err)
				lastErr = err
			}
		}
		return lastErr
	}

	// Fallback: send raw body as-is.
	if len(msg.RawBody) > 0 {
		return sendOne(json.RawMessage(msg.RawBody))
	}

	return nil
}

// processSyslogMessages converts SyslogMessages to Kafka format and produces them.
func processSyslogMessages(
	ctx context.Context,
	syslogChan <-chan *receiver.SyslogMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) {
	logger.Info("syslog message processor started", "topic", topic)

	for {
		select {
		case <-ctx.Done():
			logger.Info("syslog message processor stopping")
			return

		case msg, ok := <-syslogChan:
			if !ok {
				logger.Info("syslog channel closed, processor exiting")
				return
			}

			if err := sendSyslogToKafka(msg, producer, topic, stats, logger); err != nil {
				logger.Error("failed to send syslog message to kafka",
					"error", err,
					"source_ip", msg.SourceIP,
					"hostname", msg.Hostname,
				)
				stats.produceErrors.Add(1)
			}
		}
	}
}

// sendSyslogToKafka converts a SyslogMessage to a Kafka message and produces it.
func sendSyslogToKafka(
	msg *receiver.SyslogMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) error {
	type syslogEnvelope struct {
		SourceType  string                       `json:"source_type"`
		ReceivedAt  string                       `json:"received_at"`
		Timestamp   string                       `json:"timestamp"`
		Hostname    string                       `json:"hostname"`
		AppName     string                       `json:"app_name"`
		ProcID      string                       `json:"proc_id"`
		MsgID       string                       `json:"msg_id"`
		Facility    int                          `json:"facility"`
		Severity    int                          `json:"severity"`
		Priority    int                          `json:"priority"`
		Version     int                          `json:"version"`
		Message     string                       `json:"message"`
		RawMessage  string                       `json:"raw_message"`
		SourceIP    string                       `json:"source_ip"`
		SourcePort  int                          `json:"source_port"`
		Protocol    string                       `json:"protocol"`
		RFC         string                       `json:"rfc"`
		StructData  map[string]map[string]string `json:"struct_data,omitempty"`
	}

	env := syslogEnvelope{
		SourceType: "syslog",
		ReceivedAt: msg.ReceivedAt.UTC().Format(time.RFC3339Nano),
		Timestamp:  msg.Timestamp.UTC().Format(time.RFC3339Nano),
		Hostname:   msg.Hostname,
		AppName:    msg.AppName,
		ProcID:     msg.ProcID,
		MsgID:      msg.MsgID,
		Facility:   msg.Facility,
		Severity:   msg.Severity,
		Priority:   msg.Priority,
		Version:    msg.Version,
		Message:    msg.Message,
		RawMessage: msg.RawMessage,
		SourceIP:   msg.SourceIP,
		SourcePort: msg.SourcePort,
		Protocol:   msg.Protocol,
		RFC:        msg.RFC,
		StructData: msg.StructData,
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal syslog envelope: %w", err)
	}

	// Use hostname as the partition key (falls back to source IP when empty)
	partitionKey := msg.Hostname
	if partitionKey == "" {
		partitionKey = msg.SourceIP
	}

	kafkaMsg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(partitionKey),
		Value: sarama.ByteEncoder(data),
		Headers: []sarama.RecordHeader{
			{Key: []byte("source_type"), Value: []byte("syslog")},
			{Key: []byte("protocol"), Value: []byte(msg.Protocol)},
			{Key: []byte("rfc"), Value: []byte(msg.RFC)},
		},
	}

	_, _, err = producer.SendMessage(kafkaMsg)
	if err != nil {
		return err
	}

	stats.messagesProduced.Add(1)
	stats.bytesProduced.Add(uint64(len(data)))

	logger.Debug("syslog message forwarded to kafka",
		"hostname", msg.Hostname,
		"app_name", msg.AppName,
		"source_ip", msg.SourceIP,
		"protocol", msg.Protocol,
	)

	return nil
}

// processKafkaConsumerMessages forwards consumed Kafka messages to the producer topic.
func processKafkaConsumerMessages(
	ctx context.Context,
	kafkaChan <-chan *receiver.KafkaMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) {
	logger.Info("kafka consumer message processor started", "output_topic", topic)

	for {
		select {
		case <-ctx.Done():
			logger.Info("kafka consumer message processor stopping")
			return

		case msg, ok := <-kafkaChan:
			if !ok {
				logger.Info("kafka consumer channel closed, processor exiting")
				return
			}

			if err := forwardKafkaMessage(msg, producer, topic, stats, logger); err != nil {
				logger.Error("failed to forward kafka consumer message",
					"error", err,
					"source_topic", msg.Topic,
					"partition", msg.Partition,
					"offset", msg.Offset,
				)
				stats.produceErrors.Add(1)
			}
		}
	}
}

// forwardKafkaMessage re-publishes a consumed Kafka message to the output topic.
func forwardKafkaMessage(
	msg *receiver.KafkaMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) error {
	type kafkaEnvelope struct {
		SourceType  string            `json:"source_type"`
		SourceTopic string            `json:"source_topic"`
		Partition   int32             `json:"partition"`
		Offset      int64             `json:"offset"`
		Key         string            `json:"key"`
		Value       string            `json:"value"`
		Headers     map[string]string `json:"headers,omitempty"`
		Timestamp   string            `json:"timestamp"`
		ReceivedAt  string            `json:"received_at"`
	}

	env := kafkaEnvelope{
		SourceType:  "kafka",
		SourceTopic: msg.Topic,
		Partition:   msg.Partition,
		Offset:      msg.Offset,
		Key:         string(msg.Key),
		Value:       string(msg.Value),
		Headers:     msg.Headers,
		Timestamp:   msg.Timestamp.UTC().Format(time.RFC3339Nano),
		ReceivedAt:  msg.ReceivedAt.UTC().Format(time.RFC3339Nano),
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal kafka envelope: %w", err)
	}

	// Preserve the original key if present; otherwise fall back to source topic.
	partitionKey := string(msg.Key)
	if partitionKey == "" {
		partitionKey = msg.Topic
	}

	headers := []sarama.RecordHeader{
		{Key: []byte("source_type"), Value: []byte("kafka")},
		{Key: []byte("source_topic"), Value: []byte(msg.Topic)},
	}
	// Carry over original headers
	for k, v := range msg.Headers {
		headers = append(headers, sarama.RecordHeader{
			Key:   []byte(k),
			Value: []byte(v),
		})
	}

	kafkaMsg := &sarama.ProducerMessage{
		Topic:   topic,
		Key:     sarama.StringEncoder(partitionKey),
		Value:   sarama.ByteEncoder(data),
		Headers: headers,
	}

	_, _, err = producer.SendMessage(kafkaMsg)
	if err != nil {
		return err
	}

	stats.messagesProduced.Add(1)
	stats.bytesProduced.Add(uint64(len(data)))

	logger.Debug("kafka consumer message forwarded",
		"source_topic", msg.Topic,
		"partition", msg.Partition,
		"offset", msg.Offset,
	)

	return nil
}

// processAPIEvents reads APIEvents from the channel and writes them to Kafka.
func processAPIEvents(
	ctx context.Context,
	apiEventChan <-chan *poller.APIEvent,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) {
	logger.Info("API poller event processor started", "topic", topic)

	type apiEnvelope struct {
		SourceName string          `json:"source_name"`
		SourceType string          `json:"source_type"`
		TenantID   string          `json:"tenant_id"`
		Timestamp  string          `json:"timestamp"`
		ReceivedAt string          `json:"received_at"`
		Payload    json.RawMessage `json:"payload"`
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("API poller event processor stopping")
			return

		case event, ok := <-apiEventChan:
			if !ok {
				logger.Info("API event channel closed, processor exiting")
				return
			}

			env := apiEnvelope{
				SourceName: event.SourceName,
				SourceType: event.SourceType,
				TenantID:   event.TenantID,
				Timestamp:  event.Timestamp.UTC().Format(time.RFC3339Nano),
				ReceivedAt: event.ReceivedAt.UTC().Format(time.RFC3339Nano),
				Payload:    event.Data,
			}

			data, err := json.Marshal(env)
			if err != nil {
				logger.Error("failed to marshal API event envelope",
					"error", err,
					"source_name", event.SourceName,
				)
				stats.produceErrors.Add(1)
				continue
			}

			partitionKey := event.TenantID
			if partitionKey == "" {
				partitionKey = event.SourceName
			}

			kafkaMsg := &sarama.ProducerMessage{
				Topic: topic,
				Key:   sarama.StringEncoder(partitionKey),
				Value: sarama.ByteEncoder(data),
				Headers: []sarama.RecordHeader{
					{Key: []byte("source_type"), Value: []byte(event.SourceType)},
					{Key: []byte("source_name"), Value: []byte(event.SourceName)},
					{Key: []byte("tenant_id"), Value: []byte(event.TenantID)},
				},
			}

			_, _, err = producer.SendMessage(kafkaMsg)
			if err != nil {
				logger.Error("failed to send API event to kafka",
					"error", err,
					"source_name", event.SourceName,
					"tenant_id", event.TenantID,
				)
				stats.produceErrors.Add(1)
				continue
			}

			stats.messagesProduced.Add(1)
			stats.bytesProduced.Add(uint64(len(data)))

			logger.Debug("API event forwarded to kafka",
				"source_name", event.SourceName,
				"source_type", event.SourceType,
				"tenant_id", event.TenantID,
			)
		}
	}
}

// processS3Events reads S3Events from the channel and writes them to Kafka.
func processS3Events(
	ctx context.Context,
	s3EventChan <-chan *poller.S3Event,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
) {
	logger.Info("S3 poller event processor started", "topic", topic)

	type s3Envelope struct {
		SourceName string          `json:"source_name"`
		SourceType string          `json:"source_type"`
		TenantID   string          `json:"tenant_id"`
		Bucket     string          `json:"bucket"`
		Key        string          `json:"key"`
		Timestamp  string          `json:"timestamp"`
		ReceivedAt string          `json:"received_at"`
		Payload    json.RawMessage `json:"payload"`
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("S3 poller event processor stopping")
			return

		case event, ok := <-s3EventChan:
			if !ok {
				logger.Info("S3 event channel closed, processor exiting")
				return
			}

			// Ensure payload is valid JSON; wrap plain text in a JSON string.
			payload := json.RawMessage(event.Data)
			if !json.Valid(payload) {
				quoted, qErr := json.Marshal(string(event.Data))
				if qErr != nil {
					logger.Warn("failed to quote S3 plain-text payload", "error", qErr)
					quoted = []byte(`""`)
				}
				payload = quoted
			}

			env := s3Envelope{
				SourceName: event.SourceName,
				SourceType: event.SourceType,
				TenantID:   event.TenantID,
				Bucket:     event.Bucket,
				Key:        event.Key,
				Timestamp:  event.Timestamp.UTC().Format(time.RFC3339Nano),
				ReceivedAt: event.ReceivedAt.UTC().Format(time.RFC3339Nano),
				Payload:    payload,
			}

			data, err := json.Marshal(env)
			if err != nil {
				logger.Error("failed to marshal S3 event envelope",
					"error", err,
					"source_name", event.SourceName,
					"bucket", event.Bucket,
					"key", event.Key,
				)
				stats.produceErrors.Add(1)
				continue
			}

			partitionKey := event.TenantID
			if partitionKey == "" {
				partitionKey = event.Bucket
			}

			kafkaMsg := &sarama.ProducerMessage{
				Topic: topic,
				Key:   sarama.StringEncoder(partitionKey),
				Value: sarama.ByteEncoder(data),
				Headers: []sarama.RecordHeader{
					{Key: []byte("source_type"), Value: []byte(event.SourceType)},
					{Key: []byte("source_name"), Value: []byte(event.SourceName)},
					{Key: []byte("tenant_id"), Value: []byte(event.TenantID)},
					{Key: []byte("s3_bucket"), Value: []byte(event.Bucket)},
					{Key: []byte("s3_key"), Value: []byte(event.Key)},
				},
			}

			_, _, err = producer.SendMessage(kafkaMsg)
			if err != nil {
				logger.Error("failed to send S3 event to kafka",
					"error", err,
					"source_name", event.SourceName,
					"bucket", event.Bucket,
					"key", event.Key,
				)
				stats.produceErrors.Add(1)
				continue
			}

			stats.messagesProduced.Add(1)
			stats.bytesProduced.Add(uint64(len(data)))

			logger.Debug("S3 event forwarded to kafka",
				"source_name", event.SourceName,
				"bucket", event.Bucket,
				"key", event.Key,
			)
		}
	}
}

// drainChannel processes remaining messages after shutdown signal with a deadline.
func drainChannel(
	msgChan <-chan *receiver.HTTPMessage,
	producer sarama.SyncProducer,
	topic string,
	stats *kafkaStats,
	logger *slog.Logger,
	timeout time.Duration,
) {
	deadline := time.After(timeout)
	drained := 0
	for {
		select {
		case <-deadline:
			logger.Info("drain deadline reached", "drained", drained)
			return
		case msg, ok := <-msgChan:
			if !ok {
				logger.Info("channel closed during drain", "drained", drained)
				return
			}
			if err := sendToKafka(msg, producer, topic, stats, logger); err != nil {
				logger.Warn("drain: failed to produce message", "error", err)
			}
			drained++
		default:
			logger.Info("channel empty, drain complete", "drained", drained)
			return
		}
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := loadAppConfig()

	logger.Info("starting collector service",
		"service", serviceName,
		"management_port", cfg.managementPort,
		"http_receiver_port", cfg.httpReceiverPort,
		"kafka_brokers", cfg.kafkaBrokers,
		"kafka_topic", cfg.kafkaTopic,
		"syslog_udp_port", cfg.syslogUDPPort,
		"syslog_tcp_port", cfg.syslogTCPPort,
		"syslog_tls_port", cfg.syslogTLSPort,
		"kafka_consumer_topics", cfg.kafkaConsumerTopics,
		"kafka_consumer_group", cfg.kafkaConsumerGroup,
	)

	// --- Kafka producer ---
	producer, err := newSaramaProducer(cfg.kafkaBrokers)
	if err != nil {
		logger.Error("failed to create kafka producer", "error", err)
		os.Exit(1)
	}
	defer producer.Close()

	stats := &kafkaStats{}

	// --- Processor context (cancelled during shutdown) ---
	processorCtx, cancelProcessor := context.WithCancel(context.Background())
	defer cancelProcessor()

	// --- HTTP Receiver (port 8087) ---
	msgChan := make(chan *receiver.HTTPMessage, 10000)

	receiverCfg := receiver.HTTPReceiverConfig{
		ListenAddr:     ":" + cfg.httpReceiverPort,
		TLSEnabled:     false,
		MaxBodySize:    10 * 1024 * 1024, // 10MB
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		APIKeyHeader:   "X-API-Key",
		RateLimitRPS:   10000,
		RateLimitBurst: 20000,
	}

	httpReceiver := receiver.NewHTTPReceiver(receiverCfg, msgChan, logger)
	if err := httpReceiver.Start(); err != nil {
		logger.Error("failed to start http receiver", "error", err)
		os.Exit(1)
	}
	logger.Info("HTTP receiver started", "addr", receiverCfg.ListenAddr)

	go processMessages(processorCtx, msgChan, producer, cfg.kafkaTopic, stats, logger)

	// --- Syslog Receiver ---
	syslogChan := make(chan *receiver.SyslogMessage, 10000)

	syslogCfg := receiver.SyslogConfig{
		UDPAddr:    ":" + cfg.syslogUDPPort,
		TCPAddr:    ":" + cfg.syslogTCPPort,
		MaxMsgSize: 64 * 1024, // 64KB
		ParseRFC:   true,
	}
	if cfg.syslogTLSPort != "" {
		syslogCfg.TLSAddr = ":" + cfg.syslogTLSPort
		syslogCfg.TLSCertPath = cfg.syslogTLSCert
		syslogCfg.TLSKeyPath = cfg.syslogTLSKey
	}

	syslogReceiver := receiver.NewSyslogReceiver(syslogCfg, syslogChan, logger)
	if err := syslogReceiver.Start(); err != nil {
		logger.Error("failed to start syslog receiver", "error", err)
		os.Exit(1)
	}
	logger.Info("Syslog receiver started",
		"udp_addr", syslogCfg.UDPAddr,
		"tcp_addr", syslogCfg.TCPAddr,
		"tls_addr", syslogCfg.TLSAddr,
	)

	go processSyslogMessages(processorCtx, syslogChan, producer, cfg.kafkaTopic, stats, logger)

	// --- Kafka Consumer Receiver (optional, only when topics are configured) ---
	var kafkaConsumerReceiver *receiver.KafkaReceiver
	var kafkaChan chan *receiver.KafkaMessage

	if len(cfg.kafkaConsumerTopics) > 0 {
		kafkaChan = make(chan *receiver.KafkaMessage, 10000)

		kafkaConsumerCfg := receiver.KafkaReceiverConfig{
			Brokers:            cfg.kafkaBrokers,
			Topics:             cfg.kafkaConsumerTopics,
			GroupID:            cfg.kafkaConsumerGroup,
			ClientID:           serviceName + "-consumer",
			AutoCommit:         true,
			AutoCommitInterval: 5 * time.Second,
			MaxPollRecords:     500,
			SessionTimeout:     30 * time.Second,
			HeartbeatInterval:  10 * time.Second,
			RebalanceStrategy:  "roundrobin",
			OffsetReset:        "latest",
		}

		kafkaConsumerReceiver, err = receiver.NewKafkaReceiver(kafkaConsumerCfg, kafkaChan, logger)
		if err != nil {
			logger.Error("failed to create kafka consumer receiver", "error", err)
			os.Exit(1)
		}

		if err := kafkaConsumerReceiver.Start(); err != nil {
			logger.Error("failed to start kafka consumer receiver", "error", err)
			os.Exit(1)
		}
		logger.Info("Kafka consumer receiver started",
			"topics", cfg.kafkaConsumerTopics,
			"group", cfg.kafkaConsumerGroup,
		)

		go processKafkaConsumerMessages(processorCtx, kafkaChan, producer, cfg.kafkaTopic, stats, logger)
	} else {
		logger.Info("Kafka consumer receiver disabled (KAFKA_CONSUMER_TOPICS not set)")
	}

	// --- API Poller Manager ---
	apiEventChan := make(chan *poller.APIEvent, 10000)
	apiPollerManager := poller.NewAPIPollerManager(apiEventChan, logger)
	logger.Info("API poller manager initialized")

	go processAPIEvents(processorCtx, apiEventChan, producer, cfg.kafkaTopic, stats, logger)

	// --- S3 Poller Manager ---
	s3EventChan := make(chan *poller.S3Event, 10000)
	s3PollerManager := poller.NewS3PollerManager(s3EventChan, logger)
	logger.Info("S3 poller manager initialized")

	go processS3Events(processorCtx, s3EventChan, producer, cfg.kafkaTopic, stats, logger)

	// --- Management API server (port 8086) ---
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","service":"%s"}`, serviceName)
	})

	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready","service":"%s"}`, serviceName)
	})

	mux.HandleFunc("GET /api/v1/sources", listSourcesHandler)
	mux.HandleFunc("POST /api/v1/sources", createSourceHandler)
	mux.HandleFunc("GET /api/v1/sources/{id}/status", sourceStatusHandler)

	// --- API Poller Management Endpoints ---
	mux.HandleFunc("POST /api/v1/pollers/api", func(w http.ResponseWriter, r *http.Request) {
		var cfg poller.APISourceConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if cfg.Name == "" {
			http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
			return
		}
		if err := apiPollerManager.AddSource(cfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"message":"API poller source added","name":%q}`, cfg.Name)
	})

	mux.HandleFunc("DELETE /api/v1/pollers/api/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := apiPollerManager.RemoveSource(name); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message":"API poller source removed","name":%q}`, name)
	})

	mux.HandleFunc("GET /api/v1/pollers/api", func(w http.ResponseWriter, r *http.Request) {
		pollerStats := apiPollerManager.Stats()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"pollers": pollerStats,
			"count":   len(pollerStats),
		}); err != nil {
			logger.Warn("failed to encode API pollers response", "error", err)
		}
	})

	// --- S3 Poller Management Endpoints ---
	mux.HandleFunc("POST /api/v1/pollers/s3", func(w http.ResponseWriter, r *http.Request) {
		var cfg poller.S3SourceConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if cfg.Name == "" {
			http.Error(w, `{"error":"name is required"}`, http.StatusBadRequest)
			return
		}
		if err := s3PollerManager.AddSource(cfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"message":"S3 poller source added","name":%q}`, cfg.Name)
	})

	mux.HandleFunc("DELETE /api/v1/pollers/s3/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := s3PollerManager.RemoveSource(name); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message":"S3 poller source removed","name":%q}`, name)
	})

	mux.HandleFunc("GET /api/v1/pollers/s3", func(w http.ResponseWriter, r *http.Request) {
		pollerStats := s3PollerManager.Stats()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"pollers": pollerStats,
			"count":   len(pollerStats),
		}); err != nil {
			logger.Warn("failed to encode S3 pollers response", "error", err)
		}
	})

	// --- Stats Endpoint ---
	mux.HandleFunc("GET /api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		recvStats := httpReceiver.Stats()
		syslogStats := syslogReceiver.Stats()

		type statsResponse struct {
			HTTP          map[string]uint64            `json:"http_receiver"`
			Syslog        map[string]uint64            `json:"syslog_receiver"`
			KafkaConsumer map[string]uint64            `json:"kafka_consumer,omitempty"`
			KafkaProducer map[string]uint64            `json:"kafka_producer"`
			HTTPChannel   map[string]int               `json:"http_channel"`
			SyslogChannel map[string]int               `json:"syslog_channel"`
			KafkaChannel  map[string]int               `json:"kafka_channel,omitempty"`
			APIPollers    map[string]map[string]uint64 `json:"api_pollers"`
			S3Pollers     map[string]map[string]uint64 `json:"s3_pollers"`
			APIChannel    map[string]int               `json:"api_channel"`
			S3Channel     map[string]int               `json:"s3_channel"`
		}

		resp := statsResponse{
			HTTP:   recvStats,
			Syslog: syslogStats,
			KafkaProducer: map[string]uint64{
				"messages_produced": stats.messagesProduced.Load(),
				"bytes_produced":    stats.bytesProduced.Load(),
				"produce_errors":    stats.produceErrors.Load(),
			},
			HTTPChannel: map[string]int{
				"buffer_size": cap(msgChan),
				"pending":     len(msgChan),
			},
			SyslogChannel: map[string]int{
				"buffer_size": cap(syslogChan),
				"pending":     len(syslogChan),
			},
			APIPollers: apiPollerManager.Stats(),
			S3Pollers:  s3PollerManager.Stats(),
			APIChannel: map[string]int{
				"buffer_size": cap(apiEventChan),
				"pending":     len(apiEventChan),
			},
			S3Channel: map[string]int{
				"buffer_size": cap(s3EventChan),
				"pending":     len(s3EventChan),
			},
		}

		if kafkaConsumerReceiver != nil {
			resp.KafkaConsumer = kafkaConsumerReceiver.Stats()
			resp.KafkaChannel = map[string]int{
				"buffer_size": cap(kafkaChan),
				"pending":     len(kafkaChan),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Warn("failed to encode stats response", "error", err)
		}
	})

	mgmtServer := &http.Server{
		Addr:         ":" + cfg.managementPort,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("management API started", "service", serviceName, "port", cfg.managementPort)
		if err := mgmtServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("management server error", "error", err)
			os.Exit(1)
		}
	}()

	// --- Wait for shutdown signal ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutdown signal received, starting graceful shutdown")

	// 1. Stop HTTP receiver so no new messages enter the HTTP channel.
	if err := httpReceiver.Stop(); err != nil {
		logger.Error("error stopping http receiver", "error", err)
	}
	logger.Info("HTTP receiver stopped")

	// 2. Stop Syslog receiver.
	if err := syslogReceiver.Stop(); err != nil {
		logger.Error("error stopping syslog receiver", "error", err)
	}
	logger.Info("syslog receiver stopped")

	// 3. Stop Kafka consumer receiver (if running).
	if kafkaConsumerReceiver != nil {
		if err := kafkaConsumerReceiver.Stop(); err != nil {
			logger.Error("error stopping kafka consumer receiver", "error", err)
		}
		logger.Info("kafka consumer receiver stopped")
	}

	// 4. Stop API poller manager.
	if err := apiPollerManager.StopAll(); err != nil {
		logger.Error("error stopping API poller manager", "error", err)
	}
	logger.Info("API poller manager stopped")

	// 5. Stop S3 poller manager.
	if err := s3PollerManager.StopAll(); err != nil {
		logger.Error("error stopping S3 poller manager", "error", err)
	}
	logger.Info("S3 poller manager stopped")

	// 6. Cancel all message processor goroutines.
	cancelProcessor()
	logger.Info("processor goroutines cancelled")

	// 7. Drain the HTTP message channel (up to 15 seconds).
	logger.Info("draining HTTP message channel", "pending", len(msgChan))
	drainChannel(msgChan, producer, cfg.kafkaTopic, stats, logger, 15*time.Second)

	// 8. Shut down the management API server.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mgmtServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("management server forced to shutdown", "error", err)
	}

	logger.Info("collector service exited",
		"messages_produced", stats.messagesProduced.Load(),
		"bytes_produced", stats.bytesProduced.Load(),
		"produce_errors", stats.produceErrors.Load(),
	)
}

func listSourcesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"sources":[]}`)
}

func createSourceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"message":"source created","id":""}`)
}

func sourceStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"id":"","status":"active","events_per_second":0}`)
}
