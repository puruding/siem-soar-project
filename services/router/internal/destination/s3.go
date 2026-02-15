// Package destination provides routing destination implementations.
package destination

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config holds S3 destination configuration.
type S3Config struct {
	Name           string
	Region         string
	Bucket         string
	Prefix         string
	Endpoint       string // Custom endpoint for S3-compatible storage
	AccessKey      string
	SecretKey      string
	BatchSize      int
	FlushInterval  time.Duration
	Compression    bool
	FileFormat     string // json, ndjson
	PartitionBy    string // day, hour, tenant
	MaxFileSize    int64
}

// S3Destination sends events to S3.
type S3Destination struct {
	config    S3Config
	client    *s3.Client
	logger    *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// Batching
	buffer    []*Event
	bufferMu  sync.Mutex
	flushChan chan struct{}

	// Health
	healthy   atomic.Bool
	lastError atomic.Value

	// Metrics
	eventsSent   atomic.Uint64
	filesSent    atomic.Uint64
	bytesSent    atomic.Uint64
	errors       atomic.Uint64
}

// NewS3Destination creates a new S3 destination.
func NewS3Destination(cfg S3Config, logger *slog.Logger) (*S3Destination, error) {
	ctx, cancel := context.WithCancel(context.Background())

	d := &S3Destination{
		config:    cfg,
		logger:    logger.With("component", "s3-dest", "name", cfg.Name),
		ctx:       ctx,
		cancel:    cancel,
		buffer:    make([]*Event, 0, cfg.BatchSize),
		flushChan: make(chan struct{}, 1),
	}

	// Set defaults
	if d.config.BatchSize == 0 {
		d.config.BatchSize = 10000
	}
	if d.config.FlushInterval == 0 {
		d.config.FlushInterval = time.Minute
	}
	if d.config.FileFormat == "" {
		d.config.FileFormat = "ndjson"
	}
	if d.config.PartitionBy == "" {
		d.config.PartitionBy = "hour"
	}
	if d.config.MaxFileSize == 0 {
		d.config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}

	// Create S3 client
	if err := d.createClient(); err != nil {
		cancel()
		return nil, err
	}

	// Start background flusher
	d.wg.Add(1)
	go d.flushLoop()

	return d, nil
}

func (d *S3Destination) createClient() error {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(d.config.Region),
	}

	// Use static credentials if provided
	if d.config.AccessKey != "" && d.config.SecretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				d.config.AccessKey,
				d.config.SecretKey,
				"",
			),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(d.ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Opts := []func(*s3.Options){}

	// Custom endpoint for S3-compatible storage
	if d.config.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(d.config.Endpoint)
			o.UsePathStyle = true
		})
	}

	d.client = s3.NewFromConfig(awsCfg, s3Opts...)
	d.healthy.Store(true)

	d.logger.Info("connected to S3",
		"region", d.config.Region,
		"bucket", d.config.Bucket,
		"prefix", d.config.Prefix)

	return nil
}

// Name returns the destination name.
func (d *S3Destination) Name() string {
	return d.config.Name
}

// Type returns the destination type.
func (d *S3Destination) Type() string {
	return "s3"
}

// Send sends events to S3.
func (d *S3Destination) Send(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	d.bufferMu.Lock()
	d.buffer = append(d.buffer, events...)
	shouldFlush := len(d.buffer) >= d.config.BatchSize
	d.bufferMu.Unlock()

	if shouldFlush {
		select {
		case d.flushChan <- struct{}{}:
		default:
		}
	}

	return nil
}

// IsHealthy returns true if the destination is healthy.
func (d *S3Destination) IsHealthy() bool {
	return d.healthy.Load()
}

// Close closes the destination.
func (d *S3Destination) Close() error {
	d.cancel()
	d.wg.Wait()

	// Final flush
	d.bufferMu.Lock()
	events := d.buffer
	d.buffer = nil
	d.bufferMu.Unlock()

	if len(events) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		d.flush(ctx, events)
	}

	return nil
}

// Stats returns destination statistics.
func (d *S3Destination) Stats() map[string]interface{} {
	return map[string]interface{}{
		"events_sent":  d.eventsSent.Load(),
		"files_sent":   d.filesSent.Load(),
		"bytes_sent":   d.bytesSent.Load(),
		"errors":       d.errors.Load(),
		"healthy":      d.healthy.Load(),
		"buffer_size":  len(d.buffer),
	}
}

func (d *S3Destination) flushLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(d.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.flushChan:
			d.doFlush()
		case <-ticker.C:
			d.doFlush()
		}
	}
}

func (d *S3Destination) doFlush() {
	d.bufferMu.Lock()
	if len(d.buffer) == 0 {
		d.bufferMu.Unlock()
		return
	}
	events := d.buffer
	d.buffer = make([]*Event, 0, d.config.BatchSize)
	d.bufferMu.Unlock()

	ctx, cancel := context.WithTimeout(d.ctx, 2*time.Minute)
	defer cancel()

	if err := d.flush(ctx, events); err != nil {
		d.errors.Add(1)
		d.lastError.Store(err)
		d.logger.Error("flush failed", "error", err, "event_count", len(events))
	}
}

func (d *S3Destination) flush(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	// Group events by partition
	partitions := d.partitionEvents(events)

	for partitionKey, partEvents := range partitions {
		// Serialize events
		data, err := d.serializeEvents(partEvents)
		if err != nil {
			return fmt.Errorf("failed to serialize events: %w", err)
		}

		// Compress if enabled
		if d.config.Compression {
			compressed, err := d.compress(data)
			if err != nil {
				return fmt.Errorf("failed to compress: %w", err)
			}
			data = compressed
		}

		// Generate key
		key := d.generateKey(partitionKey)

		// Upload to S3
		if err := d.upload(ctx, key, data); err != nil {
			return err
		}

		d.eventsSent.Add(uint64(len(partEvents)))
		d.filesSent.Add(1)
		d.bytesSent.Add(uint64(len(data)))
	}

	return nil
}

func (d *S3Destination) partitionEvents(events []*Event) map[string][]*Event {
	partitions := make(map[string][]*Event)

	for _, event := range events {
		var key string

		switch d.config.PartitionBy {
		case "day":
			key = event.Timestamp.Format("2006/01/02")
		case "hour":
			key = event.Timestamp.Format("2006/01/02/15")
		case "tenant":
			key = path.Join(event.TenantID, event.Timestamp.Format("2006/01/02/15"))
		default:
			key = event.Timestamp.Format("2006/01/02/15")
		}

		partitions[key] = append(partitions[key], event)
	}

	return partitions
}

func (d *S3Destination) serializeEvents(events []*Event) ([]byte, error) {
	var buf bytes.Buffer

	switch d.config.FileFormat {
	case "json":
		if err := json.NewEncoder(&buf).Encode(events); err != nil {
			return nil, err
		}
	case "ndjson":
		for _, event := range events {
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			buf.Write(data)
			buf.WriteByte('\n')
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", d.config.FileFormat)
	}

	return buf.Bytes(), nil
}

func (d *S3Destination) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (d *S3Destination) generateKey(partitionKey string) string {
	timestamp := time.Now().Format("20060102T150405")
	filename := fmt.Sprintf("events_%s.%s", timestamp, d.config.FileFormat)

	if d.config.Compression {
		filename += ".gz"
	}

	return path.Join(d.config.Prefix, partitionKey, filename)
}

func (d *S3Destination) upload(ctx context.Context, key string, data []byte) error {
	contentType := "application/json"
	if d.config.FileFormat == "ndjson" {
		contentType = "application/x-ndjson"
	}
	if d.config.Compression {
		contentType = "application/gzip"
	}

	_, err := d.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(d.config.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	})

	if err != nil {
		d.healthy.Store(false)
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	d.healthy.Store(true)
	d.logger.Debug("uploaded to S3", "key", key, "bytes", len(data))

	return nil
}
