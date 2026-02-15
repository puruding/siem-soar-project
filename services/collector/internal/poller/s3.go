// Package poller provides polling-based log collection from various sources.
package poller

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Event represents an event retrieved from S3.
type S3Event struct {
	SourceName  string
	SourceType  string
	TenantID    string
	Bucket      string
	Key         string
	Data        []byte
	Timestamp   time.Time
	ReceivedAt  time.Time
}

// S3SourceConfig holds S3 polling source configuration.
type S3SourceConfig struct {
	Name         string
	Enabled      bool
	Region       string
	Bucket       string
	Prefix       string
	Endpoint     string // Custom endpoint for S3-compatible storage
	AccessKey    string
	SecretKey    string
	PollInterval time.Duration
	BatchSize    int
	DeleteAfter  bool
	MoveAfter    string // Prefix to move processed files to
	TenantID     string
	SourceType   string
	FilePattern  string // Glob pattern for filtering files
}

// S3Poller polls S3 buckets for log files.
type S3Poller struct {
	config     S3SourceConfig
	output     chan<- *S3Event
	client     *s3.Client
	logger     *slog.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// State - tracks processed files
	processed   map[string]time.Time
	processedMu sync.RWMutex

	// Metrics
	filesProcessed  atomic.Uint64
	eventsReceived  atomic.Uint64
	bytesReceived   atomic.Uint64
	errors          atomic.Uint64
}

// NewS3Poller creates a new S3 poller.
func NewS3Poller(cfg S3SourceConfig, output chan<- *S3Event, logger *slog.Logger) (*S3Poller, error) {
	ctx, cancel := context.WithCancel(context.Background())

	poller := &S3Poller{
		config:    cfg,
		output:    output,
		logger:    logger.With("component", "s3-poller", "source", cfg.Name),
		ctx:       ctx,
		cancel:    cancel,
		processed: make(map[string]time.Time),
	}

	// Initialize S3 client
	if err := poller.initClient(); err != nil {
		cancel()
		return nil, err
	}

	return poller, nil
}

func (p *S3Poller) initClient() error {
	var awsCfg aws.Config
	var err error

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(p.config.Region),
	}

	// Use static credentials if provided
	if p.config.AccessKey != "" && p.config.SecretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				p.config.AccessKey,
				p.config.SecretKey,
				"",
			),
		))
	}

	awsCfg, err = config.LoadDefaultConfig(p.ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client options
	s3Opts := []func(*s3.Options){}

	// Custom endpoint for S3-compatible storage (MinIO, etc.)
	if p.config.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(p.config.Endpoint)
			o.UsePathStyle = true
		})
	}

	p.client = s3.NewFromConfig(awsCfg, s3Opts...)
	return nil
}

// Start begins polling S3.
func (p *S3Poller) Start() error {
	if !p.config.Enabled {
		p.logger.Info("S3 poller disabled")
		return nil
	}

	p.logger.Info("starting S3 poller",
		"bucket", p.config.Bucket,
		"prefix", p.config.Prefix,
		"interval", p.config.PollInterval)

	p.wg.Add(1)
	go p.pollLoop()

	return nil
}

// Stop stops the S3 poller.
func (p *S3Poller) Stop() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

// Stats returns poller statistics.
func (p *S3Poller) Stats() map[string]uint64 {
	return map[string]uint64{
		"files_processed": p.filesProcessed.Load(),
		"events_received": p.eventsReceived.Load(),
		"bytes_received":  p.bytesReceived.Load(),
		"errors":          p.errors.Load(),
	}
}

func (p *S3Poller) pollLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	// Initial poll
	p.poll()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

func (p *S3Poller) poll() {
	// List objects in bucket
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(p.config.Bucket),
		Prefix:  aws.String(p.config.Prefix),
		MaxKeys: aws.Int32(int32(p.config.BatchSize)),
	}

	paginator := s3.NewListObjectsV2Paginator(p.client, input)

	for paginator.HasMorePages() {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		page, err := paginator.NextPage(p.ctx)
		if err != nil {
			p.errors.Add(1)
			p.logger.Error("failed to list objects", "error", err)
			return
		}

		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}

			key := *obj.Key

			// Skip if already processed
			if p.isProcessed(key) {
				continue
			}

			// Check file pattern if specified
			if p.config.FilePattern != "" {
				matched, _ := filepath.Match(p.config.FilePattern, filepath.Base(key))
				if !matched {
					continue
				}
			}

			// Process the file
			if err := p.processFile(key); err != nil {
				p.errors.Add(1)
				p.logger.Error("failed to process file", "key", key, "error", err)
				continue
			}

			p.markProcessed(key)
			p.filesProcessed.Add(1)
		}
	}

	// Clean up old processed entries
	p.cleanupProcessed()
}

func (p *S3Poller) processFile(key string) error {
	// Get object
	getOutput, err := p.client.GetObject(p.ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to get object: %w", err)
	}
	defer getOutput.Body.Close()

	// Read content
	var reader io.Reader = getOutput.Body

	// Handle gzip compression
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(getOutput.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Read all content
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}
	p.bytesReceived.Add(uint64(len(content)))

	// Parse content based on file type
	events, err := p.parseContent(key, content)
	if err != nil {
		return fmt.Errorf("failed to parse content: %w", err)
	}

	// Send events
	for _, event := range events {
		select {
		case p.output <- event:
			p.eventsReceived.Add(1)
		case <-p.ctx.Done():
			return p.ctx.Err()
		}
	}

	// Post-processing
	if p.config.DeleteAfter {
		if err := p.deleteFile(key); err != nil {
			p.logger.Warn("failed to delete file", "key", key, "error", err)
		}
	} else if p.config.MoveAfter != "" {
		if err := p.moveFile(key); err != nil {
			p.logger.Warn("failed to move file", "key", key, "error", err)
		}
	}

	return nil
}

func (p *S3Poller) parseContent(key string, content []byte) ([]*S3Event, error) {
	var events []*S3Event

	// Determine file type and parse accordingly
	ext := strings.ToLower(filepath.Ext(strings.TrimSuffix(key, ".gz")))

	switch ext {
	case ".json":
		// Try JSON array first
		var array []json.RawMessage
		if err := json.Unmarshal(content, &array); err == nil {
			for _, item := range array {
				events = append(events, &S3Event{
					SourceName: p.config.Name,
					SourceType: p.config.SourceType,
					TenantID:   p.config.TenantID,
					Bucket:     p.config.Bucket,
					Key:        key,
					Data:       item,
					Timestamp:  time.Now(),
					ReceivedAt: time.Now(),
				})
			}
		} else {
			// Single JSON object
			events = append(events, &S3Event{
				SourceName: p.config.Name,
				SourceType: p.config.SourceType,
				TenantID:   p.config.TenantID,
				Bucket:     p.config.Bucket,
				Key:        key,
				Data:       content,
				Timestamp:  time.Now(),
				ReceivedAt: time.Now(),
			})
		}

	case ".ndjson", ".jsonl":
		// Newline-delimited JSON
		scanner := bufio.NewScanner(bytes.NewReader(content))
		scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			// Make a copy of the line
			data := make([]byte, len(line))
			copy(data, line)

			events = append(events, &S3Event{
				SourceName: p.config.Name,
				SourceType: p.config.SourceType,
				TenantID:   p.config.TenantID,
				Bucket:     p.config.Bucket,
				Key:        key,
				Data:       data,
				Timestamp:  time.Now(),
				ReceivedAt: time.Now(),
			})
		}

	default:
		// Plain text - each line is an event
		scanner := bufio.NewScanner(bytes.NewReader(content))
		scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line

		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			events = append(events, &S3Event{
				SourceName: p.config.Name,
				SourceType: p.config.SourceType,
				TenantID:   p.config.TenantID,
				Bucket:     p.config.Bucket,
				Key:        key,
				Data:       []byte(line),
				Timestamp:  time.Now(),
				ReceivedAt: time.Now(),
			})
		}
	}

	return events, nil
}

func (p *S3Poller) deleteFile(key string) error {
	_, err := p.client.DeleteObject(p.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.config.Bucket),
		Key:    aws.String(key),
	})
	return err
}

func (p *S3Poller) moveFile(key string) error {
	newKey := p.config.MoveAfter + "/" + filepath.Base(key)

	// Copy to new location
	_, err := p.client.CopyObject(p.ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(p.config.Bucket),
		Key:        aws.String(newKey),
		CopySource: aws.String(p.config.Bucket + "/" + key),
	})
	if err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}

	// Delete original
	return p.deleteFile(key)
}

func (p *S3Poller) isProcessed(key string) bool {
	p.processedMu.RLock()
	defer p.processedMu.RUnlock()
	_, ok := p.processed[key]
	return ok
}

func (p *S3Poller) markProcessed(key string) {
	p.processedMu.Lock()
	defer p.processedMu.Unlock()
	p.processed[key] = time.Now()
}

func (p *S3Poller) cleanupProcessed() {
	p.processedMu.Lock()
	defer p.processedMu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for key, ts := range p.processed {
		if ts.Before(cutoff) {
			delete(p.processed, key)
		}
	}
}

// S3PollerManager manages multiple S3 pollers.
type S3PollerManager struct {
	pollers map[string]*S3Poller
	output  chan<- *S3Event
	logger  *slog.Logger
	mu      sync.RWMutex
}

// NewS3PollerManager creates a new S3 poller manager.
func NewS3PollerManager(output chan<- *S3Event, logger *slog.Logger) *S3PollerManager {
	return &S3PollerManager{
		pollers: make(map[string]*S3Poller),
		output:  output,
		logger:  logger,
	}
}

// AddSource adds a new S3 source.
func (m *S3PollerManager) AddSource(cfg S3SourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pollers[cfg.Name]; exists {
		return fmt.Errorf("source %s already exists", cfg.Name)
	}

	poller, err := NewS3Poller(cfg, m.output, m.logger)
	if err != nil {
		return err
	}

	m.pollers[cfg.Name] = poller
	return poller.Start()
}

// RemoveSource removes an S3 source.
func (m *S3PollerManager) RemoveSource(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	poller, exists := m.pollers[name]
	if !exists {
		return fmt.Errorf("source %s not found", name)
	}

	if err := poller.Stop(); err != nil {
		return err
	}

	delete(m.pollers, name)
	return nil
}

// StopAll stops all pollers.
func (m *S3PollerManager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for name, poller := range m.pollers {
		if err := poller.Stop(); err != nil {
			lastErr = err
			m.logger.Error("failed to stop poller", "name", name, "error", err)
		}
	}
	return lastErr
}

// Stats returns statistics for all pollers.
func (m *S3PollerManager) Stats() map[string]map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]map[string]uint64)
	for name, poller := range m.pollers {
		stats[name] = poller.Stats()
	}
	return stats
}
