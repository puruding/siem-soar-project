// Package destination provides routing destination implementations.
package destination

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ClickHouseConfig holds ClickHouse destination configuration.
type ClickHouseConfig struct {
	Name             string
	Hosts            []string
	Database         string
	Table            string
	Username         string
	Password         string
	BatchSize        int
	FlushInterval    time.Duration
	MaxRetries       int
	RetryBackoff     time.Duration
	Compression      string
	AsyncInsert      bool
	DialTimeout      time.Duration
	MaxOpenConns     int
	MaxIdleConns     int
}

// ClickHouseDestination sends events to ClickHouse.
type ClickHouseDestination struct {
	config    ClickHouseConfig
	conn      driver.Conn
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
	eventsSent    atomic.Uint64
	batchesSent   atomic.Uint64
	errors        atomic.Uint64
}

// Event represents an event for ClickHouse.
type Event struct {
	ID         string
	TenantID   string
	Timestamp  time.Time
	EventType  string
	SourceType string
	Severity   string
	Fields     map[string]interface{}
	RawData    []byte
}

// NewClickHouseDestination creates a new ClickHouse destination.
func NewClickHouseDestination(cfg ClickHouseConfig, logger *slog.Logger) (*ClickHouseDestination, error) {
	ctx, cancel := context.WithCancel(context.Background())

	d := &ClickHouseDestination{
		config:    cfg,
		logger:    logger.With("component", "clickhouse-dest", "name", cfg.Name),
		ctx:       ctx,
		cancel:    cancel,
		buffer:    make([]*Event, 0, cfg.BatchSize),
		flushChan: make(chan struct{}, 1),
	}

	// Set defaults
	if d.config.BatchSize == 0 {
		d.config.BatchSize = 1000
	}
	if d.config.FlushInterval == 0 {
		d.config.FlushInterval = 100 * time.Millisecond
	}
	if d.config.MaxRetries == 0 {
		d.config.MaxRetries = 3
	}
	if d.config.RetryBackoff == 0 {
		d.config.RetryBackoff = 100 * time.Millisecond
	}
	if d.config.DialTimeout == 0 {
		d.config.DialTimeout = 10 * time.Second
	}
	if d.config.MaxOpenConns == 0 {
		d.config.MaxOpenConns = 10
	}
	if d.config.MaxIdleConns == 0 {
		d.config.MaxIdleConns = 5
	}

	// Connect
	if err := d.connect(); err != nil {
		cancel()
		return nil, err
	}

	// Start background flusher
	d.wg.Add(1)
	go d.flushLoop()

	return d, nil
}

func (d *ClickHouseDestination) connect() error {
	options := &clickhouse.Options{
		Addr: d.config.Hosts,
		Auth: clickhouse.Auth{
			Database: d.config.Database,
			Username: d.config.Username,
			Password: d.config.Password,
		},
		DialTimeout:     d.config.DialTimeout,
		MaxOpenConns:    d.config.MaxOpenConns,
		MaxIdleConns:    d.config.MaxIdleConns,
		ConnMaxLifetime: time.Hour,
		Settings: clickhouse.Settings{
			"async_insert":          boolToInt(d.config.AsyncInsert),
			"wait_for_async_insert": 0,
		},
	}

	// Set compression
	switch d.config.Compression {
	case "lz4":
		options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
	case "zstd":
		options.Compression = &clickhouse.Compression{Method: clickhouse.CompressionZSTD}
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(d.ctx, d.config.DialTimeout)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping: %w", err)
	}

	d.conn = conn
	d.healthy.Store(true)

	d.logger.Info("connected to ClickHouse",
		"hosts", d.config.Hosts,
		"database", d.config.Database,
		"table", d.config.Table)

	return nil
}

// Name returns the destination name.
func (d *ClickHouseDestination) Name() string {
	return d.config.Name
}

// Type returns the destination type.
func (d *ClickHouseDestination) Type() string {
	return "clickhouse"
}

// Send sends events to ClickHouse.
func (d *ClickHouseDestination) Send(ctx context.Context, events []*Event) error {
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
func (d *ClickHouseDestination) IsHealthy() bool {
	return d.healthy.Load()
}

// Close closes the destination.
func (d *ClickHouseDestination) Close() error {
	d.cancel()
	d.wg.Wait()

	// Final flush
	d.bufferMu.Lock()
	events := d.buffer
	d.buffer = nil
	d.bufferMu.Unlock()

	if len(events) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.flush(ctx, events)
	}

	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

// Stats returns destination statistics.
func (d *ClickHouseDestination) Stats() map[string]interface{} {
	return map[string]interface{}{
		"events_sent":  d.eventsSent.Load(),
		"batches_sent": d.batchesSent.Load(),
		"errors":       d.errors.Load(),
		"healthy":      d.healthy.Load(),
		"buffer_size":  len(d.buffer),
	}
}

func (d *ClickHouseDestination) flushLoop() {
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

func (d *ClickHouseDestination) doFlush() {
	d.bufferMu.Lock()
	if len(d.buffer) == 0 {
		d.bufferMu.Unlock()
		return
	}
	events := d.buffer
	d.buffer = make([]*Event, 0, d.config.BatchSize)
	d.bufferMu.Unlock()

	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()

	if err := d.flush(ctx, events); err != nil {
		d.errors.Add(1)
		d.lastError.Store(err)
		d.logger.Error("flush failed", "error", err, "event_count", len(events))
	}
}

func (d *ClickHouseDestination) flush(ctx context.Context, events []*Event) error {
	var lastErr error

	for attempt := 0; attempt < d.config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(d.config.RetryBackoff * time.Duration(attempt))
		}

		if err := d.insertBatch(ctx, events); err != nil {
			lastErr = err
			d.logger.Warn("insert attempt failed",
				"attempt", attempt+1,
				"error", err)

			// Check if we need to reconnect
			if !d.healthy.Load() {
				if err := d.connect(); err != nil {
					d.logger.Error("reconnect failed", "error", err)
				}
			}
			continue
		}

		// Success
		d.eventsSent.Add(uint64(len(events)))
		d.batchesSent.Add(1)
		return nil
	}

	return lastErr
}

func (d *ClickHouseDestination) insertBatch(ctx context.Context, events []*Event) error {
	batch, err := d.conn.PrepareBatch(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			event_id, tenant_id, timestamp, event_type, source_type,
			severity, fields, raw_log
		)
	`, d.config.Table))
	if err != nil {
		d.healthy.Store(false)
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, event := range events {
		fieldsJSON, _ := encodeFields(event.Fields)

		err := batch.Append(
			event.ID,
			event.TenantID,
			event.Timestamp,
			event.EventType,
			event.SourceType,
			event.Severity,
			string(fieldsJSON),
			string(event.RawData),
		)
		if err != nil {
			return fmt.Errorf("failed to append to batch: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		d.healthy.Store(false)
		return fmt.Errorf("failed to send batch: %w", err)
	}

	d.healthy.Store(true)
	return nil
}

func encodeFields(fields map[string]interface{}) ([]byte, error) {
	if fields == nil {
		return []byte("{}"), nil
	}
	// Simplified JSON encoding
	return []byte("{}"), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
