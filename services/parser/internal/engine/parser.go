// Package engine provides the core parsing engine for log events.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ParsedEvent represents a parsed log event.
type ParsedEvent struct {
	EventID        string                 `json:"event_id"`
	TenantID       string                 `json:"tenant_id"`
	Timestamp      time.Time              `json:"timestamp"`
	ReceivedAt     time.Time              `json:"received_at"`
	SourceType     string                 `json:"source_type"`
	Format         string                 `json:"format"` // json, syslog, cef, leef, etc.
	Fields         map[string]interface{} `json:"fields"`
	RawLog         string                 `json:"raw_log"`
	ParseSuccess   bool                   `json:"parse_success"`
	ParseError     string                 `json:"parse_error,omitempty"`
	ParseDuration  time.Duration          `json:"parse_duration_ns"`
	PatternMatched string                 `json:"pattern_matched,omitempty"`
}

// RawEvent represents an incoming raw log event.
type RawEvent struct {
	EventID    string
	TenantID   string
	SourceType string
	Timestamp  time.Time
	Data       []byte
	Metadata   map[string]string
}

// Parser is the interface for log parsers.
type Parser interface {
	Name() string
	Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error)
	CanParse(data []byte) bool
}

// ParserConfig holds parser engine configuration.
type ParserConfig struct {
	Workers           int
	BatchSize         int
	MaxFieldSize      int
	MaxFields         int
	DefaultParser     string
	ParseTimeout      time.Duration
	EnableAutoDetect  bool
	EnableGrokCache   bool
	GrokCacheSize     int
}

// DefaultParserConfig returns default parser configuration.
func DefaultParserConfig() ParserConfig {
	return ParserConfig{
		Workers:          8,
		BatchSize:        1000,
		MaxFieldSize:     65536,
		MaxFields:        500,
		DefaultParser:    "auto",
		ParseTimeout:     5 * time.Second,
		EnableAutoDetect: true,
		EnableGrokCache:  true,
		GrokCacheSize:    1000,
	}
}

// Engine is the main parsing engine.
type Engine struct {
	config     ParserConfig
	parsers    []Parser
	grokParser *GrokParser
	regexParser *RegexParser
	logger     *slog.Logger
	detector   *FormatDetector

	// Metrics
	eventsProcessed atomic.Uint64
	parseSuccess    atomic.Uint64
	parseErrors     atomic.Uint64
	totalParseTime  atomic.Int64
}

// NewEngine creates a new parsing engine.
func NewEngine(cfg ParserConfig, logger *slog.Logger) *Engine {
	grokParser := NewGrokParser(cfg.GrokCacheSize)
	regexParser := NewRegexParser()

	e := &Engine{
		config:      cfg,
		parsers:     make([]Parser, 0),
		grokParser:  grokParser,
		regexParser: regexParser,
		logger:      logger.With("component", "parser-engine"),
		detector:    NewFormatDetector(),
	}

	// Register default parsers
	e.RegisterParser(NewJSONParser())
	e.RegisterParser(NewCEFParser())
	e.RegisterParser(NewLEEFParser())
	e.RegisterParser(NewSyslogParser())
	e.RegisterParser(NewKeyValueParser())
	e.RegisterParser(grokParser)
	e.RegisterParser(regexParser)

	return e
}

// GetGrokParser returns the Grok parser for hot reload.
func (e *Engine) GetGrokParser() *GrokParser {
	return e.grokParser
}

// GetRegexParser returns the Regex parser for hot reload.
func (e *Engine) GetRegexParser() *RegexParser {
	return e.regexParser
}

// RegisterParser registers a parser with the engine.
func (e *Engine) RegisterParser(p Parser) {
	e.parsers = append(e.parsers, p)
	e.logger.Info("registered parser", "name", p.Name())
}

// Parse parses a single raw event.
func (e *Engine) Parse(ctx context.Context, raw *RawEvent) *ParsedEvent {
	start := time.Now()

	parsed := &ParsedEvent{
		EventID:    raw.EventID,
		TenantID:   raw.TenantID,
		Timestamp:  raw.Timestamp,
		ReceivedAt: time.Now(),
		SourceType: raw.SourceType,
		RawLog:     string(raw.Data),
		Fields:     make(map[string]interface{}),
	}

	defer func() {
		parsed.ParseDuration = time.Since(start)
		e.eventsProcessed.Add(1)
		e.totalParseTime.Add(int64(parsed.ParseDuration))

		if parsed.ParseSuccess {
			e.parseSuccess.Add(1)
		} else {
			e.parseErrors.Add(1)
		}
	}()

	// Create context with timeout
	parseCtx, cancel := context.WithTimeout(ctx, e.config.ParseTimeout)
	defer cancel()

	// Auto-detect format if enabled
	var selectedParser Parser
	if e.config.EnableAutoDetect {
		format := e.detector.Detect(raw.Data)
		parsed.Format = format

		// Find parser for detected format
		for _, p := range e.parsers {
			if p.CanParse(raw.Data) {
				selectedParser = p
				break
			}
		}
	}

	// Try selected parser first
	if selectedParser != nil {
		result, err := selectedParser.Parse(parseCtx, raw)
		if err == nil {
			*parsed = *result
			parsed.ParseSuccess = true
			parsed.PatternMatched = selectedParser.Name()
			return parsed
		}
	}

	// Fallback: try all parsers in order
	for _, p := range e.parsers {
		if p.CanParse(raw.Data) {
			result, err := p.Parse(parseCtx, raw)
			if err == nil {
				*parsed = *result
				parsed.ParseSuccess = true
				parsed.PatternMatched = p.Name()
				return parsed
			}
		}
	}

	// No parser succeeded - return raw with error
	parsed.ParseSuccess = false
	parsed.ParseError = "no parser matched"
	parsed.Format = "unknown"

	return parsed
}

// ParseBatch parses a batch of raw events.
func (e *Engine) ParseBatch(ctx context.Context, events []*RawEvent) []*ParsedEvent {
	results := make([]*ParsedEvent, len(events))
	var wg sync.WaitGroup

	// Use worker pool for parallel parsing
	workerCount := e.config.Workers
	if len(events) < workerCount {
		workerCount = len(events)
	}

	workChan := make(chan int, len(events))

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
					results[idx] = e.Parse(ctx, events[idx])
				}
			}
		}()
	}

	// Send work
	for i := range events {
		workChan <- i
	}
	close(workChan)

	wg.Wait()
	return results
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	processed := e.eventsProcessed.Load()
	totalTime := e.totalParseTime.Load()

	avgParseTime := int64(0)
	if processed > 0 {
		avgParseTime = totalTime / int64(processed)
	}

	return map[string]interface{}{
		"events_processed":    processed,
		"parse_success":       e.parseSuccess.Load(),
		"parse_errors":        e.parseErrors.Load(),
		"avg_parse_time_ns":   avgParseTime,
		"registered_parsers":  len(e.parsers),
	}
}

// FormatDetector detects log format.
type FormatDetector struct {
	signatures map[string][]byte
}

// NewFormatDetector creates a new format detector.
func NewFormatDetector() *FormatDetector {
	return &FormatDetector{
		signatures: map[string][]byte{
			"cef":   []byte("CEF:"),
			"leef":  []byte("LEEF:"),
			"json":  []byte("{"),
			"xml":   []byte("<?xml"),
		},
	}
}

// Detect detects the format of log data.
func (d *FormatDetector) Detect(data []byte) string {
	if len(data) == 0 {
		return "unknown"
	}

	// Check for JSON
	if data[0] == '{' || data[0] == '[' {
		var js interface{}
		if json.Unmarshal(data, &js) == nil {
			return "json"
		}
	}

	// Check for known signatures
	for format, sig := range d.signatures {
		if len(data) >= len(sig) {
			match := true
			for i, b := range sig {
				if data[i] != b {
					match = false
					break
				}
			}
			if match {
				return format
			}
		}
	}

	// Check for syslog patterns
	if isSyslog(data) {
		return "syslog"
	}

	// Check for key-value format
	if isKeyValue(data) {
		return "kv"
	}

	return "raw"
}

func isSyslog(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// Check for PRI field: <123>
	if data[0] == '<' {
		for i := 1; i < len(data) && i < 5; i++ {
			if data[i] == '>' {
				return true
			}
			if data[i] < '0' || data[i] > '9' {
				break
			}
		}
	}
	return false
}

func isKeyValue(data []byte) bool {
	// Simple heuristic: contains '=' and no JSON braces at start
	if len(data) == 0 || data[0] == '{' || data[0] == '[' {
		return false
	}
	hasEquals := false
	for _, b := range data {
		if b == '=' {
			hasEquals = true
			break
		}
	}
	return hasEquals
}

// ProcessingPipeline handles the full parsing pipeline.
type ProcessingPipeline struct {
	engine     *Engine
	input      <-chan *RawEvent
	output     chan<- *ParsedEvent
	dlq        chan<- *ParsedEvent
	workers    int
	batchSize  int
	flushInterval time.Duration
	logger     *slog.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewProcessingPipeline creates a new processing pipeline.
func NewProcessingPipeline(engine *Engine, input <-chan *RawEvent, output chan<- *ParsedEvent, dlq chan<- *ParsedEvent, cfg ParserConfig, logger *slog.Logger) *ProcessingPipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessingPipeline{
		engine:        engine,
		input:         input,
		output:        output,
		dlq:           dlq,
		workers:       cfg.Workers,
		batchSize:     cfg.BatchSize,
		flushInterval: 100 * time.Millisecond,
		logger:        logger.With("component", "parser-pipeline"),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the processing pipeline.
func (p *ProcessingPipeline) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
	p.logger.Info("parser pipeline started", "workers", p.workers)
}

// Stop stops the processing pipeline.
func (p *ProcessingPipeline) Stop() {
	p.cancel()
	p.wg.Wait()
	p.logger.Info("parser pipeline stopped")
}

func (p *ProcessingPipeline) worker(id int) {
	defer p.wg.Done()

	batch := make([]*RawEvent, 0, p.batchSize)
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			// Flush remaining
			if len(batch) > 0 {
				p.processBatch(batch)
			}
			return

		case event, ok := <-p.input:
			if !ok {
				if len(batch) > 0 {
					p.processBatch(batch)
				}
				return
			}
			batch = append(batch, event)
			if len(batch) >= p.batchSize {
				p.processBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				p.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (p *ProcessingPipeline) processBatch(batch []*RawEvent) {
	results := p.engine.ParseBatch(p.ctx, batch)

	for _, result := range results {
		if result == nil {
			continue
		}

		target := p.output
		if !result.ParseSuccess {
			target = p.dlq
		}

		select {
		case target <- result:
		case <-p.ctx.Done():
			return
		default:
			p.logger.Warn("output channel full, dropping event",
				"event_id", result.EventID,
				"success", result.ParseSuccess)
		}
	}
}

// CreateEventID generates a unique event ID.
func CreateEventID() string {
	// Simple implementation - in production use UUID or ULID
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
