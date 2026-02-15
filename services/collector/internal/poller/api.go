// Package poller provides polling-based log collection from various sources.
package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// APIEvent represents an event retrieved from an API.
type APIEvent struct {
	SourceName  string
	SourceType  string
	TenantID    string
	Data        json.RawMessage
	Cursor      string
	Timestamp   time.Time
	ReceivedAt  time.Time
}

// APISourceConfig holds API polling source configuration.
type APISourceConfig struct {
	Name            string
	Enabled         bool
	URL             string
	Method          string
	Headers         map[string]string
	QueryParams     map[string]string
	AuthType        string // "none", "basic", "bearer", "oauth2", "api_key"
	AuthCredentials map[string]string
	PollInterval    time.Duration
	PageSize        int
	MaxPages        int
	RateLimitRPS    int
	TenantID        string
	SourceType      string
	CursorField     string // Field name for pagination cursor
	DataField       string // JSON path to data array
	TimestampField  string // Field for timestamp filtering
}

// APIPoller polls REST APIs for log data.
type APIPoller struct {
	config     APISourceConfig
	output     chan<- *APIEvent
	client     *http.Client
	logger     *slog.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// State
	cursor     string
	cursorMu   sync.RWMutex

	// Metrics
	requestsSent     atomic.Uint64
	eventsReceived   atomic.Uint64
	bytesReceived    atomic.Uint64
	errors           atomic.Uint64
}

// NewAPIPoller creates a new API poller.
func NewAPIPoller(cfg APISourceConfig, output chan<- *APIEvent, logger *slog.Logger) *APIPoller {
	ctx, cancel := context.WithCancel(context.Background())

	return &APIPoller{
		config: cfg,
		output: output,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger.With("component", "api-poller", "source", cfg.Name),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins polling the API.
func (p *APIPoller) Start() error {
	if !p.config.Enabled {
		p.logger.Info("API poller disabled")
		return nil
	}

	p.logger.Info("starting API poller",
		"url", p.config.URL,
		"interval", p.config.PollInterval)

	p.wg.Add(1)
	go p.pollLoop()

	return nil
}

// Stop stops the API poller.
func (p *APIPoller) Stop() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

// SetCursor sets the pagination cursor.
func (p *APIPoller) SetCursor(cursor string) {
	p.cursorMu.Lock()
	defer p.cursorMu.Unlock()
	p.cursor = cursor
}

// GetCursor gets the current pagination cursor.
func (p *APIPoller) GetCursor() string {
	p.cursorMu.RLock()
	defer p.cursorMu.RUnlock()
	return p.cursor
}

// Stats returns poller statistics.
func (p *APIPoller) Stats() map[string]uint64 {
	return map[string]uint64{
		"requests_sent":   p.requestsSent.Load(),
		"events_received": p.eventsReceived.Load(),
		"bytes_received":  p.bytesReceived.Load(),
		"errors":          p.errors.Load(),
	}
}

func (p *APIPoller) pollLoop() {
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

func (p *APIPoller) poll() {
	pageCount := 0
	hasMore := true

	for hasMore && pageCount < p.config.MaxPages {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		events, nextCursor, more, err := p.fetchPage()
		if err != nil {
			p.errors.Add(1)
			p.logger.Error("failed to fetch page", "error", err, "page", pageCount)
			return
		}

		for _, event := range events {
			select {
			case p.output <- event:
				p.eventsReceived.Add(1)
			case <-p.ctx.Done():
				return
			}
		}

		if nextCursor != "" {
			p.SetCursor(nextCursor)
		}

		hasMore = more
		pageCount++

		// Rate limiting between pages
		if hasMore && p.config.RateLimitRPS > 0 {
			time.Sleep(time.Second / time.Duration(p.config.RateLimitRPS))
		}
	}
}

func (p *APIPoller) fetchPage() ([]*APIEvent, string, bool, error) {
	// Build request URL with query parameters
	reqURL, err := url.Parse(p.config.URL)
	if err != nil {
		return nil, "", false, fmt.Errorf("invalid URL: %w", err)
	}

	query := reqURL.Query()
	for k, v := range p.config.QueryParams {
		query.Set(k, v)
	}

	// Add pagination parameters
	if p.config.PageSize > 0 {
		query.Set("limit", fmt.Sprintf("%d", p.config.PageSize))
		query.Set("page_size", fmt.Sprintf("%d", p.config.PageSize))
	}

	cursor := p.GetCursor()
	if cursor != "" {
		query.Set("cursor", cursor)
		query.Set("offset", cursor)
		query.Set("next_token", cursor)
	}

	reqURL.RawQuery = query.Encode()

	// Create request
	method := p.config.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(p.ctx, method, reqURL.String(), nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	// Add authentication
	if err := p.addAuth(req); err != nil {
		return nil, "", false, fmt.Errorf("failed to add auth: %w", err)
	}

	// Execute request
	p.requestsSent.Add(1)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to read response: %w", err)
	}
	p.bytesReceived.Add(uint64(len(body)))

	// Parse response
	return p.parseResponse(body)
}

func (p *APIPoller) addAuth(req *http.Request) error {
	switch p.config.AuthType {
	case "basic":
		username := p.config.AuthCredentials["username"]
		password := p.config.AuthCredentials["password"]
		req.SetBasicAuth(username, password)

	case "bearer":
		token := p.config.AuthCredentials["token"]
		req.Header.Set("Authorization", "Bearer "+token)

	case "api_key":
		header := p.config.AuthCredentials["header"]
		if header == "" {
			header = "X-API-Key"
		}
		key := p.config.AuthCredentials["key"]
		req.Header.Set(header, key)

	case "oauth2":
		// OAuth2 would require token refresh logic
		token := p.config.AuthCredentials["access_token"]
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return nil
}

func (p *APIPoller) parseResponse(body []byte) ([]*APIEvent, string, bool, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// Try as array
		var array []interface{}
		if err := json.Unmarshal(body, &array); err != nil {
			return nil, "", false, fmt.Errorf("failed to parse response: %w", err)
		}
		// Convert array to events
		events := make([]*APIEvent, 0, len(array))
		for _, item := range array {
			data, _ := json.Marshal(item)
			events = append(events, &APIEvent{
				SourceName: p.config.Name,
				SourceType: p.config.SourceType,
				TenantID:   p.config.TenantID,
				Data:       data,
				Timestamp:  time.Now(),
				ReceivedAt: time.Now(),
			})
		}
		return events, "", false, nil
	}

	// Extract data array
	dataField := p.config.DataField
	if dataField == "" {
		dataField = "data"
	}

	var items []interface{}
	if data, ok := result[dataField].([]interface{}); ok {
		items = data
	} else if data, ok := result["items"].([]interface{}); ok {
		items = data
	} else if data, ok := result["results"].([]interface{}); ok {
		items = data
	} else if data, ok := result["events"].([]interface{}); ok {
		items = data
	} else {
		// Treat whole response as single item
		items = []interface{}{result}
	}

	events := make([]*APIEvent, 0, len(items))
	for _, item := range items {
		data, _ := json.Marshal(item)
		events = append(events, &APIEvent{
			SourceName: p.config.Name,
			SourceType: p.config.SourceType,
			TenantID:   p.config.TenantID,
			Data:       data,
			Timestamp:  time.Now(),
			ReceivedAt: time.Now(),
		})
	}

	// Extract cursor for pagination
	cursorField := p.config.CursorField
	if cursorField == "" {
		cursorField = "next_cursor"
	}

	nextCursor := ""
	hasMore := false

	if cursor, ok := result[cursorField].(string); ok && cursor != "" {
		nextCursor = cursor
		hasMore = true
	} else if cursor, ok := result["next_token"].(string); ok && cursor != "" {
		nextCursor = cursor
		hasMore = true
	} else if cursor, ok := result["cursor"].(string); ok && cursor != "" {
		nextCursor = cursor
		hasMore = true
	}

	// Check for has_more flag
	if more, ok := result["has_more"].(bool); ok {
		hasMore = more
	} else if more, ok := result["hasMore"].(bool); ok {
		hasMore = more
	}

	return events, nextCursor, hasMore, nil
}

// APIPollerManager manages multiple API pollers.
type APIPollerManager struct {
	pollers map[string]*APIPoller
	output  chan<- *APIEvent
	logger  *slog.Logger
	mu      sync.RWMutex
}

// NewAPIPollerManager creates a new API poller manager.
func NewAPIPollerManager(output chan<- *APIEvent, logger *slog.Logger) *APIPollerManager {
	return &APIPollerManager{
		pollers: make(map[string]*APIPoller),
		output:  output,
		logger:  logger,
	}
}

// AddSource adds a new API source.
func (m *APIPollerManager) AddSource(cfg APISourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pollers[cfg.Name]; exists {
		return fmt.Errorf("source %s already exists", cfg.Name)
	}

	poller := NewAPIPoller(cfg, m.output, m.logger)
	m.pollers[cfg.Name] = poller

	return poller.Start()
}

// RemoveSource removes an API source.
func (m *APIPollerManager) RemoveSource(name string) error {
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
func (m *APIPollerManager) StopAll() error {
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
func (m *APIPollerManager) Stats() map[string]map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]map[string]uint64)
	for name, poller := range m.pollers {
		stats[name] = poller.Stats()
	}
	return stats
}
