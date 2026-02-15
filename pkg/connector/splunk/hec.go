// Package splunk provides Splunk HTTP Event Collector (HEC) implementation.
package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"siem-soar-project/pkg/connector"
)

// HECClient handles Splunk HTTP Event Collector operations.
type HECClient struct {
	config     *HECConfig
	baseURL    string
	httpClient *http.Client
	mu         sync.Mutex
	batch      []HECEvent
	lastFlush  time.Time
	ackEnabled bool
	channel    string
}

// HECEvent represents an event to send via HEC.
type HECEvent struct {
	Time       int64                  `json:"time,omitempty"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	SourceType string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      interface{}            `json:"event"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// HECResponse represents the HEC API response.
type HECResponse struct {
	Text    string `json:"text"`
	Code    int    `json:"code"`
	AckID   int64  `json:"ackId,omitempty"`
	Invalid int    `json:"invalid-event-number,omitempty"`
}

// HECAckResponse represents the HEC ack status response.
type HECAckResponse struct {
	Acks map[string]bool `json:"acks"`
}

// NewHECClient creates a new HEC client.
func NewHECClient(baseURL string, config *HECConfig, httpClient *http.Client) *HECClient {
	return &HECClient{
		config:     config,
		baseURL:    baseURL,
		httpClient: httpClient,
		batch:      make([]HECEvent, 0, config.BatchSize),
		ackEnabled: config.UseAck,
		channel:    config.Channel,
	}
}

// GetHECClient returns the HEC client from a Splunk client.
func (c *Client) GetHECClient() *HECClient {
	if !c.config.HEC.Enabled {
		return nil
	}
	return NewHECClient(c.config.GetHECURL(), &c.config.HEC, c.httpClient)
}

// SendEvent sends a single event via HEC.
func (h *HECClient) SendEvent(ctx context.Context, event HECEvent) (*HECResponse, error) {
	return h.sendEvents(ctx, []HECEvent{event})
}

// SendEvents sends multiple events via HEC.
func (h *HECClient) SendEvents(ctx context.Context, events []HECEvent) (*HECResponse, error) {
	return h.sendEvents(ctx, events)
}

// sendEvents is the internal implementation for sending events.
func (h *HECClient) sendEvents(ctx context.Context, events []HECEvent) (*HECResponse, error) {
	if len(events) == 0 {
		return &HECResponse{Text: "Success", Code: 0}, nil
	}

	// Build the request body (newline-delimited JSON)
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	for _, event := range events {
		// Apply defaults
		if event.Index == "" && h.config.Index != "" {
			event.Index = h.config.Index
		}
		if event.Source == "" && h.config.Source != "" {
			event.Source = h.config.Source
		}
		if event.SourceType == "" && h.config.SourceType != "" {
			event.SourceType = h.config.SourceType
		}
		if event.Host == "" && h.config.Host != "" {
			event.Host = h.config.Host
		}

		if err := encoder.Encode(event); err != nil {
			return nil, fmt.Errorf("failed to encode event: %w", err)
		}
	}

	// Determine endpoint
	endpoint := h.config.Endpoint
	if endpoint == "" {
		endpoint = "/services/collector/event"
	}

	url := h.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)
	req.Header.Set("Content-Type", "application/json")

	if h.channel != "" {
		req.Header.Set("X-Splunk-Request-Channel", h.channel)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var hecResp HECResponse
	if err := json.NewDecoder(resp.Body).Decode(&hecResp); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to parse HEC response: %w, body: %s", err, string(body))
	}

	if hecResp.Code != 0 {
		return &hecResp, fmt.Errorf("HEC error: %s (code: %d)", hecResp.Text, hecResp.Code)
	}

	return &hecResp, nil
}

// SendRaw sends raw event data via HEC.
func (h *HECClient) SendRaw(ctx context.Context, data []byte, params map[string]string) (*HECResponse, error) {
	endpoint := "/services/collector/raw"
	url := h.baseURL + endpoint

	// Add query parameters
	if len(params) > 0 {
		url += "?"
		for k, v := range params {
			url += fmt.Sprintf("%s=%s&", k, v)
		}
		url = url[:len(url)-1] // Remove trailing &
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)

	if h.channel != "" {
		req.Header.Set("X-Splunk-Request-Channel", h.channel)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var hecResp HECResponse
	if err := json.NewDecoder(resp.Body).Decode(&hecResp); err != nil {
		return nil, fmt.Errorf("failed to parse HEC response: %w", err)
	}

	if hecResp.Code != 0 {
		return &hecResp, fmt.Errorf("HEC error: %s (code: %d)", hecResp.Text, hecResp.Code)
	}

	return &hecResp, nil
}

// BatchEvent adds an event to the batch.
func (h *HECClient) BatchEvent(event HECEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.batch = append(h.batch, event)
}

// Flush sends all batched events.
func (h *HECClient) Flush(ctx context.Context) (*HECResponse, error) {
	h.mu.Lock()
	if len(h.batch) == 0 {
		h.mu.Unlock()
		return &HECResponse{Text: "Success", Code: 0}, nil
	}

	events := h.batch
	h.batch = make([]HECEvent, 0, h.config.BatchSize)
	h.lastFlush = time.Now()
	h.mu.Unlock()

	return h.sendEvents(ctx, events)
}

// AutoFlush starts automatic batch flushing.
func (h *HECClient) AutoFlush(ctx context.Context) {
	ticker := time.NewTicker(h.config.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush
			h.Flush(context.Background())
			return
		case <-ticker.C:
			h.mu.Lock()
			shouldFlush := len(h.batch) > 0 && time.Since(h.lastFlush) >= h.config.BatchTimeout
			h.mu.Unlock()

			if shouldFlush {
				h.Flush(ctx)
			}
		}
	}
}

// CheckAck checks the acknowledgment status of events.
func (h *HECClient) CheckAck(ctx context.Context, ackIDs []int64) (*HECAckResponse, error) {
	if !h.ackEnabled {
		return nil, fmt.Errorf("ack is not enabled")
	}

	url := h.baseURL + "/services/collector/ack"

	body := map[string][]int64{"acks": ackIDs}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)
	req.Header.Set("Content-Type", "application/json")

	if h.channel != "" {
		req.Header.Set("X-Splunk-Request-Channel", h.channel)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ackResp HECAckResponse
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		return nil, fmt.Errorf("failed to parse ack response: %w", err)
	}

	return &ackResp, nil
}

// Health checks HEC health.
func (h *HECClient) Health(ctx context.Context) error {
	url := h.baseURL + "/services/collector/health"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Splunk "+h.config.Token)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HEC health check failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// Ingest implements the EventIngester interface.
func (c *Client) Ingest(ctx context.Context, events []connector.Event) (*connector.IngestResult, error) {
	hec := c.GetHECClient()
	if hec == nil {
		return nil, fmt.Errorf("HEC is not enabled")
	}

	hecEvents := make([]HECEvent, len(events))
	for i, event := range events {
		hecEvents[i] = HECEvent{
			Time:       event.Timestamp.Unix(),
			Host:       event.Host,
			Source:     event.Source,
			SourceType: event.SourceType,
			Index:      event.Index,
			Event:      event.Fields,
			Fields:     map[string]interface{}{"tags": event.Tags},
		}
	}

	start := time.Now()
	resp, err := hec.SendEvents(ctx, hecEvents)

	result := &connector.IngestResult{
		TotalEvents:   len(events),
		ExecutionTime: time.Since(start),
	}

	if err != nil {
		result.FailedCount = len(events)
		result.Errors = []connector.IngestError{{
			Message: err.Error(),
			Code:    fmt.Sprintf("%d", resp.Code),
		}}
		return result, err
	}

	result.SuccessCount = len(events)
	return result, nil
}

// IngestBatch implements the EventIngester interface for batch ingestion.
func (c *Client) IngestBatch(ctx context.Context, batch *connector.EventBatch) (*connector.IngestResult, error) {
	result := &connector.IngestResult{
		BatchID:     batch.BatchID,
		TotalEvents: len(batch.Events),
	}

	return result, c.Ingest(ctx, batch.Events).Error
}
