// Package sentinel provides Azure Event Hub integration for data ingestion.
package sentinel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"siem-soar-project/pkg/connector"
)

// EventHubClient handles Azure Event Hub operations.
type EventHubClient struct {
	config         *EventHubConfig
	httpClient     *http.Client
	parsedConnStr  *EventHubConnectionString
	mu             sync.Mutex
	batch          [][]byte
	lastFlush      time.Time
}

// EventHubConnectionString holds parsed connection string components.
type EventHubConnectionString struct {
	Endpoint          string
	SharedAccessKey   string
	SharedAccessKeyName string
	EntityPath        string
}

// EventHubMessage represents a message to send to Event Hub.
type EventHubMessage struct {
	Body       interface{}            `json:"Body"`
	Properties map[string]interface{} `json:"Properties,omitempty"`
}

// NewEventHubClient creates a new Event Hub client.
func NewEventHubClient(config *EventHubConfig, httpClient *http.Client) (*EventHubClient, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("event hub is not enabled")
	}

	parsed, err := parseConnectionString(config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	return &EventHubClient{
		config:        config,
		httpClient:    httpClient,
		parsedConnStr: parsed,
		batch:         make([][]byte, 0),
		lastFlush:     time.Now(),
	}, nil
}

// parseConnectionString parses an Event Hub connection string.
func parseConnectionString(connStr string) (*EventHubConnectionString, error) {
	parsed := &EventHubConnectionString{}

	parts := strings.Split(connStr, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "Endpoint":
			parsed.Endpoint = value
		case "SharedAccessKeyName":
			parsed.SharedAccessKeyName = value
		case "SharedAccessKey":
			parsed.SharedAccessKey = value
		case "EntityPath":
			parsed.EntityPath = value
		}
	}

	if parsed.Endpoint == "" || parsed.SharedAccessKeyName == "" || parsed.SharedAccessKey == "" {
		return nil, fmt.Errorf("invalid connection string: missing required components")
	}

	return parsed, nil
}

// GetEventHubClient returns an Event Hub client from the Sentinel client.
func (c *Client) GetEventHubClient() (*EventHubClient, error) {
	if !c.config.EventHub.Enabled {
		return nil, fmt.Errorf("event hub is not enabled")
	}
	return NewEventHubClient(&c.config.EventHub, c.httpClient)
}

// SendEvent sends a single event to Event Hub.
func (e *EventHubClient) SendEvent(ctx context.Context, event interface{}) error {
	return e.SendEvents(ctx, []interface{}{event})
}

// SendEvents sends multiple events to Event Hub.
func (e *EventHubClient) SendEvents(ctx context.Context, events []interface{}) error {
	if len(events) == 0 {
		return nil
	}

	// Build the request body
	messages := make([]EventHubMessage, len(events))
	for i, event := range events {
		messages[i] = EventHubMessage{Body: event}
	}

	data, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	// Build URL
	eventHubURL := e.getEventHubURL()

	// Create SAS token
	sasToken, err := e.createSASToken(eventHubURL, time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create SAS token: %w", err)
	}

	// Send request
	req, err := http.NewRequestWithContext(ctx, "POST", eventHubURL+"/messages", bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", sasToken)
	req.Header.Set("Content-Type", "application/vnd.microsoft.servicebus.json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("event hub send failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// getEventHubURL returns the Event Hub URL.
func (e *EventHubClient) getEventHubURL() string {
	endpoint := strings.TrimSuffix(e.parsedConnStr.Endpoint, "/")
	endpoint = strings.Replace(endpoint, "sb://", "https://", 1)

	entityPath := e.parsedConnStr.EntityPath
	if entityPath == "" {
		entityPath = e.config.Name
	}

	return fmt.Sprintf("%s/%s", endpoint, entityPath)
}

// createSASToken creates a Shared Access Signature token.
func (e *EventHubClient) createSASToken(resourceURI string, duration time.Duration) (string, error) {
	expiry := time.Now().Add(duration).Unix()

	// URL encode the resource URI
	encodedURI := url.QueryEscape(resourceURI)

	// Create the string to sign
	stringToSign := encodedURI + "\n" + fmt.Sprintf("%d", expiry)

	// Decode the key
	key, err := base64.StdEncoding.DecodeString(e.parsedConnStr.SharedAccessKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode key: %w", err)
	}

	// Create HMAC signature
	h := hmac.New(sha256.New, key)
	h.Write([]byte(stringToSign))
	signature := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))

	// Build the token
	token := fmt.Sprintf("SharedAccessSignature sr=%s&sig=%s&se=%d&skn=%s",
		encodedURI,
		signature,
		expiry,
		e.parsedConnStr.SharedAccessKeyName,
	)

	return token, nil
}

// BatchEvent adds an event to the batch.
func (e *EventHubClient) BatchEvent(event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.batch = append(e.batch, data)
	return nil
}

// Flush sends all batched events.
func (e *EventHubClient) Flush(ctx context.Context) error {
	e.mu.Lock()
	if len(e.batch) == 0 {
		e.mu.Unlock()
		return nil
	}

	batch := e.batch
	e.batch = make([][]byte, 0)
	e.lastFlush = time.Now()
	e.mu.Unlock()

	// Convert batch to interface slice
	events := make([]interface{}, len(batch))
	for i, data := range batch {
		var event interface{}
		json.Unmarshal(data, &event)
		events[i] = event
	}

	return e.SendEvents(ctx, events)
}

// Ingest implements the EventIngester interface for Event Hub.
func (c *Client) Ingest(ctx context.Context, events []connector.Event) (*connector.IngestResult, error) {
	// Check if Event Hub is enabled
	if c.config.EventHub.Enabled {
		return c.ingestViaEventHub(ctx, events)
	}

	// Check if Data Collection is enabled
	if c.config.DataCollection.Enabled {
		return c.ingestViaDataCollection(ctx, events)
	}

	return nil, fmt.Errorf("no ingestion method enabled (Event Hub or Data Collection)")
}

// ingestViaEventHub sends events via Event Hub.
func (c *Client) ingestViaEventHub(ctx context.Context, events []connector.Event) (*connector.IngestResult, error) {
	ehClient, err := c.GetEventHubClient()
	if err != nil {
		return nil, err
	}

	start := time.Now()

	// Convert events
	ehEvents := make([]interface{}, len(events))
	for i, event := range events {
		ehEvents[i] = map[string]interface{}{
			"TimeGenerated": event.Timestamp.Format(time.RFC3339),
			"Source":        event.Source,
			"SourceType":    event.SourceType,
			"Host":          event.Host,
			"RawData":       event.Raw,
			"Fields":        event.Fields,
			"Tags":          event.Tags,
		}
	}

	err = ehClient.SendEvents(ctx, ehEvents)

	result := &connector.IngestResult{
		TotalEvents:   len(events),
		ExecutionTime: time.Since(start),
	}

	if err != nil {
		result.FailedCount = len(events)
		result.Errors = []connector.IngestError{{Message: err.Error()}}
		return result, err
	}

	result.SuccessCount = len(events)
	return result, nil
}

// ingestViaDataCollection sends events via Data Collection Rules.
func (c *Client) ingestViaDataCollection(ctx context.Context, events []connector.Event) (*connector.IngestResult, error) {
	start := time.Now()

	// Build DCE URL
	dceURL := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01",
		c.config.DataCollection.Endpoint,
		c.config.DataCollection.RuleID,
		c.config.DataCollection.StreamName,
	)

	// Convert events to the expected format
	records := make([]map[string]interface{}, len(events))
	for i, event := range events {
		record := event.Fields
		if record == nil {
			record = make(map[string]interface{})
		}
		record["TimeGenerated"] = event.Timestamp.Format(time.RFC3339)
		record["Computer"] = event.Host
		record["RawData"] = event.Raw
		records[i] = record
	}

	data, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal events: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", dceURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &connector.IngestResult{
		TotalEvents:   len(events),
		ExecutionTime: time.Since(start),
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		result.FailedCount = len(events)
		result.Errors = []connector.IngestError{{
			Message: fmt.Sprintf("DCE ingest failed: %s - %s", resp.Status, string(body)),
		}}
		return result, fmt.Errorf("DCE ingest failed: %s", resp.Status)
	}

	result.SuccessCount = len(events)
	return result, nil
}

// IngestBatch implements the EventIngester interface for batch ingestion.
func (c *Client) IngestBatch(ctx context.Context, batch *connector.EventBatch) (*connector.IngestResult, error) {
	result, err := c.Ingest(ctx, batch.Events)
	if result != nil {
		result.BatchID = batch.BatchID
	}
	return result, err
}
