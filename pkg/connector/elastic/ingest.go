// Package elastic provides Elasticsearch bulk ingestion implementation.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"siem-soar-project/pkg/connector"
)

// BulkIndexer handles bulk indexing operations.
type BulkIndexer struct {
	client        *Client
	config        *BulkConfig
	mu            sync.Mutex
	items         []BulkItem
	currentSize   int
	lastFlush     time.Time
	flushCallback func(*BulkResponse)
}

// BulkItem represents an item to be indexed.
type BulkItem struct {
	Index    string                 `json:"index"`
	ID       string                 `json:"id,omitempty"`
	Pipeline string                 `json:"pipeline,omitempty"`
	Document map[string]interface{} `json:"document"`
}

// BulkResponse represents a bulk API response.
type BulkResponse struct {
	Took   int  `json:"took"`
	Errors bool `json:"errors"`
	Items  []BulkResponseItem `json:"items"`
}

// BulkResponseItem represents a single item response.
type BulkResponseItem struct {
	Index  *BulkItemResult `json:"index,omitempty"`
	Create *BulkItemResult `json:"create,omitempty"`
	Update *BulkItemResult `json:"update,omitempty"`
	Delete *BulkItemResult `json:"delete,omitempty"`
}

// BulkItemResult represents the result of a bulk item operation.
type BulkItemResult struct {
	Index       string `json:"_index"`
	ID          string `json:"_id"`
	Version     int64  `json:"_version"`
	Result      string `json:"result"`
	Status      int    `json:"status"`
	SeqNo       int64  `json:"_seq_no"`
	PrimaryTerm int64  `json:"_primary_term"`
	Error       *BulkError `json:"error,omitempty"`
}

// BulkError represents a bulk operation error.
type BulkError struct {
	Type     string `json:"type"`
	Reason   string `json:"reason"`
	CausedBy *BulkError `json:"caused_by,omitempty"`
}

// NewBulkIndexer creates a new bulk indexer.
func (c *Client) NewBulkIndexer() *BulkIndexer {
	return &BulkIndexer{
		client:    c,
		config:    &c.config.Bulk,
		items:     make([]BulkItem, 0, c.config.Bulk.BatchSize),
		lastFlush: time.Now(),
	}
}

// Add adds an item to the bulk indexer.
func (bi *BulkIndexer) Add(item BulkItem) error {
	bi.mu.Lock()
	defer bi.mu.Unlock()

	bi.items = append(bi.items, item)

	// Estimate size
	data, _ := json.Marshal(item.Document)
	bi.currentSize += len(data) + 100 // Add overhead for metadata

	// Check if we should flush
	if len(bi.items) >= bi.config.BatchSize || bi.currentSize >= bi.config.FlushBytes {
		return bi.flushLocked(context.Background())
	}

	return nil
}

// Flush flushes all pending items.
func (bi *BulkIndexer) Flush(ctx context.Context) error {
	bi.mu.Lock()
	defer bi.mu.Unlock()
	return bi.flushLocked(ctx)
}

// flushLocked performs the flush (must be called with lock held).
func (bi *BulkIndexer) flushLocked(ctx context.Context) error {
	if len(bi.items) == 0 {
		return nil
	}

	items := bi.items
	bi.items = make([]BulkItem, 0, bi.config.BatchSize)
	bi.currentSize = 0
	bi.lastFlush = time.Now()

	// Execute bulk request
	resp, err := bi.client.Bulk(ctx, items)
	if err != nil {
		return err
	}

	if bi.flushCallback != nil {
		bi.flushCallback(resp)
	}

	return nil
}

// SetFlushCallback sets a callback for flush operations.
func (bi *BulkIndexer) SetFlushCallback(callback func(*BulkResponse)) {
	bi.mu.Lock()
	defer bi.mu.Unlock()
	bi.flushCallback = callback
}

// AutoFlush starts automatic flushing based on time interval.
func (bi *BulkIndexer) AutoFlush(ctx context.Context) {
	ticker := time.NewTicker(bi.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			bi.Flush(context.Background())
			return
		case <-ticker.C:
			bi.mu.Lock()
			shouldFlush := len(bi.items) > 0 && time.Since(bi.lastFlush) >= bi.config.FlushInterval
			bi.mu.Unlock()

			if shouldFlush {
				bi.Flush(ctx)
			}
		}
	}
}

// Bulk performs a bulk indexing operation.
func (c *Client) Bulk(ctx context.Context, items []BulkItem) (*BulkResponse, error) {
	if len(items) == 0 {
		return &BulkResponse{}, nil
	}

	// Build NDJSON body
	var buf bytes.Buffer
	for _, item := range items {
		// Write action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": item.Index,
			},
		}
		if item.ID != "" {
			action["index"].(map[string]interface{})["_id"] = item.ID
		}
		if item.Pipeline != "" {
			action["index"].(map[string]interface{})["pipeline"] = item.Pipeline
		}

		actionBytes, err := json.Marshal(action)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal action: %w", err)
		}
		buf.Write(actionBytes)
		buf.WriteByte('\n')

		// Write document line
		docBytes, err := json.Marshal(item.Document)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal document: %w", err)
		}
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	// Build URL
	bulkURL := fmt.Sprintf("%s/_bulk", c.baseURL)
	if c.config.Bulk.RefreshPolicy != "" && c.config.Bulk.RefreshPolicy != "false" {
		bulkURL += "?refresh=" + c.config.Bulk.RefreshPolicy
	}
	if c.config.Bulk.Pipeline != "" {
		if contains(bulkURL, "?") {
			bulkURL += "&"
		} else {
			bulkURL += "?"
		}
		bulkURL += "pipeline=" + c.config.Bulk.Pipeline
	}

	resp, err := c.doRequest(ctx, "POST", bulkURL, &buf)
	if err != nil {
		return nil, fmt.Errorf("bulk request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bulk request failed: %s - %s", resp.Status, string(body))
	}

	var bulkResp BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return nil, fmt.Errorf("failed to parse bulk response: %w", err)
	}

	return &bulkResp, nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr) >= 0))
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Index indexes a single document.
func (c *Client) Index(ctx context.Context, index, id string, document map[string]interface{}) (*IndexResponse, error) {
	var indexURL string
	var method string

	if id != "" {
		indexURL = fmt.Sprintf("%s/%s/_doc/%s", c.baseURL, index, id)
		method = "PUT"
	} else {
		indexURL = fmt.Sprintf("%s/%s/_doc", c.baseURL, index)
		method = "POST"
	}

	resp, err := c.doJSONRequest(ctx, method, indexURL, document)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("index request failed: %s - %s", resp.Status, string(body))
	}

	var indexResp IndexResponse
	if err := json.NewDecoder(resp.Body).Decode(&indexResp); err != nil {
		return nil, err
	}

	return &indexResp, nil
}

// IndexResponse represents an index API response.
type IndexResponse struct {
	Index       string `json:"_index"`
	ID          string `json:"_id"`
	Version     int64  `json:"_version"`
	Result      string `json:"result"`
	SeqNo       int64  `json:"_seq_no"`
	PrimaryTerm int64  `json:"_primary_term"`
	Shards      struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
}

// Ingest implements the EventIngester interface.
func (c *Client) Ingest(ctx context.Context, events []connector.Event) (*connector.IngestResult, error) {
	start := time.Now()

	items := make([]BulkItem, len(events))
	for i, event := range events {
		index := c.config.GetIndexName(event.SourceType, event.Timestamp)
		doc := event.Fields
		if doc == nil {
			doc = make(map[string]interface{})
		}
		doc["@timestamp"] = event.Timestamp.Format(time.RFC3339Nano)
		doc["source"] = event.Source
		doc["source_type"] = event.SourceType
		if event.Host != "" {
			doc["host"] = map[string]interface{}{"name": event.Host}
		}
		if len(event.Tags) > 0 {
			doc["tags"] = event.Tags
		}
		if event.Raw != "" {
			doc["message"] = event.Raw
		}

		items[i] = BulkItem{
			Index:    index,
			ID:       event.ID,
			Document: doc,
		}
	}

	bulkResp, err := c.Bulk(ctx, items)

	result := &connector.IngestResult{
		TotalEvents:   len(events),
		ExecutionTime: time.Since(start),
	}

	if err != nil {
		result.FailedCount = len(events)
		result.Errors = []connector.IngestError{{Message: err.Error()}}
		return result, err
	}

	// Count successes and failures
	for _, item := range bulkResp.Items {
		var itemResult *BulkItemResult
		if item.Index != nil {
			itemResult = item.Index
		} else if item.Create != nil {
			itemResult = item.Create
		}

		if itemResult != nil {
			if itemResult.Status >= 200 && itemResult.Status < 300 {
				result.SuccessCount++
			} else {
				result.FailedCount++
				if itemResult.Error != nil {
					result.Errors = append(result.Errors, connector.IngestError{
						EventID: itemResult.ID,
						Message: itemResult.Error.Reason,
						Code:    itemResult.Error.Type,
					})
				}
			}
		}
	}

	if result.FailedCount > 0 {
		return result, fmt.Errorf("bulk indexing had %d failures", result.FailedCount)
	}

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

// UpdateByQuery updates documents matching a query.
func (c *Client) UpdateByQuery(ctx context.Context, index string, query map[string]interface{}, script map[string]interface{}) (*UpdateByQueryResponse, error) {
	updateURL := fmt.Sprintf("%s/%s/_update_by_query", c.baseURL, index)

	body := map[string]interface{}{
		"query":  query,
		"script": script,
	}

	resp, err := c.doJSONRequest(ctx, "POST", updateURL, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("update by query failed: %s - %s", resp.Status, string(body))
	}

	var updateResp UpdateByQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&updateResp); err != nil {
		return nil, err
	}

	return &updateResp, nil
}

// UpdateByQueryResponse represents an update by query response.
type UpdateByQueryResponse struct {
	Took             int64  `json:"took"`
	TimedOut         bool   `json:"timed_out"`
	Total            int64  `json:"total"`
	Updated          int64  `json:"updated"`
	Deleted          int64  `json:"deleted"`
	Batches          int    `json:"batches"`
	VersionConflicts int64  `json:"version_conflicts"`
	Noops            int64  `json:"noops"`
	Retries          struct {
		Bulk   int64 `json:"bulk"`
		Search int64 `json:"search"`
	} `json:"retries"`
}

// DeleteByQuery deletes documents matching a query.
func (c *Client) DeleteByQuery(ctx context.Context, index string, query map[string]interface{}) (*DeleteByQueryResponse, error) {
	deleteURL := fmt.Sprintf("%s/%s/_delete_by_query", c.baseURL, index)

	body := map[string]interface{}{
		"query": query,
	}

	resp, err := c.doJSONRequest(ctx, "POST", deleteURL, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("delete by query failed: %s - %s", resp.Status, string(body))
	}

	var deleteResp DeleteByQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&deleteResp); err != nil {
		return nil, err
	}

	return &deleteResp, nil
}

// DeleteByQueryResponse represents a delete by query response.
type DeleteByQueryResponse struct {
	Took             int64 `json:"took"`
	TimedOut         bool  `json:"timed_out"`
	Total            int64 `json:"total"`
	Deleted          int64 `json:"deleted"`
	Batches          int   `json:"batches"`
	VersionConflicts int64 `json:"version_conflicts"`
	Noops            int64 `json:"noops"`
	Retries          struct {
		Bulk   int64 `json:"bulk"`
		Search int64 `json:"search"`
	} `json:"retries"`
}
