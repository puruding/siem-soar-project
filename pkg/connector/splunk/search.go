// Package splunk provides Splunk search API implementation.
package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"siem-soar-project/pkg/connector"
)

// SearchJob represents a Splunk search job.
type SearchJob struct {
	SID           string    `json:"sid"`
	DispatchState string    `json:"dispatchState"`
	IsDone        bool      `json:"isDone"`
	IsFailed      bool      `json:"isFailed"`
	IsFinalized   bool      `json:"isFinalized"`
	IsPaused      bool      `json:"isPaused"`
	IsPreviewEnabled bool   `json:"isPreviewEnabled"`
	IsRealTimeSearch bool   `json:"isRealTimeSearch"`
	IsSaved       bool      `json:"isSaved"`
	IsZombie      bool      `json:"isZombie"`
	DoneProgress  float64   `json:"doneProgress"`
	DropCount     int       `json:"dropCount"`
	EventCount    int64     `json:"eventCount"`
	ResultCount   int64     `json:"resultCount"`
	ScanCount     int64     `json:"scanCount"`
	RunDuration   float64   `json:"runDuration"`
	Priority      int       `json:"priority"`
	Messages      []Message `json:"messages,omitempty"`
	Request       SearchRequest `json:"request,omitempty"`
}

// Message represents a Splunk message.
type Message struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// SearchRequest represents the original search request.
type SearchRequest struct {
	Search     string `json:"search"`
	EarliestTime string `json:"earliest_time"`
	LatestTime   string `json:"latest_time"`
}

// Query executes a synchronous search query.
func (c *Client) Query(ctx context.Context, req *connector.QueryRequest) (*connector.QueryResult, error) {
	// Start async search
	sid, err := c.AsyncQuery(ctx, req)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	result, err := c.waitForSearch(ctx, sid, req.Timeout)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// AsyncQuery starts an asynchronous search.
func (c *Client) AsyncQuery(ctx context.Context, req *connector.QueryRequest) (string, error) {
	searchURL := c.config.GetSearchURL()

	data := url.Values{}
	data.Set("search", req.Query)
	data.Set("output_mode", "json")
	data.Set("exec_mode", "normal")

	// Set time range
	if !req.TimeRange.Start.IsZero() {
		data.Set("earliest_time", req.TimeRange.Start.Format(time.RFC3339))
	} else if req.TimeRange.Relative != "" {
		data.Set("earliest_time", req.TimeRange.Relative)
	} else {
		data.Set("earliest_time", c.config.Search.DefaultEarliest)
	}

	if !req.TimeRange.End.IsZero() {
		data.Set("latest_time", req.TimeRange.End.Format(time.RFC3339))
	} else {
		data.Set("latest_time", c.config.Search.DefaultLatest)
	}

	// Set max results
	maxResults := req.MaxResults
	if maxResults == 0 {
		maxResults = c.config.Search.MaxResults
	}
	data.Set("max_count", fmt.Sprintf("%d", maxResults))

	// Set timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.config.Search.SearchTimeout
	}
	data.Set("timeout", fmt.Sprintf("%d", int(timeout.Seconds())))

	// Add custom parameters
	for k, v := range req.Parameters {
		data.Set(k, fmt.Sprintf("%v", v))
	}

	resp, err := c.doRequest(ctx, "POST", searchURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create search job: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create search job: %s - %s", resp.Status, string(body))
	}

	var result struct {
		SID string `json:"sid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse search response: %w", err)
	}

	return result.SID, nil
}

// GetQueryStatus gets the status of an async query.
func (c *Client) GetQueryStatus(ctx context.Context, queryID string) (*connector.QueryResult, error) {
	job, err := c.getJobStatus(ctx, queryID)
	if err != nil {
		return nil, err
	}

	result := &connector.QueryResult{
		ID:       queryID,
		Language: connector.QueryLanguageSPL,
		Metadata: connector.QueryMetadata{
			SIEM: connector.SIEMSplunk,
		},
	}

	switch {
	case job.IsFailed:
		result.Status = connector.QueryStatusFailed
		if len(job.Messages) > 0 {
			result.Error = job.Messages[0].Text
		}
	case job.IsDone:
		result.Status = connector.QueryStatusCompleted
		result.Metadata.TotalResults = job.ResultCount
		result.Metadata.ExecutionTime = time.Duration(job.RunDuration * float64(time.Second))
	default:
		result.Status = connector.QueryStatusRunning
	}

	return result, nil
}

// getJobStatus retrieves the status of a search job.
func (c *Client) getJobStatus(ctx context.Context, sid string) (*SearchJob, error) {
	statusURL := fmt.Sprintf("%s/%s?output_mode=json", c.config.GetSearchURL(), url.PathEscape(sid))

	resp, err := c.doRequest(ctx, "GET", statusURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get job status: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Entry []struct {
			Content SearchJob `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse job status: %w", err)
	}

	if len(result.Entry) == 0 {
		return nil, fmt.Errorf("search job %s not found", sid)
	}

	return &result.Entry[0].Content, nil
}

// waitForSearch waits for a search to complete and returns results.
func (c *Client) waitForSearch(ctx context.Context, sid string, timeout time.Duration) (*connector.QueryResult, error) {
	if timeout == 0 {
		timeout = c.config.Search.SearchTimeout
	}

	deadline := time.Now().Add(timeout)
	interval := c.config.Search.StatusInterval
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("search timeout after %v", timeout)
		}

		job, err := c.getJobStatus(ctx, sid)
		if err != nil {
			return nil, err
		}

		if job.IsFailed {
			errMsg := "search failed"
			if len(job.Messages) > 0 {
				errMsg = job.Messages[0].Text
			}
			return &connector.QueryResult{
				ID:        sid,
				Status:    connector.QueryStatusFailed,
				Error:     errMsg,
				StartTime: startTime,
				EndTime:   time.Now(),
			}, nil
		}

		if job.IsDone {
			// Fetch results
			results, err := c.getSearchResults(ctx, sid, 0, int(job.ResultCount))
			if err != nil {
				return nil, err
			}

			return &connector.QueryResult{
				ID:        sid,
				Status:    connector.QueryStatusCompleted,
				Language:  connector.QueryLanguageSPL,
				Results:   results,
				StartTime: startTime,
				EndTime:   time.Now(),
				Metadata: connector.QueryMetadata{
					TotalResults:    job.ResultCount,
					ReturnedResults: len(results),
					ExecutionTime:   time.Duration(job.RunDuration * float64(time.Second)),
					SIEM:            connector.SIEMSplunk,
				},
			}, nil
		}

		// Wait before next poll
		time.Sleep(interval)
	}
}

// getSearchResults retrieves search results.
func (c *Client) getSearchResults(ctx context.Context, sid string, offset, count int) ([]map[string]interface{}, error) {
	resultsURL := fmt.Sprintf("%s/%s/results?output_mode=json&offset=%d&count=%d",
		c.config.GetSearchURL(),
		url.PathEscape(sid),
		offset,
		count,
	)

	resp, err := c.doRequest(ctx, "GET", resultsURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get results: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Results []map[string]interface{} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	return result.Results, nil
}

// CancelQuery cancels a running query.
func (c *Client) CancelQuery(ctx context.Context, queryID string) error {
	controlURL := fmt.Sprintf("%s/%s/control", c.config.GetSearchURL(), url.PathEscape(queryID))

	data := url.Values{}
	data.Set("action", "cancel")

	resp, err := c.doRequest(ctx, "POST", controlURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to cancel search: %s - %s", resp.Status, string(body))
	}

	return nil
}

// PauseSearch pauses a running search.
func (c *Client) PauseSearch(ctx context.Context, sid string) error {
	return c.controlSearch(ctx, sid, "pause")
}

// ResumeSearch resumes a paused search.
func (c *Client) ResumeSearch(ctx context.Context, sid string) error {
	return c.controlSearch(ctx, sid, "unpause")
}

// FinalizeSearch finalizes a search.
func (c *Client) FinalizeSearch(ctx context.Context, sid string) error {
	return c.controlSearch(ctx, sid, "finalize")
}

// controlSearch sends a control action to a search.
func (c *Client) controlSearch(ctx context.Context, sid, action string) error {
	controlURL := fmt.Sprintf("%s/%s/control", c.config.GetSearchURL(), url.PathEscape(sid))

	data := url.Values{}
	data.Set("action", action)

	resp, err := c.doRequest(ctx, "POST", controlURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to %s search: %s - %s", action, resp.Status, string(body))
	}

	return nil
}

// GetSearchEvents retrieves raw events from a search.
func (c *Client) GetSearchEvents(ctx context.Context, sid string, offset, count int) ([]map[string]interface{}, error) {
	eventsURL := fmt.Sprintf("%s/%s/events?output_mode=json&offset=%d&count=%d",
		c.config.GetSearchURL(),
		url.PathEscape(sid),
		offset,
		count,
	)

	resp, err := c.doRequest(ctx, "GET", eventsURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get events: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Results []map[string]interface{} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse events: %w", err)
	}

	return result.Results, nil
}

// ExportSearch exports search results to a specified format.
func (c *Client) ExportSearch(ctx context.Context, query string, timeRange connector.TimeRange, format string) (io.ReadCloser, error) {
	exportURL := fmt.Sprintf("%s/services/search/jobs/export", c.config.GetManagementURL())

	data := url.Values{}
	data.Set("search", query)
	data.Set("output_mode", format) // "json", "csv", "xml"

	if !timeRange.Start.IsZero() {
		data.Set("earliest_time", timeRange.Start.Format(time.RFC3339))
	} else if timeRange.Relative != "" {
		data.Set("earliest_time", timeRange.Relative)
	}

	if !timeRange.End.IsZero() {
		data.Set("latest_time", timeRange.End.Format(time.RFC3339))
	}

	resp, err := c.doRequest(ctx, "POST", exportURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("failed to export search: %s - %s", resp.Status, string(body))
	}

	return resp.Body, nil
}

// OneShot performs a one-shot search (blocking).
func (c *Client) OneShot(ctx context.Context, query string, timeRange connector.TimeRange, maxResults int) ([]map[string]interface{}, error) {
	searchURL := fmt.Sprintf("%s/services/search/jobs/oneshot", c.config.GetManagementURL())

	data := url.Values{}
	data.Set("search", query)
	data.Set("output_mode", "json")

	if maxResults > 0 {
		data.Set("max_count", fmt.Sprintf("%d", maxResults))
	}

	if !timeRange.Start.IsZero() {
		data.Set("earliest_time", timeRange.Start.Format(time.RFC3339))
	} else if timeRange.Relative != "" {
		data.Set("earliest_time", timeRange.Relative)
	}

	if !timeRange.End.IsZero() {
		data.Set("latest_time", timeRange.End.Format(time.RFC3339))
	}

	resp, err := c.doRequest(ctx, "POST", searchURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("oneshot search failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Results []map[string]interface{} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse oneshot results: %w", err)
	}

	return result.Results, nil
}
