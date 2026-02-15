package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// HTTPClient wraps http.Client with convenience methods for ML service calls.
type HTTPClient struct {
	client  *http.Client
	baseURL string
	timeout time.Duration
}

// NewHTTPClient creates a new HTTP client for ML service communication.
func NewHTTPClient(baseURL string, timeout time.Duration) *HTTPClient {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &HTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		baseURL: baseURL,
		timeout: timeout,
	}
}

// Request represents an HTTP request configuration.
type Request struct {
	Method  string
	Path    string
	Body    interface{}
	Headers map[string]string
}

// Response represents an HTTP response.
type Response struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	Latency    time.Duration
}

// Do executes an HTTP request to the ML service.
func (c *HTTPClient) Do(ctx context.Context, req Request) (*Response, error) {
	start := time.Now()

	// Prepare body
	var bodyReader io.Reader
	if req.Body != nil {
		bodyBytes, err := json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create request
	url := c.baseURL + req.Path
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Execute request
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	latency := time.Since(start)

	slog.Debug("http request completed",
		"method", req.Method,
		"path", req.Path,
		"status", resp.StatusCode,
		"latency_ms", latency.Milliseconds(),
	)

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Headers:    resp.Header,
		Latency:    latency,
	}, nil
}

// Post is a convenience method for POST requests.
func (c *HTTPClient) Post(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.Do(ctx, Request{
		Method: http.MethodPost,
		Path:   path,
		Body:   body,
	})
}

// Get is a convenience method for GET requests.
func (c *HTTPClient) Get(ctx context.Context, path string) (*Response, error) {
	return c.Do(ctx, Request{
		Method: http.MethodGet,
		Path:   path,
	})
}

// HealthCheck checks if the service is healthy.
func (c *HTTPClient) HealthCheck(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, "/health")
	if err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// BaseURL returns the base URL of the client.
func (c *HTTPClient) BaseURL() string {
	return c.baseURL
}

// SetBaseURL updates the base URL.
func (c *HTTPClient) SetBaseURL(url string) {
	c.baseURL = url
}
