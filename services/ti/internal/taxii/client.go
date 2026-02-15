// Package taxii provides an enhanced TAXII 2.1 client implementation.
package taxii

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ClientConfig holds TAXII client configuration.
type ClientConfig struct {
	BaseURL          string        `json:"base_url"`
	APIRoot          string        `json:"api_root"`
	Username         string        `json:"username"`
	Password         string        `json:"password"`
	APIKey           string        `json:"api_key"`
	CertPath         string        `json:"cert_path"`
	CertPassword     string        `json:"cert_password"`
	Timeout          time.Duration `json:"timeout"`
	RetryCount       int           `json:"retry_count"`
	MaxObjectsPerReq int           `json:"max_objects_per_req"`
	Headers          map[string]string `json:"headers"`
}

// DefaultClientConfig returns default client configuration.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Timeout:          5 * time.Minute,
		RetryCount:       3,
		MaxObjectsPerReq: 10000,
	}
}

// Client implements a comprehensive TAXII 2.1 client.
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
	logger     *slog.Logger
	cache      sync.Map // Collection cache
}

// NewClient creates a new TAXII 2.1 client.
func NewClient(config *ClientConfig, logger *slog.Logger) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger.With("component", "taxii-client"),
	}
}

// Discovery represents TAXII server discovery response.
type Discovery struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Contact     string   `json:"contact,omitempty"`
	Default     string   `json:"default,omitempty"`
	APIRoots    []string `json:"api_roots"`
}

// APIRoot represents a TAXII API Root.
type APIRoot struct {
	Title            string   `json:"title"`
	Description      string   `json:"description,omitempty"`
	Versions         []string `json:"versions"`
	MaxContentLength int64    `json:"max_content_length,omitempty"`
}

// Collection represents a TAXII collection.
type Collection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Alias       string   `json:"alias,omitempty"`
	CanRead     bool     `json:"can_read"`
	CanWrite    bool     `json:"can_write"`
	MediaTypes  []string `json:"media_types,omitempty"`
}

// Collections represents a list of collections.
type Collections struct {
	Collections []Collection `json:"collections"`
}

// Envelope represents a TAXII envelope containing STIX objects.
type Envelope struct {
	More    bool            `json:"more,omitempty"`
	Next    string          `json:"next,omitempty"`
	Objects json.RawMessage `json:"objects,omitempty"`
}

// Status represents a TAXII status response.
type Status struct {
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	RequestTimestamp time.Time `json:"request_timestamp,omitempty"`
	TotalCount       int       `json:"total_count,omitempty"`
	SuccessCount     int       `json:"success_count,omitempty"`
	Successes        []string  `json:"successes,omitempty"`
	FailureCount     int       `json:"failure_count,omitempty"`
	Failures         []StatusFailure `json:"failures,omitempty"`
	PendingCount     int       `json:"pending_count,omitempty"`
	Pendings         []string  `json:"pendings,omitempty"`
}

// StatusFailure represents a failure in status response.
type StatusFailure struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Manifest represents a collection manifest.
type Manifest struct {
	More    bool           `json:"more,omitempty"`
	Objects []ManifestEntry `json:"objects,omitempty"`
}

// ManifestEntry represents a manifest entry.
type ManifestEntry struct {
	ID            string    `json:"id"`
	DateAdded     time.Time `json:"date_added"`
	Version       string    `json:"version"`
	MediaTypes    []string  `json:"media_types,omitempty"`
}

// GetObjectsParams holds parameters for GetObjects.
type GetObjectsParams struct {
	AddedAfter  *time.Time
	Limit       int
	Next        string
	MatchID     []string
	MatchType   []string
	MatchVersion string
}

// Discover performs TAXII server discovery.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	u, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return nil, err
	}

	// Standard discovery endpoint
	u.Path = "/taxii2/"

	var discovery Discovery
	if err := c.doRequest(ctx, "GET", u.String(), nil, &discovery); err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	return &discovery, nil
}

// GetAPIRoot retrieves API root information.
func (c *Client) GetAPIRoot(ctx context.Context, apiRoot string) (*APIRoot, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	var root APIRoot
	if err := c.doRequest(ctx, "GET", apiRoot, nil, &root); err != nil {
		return nil, fmt.Errorf("get API root failed: %w", err)
	}

	return &root, nil
}

// GetCollections retrieves collections from an API root.
func (c *Client) GetCollections(ctx context.Context, apiRoot string) ([]Collection, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := apiRoot + "/collections/"

	var collections Collections
	if err := c.doRequest(ctx, "GET", u, nil, &collections); err != nil {
		return nil, fmt.Errorf("get collections failed: %w", err)
	}

	return collections.Collections, nil
}

// GetCollection retrieves a specific collection.
func (c *Client) GetCollection(ctx context.Context, apiRoot, collectionID string) (*Collection, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/", apiRoot, collectionID)

	var collection Collection
	if err := c.doRequest(ctx, "GET", u, nil, &collection); err != nil {
		return nil, fmt.Errorf("get collection failed: %w", err)
	}

	return &collection, nil
}

// GetObjects retrieves objects from a collection.
func (c *Client) GetObjects(ctx context.Context, apiRoot, collectionID string, params *GetObjectsParams) (*Envelope, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/objects/", apiRoot, collectionID)

	// Build query parameters
	query := url.Values{}
	if params != nil {
		if params.AddedAfter != nil {
			query.Set("added_after", params.AddedAfter.Format(time.RFC3339))
		}
		if params.Limit > 0 {
			query.Set("limit", fmt.Sprintf("%d", params.Limit))
		}
		if params.Next != "" {
			query.Set("next", params.Next)
		}
		for _, id := range params.MatchID {
			query.Add("match[id]", id)
		}
		for _, t := range params.MatchType {
			query.Add("match[type]", t)
		}
		if params.MatchVersion != "" {
			query.Set("match[version]", params.MatchVersion)
		}
	}

	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var envelope Envelope
	if err := c.doRequestSTIX(ctx, "GET", u, nil, &envelope); err != nil {
		return nil, fmt.Errorf("get objects failed: %w", err)
	}

	return &envelope, nil
}

// GetObject retrieves a specific object from a collection.
func (c *Client) GetObject(ctx context.Context, apiRoot, collectionID, objectID string) (*Envelope, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/objects/%s/", apiRoot, collectionID, url.PathEscape(objectID))

	var envelope Envelope
	if err := c.doRequestSTIX(ctx, "GET", u, nil, &envelope); err != nil {
		return nil, fmt.Errorf("get object failed: %w", err)
	}

	return &envelope, nil
}

// AddObjects adds objects to a collection.
func (c *Client) AddObjects(ctx context.Context, apiRoot, collectionID string, objects []json.RawMessage) (*Status, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/objects/", apiRoot, collectionID)

	// Build envelope
	envelope := map[string]interface{}{
		"objects": objects,
	}

	var status Status
	if err := c.doRequestSTIX(ctx, "POST", u, envelope, &status); err != nil {
		return nil, fmt.Errorf("add objects failed: %w", err)
	}

	return &status, nil
}

// GetManifest retrieves the manifest of a collection.
func (c *Client) GetManifest(ctx context.Context, apiRoot, collectionID string, params *GetObjectsParams) (*Manifest, error) {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/manifest/", apiRoot, collectionID)

	// Build query parameters
	if params != nil {
		query := url.Values{}
		if params.AddedAfter != nil {
			query.Set("added_after", params.AddedAfter.Format(time.RFC3339))
		}
		if params.Limit > 0 {
			query.Set("limit", fmt.Sprintf("%d", params.Limit))
		}
		if len(query) > 0 {
			u += "?" + query.Encode()
		}
	}

	var manifest Manifest
	if err := c.doRequest(ctx, "GET", u, nil, &manifest); err != nil {
		return nil, fmt.Errorf("get manifest failed: %w", err)
	}

	return &manifest, nil
}

// DeleteObject deletes an object from a collection.
func (c *Client) DeleteObject(ctx context.Context, apiRoot, collectionID, objectID string) error {
	if apiRoot == "" {
		apiRoot = c.config.APIRoot
	}

	u := fmt.Sprintf("%s/collections/%s/objects/%s/", apiRoot, collectionID, url.PathEscape(objectID))

	if err := c.doRequest(ctx, "DELETE", u, nil, nil); err != nil {
		return fmt.Errorf("delete object failed: %w", err)
	}

	return nil
}

// Poll retrieves all objects since a given time.
func (c *Client) Poll(ctx context.Context, apiRoot, collectionID string, since time.Time) (<-chan json.RawMessage, <-chan error) {
	objectsCh := make(chan json.RawMessage, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(objectsCh)
		defer close(errCh)

		params := &GetObjectsParams{
			AddedAfter: &since,
			Limit:      c.config.MaxObjectsPerReq,
		}

		for {
			envelope, err := c.GetObjects(ctx, apiRoot, collectionID, params)
			if err != nil {
				errCh <- err
				return
			}

			// Parse objects
			var objects []json.RawMessage
			if err := json.Unmarshal(envelope.Objects, &objects); err != nil {
				c.logger.Warn("failed to parse objects", "error", err)
			} else {
				for _, obj := range objects {
					select {
					case <-ctx.Done():
						return
					case objectsCh <- obj:
					}
				}
			}

			// Check for more pages
			if !envelope.More || envelope.Next == "" {
				break
			}

			params.Next = envelope.Next
		}
	}()

	return objectsCh, errCh
}

// StreamObjects streams objects from a collection.
func (c *Client) StreamObjects(ctx context.Context, apiRoot, collectionID string, since time.Time, handler func(json.RawMessage) error) error {
	params := &GetObjectsParams{
		AddedAfter: &since,
		Limit:      c.config.MaxObjectsPerReq,
	}

	for {
		envelope, err := c.GetObjects(ctx, apiRoot, collectionID, params)
		if err != nil {
			return err
		}

		// Parse objects
		var objects []json.RawMessage
		if err := json.Unmarshal(envelope.Objects, &objects); err != nil {
			c.logger.Warn("failed to parse objects", "error", err)
		} else {
			for _, obj := range objects {
				if err := handler(obj); err != nil {
					return err
				}
			}
		}

		// Check for more pages
		if !envelope.More || envelope.Next == "" {
			break
		}

		params.Next = envelope.Next
	}

	return nil
}

// Test tests connectivity to the TAXII server.
func (c *Client) Test(ctx context.Context) error {
	_, err := c.Discover(ctx)
	return err
}

// doRequest performs an HTTP request with TAXII headers.
func (c *Client) doRequest(ctx context.Context, method, u string, body interface{}, result interface{}) error {
	return c.doRequestWithContentType(ctx, method, u, body, result, "application/taxii+json;version=2.1", "application/taxii+json;version=2.1")
}

// doRequestSTIX performs an HTTP request with STIX headers.
func (c *Client) doRequestSTIX(ctx context.Context, method, u string, body interface{}, result interface{}) error {
	return c.doRequestWithContentType(ctx, method, u, body, result, "application/stix+json;version=2.1", "application/stix+json;version=2.1")
}

// doRequestWithContentType performs an HTTP request with specified content types.
func (c *Client) doRequestWithContentType(ctx context.Context, method, u string, body interface{}, result interface{}, contentType, accept string) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return err
	}

	// Add authentication
	if c.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	} else if c.config.Username != "" && c.config.Password != "" {
		req.SetBasicAuth(c.config.Username, c.config.Password)
	}

	// Add headers
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", accept)

	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	// Execute with retry
	var resp *http.Response
	var lastErr error

	for i := 0; i <= c.config.RetryCount; i++ {
		resp, lastErr = c.httpClient.Do(req)
		if lastErr == nil {
			break
		}

		if i < c.config.RetryCount {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	if lastErr != nil {
		return fmt.Errorf("request failed after %d retries: %w", c.config.RetryCount, lastErr)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode >= 400 {
		return fmt.Errorf("TAXII error %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse result
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// Subscription represents a TAXII subscription for real-time updates.
type Subscription struct {
	client       *Client
	apiRoot      string
	collectionID string
	interval     time.Duration
	lastPoll     time.Time
	handler      func(json.RawMessage) error
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// Subscribe creates a new subscription for real-time updates.
func (c *Client) Subscribe(ctx context.Context, apiRoot, collectionID string, interval time.Duration, handler func(json.RawMessage) error) *Subscription {
	subCtx, cancel := context.WithCancel(ctx)

	return &Subscription{
		client:       c,
		apiRoot:      apiRoot,
		collectionID: collectionID,
		interval:     interval,
		lastPoll:     time.Now(),
		handler:      handler,
		ctx:          subCtx,
		cancel:       cancel,
	}
}

// Start starts the subscription.
func (s *Subscription) Start() {
	s.wg.Add(1)
	go s.poll()
}

// Stop stops the subscription.
func (s *Subscription) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Subscription) poll() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.client.StreamObjects(s.ctx, s.apiRoot, s.collectionID, s.lastPoll, s.handler); err != nil {
				s.client.logger.Error("poll failed", "error", err)
			}
			s.lastPoll = time.Now()
		}
	}
}
