// Package elastic provides Elasticsearch client implementation.
package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
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

// Client implements the Elasticsearch connector.
type Client struct {
	config     *Config
	httpClient *http.Client
	baseURL    string
	mu         sync.RWMutex
	connected  bool
	lastHealth *connector.ConnectorHealth
	clusterInfo *ClusterInfo
}

// ClusterInfo holds Elasticsearch cluster information.
type ClusterInfo struct {
	Name        string `json:"cluster_name"`
	UUID        string `json:"cluster_uuid"`
	Version     VersionInfo `json:"version"`
	Tagline     string `json:"tagline"`
}

// VersionInfo holds version information.
type VersionInfo struct {
	Number        string `json:"number"`
	BuildFlavor   string `json:"build_flavor"`
	BuildType     string `json:"build_type"`
	BuildHash     string `json:"build_hash"`
	BuildDate     string `json:"build_date"`
	BuildSnapshot bool   `json:"build_snapshot"`
	LuceneVersion string `json:"lucene_version"`
}

// NewClient creates a new Elasticsearch client.
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Base.TLS.SkipVerify,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Base.Timeout,
	}

	// Get base URL
	baseURL := ""
	if len(config.Addresses) > 0 {
		baseURL = strings.TrimSuffix(config.Addresses[0], "/")
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
		baseURL:    baseURL,
	}, nil
}

// Type returns the connector type.
func (c *Client) Type() connector.ConnectorType {
	return connector.TypeHTTP
}

// SIEM returns the SIEM type.
func (c *Client) SIEM() connector.SIEMType {
	return connector.SIEMElastic
}

// QueryLanguages returns supported query languages.
func (c *Client) QueryLanguages() []connector.QueryLanguage {
	return []connector.QueryLanguage{
		connector.QueryLanguageDSL,
		connector.QueryLanguageEQL,
	}
}

// Connect establishes a connection to Elasticsearch.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Test connection by getting cluster info
	info, err := c.getClusterInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.clusterInfo = info
	c.connected = true
	return nil
}

// getClusterInfo retrieves cluster information.
func (c *Client) getClusterInfo(ctx context.Context) (*ClusterInfo, error) {
	resp, err := c.doRequest(ctx, "GET", c.baseURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get cluster info: %s - %s", resp.Status, string(body))
	}

	var info ClusterInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse cluster info: %w", err)
	}

	return &info, nil
}

// Disconnect closes the connection.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
	c.clusterInfo = nil
	return nil
}

// Health returns the current health status.
func (c *Client) Health(ctx context.Context) (*connector.ConnectorHealth, error) {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return &connector.ConnectorHealth{
			Status:       connector.StatusInactive,
			ErrorMessage: "not connected",
		}, nil
	}

	start := time.Now()

	// Check cluster health
	healthURL := fmt.Sprintf("%s/_cluster/health", c.baseURL)
	resp, err := c.doRequest(ctx, "GET", healthURL, nil)
	if err != nil {
		return &connector.ConnectorHealth{
			Status:       connector.StatusError,
			ErrorMessage: err.Error(),
			LastCheck:    time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		return &connector.ConnectorHealth{
			Status:       connector.StatusError,
			ErrorMessage: fmt.Sprintf("cluster health returned %s", resp.Status),
			LastCheck:    time.Now(),
			Latency:      latency,
		}, nil
	}

	var clusterHealth struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clusterHealth); err != nil {
		return nil, err
	}

	status := connector.StatusActive
	if clusterHealth.Status == "red" {
		status = connector.StatusError
	}

	health := &connector.ConnectorHealth{
		Status:      status,
		LastCheck:   time.Now(),
		LastSuccess: time.Now(),
		Latency:     latency,
	}

	c.mu.Lock()
	c.lastHealth = health
	c.mu.Unlock()

	return health, nil
}

// IsConnected returns true if connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// doRequest performs an HTTP request with authentication.
func (c *Client) doRequest(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	// Set authentication
	creds := c.config.Base.Credentials
	switch creds.Type {
	case "basic":
		req.SetBasicAuth(creds.Username, creds.Password)
	case "api_key":
		req.Header.Set("Authorization", "ApiKey "+c.config.APIKey)
	case "token":
		req.Header.Set("Authorization", "Bearer "+creds.Token)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

// doJSONRequest performs a JSON request.
func (c *Client) doJSONRequest(ctx context.Context, method, urlStr string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	return c.doRequest(ctx, method, urlStr, bodyReader)
}

// GetClusterInfo returns the cluster information.
func (c *Client) GetClusterInfo() *ClusterInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clusterInfo
}

// GetClusterHealth returns detailed cluster health.
func (c *Client) GetClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	healthURL := fmt.Sprintf("%s/_cluster/health", c.baseURL)

	resp, err := c.doRequest(ctx, "GET", healthURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get cluster health: %s - %s", resp.Status, string(body))
	}

	var health ClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, err
	}

	return &health, nil
}

// ClusterHealth holds cluster health information.
type ClusterHealth struct {
	ClusterName                 string  `json:"cluster_name"`
	Status                      string  `json:"status"`
	TimedOut                    bool    `json:"timed_out"`
	NumberOfNodes               int     `json:"number_of_nodes"`
	NumberOfDataNodes           int     `json:"number_of_data_nodes"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	ActiveShards                int     `json:"active_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	DelayedUnassignedShards     int     `json:"delayed_unassigned_shards"`
	NumberOfPendingTasks        int     `json:"number_of_pending_tasks"`
	NumberOfInFlightFetch       int     `json:"number_of_in_flight_fetch"`
	TaskMaxWaitingInQueueMillis int     `json:"task_max_waiting_in_queue_millis"`
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

// ListIndices returns a list of indices.
func (c *Client) ListIndices(ctx context.Context, pattern string) ([]IndexInfo, error) {
	if pattern == "" {
		pattern = "*"
	}

	indexURL := fmt.Sprintf("%s/_cat/indices/%s?format=json", c.baseURL, url.PathEscape(pattern))

	resp, err := c.doRequest(ctx, "GET", indexURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list indices: %s - %s", resp.Status, string(body))
	}

	var indices []IndexInfo
	if err := json.NewDecoder(resp.Body).Decode(&indices); err != nil {
		return nil, err
	}

	return indices, nil
}

// IndexInfo holds index information.
type IndexInfo struct {
	Health       string `json:"health"`
	Status       string `json:"status"`
	Index        string `json:"index"`
	UUID         string `json:"uuid"`
	Pri          string `json:"pri"`
	Rep          string `json:"rep"`
	DocsCount    string `json:"docs.count"`
	DocsDeleted  string `json:"docs.deleted"`
	StoreSize    string `json:"store.size"`
	PriStoreSize string `json:"pri.store.size"`
}

// CreateIndex creates a new index.
func (c *Client) CreateIndex(ctx context.Context, name string, settings map[string]interface{}) error {
	indexURL := fmt.Sprintf("%s/%s", c.baseURL, url.PathEscape(name))

	resp, err := c.doJSONRequest(ctx, "PUT", indexURL, settings)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create index: %s - %s", resp.Status, string(body))
	}

	return nil
}

// DeleteIndex deletes an index.
func (c *Client) DeleteIndex(ctx context.Context, name string) error {
	indexURL := fmt.Sprintf("%s/%s", c.baseURL, url.PathEscape(name))

	resp, err := c.doRequest(ctx, "DELETE", indexURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete index: %s - %s", resp.Status, string(body))
	}

	return nil
}

// RefreshIndex refreshes an index.
func (c *Client) RefreshIndex(ctx context.Context, name string) error {
	refreshURL := fmt.Sprintf("%s/%s/_refresh", c.baseURL, url.PathEscape(name))

	resp, err := c.doRequest(ctx, "POST", refreshURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to refresh index: %s - %s", resp.Status, string(body))
	}

	return nil
}

// Factory creates a new Elasticsearch client from SIEM config.
func Factory(config *connector.SIEMConfig) (connector.SIEMConnector, error) {
	// Convert SIEMConfig to Elasticsearch-specific config
	esConfig := DefaultConfig()
	esConfig.Base = *config

	// Parse endpoint to get addresses
	if config.Endpoint != "" {
		esConfig.Addresses = []string{config.Endpoint}
	}

	// Apply extra config
	for k, v := range config.Extra {
		switch k {
		case "cloud_id":
			esConfig.CloudID = v
		case "api_key":
			esConfig.APIKey = v
		case "default_index":
			esConfig.Index.DefaultIndex = v
		case "data_stream":
			esConfig.Index.DataStream = v
		}
	}

	return NewClient(esConfig)
}

// init registers the Elasticsearch factory.
func init() {
	connector.GlobalRegistry().RegisterSIEMFactory(connector.SIEMElastic, Factory)
}
