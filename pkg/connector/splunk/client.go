// Package splunk provides Splunk REST API client implementation.
package splunk

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

// Client implements the Splunk connector.
type Client struct {
	config     *Config
	httpClient *http.Client
	sessionKey string
	mu         sync.RWMutex
	connected  bool
	lastHealth *connector.ConnectorHealth
}

// NewClient creates a new Splunk client.
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Base.TLS.SkipVerify,
	}
	if config.Base.TLS.MinVersion != "" {
		// Set minimum TLS version
		switch config.Base.TLS.MinVersion {
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        config.MaxIdleConns,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Base.Timeout,
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// Type returns the connector type.
func (c *Client) Type() connector.ConnectorType {
	return connector.TypeHTTP
}

// SIEM returns the SIEM type.
func (c *Client) SIEM() connector.SIEMType {
	return connector.SIEMSplunk
}

// QueryLanguages returns supported query languages.
func (c *Client) QueryLanguages() []connector.QueryLanguage {
	return []connector.QueryLanguage{connector.QueryLanguageSPL}
}

// Connect establishes a connection to Splunk.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Authenticate based on credential type
	creds := c.config.Base.Credentials
	switch creds.Type {
	case "basic":
		if err := c.authenticateBasic(ctx, creds.Username, creds.Password); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	case "token":
		c.sessionKey = creds.Token
	default:
		return fmt.Errorf("unsupported credential type: %s", creds.Type)
	}

	c.connected = true
	return nil
}

// authenticateBasic performs basic authentication and obtains a session key.
func (c *Client) authenticateBasic(ctx context.Context, username, password string) error {
	authURL := fmt.Sprintf("%s/services/auth/login", c.config.GetManagementURL())

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: %s - %s", resp.Status, string(body))
	}

	var authResp struct {
		SessionKey string `json:"sessionKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	c.sessionKey = authResp.SessionKey
	return nil
}

// Disconnect closes the connection.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
	c.sessionKey = ""
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

	// Check server info
	infoURL := fmt.Sprintf("%s/services/server/info?output_mode=json", c.config.GetManagementURL())
	req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeader(req)

	resp, err := c.httpClient.Do(req)
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
			ErrorMessage: fmt.Sprintf("server returned %s", resp.Status),
			LastCheck:    time.Now(),
			Latency:      latency,
		}, nil
	}

	health := &connector.ConnectorHealth{
		Status:      connector.StatusActive,
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

// setAuthHeader sets the authorization header on a request.
func (c *Client) setAuthHeader(req *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.sessionKey != "" {
		req.Header.Set("Authorization", "Splunk "+c.sessionKey)
	}
}

// doRequest performs an HTTP request with authentication.
func (c *Client) doRequest(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

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

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return c.httpClient.Do(req)
}

// GetServerInfo returns Splunk server information.
func (c *Client) GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	infoURL := fmt.Sprintf("%s/services/server/info?output_mode=json", c.config.GetManagementURL())

	resp, err := c.doRequest(ctx, "GET", infoURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get server info: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Entry []struct {
			Content ServerInfo `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse server info: %w", err)
	}

	if len(result.Entry) == 0 {
		return nil, fmt.Errorf("no server info returned")
	}

	return &result.Entry[0].Content, nil
}

// ServerInfo contains Splunk server information.
type ServerInfo struct {
	ServerName     string `json:"serverName"`
	Version        string `json:"version"`
	Build          string `json:"build"`
	GUID           string `json:"guid"`
	IsFree         bool   `json:"isFree"`
	IsTrial        bool   `json:"isTrial"`
	LicenseState   string `json:"licenseState"`
	Mode           string `json:"mode"`
	OS             string `json:"os_name"`
	OSVersion      string `json:"os_version"`
	CPUArch        string `json:"cpu_arch"`
	NumberOfCores  int    `json:"numberOfCores"`
	PhysicalMemory int64  `json:"physicalMemoryMB"`
}

// ListIndexes returns a list of available indexes.
func (c *Client) ListIndexes(ctx context.Context) ([]IndexInfo, error) {
	indexURL := fmt.Sprintf("%s/services/data/indexes?output_mode=json", c.config.GetManagementURL())

	resp, err := c.doRequest(ctx, "GET", indexURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list indexes: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Entry []struct {
			Name    string    `json:"name"`
			Content IndexInfo `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse index list: %w", err)
	}

	indexes := make([]IndexInfo, len(result.Entry))
	for i, entry := range result.Entry {
		indexes[i] = entry.Content
		indexes[i].Name = entry.Name
	}

	return indexes, nil
}

// IndexInfo contains information about a Splunk index.
type IndexInfo struct {
	Name                string `json:"name"`
	DataType            string `json:"datatype"`
	TotalEventCount     int64  `json:"totalEventCount"`
	CurrentDBSizeMB     int64  `json:"currentDBSizeMB"`
	MaxDataSizeMB       int64  `json:"maxDataSizeMB"`
	MaxWarmDBCount      int    `json:"maxWarmDBCount"`
	MinTime             string `json:"minTime"`
	MaxTime             string `json:"maxTime"`
	FrozenTimePeriodSecs int64 `json:"frozenTimePeriodInSecs"`
	Disabled            bool   `json:"disabled"`
}

// ListSavedSearches returns a list of saved searches.
func (c *Client) ListSavedSearches(ctx context.Context) ([]SavedSearch, error) {
	searchURL := fmt.Sprintf("%s/servicesNS/-/%s/saved/searches?output_mode=json&count=0",
		c.config.GetManagementURL(),
		c.config.App,
	)

	resp, err := c.doRequest(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list saved searches: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Entry []struct {
			Name    string      `json:"name"`
			Content SavedSearch `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse saved searches: %w", err)
	}

	searches := make([]SavedSearch, len(result.Entry))
	for i, entry := range result.Entry {
		searches[i] = entry.Content
		searches[i].Name = entry.Name
	}

	return searches, nil
}

// SavedSearch contains information about a Splunk saved search.
type SavedSearch struct {
	Name              string `json:"name"`
	Search            string `json:"search"`
	Description       string `json:"description,omitempty"`
	CronSchedule      string `json:"cron_schedule,omitempty"`
	IsScheduled       bool   `json:"is_scheduled"`
	Disabled          bool   `json:"disabled"`
	EarliestTime      string `json:"dispatch.earliest_time,omitempty"`
	LatestTime        string `json:"dispatch.latest_time,omitempty"`
	Actions           string `json:"actions,omitempty"`
	AlertType         string `json:"alert_type,omitempty"`
	AlertSeverity     int    `json:"alert.severity,omitempty"`
	AlertThreshold    string `json:"alert_threshold,omitempty"`
	AlertComparator   string `json:"alert_comparator,omitempty"`
	NextScheduledTime string `json:"next_scheduled_time,omitempty"`
}

// RunSavedSearch executes a saved search.
func (c *Client) RunSavedSearch(ctx context.Context, name string, args map[string]string) (string, error) {
	searchURL := fmt.Sprintf("%s/servicesNS/-/%s/saved/searches/%s/dispatch",
		c.config.GetManagementURL(),
		c.config.App,
		url.PathEscape(name),
	)

	data := url.Values{}
	data.Set("output_mode", "json")
	for k, v := range args {
		data.Set(k, v)
	}

	resp, err := c.doRequest(ctx, "POST", searchURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to run saved search: %s - %s", resp.Status, string(body))
	}

	var result struct {
		SID string `json:"sid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse dispatch response: %w", err)
	}

	return result.SID, nil
}

// Factory creates a new Splunk client from SIEM config.
func Factory(config *connector.SIEMConfig) (connector.SIEMConnector, error) {
	// Convert SIEMConfig to Splunk-specific config
	splunkConfig := DefaultConfig()
	splunkConfig.Base = *config

	// Parse endpoint to get host and port
	if config.Endpoint != "" {
		u, err := url.Parse(config.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint URL: %w", err)
		}
		splunkConfig.Host = u.Hostname()
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &splunkConfig.Port)
		}
		splunkConfig.Scheme = u.Scheme
	}

	// Apply extra config
	for k, v := range config.Extra {
		switch k {
		case "app":
			splunkConfig.App = v
		case "hec_token":
			splunkConfig.HEC.Token = v
			splunkConfig.HEC.Enabled = true
		case "hec_index":
			splunkConfig.HEC.Index = v
		}
	}

	return NewClient(splunkConfig)
}

// init registers the Splunk factory.
func init() {
	connector.GlobalRegistry().RegisterSIEMFactory(connector.SIEMSplunk, Factory)
}
