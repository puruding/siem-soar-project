// Package sentinel provides Microsoft Sentinel client implementation.
package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"siem-soar-project/pkg/connector"
)

// Client implements the Microsoft Sentinel connector.
type Client struct {
	config      *Config
	httpClient  *http.Client
	tokenCache  *TokenCache
	mu          sync.RWMutex
	connected   bool
	lastHealth  *connector.ConnectorHealth
}

// TokenCache holds Azure AD tokens.
type TokenCache struct {
	AccessToken string
	ExpiresAt   time.Time
	mu          sync.RWMutex
}

// AzureToken represents an Azure AD token response.
type AzureToken struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// NewClient creates a new Sentinel client.
func NewClient(config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	httpClient := &http.Client{
		Timeout: config.Base.Timeout,
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
		tokenCache: &TokenCache{},
	}, nil
}

// Type returns the connector type.
func (c *Client) Type() connector.ConnectorType {
	return connector.TypeCloud
}

// SIEM returns the SIEM type.
func (c *Client) SIEM() connector.SIEMType {
	return connector.SIEMSentinel
}

// QueryLanguages returns supported query languages.
func (c *Client) QueryLanguages() []connector.QueryLanguage {
	return []connector.QueryLanguage{connector.QueryLanguageKQL}
}

// Connect establishes a connection to Sentinel.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Authenticate and get token
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.connected = true
	return nil
}

// authenticate obtains an Azure AD token.
func (c *Client) authenticate(ctx context.Context) error {
	if c.config.UseManagedIdentity {
		return c.authenticateManagedIdentity(ctx)
	}
	return c.authenticateClientCredentials(ctx)
}

// authenticateClientCredentials obtains a token using client credentials.
func (c *Client) authenticateClientCredentials(ctx context.Context) error {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.config.TenantID)

	data := url.Values{}
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)
	data.Set("scope", "https://management.azure.com/.default")
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBufferString(data.Encode()))
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
		return fmt.Errorf("token request failed: %s - %s", resp.Status, string(body))
	}

	var token AzureToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	c.tokenCache.mu.Lock()
	c.tokenCache.AccessToken = token.AccessToken
	c.tokenCache.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)
	c.tokenCache.mu.Unlock()

	return nil
}

// authenticateManagedIdentity obtains a token using managed identity.
func (c *Client) authenticateManagedIdentity(ctx context.Context) error {
	// Azure IMDS endpoint for managed identity
	tokenURL := "http://169.254.169.254/metadata/identity/oauth2/token"
	tokenURL += "?api-version=2019-08-01"
	tokenURL += "&resource=" + url.QueryEscape("https://management.azure.com/")

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Metadata", "true")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("managed identity token request failed: %s - %s", resp.Status, string(body))
	}

	var token AzureToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	c.tokenCache.mu.Lock()
	c.tokenCache.AccessToken = token.AccessToken
	c.tokenCache.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)
	c.tokenCache.mu.Unlock()

	return nil
}

// getToken returns a valid access token, refreshing if necessary.
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.tokenCache.mu.RLock()
	token := c.tokenCache.AccessToken
	expiresAt := c.tokenCache.ExpiresAt
	c.tokenCache.mu.RUnlock()

	if token != "" && time.Now().Before(expiresAt) {
		return token, nil
	}

	// Token expired or not set, refresh
	if err := c.authenticate(ctx); err != nil {
		return "", err
	}

	c.tokenCache.mu.RLock()
	token = c.tokenCache.AccessToken
	c.tokenCache.mu.RUnlock()

	return token, nil
}

// Disconnect closes the connection.
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
	c.tokenCache.mu.Lock()
	c.tokenCache.AccessToken = ""
	c.tokenCache.ExpiresAt = time.Time{}
	c.tokenCache.mu.Unlock()

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

	// Try to get workspace info to verify connection
	_, err := c.getWorkspaceInfo(ctx)
	latency := time.Since(start)

	if err != nil {
		return &connector.ConnectorHealth{
			Status:       connector.StatusError,
			ErrorMessage: err.Error(),
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

// getWorkspaceInfo retrieves workspace information.
func (c *Client) getWorkspaceInfo(ctx context.Context) (map[string]interface{}, error) {
	workspaceURL := fmt.Sprintf(
		"%s%s?api-version=2021-12-01-preview",
		c.config.GetAzureResourceManagerURL(),
		c.config.GetSentinelResourceID(),
	)

	resp, err := c.doRequest(ctx, "GET", workspaceURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get workspace info: %s - %s", resp.Status, string(body))
	}

	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return info, nil
}

// IsConnected returns true if connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// doRequest performs an HTTP request with authentication.
func (c *Client) doRequest(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
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

// Factory creates a new Sentinel client from SIEM config.
func Factory(config *connector.SIEMConfig) (connector.SIEMConnector, error) {
	// Convert SIEMConfig to Sentinel-specific config
	sentinelConfig := DefaultConfig()
	sentinelConfig.Base = *config

	// Apply credentials
	creds := config.Credentials
	sentinelConfig.TenantID = creds.TenantID
	sentinelConfig.ClientID = creds.ClientID
	sentinelConfig.ClientSecret = creds.ClientSecret
	sentinelConfig.SubscriptionID = creds.SubscriptionID
	sentinelConfig.ResourceGroup = creds.ResourceGroup
	sentinelConfig.WorkspaceID = creds.WorkspaceID

	// Apply extra config
	for k, v := range config.Extra {
		switch k {
		case "workspace_name":
			sentinelConfig.WorkspaceName = v
		case "use_managed_identity":
			sentinelConfig.UseManagedIdentity = v == "true"
		case "event_hub_namespace":
			sentinelConfig.EventHub.Namespace = v
			sentinelConfig.EventHub.Enabled = true
		case "event_hub_name":
			sentinelConfig.EventHub.Name = v
		case "event_hub_connection_string":
			sentinelConfig.EventHub.ConnectionString = v
		case "dce_endpoint":
			sentinelConfig.DataCollection.Endpoint = v
			sentinelConfig.DataCollection.Enabled = true
		case "dcr_id":
			sentinelConfig.DataCollection.RuleID = v
		case "stream_name":
			sentinelConfig.DataCollection.StreamName = v
		}
	}

	return NewClient(sentinelConfig)
}

// init registers the Sentinel factory.
func init() {
	connector.GlobalRegistry().RegisterSIEMFactory(connector.SIEMSentinel, Factory)
}
