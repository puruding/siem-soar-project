// Package feed provides TAXII 2.1 client implementation.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// TAXIIDiscovery represents a TAXII discovery response.
type TAXIIDiscovery struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Contact     string   `json:"contact,omitempty"`
	Default     string   `json:"default,omitempty"`
	APIRoots    []string `json:"api_roots"`
}

// TAXIIAPIRoot represents a TAXII API root.
type TAXIIAPIRoot struct {
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	Versions      []string `json:"versions"`
	MaxContentLength int64 `json:"max_content_length,omitempty"`
}

// TAXIICollection represents a TAXII collection.
type TAXIICollection struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	Alias         string   `json:"alias,omitempty"`
	CanRead       bool     `json:"can_read"`
	CanWrite      bool     `json:"can_write"`
	MediaTypes    []string `json:"media_types,omitempty"`
}

// TAXIICollections represents a TAXII collections response.
type TAXIICollections struct {
	Collections []TAXIICollection `json:"collections"`
}

// TAXIIEnvelope represents a TAXII envelope containing STIX objects.
type TAXIIEnvelope struct {
	More    bool            `json:"more,omitempty"`
	Next    string          `json:"next,omitempty"`
	Objects json.RawMessage `json:"objects,omitempty"`
}

// TAXIIStatus represents a TAXII status response.
type TAXIIStatus struct {
	ID                string    `json:"id"`
	Status            string    `json:"status"`
	RequestTimestamp  time.Time `json:"request_timestamp,omitempty"`
	TotalCount        int       `json:"total_count,omitempty"`
	SuccessCount      int       `json:"success_count,omitempty"`
	Successes         []string  `json:"successes,omitempty"`
	FailureCount      int       `json:"failure_count,omitempty"`
	Failures          []string  `json:"failures,omitempty"`
	PendingCount      int       `json:"pending_count,omitempty"`
	Pendings          []string  `json:"pendings,omitempty"`
}

// TAXIIClient implements a TAXII 2.1 client.
type TAXIIClient struct {
	client *http.Client
	logger *slog.Logger
	parser *STIXParser
}

// NewTAXIIClient creates a new TAXII client.
func NewTAXIIClient(logger *slog.Logger) *TAXIIClient {
	return &TAXIIClient{
		client: &http.Client{Timeout: 5 * time.Minute},
		logger: logger.With("component", "taxii-client"),
		parser: NewSTIXParser(logger),
	}
}

// Fetch fetches IOCs from a TAXII collection.
func (c *TAXIIClient) Fetch(ctx context.Context, feed *Feed, lastSync time.Time) ([]*IOC, error) {
	objectsURL := c.buildObjectsURL(feed)

	var allIOCs []*IOC
	next := ""

	for {
		url := objectsURL
		if next != "" {
			url = next
		}

		// Add filters
		url = c.addFilters(url, lastSync, feed.IOCTypes)

		envelope, err := c.fetchPage(ctx, url, feed)
		if err != nil {
			return nil, err
		}

		if envelope.Objects != nil {
			// Parse STIX objects
			var stixObjects []STIXObject
			if err := json.Unmarshal(envelope.Objects, &stixObjects); err != nil {
				c.logger.Warn("failed to parse STIX objects", "error", err)
			} else {
				iocs := c.parseObjects(stixObjects, feed.ID)
				allIOCs = append(allIOCs, iocs...)
			}
		}

		if !envelope.More || envelope.Next == "" {
			break
		}
		next = envelope.Next
	}

	c.logger.Info("fetched IOCs from TAXII", "count", len(allIOCs), "collection", feed.CollectionID)
	return allIOCs, nil
}

// Test tests connectivity to a TAXII server.
func (c *TAXIIClient) Test(ctx context.Context, feed *Feed) error {
	// Try discovery endpoint
	discoveryURL, err := c.getDiscoveryURL(feed.URL)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return err
	}

	c.addAuthHeaders(req, feed)
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to TAXII server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("TAXII server returned status %d", resp.StatusCode)
	}

	return nil
}

// Discover performs TAXII discovery.
func (c *TAXIIClient) Discover(ctx context.Context, baseURL, apiKey string) (*TAXIIDiscovery, error) {
	discoveryURL, err := c.getDiscoveryURL(baseURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed: %d", resp.StatusCode)
	}

	var discovery TAXIIDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, err
	}

	return &discovery, nil
}

// GetAPIRoot gets information about an API root.
func (c *TAXIIClient) GetAPIRoot(ctx context.Context, apiRootURL, apiKey string) (*TAXIIAPIRoot, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiRootURL, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get API root failed: %d", resp.StatusCode)
	}

	var apiRoot TAXIIAPIRoot
	if err := json.NewDecoder(resp.Body).Decode(&apiRoot); err != nil {
		return nil, err
	}

	return &apiRoot, nil
}

// ListCollections lists collections in an API root.
func (c *TAXIIClient) ListCollections(ctx context.Context, apiRootURL, apiKey string) ([]TAXIICollection, error) {
	collectionsURL := apiRootURL + "/collections/"

	req, err := http.NewRequestWithContext(ctx, "GET", collectionsURL, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list collections failed: %d", resp.StatusCode)
	}

	var collections TAXIICollections
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return nil, err
	}

	return collections.Collections, nil
}

// GetCollection gets a specific collection.
func (c *TAXIIClient) GetCollection(ctx context.Context, feed *Feed) (*TAXIICollection, error) {
	collectionURL := c.buildCollectionURL(feed)

	req, err := http.NewRequestWithContext(ctx, "GET", collectionURL, nil)
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, feed)
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get collection failed: %d", resp.StatusCode)
	}

	var collection TAXIICollection
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return nil, err
	}

	return &collection, nil
}

func (c *TAXIIClient) fetchPage(ctx context.Context, url string, feed *Feed) (*TAXIIEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, feed)
	req.Header.Set("Accept", "application/stix+json;version=2.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TAXII objects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("TAXII server returned %d: %s", resp.StatusCode, string(body))
	}

	var envelope TAXIIEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to parse TAXII envelope: %w", err)
	}

	return &envelope, nil
}

func (c *TAXIIClient) buildObjectsURL(feed *Feed) string {
	// feed.URL should be the API root URL
	return fmt.Sprintf("%s/collections/%s/objects/", feed.URL, feed.CollectionID)
}

func (c *TAXIIClient) buildCollectionURL(feed *Feed) string {
	return fmt.Sprintf("%s/collections/%s/", feed.URL, feed.CollectionID)
}

func (c *TAXIIClient) getDiscoveryURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Try standard discovery path
	u.Path = "/taxii2/"
	return u.String(), nil
}

func (c *TAXIIClient) addAuthHeaders(req *http.Request, feed *Feed) {
	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	} else if feed.Username != "" && feed.Password != "" {
		req.SetBasicAuth(feed.Username, feed.Password)
	}

	for k, v := range feed.Headers {
		req.Header.Set(k, v)
	}
}

func (c *TAXIIClient) addFilters(baseURL string, addedAfter time.Time, types []string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	q := u.Query()

	// Add added_after filter if we have a last sync time
	if !addedAfter.IsZero() {
		q.Set("added_after", addedAfter.Format(time.RFC3339))
	}

	// Filter by object types (indicators)
	q.Set("type", "indicator")

	u.RawQuery = q.Encode()
	return u.String()
}

func (c *TAXIIClient) parseObjects(objects []STIXObject, feedID string) []*IOC {
	var iocs []*IOC

	// Build object map for relationship resolution
	objectMap := make(map[string]*STIXObject)
	for i := range objects {
		objectMap[objects[i].ID] = &objects[i]
	}

	for _, obj := range objects {
		if obj.Type == "indicator" {
			parsedIOCs := c.parser.parseIndicator(&obj, feedID, objectMap)
			iocs = append(iocs, parsedIOCs...)
		}
	}

	return iocs
}
