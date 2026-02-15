// Package korea provides Korean Threat Intelligence integrations.
// KISA C-TAS (Cyber Threat Analysis System) client implementation.
package korea

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// KISAConfig holds KISA C-TAS API configuration.
type KISAConfig struct {
	BaseURL    string        `json:"base_url"`
	APIKey     string        `json:"api_key"`
	SecretKey  string        `json:"secret_key"`
	OrgCode    string        `json:"org_code"`
	Timeout    time.Duration `json:"timeout"`
	RetryCount int           `json:"retry_count"`
}

// DefaultKISAConfig returns default KISA configuration.
func DefaultKISAConfig() *KISAConfig {
	return &KISAConfig{
		BaseURL:    "https://ctas.kisa.or.kr/api/v1",
		Timeout:    30 * time.Second,
		RetryCount: 3,
	}
}

// KISAClient implements KISA C-TAS API client.
type KISAClient struct {
	config *KISAConfig
	client *http.Client
	logger *slog.Logger
}

// NewKISAClient creates a new KISA C-TAS client.
func NewKISAClient(config *KISAConfig, logger *slog.Logger) *KISAClient {
	if config == nil {
		config = DefaultKISAConfig()
	}

	return &KISAClient{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger.With("component", "kisa-client"),
	}
}

// ThreatInfo represents KISA threat intelligence information.
type ThreatInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`         // malicious_ip, malicious_domain, malicious_url, malware_hash
	Value       string    `json:"value"`        // IOC value
	ThreatType  string    `json:"threat_type"`  // c2, phishing, malware, botnet
	ThreatLevel string    `json:"threat_level"` // critical, high, medium, low
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

// MaliciousIP represents a KISA malicious IP entry.
type MaliciousIP struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	ASN         string    `json:"asn"`
	ASOrg       string    `json:"as_org"`
	ThreatType  string    `json:"threat_type"`
	Confidence  int       `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ReportCount int       `json:"report_count"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
}

// MaliciousDomain represents a KISA malicious domain entry.
type MaliciousDomain struct {
	Domain      string    `json:"domain"`
	ThreatType  string    `json:"threat_type"`
	Registrar   string    `json:"registrar,omitempty"`
	CreatedDate string    `json:"created_date,omitempty"`
	Confidence  int       `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ReportCount int       `json:"report_count"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	RelatedIPs  []string  `json:"related_ips,omitempty"`
}

// MaliciousURL represents a KISA malicious URL entry.
type MaliciousURL struct {
	URL          string    `json:"url"`
	Domain       string    `json:"domain"`
	ThreatType   string    `json:"threat_type"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	Confidence   int       `json:"confidence"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	ReportCount  int       `json:"report_count"`
	Description  string    `json:"description"`
	Tags         []string  `json:"tags"`
	RedirectChain []string `json:"redirect_chain,omitempty"`
}

// MalwareHash represents a KISA malware hash entry.
type MalwareHash struct {
	MD5          string    `json:"md5"`
	SHA1         string    `json:"sha1"`
	SHA256       string    `json:"sha256"`
	FileName     string    `json:"file_name,omitempty"`
	FileSize     int64     `json:"file_size,omitempty"`
	FileType     string    `json:"file_type,omitempty"`
	MalwareFamily string   `json:"malware_family,omitempty"`
	ThreatType   string    `json:"threat_type"`
	Confidence   int       `json:"confidence"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	AVDetections int       `json:"av_detections,omitempty"`
	Description  string    `json:"description"`
	Tags         []string  `json:"tags"`
	Behavior     []string  `json:"behavior,omitempty"`
}

// KISAResponse represents a generic KISA API response.
type KISAResponse struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
	Total   int         `json:"total,omitempty"`
	Page    int         `json:"page,omitempty"`
}

// GetThreatInfo retrieves threat intelligence from KISA C-TAS.
func (c *KISAClient) GetThreatInfo(ctx context.Context, params ThreatInfoParams) ([]ThreatInfo, error) {
	endpoint := "/threat/info"

	// Build query parameters
	query := url.Values{}
	if params.Type != "" {
		query.Set("type", params.Type)
	}
	if params.ThreatType != "" {
		query.Set("threat_type", params.ThreatType)
	}
	if !params.Since.IsZero() {
		query.Set("since", params.Since.Format(time.RFC3339))
	}
	if params.Limit > 0 {
		query.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Page > 0 {
		query.Set("page", strconv.Itoa(params.Page))
	}

	resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []ThreatInfo `json:"data"`
	}
	if err := json.Unmarshal(resp.Data.(json.RawMessage), &result.Data); err != nil {
		// Try direct unmarshal
		data, ok := resp.Data.([]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse threat info: %w", err)
		}

		jsonData, _ := json.Marshal(data)
		if err := json.Unmarshal(jsonData, &result.Data); err != nil {
			return nil, fmt.Errorf("failed to parse threat info: %w", err)
		}
	}

	c.logger.Info("fetched threat info from KISA", "count", len(result.Data))
	return result.Data, nil
}

// ThreatInfoParams holds parameters for GetThreatInfo.
type ThreatInfoParams struct {
	Type       string    // malicious_ip, malicious_domain, malicious_url, malware_hash
	ThreatType string    // c2, phishing, malware, botnet
	Since      time.Time // Fetch data since this time
	Limit      int
	Page       int
}

// GetMaliciousIPs retrieves malicious IP list from KISA.
func (c *KISAClient) GetMaliciousIPs(ctx context.Context, since time.Time, limit int) ([]MaliciousIP, error) {
	endpoint := "/threat/ip"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allIPs []MaliciousIP
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var ips []MaliciousIP
		if err := c.parseResponseData(resp, &ips); err != nil {
			return nil, err
		}

		if len(ips) == 0 {
			break
		}

		allIPs = append(allIPs, ips...)

		if limit > 0 && len(allIPs) >= limit {
			allIPs = allIPs[:limit]
			break
		}

		if resp.Total <= len(allIPs) {
			break
		}

		page++
	}

	c.logger.Info("fetched malicious IPs from KISA", "count", len(allIPs))
	return allIPs, nil
}

// GetMaliciousDomains retrieves malicious domain list from KISA.
func (c *KISAClient) GetMaliciousDomains(ctx context.Context, since time.Time, limit int) ([]MaliciousDomain, error) {
	endpoint := "/threat/domain"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allDomains []MaliciousDomain
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var domains []MaliciousDomain
		if err := c.parseResponseData(resp, &domains); err != nil {
			return nil, err
		}

		if len(domains) == 0 {
			break
		}

		allDomains = append(allDomains, domains...)

		if limit > 0 && len(allDomains) >= limit {
			allDomains = allDomains[:limit]
			break
		}

		if resp.Total <= len(allDomains) {
			break
		}

		page++
	}

	c.logger.Info("fetched malicious domains from KISA", "count", len(allDomains))
	return allDomains, nil
}

// GetMaliciousURLs retrieves malicious URL list from KISA.
func (c *KISAClient) GetMaliciousURLs(ctx context.Context, since time.Time, limit int) ([]MaliciousURL, error) {
	endpoint := "/threat/url"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allURLs []MaliciousURL
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var urls []MaliciousURL
		if err := c.parseResponseData(resp, &urls); err != nil {
			return nil, err
		}

		if len(urls) == 0 {
			break
		}

		allURLs = append(allURLs, urls...)

		if limit > 0 && len(allURLs) >= limit {
			allURLs = allURLs[:limit]
			break
		}

		if resp.Total <= len(allURLs) {
			break
		}

		page++
	}

	c.logger.Info("fetched malicious URLs from KISA", "count", len(allURLs))
	return allURLs, nil
}

// GetMalwareHashes retrieves malware hash list from KISA.
func (c *KISAClient) GetMalwareHashes(ctx context.Context, since time.Time, limit int) ([]MalwareHash, error) {
	endpoint := "/threat/hash"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allHashes []MalwareHash
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var hashes []MalwareHash
		if err := c.parseResponseData(resp, &hashes); err != nil {
			return nil, err
		}

		if len(hashes) == 0 {
			break
		}

		allHashes = append(allHashes, hashes...)

		if limit > 0 && len(allHashes) >= limit {
			allHashes = allHashes[:limit]
			break
		}

		if resp.Total <= len(allHashes) {
			break
		}

		page++
	}

	c.logger.Info("fetched malware hashes from KISA", "count", len(allHashes))
	return allHashes, nil
}

// LookupIP looks up an IP address in KISA C-TAS.
func (c *KISAClient) LookupIP(ctx context.Context, ip string) (*MaliciousIP, error) {
	endpoint := fmt.Sprintf("/threat/ip/%s", url.PathEscape(ip))

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	var result MaliciousIP
	if err := c.parseResponseData(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// LookupDomain looks up a domain in KISA C-TAS.
func (c *KISAClient) LookupDomain(ctx context.Context, domain string) (*MaliciousDomain, error) {
	endpoint := fmt.Sprintf("/threat/domain/%s", url.PathEscape(domain))

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	var result MaliciousDomain
	if err := c.parseResponseData(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// LookupHash looks up a file hash in KISA C-TAS.
func (c *KISAClient) LookupHash(ctx context.Context, hash string) (*MalwareHash, error) {
	endpoint := fmt.Sprintf("/threat/hash/%s", url.PathEscape(hash))

	resp, err := c.doRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	var result MalwareHash
	if err := c.parseResponseData(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ReportThreat reports a threat to KISA C-TAS.
func (c *KISAClient) ReportThreat(ctx context.Context, report ThreatReport) error {
	endpoint := "/threat/report"

	body, err := json.Marshal(report)
	if err != nil {
		return err
	}

	_, err = c.doRequest(ctx, "POST", endpoint, nil, body)
	if err != nil {
		return err
	}

	c.logger.Info("reported threat to KISA", "type", report.Type, "value", report.Value)
	return nil
}

// ThreatReport represents a threat report to KISA.
type ThreatReport struct {
	Type        string `json:"type"`         // ip, domain, url, hash
	Value       string `json:"value"`        // IOC value
	ThreatType  string `json:"threat_type"`  // c2, phishing, malware, botnet
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

// Test tests connectivity to KISA C-TAS.
func (c *KISAClient) Test(ctx context.Context) error {
	endpoint := "/status"

	_, err := c.doRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return fmt.Errorf("KISA C-TAS connectivity test failed: %w", err)
	}

	return nil
}

// doRequest performs an HTTP request to KISA API.
func (c *KISAClient) doRequest(ctx context.Context, method, endpoint string, query url.Values, body []byte) (*KISAResponse, error) {
	// Build URL
	u, err := url.Parse(c.config.BaseURL + endpoint)
	if err != nil {
		return nil, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	// Add authentication headers
	c.addAuthHeaders(req)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	// Execute request with retry
	var resp *http.Response
	var lastErr error

	for i := 0; i <= c.config.RetryCount; i++ {
		resp, lastErr = c.client.Do(req)
		if lastErr == nil {
			break
		}

		if i < c.config.RetryCount {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("request failed after %d retries: %w", c.config.RetryCount, lastErr)
	}
	defer resp.Body.Close()

	// Parse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("KISA API error: %s - %s", resp.Status, string(respBody))
	}

	var kisaResp KISAResponse
	if err := json.Unmarshal(respBody, &kisaResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if kisaResp.Code != "200" && kisaResp.Code != "success" && kisaResp.Code != "" {
		return nil, fmt.Errorf("KISA API error: %s - %s", kisaResp.Code, kisaResp.Message)
	}

	// Store raw data for later parsing
	kisaResp.Data = json.RawMessage(respBody)

	return &kisaResp, nil
}

// addAuthHeaders adds authentication headers to the request.
func (c *KISAClient) addAuthHeaders(req *http.Request) {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Generate HMAC signature
	message := fmt.Sprintf("%s%s%s", c.config.APIKey, timestamp, c.config.OrgCode)
	signature := c.generateSignature(message)

	req.Header.Set("X-API-Key", c.config.APIKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Org-Code", c.config.OrgCode)
}

// generateSignature generates HMAC-SHA256 signature.
func (c *KISAClient) generateSignature(message string) string {
	mac := hmac.New(sha256.New, []byte(c.config.SecretKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// parseResponseData parses the response data into the target struct.
func (c *KISAClient) parseResponseData(resp *KISAResponse, target interface{}) error {
	if resp.Data == nil {
		return nil
	}

	// Try to get the data field
	rawData, ok := resp.Data.(json.RawMessage)
	if !ok {
		// Already parsed, marshal and unmarshal
		data, err := json.Marshal(resp.Data)
		if err != nil {
			return err
		}
		rawData = data
	}

	// Parse the full response to get the data field
	var fullResp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rawData, &fullResp); err != nil {
		// Try direct unmarshal
		return json.Unmarshal(rawData, target)
	}

	if fullResp.Data != nil {
		return json.Unmarshal(fullResp.Data, target)
	}

	return json.Unmarshal(rawData, target)
}

// ConvertToIOC converts KISA threat data to IOC format.
func ConvertKISAToIOC(info ThreatInfo, feedID string) *IOC {
	iocType := mapKISATypeToIOCType(info.Type)

	return &IOC{
		ID:          fmt.Sprintf("kisa:%s", info.ID),
		Type:        iocType,
		Value:       info.Value,
		Source:      "KISA C-TAS",
		FeedID:      feedID,
		ThreatType:  mapKISAThreatType(info.ThreatType),
		Severity:    mapKISAThreatLevel(info.ThreatLevel),
		Confidence:  80, // KISA data is generally reliable
		FirstSeen:   info.FirstSeen,
		LastSeen:    info.LastSeen,
		Description: info.Description,
		Labels:      info.Tags,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// IOC represents an Indicator of Compromise (simplified for this package).
type IOC struct {
	ID          string
	Type        string
	Value       string
	Source      string
	FeedID      string
	ThreatType  string
	Severity    string
	Confidence  int
	FirstSeen   time.Time
	LastSeen    time.Time
	Description string
	Labels      []string
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func mapKISATypeToIOCType(kisaType string) string {
	switch strings.ToLower(kisaType) {
	case "malicious_ip", "ip":
		return "ip"
	case "malicious_domain", "domain":
		return "domain"
	case "malicious_url", "url":
		return "url"
	case "malware_hash", "hash", "md5", "sha1", "sha256":
		return "hash"
	default:
		return "other"
	}
}

func mapKISAThreatType(threat string) string {
	switch strings.ToLower(threat) {
	case "c2", "command_control":
		return "c2"
	case "phishing":
		return "phishing"
	case "malware":
		return "malware"
	case "botnet":
		return "botnet"
	case "ransomware":
		return "ransomware"
	case "apt":
		return "apt"
	default:
		return "unknown"
	}
}

func mapKISAThreatLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical", "1":
		return "critical"
	case "high", "2":
		return "high"
	case "medium", "3":
		return "medium"
	case "low", "4":
		return "low"
	default:
		return "medium"
	}
}
