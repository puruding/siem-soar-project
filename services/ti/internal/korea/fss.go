// Package korea provides Korean Threat Intelligence integrations.
// FSS (Financial Security Service / 금융보안원) client implementation.
package korea

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FSSConfig holds FSS API configuration.
type FSSConfig struct {
	BaseURL       string        `json:"base_url"`
	APIKey        string        `json:"api_key"`
	CertPath      string        `json:"cert_path"`
	CertPassword  string        `json:"cert_password"`
	InstitutionID string        `json:"institution_id"`
	Timeout       time.Duration `json:"timeout"`
	RetryCount    int           `json:"retry_count"`
	UseTLS        bool          `json:"use_tls"`
}

// DefaultFSSConfig returns default FSS configuration.
func DefaultFSSConfig() *FSSConfig {
	return &FSSConfig{
		BaseURL:    "https://api.fss.or.kr/api/v1",
		Timeout:    30 * time.Second,
		RetryCount: 3,
		UseTLS:     true,
	}
}

// FSSClient implements FSS (Financial Security Service) API client.
type FSSClient struct {
	config *FSSConfig
	client *http.Client
	logger *slog.Logger
}

// NewFSSClient creates a new FSS client.
func NewFSSClient(config *FSSConfig, logger *slog.Logger) *FSSClient {
	if config == nil {
		config = DefaultFSSConfig()
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Configure TLS if needed
	if config.UseTLS {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	return &FSSClient{
		config: config,
		client: httpClient,
		logger: logger.With("component", "fss-client"),
	}
}

// FinancialThreat represents a financial sector threat.
type FinancialThreat struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"` // phishing_site, malware, fraud_ip, smishing
	Value        string                 `json:"value"`
	ThreatLevel  string                 `json:"threat_level"`
	Category     string                 `json:"category"` // banking, securities, insurance, payment
	Description  string                 `json:"description"`
	TargetOrgs   []string               `json:"target_orgs,omitempty"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	ReportDate   time.Time              `json:"report_date"`
	Status       string                 `json:"status"` // active, blocked, resolved
	Evidence     []string               `json:"evidence,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// PhishingSite represents a phishing site targeting financial institutions.
type PhishingSite struct {
	URL           string    `json:"url"`
	Domain        string    `json:"domain"`
	IP            string    `json:"ip,omitempty"`
	TargetOrg     string    `json:"target_org"`     // Impersonated organization
	TargetType    string    `json:"target_type"`    // banking, card, securities
	DetectionDate time.Time `json:"detection_date"`
	BlockDate     time.Time `json:"block_date,omitempty"`
	Status        string    `json:"status"`
	SimilarityScore float64 `json:"similarity_score,omitempty"`
	Screenshots   []string  `json:"screenshots,omitempty"`
	Registrar     string    `json:"registrar,omitempty"`
	SSLInfo       *SSLInfo  `json:"ssl_info,omitempty"`
}

// SSLInfo represents SSL certificate information.
type SSLInfo struct {
	Issuer     string    `json:"issuer"`
	Subject    string    `json:"subject"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	Serial     string    `json:"serial"`
}

// FraudIP represents a fraudulent IP address.
type FraudIP struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	ASN         string    `json:"asn"`
	FraudType   string    `json:"fraud_type"` // account_takeover, payment_fraud, identity_theft
	RiskScore   int       `json:"risk_score"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ReportCount int       `json:"report_count"`
	BlockedBy   []string  `json:"blocked_by,omitempty"`
	RelatedIOCs []string  `json:"related_iocs,omitempty"`
}

// SmishingMessage represents a smishing (SMS phishing) message.
type SmishingMessage struct {
	Hash          string    `json:"hash"` // Hash of the message content
	SenderNumber  string    `json:"sender_number,omitempty"`
	MessageText   string    `json:"message_text"`
	MaliciousURL  string    `json:"malicious_url,omitempty"`
	TargetType    string    `json:"target_type"` // banking, delivery, government
	DetectionDate time.Time `json:"detection_date"`
	ReportCount   int       `json:"report_count"`
	Keywords      []string  `json:"keywords,omitempty"`
}

// FinancialMalware represents malware targeting financial sector.
type FinancialMalware struct {
	MD5           string    `json:"md5"`
	SHA256        string    `json:"sha256"`
	FileName      string    `json:"file_name,omitempty"`
	FileSize      int64     `json:"file_size,omitempty"`
	MalwareFamily string    `json:"malware_family"`
	MalwareType   string    `json:"malware_type"` // banker, rat, stealer, ransomware
	TargetOS      string    `json:"target_os"`
	Capabilities  []string  `json:"capabilities,omitempty"`
	C2Servers     []string  `json:"c2_servers,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	AVDetections  int       `json:"av_detections"`
	YaraRules     []string  `json:"yara_rules,omitempty"`
}

// SecurityIncident represents a financial sector security incident.
type SecurityIncident struct {
	ID           string    `json:"id"`
	IncidentType string    `json:"incident_type"`
	Severity     string    `json:"severity"`
	AffectedOrgs []string  `json:"affected_orgs"`
	Description  string    `json:"description"`
	IOCs         []string  `json:"iocs,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
	ReportedAt   time.Time `json:"reported_at"`
	Status       string    `json:"status"`
	Mitigations  []string  `json:"mitigations,omitempty"`
}

// FSSResponse represents a generic FSS API response.
type FSSResponse struct {
	ResultCode    string      `json:"result_code" xml:"ResultCode"`
	ResultMessage string      `json:"result_message" xml:"ResultMessage"`
	Data          interface{} `json:"data" xml:"Data"`
	TotalCount    int         `json:"total_count" xml:"TotalCount"`
	PageNo        int         `json:"page_no" xml:"PageNo"`
	PageSize      int         `json:"page_size" xml:"PageSize"`
}

// GetFinancialThreats retrieves financial sector threats.
func (c *FSSClient) GetFinancialThreats(ctx context.Context, params FinancialThreatParams) ([]FinancialThreat, error) {
	endpoint := "/threats/financial"

	query := url.Values{}
	if params.Type != "" {
		query.Set("type", params.Type)
	}
	if params.Category != "" {
		query.Set("category", params.Category)
	}
	if !params.Since.IsZero() {
		query.Set("since", params.Since.Format(time.RFC3339))
	}
	if params.Limit > 0 {
		query.Set("limit", strconv.Itoa(params.Limit))
	}

	resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
	if err != nil {
		return nil, err
	}

	var threats []FinancialThreat
	if err := c.parseResponseData(resp, &threats); err != nil {
		return nil, err
	}

	c.logger.Info("fetched financial threats from FSS", "count", len(threats))
	return threats, nil
}

// FinancialThreatParams holds parameters for GetFinancialThreats.
type FinancialThreatParams struct {
	Type     string    // phishing_site, malware, fraud_ip, smishing
	Category string    // banking, securities, insurance, payment
	Since    time.Time
	Limit    int
}

// GetPhishingSites retrieves phishing sites targeting financial institutions.
func (c *FSSClient) GetPhishingSites(ctx context.Context, since time.Time, limit int) ([]PhishingSite, error) {
	endpoint := "/threats/phishing"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allSites []PhishingSite
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var sites []PhishingSite
		if err := c.parseResponseData(resp, &sites); err != nil {
			return nil, err
		}

		if len(sites) == 0 {
			break
		}

		allSites = append(allSites, sites...)

		if limit > 0 && len(allSites) >= limit {
			allSites = allSites[:limit]
			break
		}

		if resp.TotalCount <= len(allSites) {
			break
		}

		page++
	}

	c.logger.Info("fetched phishing sites from FSS", "count", len(allSites))
	return allSites, nil
}

// GetFraudIPs retrieves fraudulent IP addresses.
func (c *FSSClient) GetFraudIPs(ctx context.Context, since time.Time, limit int) ([]FraudIP, error) {
	endpoint := "/threats/fraud-ip"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allIPs []FraudIP
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var ips []FraudIP
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

		if resp.TotalCount <= len(allIPs) {
			break
		}

		page++
	}

	c.logger.Info("fetched fraud IPs from FSS", "count", len(allIPs))
	return allIPs, nil
}

// GetSmishingMessages retrieves smishing (SMS phishing) messages.
func (c *FSSClient) GetSmishingMessages(ctx context.Context, since time.Time, limit int) ([]SmishingMessage, error) {
	endpoint := "/threats/smishing"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allMessages []SmishingMessage
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var messages []SmishingMessage
		if err := c.parseResponseData(resp, &messages); err != nil {
			return nil, err
		}

		if len(messages) == 0 {
			break
		}

		allMessages = append(allMessages, messages...)

		if limit > 0 && len(allMessages) >= limit {
			allMessages = allMessages[:limit]
			break
		}

		if resp.TotalCount <= len(allMessages) {
			break
		}

		page++
	}

	c.logger.Info("fetched smishing messages from FSS", "count", len(allMessages))
	return allMessages, nil
}

// GetFinancialMalware retrieves malware targeting financial sector.
func (c *FSSClient) GetFinancialMalware(ctx context.Context, since time.Time, limit int) ([]FinancialMalware, error) {
	endpoint := "/threats/malware"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	var allMalware []FinancialMalware
	page := 1

	for {
		query.Set("page", strconv.Itoa(page))

		resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
		if err != nil {
			return nil, err
		}

		var malware []FinancialMalware
		if err := c.parseResponseData(resp, &malware); err != nil {
			return nil, err
		}

		if len(malware) == 0 {
			break
		}

		allMalware = append(allMalware, malware...)

		if limit > 0 && len(allMalware) >= limit {
			allMalware = allMalware[:limit]
			break
		}

		if resp.TotalCount <= len(allMalware) {
			break
		}

		page++
	}

	c.logger.Info("fetched financial malware from FSS", "count", len(allMalware))
	return allMalware, nil
}

// GetSecurityIncidents retrieves security incidents.
func (c *FSSClient) GetSecurityIncidents(ctx context.Context, since time.Time, limit int) ([]SecurityIncident, error) {
	endpoint := "/incidents"

	query := url.Values{}
	if !since.IsZero() {
		query.Set("since", since.Format(time.RFC3339))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}

	resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
	if err != nil {
		return nil, err
	}

	var incidents []SecurityIncident
	if err := c.parseResponseData(resp, &incidents); err != nil {
		return nil, err
	}

	c.logger.Info("fetched security incidents from FSS", "count", len(incidents))
	return incidents, nil
}

// LookupPhishingSite looks up a URL in FSS phishing database.
func (c *FSSClient) LookupPhishingSite(ctx context.Context, urlStr string) (*PhishingSite, error) {
	endpoint := "/threats/phishing/lookup"

	query := url.Values{}
	query.Set("url", urlStr)

	resp, err := c.doRequest(ctx, "GET", endpoint, query, nil)
	if err != nil {
		return nil, err
	}

	var site PhishingSite
	if err := c.parseResponseData(resp, &site); err != nil {
		return nil, err
	}

	return &site, nil
}

// ReportPhishingSite reports a phishing site to FSS.
func (c *FSSClient) ReportPhishingSite(ctx context.Context, report PhishingReport) error {
	endpoint := "/threats/phishing/report"

	body, err := json.Marshal(report)
	if err != nil {
		return err
	}

	_, err = c.doRequest(ctx, "POST", endpoint, nil, body)
	if err != nil {
		return err
	}

	c.logger.Info("reported phishing site to FSS", "url", report.URL)
	return nil
}

// PhishingReport represents a phishing site report.
type PhishingReport struct {
	URL           string   `json:"url"`
	TargetOrg     string   `json:"target_org"`
	TargetType    string   `json:"target_type"`
	Description   string   `json:"description,omitempty"`
	DetectedAt    string   `json:"detected_at,omitempty"`
	Evidence      []string `json:"evidence,omitempty"`
	Screenshots   []string `json:"screenshots,omitempty"`
	ReporterOrg   string   `json:"reporter_org,omitempty"`
	ReporterEmail string   `json:"reporter_email,omitempty"`
}

// Test tests connectivity to FSS API.
func (c *FSSClient) Test(ctx context.Context) error {
	endpoint := "/status"

	_, err := c.doRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return fmt.Errorf("FSS connectivity test failed: %w", err)
	}

	return nil
}

// doRequest performs an HTTP request to FSS API.
func (c *FSSClient) doRequest(ctx context.Context, method, endpoint string, query url.Values, body []byte) (*FSSResponse, error) {
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
		return nil, fmt.Errorf("FSS API error: %s - %s", resp.Status, string(respBody))
	}

	var fssResp FSSResponse

	// Try JSON first, then XML
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "xml") {
		if err := xml.Unmarshal(respBody, &fssResp); err != nil {
			return nil, fmt.Errorf("failed to parse XML response: %w", err)
		}
	} else {
		if err := json.Unmarshal(respBody, &fssResp); err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}
	}

	if fssResp.ResultCode != "00" && fssResp.ResultCode != "200" && fssResp.ResultCode != "" {
		return nil, fmt.Errorf("FSS API error: %s - %s", fssResp.ResultCode, fssResp.ResultMessage)
	}

	// Store raw data for later parsing
	fssResp.Data = json.RawMessage(respBody)

	return &fssResp, nil
}

// addAuthHeaders adds authentication headers to the request.
func (c *FSSClient) addAuthHeaders(req *http.Request) {
	req.Header.Set("X-API-Key", c.config.APIKey)
	req.Header.Set("X-Institution-ID", c.config.InstitutionID)
}

// parseResponseData parses the response data into the target struct.
func (c *FSSClient) parseResponseData(resp *FSSResponse, target interface{}) error {
	if resp.Data == nil {
		return nil
	}

	rawData, ok := resp.Data.(json.RawMessage)
	if !ok {
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
		return json.Unmarshal(rawData, target)
	}

	if fullResp.Data != nil {
		return json.Unmarshal(fullResp.Data, target)
	}

	return json.Unmarshal(rawData, target)
}

// ConvertFSSToIOC converts FSS threat data to IOC format.
func ConvertFSSToIOC(threat FinancialThreat, feedID string) *IOC {
	iocType := mapFSSTypeToIOCType(threat.Type)

	return &IOC{
		ID:          fmt.Sprintf("fss:%s", threat.ID),
		Type:        iocType,
		Value:       threat.Value,
		Source:      "FSS",
		FeedID:      feedID,
		ThreatType:  mapFSSThreatType(threat.Type),
		Severity:    mapFSSThreatLevel(threat.ThreatLevel),
		Confidence:  85, // FSS data for financial sector is highly reliable
		FirstSeen:   threat.FirstSeen,
		LastSeen:    threat.LastSeen,
		Description: threat.Description,
		Labels:      append([]string{threat.Category}, threat.TargetOrgs...),
		IsActive:    threat.Status == "active",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// ConvertPhishingSiteToIOC converts phishing site to IOC format.
func ConvertPhishingSiteToIOC(site PhishingSite, feedID string) *IOC {
	return &IOC{
		ID:          fmt.Sprintf("fss:phishing:%s", site.Domain),
		Type:        "url",
		Value:       site.URL,
		Source:      "FSS",
		FeedID:      feedID,
		ThreatType:  "phishing",
		Severity:    "high",
		Confidence:  90,
		FirstSeen:   site.DetectionDate,
		LastSeen:    site.DetectionDate,
		Description: fmt.Sprintf("Phishing site targeting %s (%s)", site.TargetOrg, site.TargetType),
		Labels:      []string{"phishing", "financial", site.TargetType},
		IsActive:    site.Status == "active",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// ConvertFraudIPToIOC converts fraud IP to IOC format.
func ConvertFraudIPToIOC(fraudIP FraudIP, feedID string) *IOC {
	return &IOC{
		ID:          fmt.Sprintf("fss:fraud:%s", fraudIP.IP),
		Type:        "ip",
		Value:       fraudIP.IP,
		Source:      "FSS",
		FeedID:      feedID,
		ThreatType:  mapFSSFraudType(fraudIP.FraudType),
		Severity:    mapRiskScoreToSeverity(fraudIP.RiskScore),
		Confidence:  fraudIP.RiskScore,
		FirstSeen:   fraudIP.FirstSeen,
		LastSeen:    fraudIP.LastSeen,
		Description: fmt.Sprintf("Fraud IP: %s from %s", fraudIP.FraudType, fraudIP.Country),
		Labels:      []string{"fraud", "financial", fraudIP.FraudType},
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func mapFSSTypeToIOCType(fssType string) string {
	switch strings.ToLower(fssType) {
	case "phishing_site", "phishing":
		return "url"
	case "fraud_ip":
		return "ip"
	case "malware", "hash":
		return "hash"
	case "smishing":
		return "other"
	case "domain":
		return "domain"
	default:
		return "other"
	}
}

func mapFSSThreatType(threat string) string {
	switch strings.ToLower(threat) {
	case "phishing_site", "phishing":
		return "phishing"
	case "malware":
		return "malware"
	case "fraud_ip", "fraud":
		return "suspicious"
	case "smishing":
		return "phishing"
	default:
		return "unknown"
	}
}

func mapFSSThreatLevel(level string) string {
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

func mapFSSFraudType(fraudType string) string {
	switch strings.ToLower(fraudType) {
	case "account_takeover":
		return "compromised"
	case "payment_fraud":
		return "suspicious"
	case "identity_theft":
		return "suspicious"
	default:
		return "unknown"
	}
}

func mapRiskScoreToSeverity(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}
