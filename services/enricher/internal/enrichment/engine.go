// Package enrichment provides data enrichment capabilities.
package enrichment

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UDMEvent represents a normalized event for enrichment.
// This matches the structure from the normalizer service.
type UDMEvent struct {
	Metadata       *Metadata              `json:"metadata"`
	Principal      *Entity                `json:"principal,omitempty"`
	Target         *Entity                `json:"target,omitempty"`
	Src            *Entity                `json:"src,omitempty"`
	Observer       *Entity                `json:"observer,omitempty"`
	Network        *Network               `json:"network,omitempty"`
	SecurityResult *SecurityResult        `json:"security_result,omitempty"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// Metadata contains event metadata.
type Metadata struct {
	ID               string            `json:"id"`
	EventTimestamp   time.Time         `json:"event_timestamp"`
	CollectedTime    time.Time         `json:"collected_timestamp"`
	IngestionTime    time.Time         `json:"ingestion_timestamp"`
	EventType        string            `json:"event_type"`
	VendorName       string            `json:"vendor_name"`
	ProductName      string            `json:"product_name"`
	ProductVersion   string            `json:"product_version,omitempty"`
	ProductEventType string            `json:"product_event_type,omitempty"`
	Description      string            `json:"description,omitempty"`
	LogType          string            `json:"log_type,omitempty"`
	BaseLabels       map[string]string `json:"base_labels,omitempty"`
	EnrichmentLabels map[string]string `json:"enrichment_labels,omitempty"`
}

// Entity represents a principal, target, or observer entity.
type Entity struct {
	Hostname             string            `json:"hostname,omitempty"`
	IP                   []string          `json:"ip,omitempty"`
	MAC                  []string          `json:"mac,omitempty"`
	Port                 int               `json:"port,omitempty"`
	AssetID              string            `json:"asset_id,omitempty"`
	URL                  string            `json:"url,omitempty"`
	Application          string            `json:"application,omitempty"`
	AdministrativeDomain string            `json:"administrative_domain,omitempty"`
	Platform             string            `json:"platform,omitempty"`
	PlatformVersion      string            `json:"platform_version,omitempty"`
	User                 *User             `json:"user,omitempty"`
	Process              *Process          `json:"process,omitempty"`
	File                 *File             `json:"file,omitempty"`
	Registry             *Registry         `json:"registry,omitempty"`
	Resource             *Resource         `json:"resource,omitempty"`
	Asset                *Asset            `json:"asset,omitempty"`
	Location             *Location         `json:"location,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
}

// User represents user information.
type User struct {
	UserID          string   `json:"userid,omitempty"`
	UserName        string   `json:"user_name,omitempty"`
	DisplayName     string   `json:"user_display_name,omitempty"`
	EmailAddresses  []string `json:"email_addresses,omitempty"`
	GroupIDs        []string `json:"group_ids,omitempty"`
	WindowsSID      string   `json:"windows_sid,omitempty"`
	ProductObjectID string   `json:"product_object_id,omitempty"`
	Department      string   `json:"department,omitempty"`
	Title           string   `json:"title,omitempty"`
	Manager         string   `json:"manager,omitempty"`
	EmployeeType    string   `json:"employee_type,omitempty"`
	AccountStatus   string   `json:"account_status,omitempty"`
}

// Process represents process information.
type Process struct {
	PID                      int64    `json:"pid,omitempty"`
	CommandLine              string   `json:"command_line,omitempty"`
	ProductSpecificProcessID string   `json:"product_specific_process_id,omitempty"`
	File                     *File    `json:"file,omitempty"`
	ParentProcess            *Process `json:"parent_process,omitempty"`
}

// File represents file information.
type File struct {
	FullPath      string    `json:"full_path,omitempty"`
	FileName      string    `json:"file_name,omitempty"`
	Size          int64     `json:"size,omitempty"`
	MimeType      string    `json:"mime_type,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	SHA1          string    `json:"sha1,omitempty"`
	MD5           string    `json:"md5,omitempty"`
	FirstSeenTime time.Time `json:"first_seen_time,omitempty"`
}

// Registry represents Windows registry information.
type Registry struct {
	RegistryKey       string `json:"registry_key,omitempty"`
	RegistryValueName string `json:"registry_value_name,omitempty"`
	RegistryValueData string `json:"registry_value_data,omitempty"`
}

// Resource represents a generic resource.
type Resource struct {
	Name            string `json:"name,omitempty"`
	Type            string `json:"resource_type,omitempty"`
	SubType         string `json:"resource_subtype,omitempty"`
	ID              string `json:"id,omitempty"`
	ProductObjectID string `json:"product_object_id,omitempty"`
}

// Asset represents enriched asset information.
type Asset struct {
	AssetID         string   `json:"asset_id,omitempty"`
	ProductObjectID string   `json:"product_object_id,omitempty"`
	Hostname        string   `json:"hostname,omitempty"`
	FQDN            string   `json:"fqdn,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	AssetType       string   `json:"asset_type,omitempty"`
	OS              string   `json:"os,omitempty"`
	Owner           string   `json:"owner,omitempty"`
	Department      string   `json:"department,omitempty"`
	Criticality     string   `json:"criticality,omitempty"`
	Classification  string   `json:"classification,omitempty"`
	Environment     string   `json:"environment,omitempty"`
}

// Location represents geographical location.
type Location struct {
	City            string  `json:"city,omitempty"`
	State           string  `json:"state,omitempty"`
	CountryOrRegion string  `json:"country_or_region,omitempty"`
	RegionLatitude  float64 `json:"region_latitude,omitempty"`
	RegionLongitude float64 `json:"region_longitude,omitempty"`
	Name            string  `json:"name,omitempty"`
	PostalCode      string  `json:"postal_code,omitempty"`
	Timezone        string  `json:"timezone,omitempty"`
	ASN             uint    `json:"asn,omitempty"`
	ASOrg           string  `json:"as_org,omitempty"`
	IsAnonymous     bool    `json:"is_anonymous,omitempty"`
	IsProxy         bool    `json:"is_proxy,omitempty"`
	IsTor           bool    `json:"is_tor,omitempty"`
}

// Network represents network information.
type Network struct {
	ApplicationProtocol string  `json:"application_protocol,omitempty"`
	Direction           string  `json:"direction,omitempty"`
	IPProtocol          string  `json:"ip_protocol,omitempty"`
	ReceivedBytes       int64   `json:"received_bytes,omitempty"`
	SentBytes           int64   `json:"sent_bytes,omitempty"`
	SessionID           string  `json:"session_id,omitempty"`
	SessionDuration     float64 `json:"session_duration,omitempty"`
}

// SecurityResult represents security detection result.
type SecurityResult struct {
	Action          string              `json:"action,omitempty"`
	Severity        string              `json:"severity,omitempty"`
	SeverityDetails string              `json:"severity_details,omitempty"`
	Confidence      float32             `json:"confidence,omitempty"`
	Category        string              `json:"category,omitempty"`
	CategoryDetails []string            `json:"category_details,omitempty"`
	RuleID          string              `json:"rule_id,omitempty"`
	RuleName        string              `json:"rule_name,omitempty"`
	RuleType        string              `json:"rule_type,omitempty"`
	ThreatID        string              `json:"threat_id,omitempty"`
	ThreatName      string              `json:"threat_name,omitempty"`
	ThreatStatus    string              `json:"threat_status,omitempty"`
	ThreatType      string              `json:"threat_type,omitempty"`
	ThreatSeverity  string              `json:"threat_severity,omitempty"`
	ThreatSources   []string            `json:"threat_sources,omitempty"`
	RuleLabels      map[string]string   `json:"rule_labels,omitempty"`
}

// EnrichmentResult contains the enrichment results.
type EnrichmentResult struct {
	EnrichedEvent *UDMEvent                 `json:"enriched_event"`
	GeoIP         map[string]*GeoIPResult   `json:"geoip,omitempty"`
	Assets        map[string]*AssetInfo     `json:"assets,omitempty"`
	Users         map[string]*UserInfo      `json:"users,omitempty"`
	Threats       map[string]*ThreatInfo    `json:"threats,omitempty"`
	EnrichTimeMs  int64                     `json:"enrich_time_ms"`
	Errors        []string                  `json:"errors,omitempty"`
}

// EngineConfig holds engine configuration.
type EngineConfig struct {
	EnableGeoIP    bool
	EnableAsset    bool
	EnableUser     bool
	EnableThreat   bool
	SkipPrivateIPs bool
}

// Engine orchestrates all enrichers.
type Engine struct {
	geoip  *GeoIPEnricher
	asset  *AssetEnricher
	user   *UserEnricher
	threat *ThreatEnricher
	config EngineConfig
	logger *slog.Logger

	// Metrics
	eventsEnriched   atomic.Uint64
	enrichErrors     atomic.Uint64
	totalEnrichTimeMs atomic.Int64
}

// NewEngine creates a new enrichment engine.
func NewEngine(
	geoip *GeoIPEnricher,
	asset *AssetEnricher,
	user *UserEnricher,
	threat *ThreatEnricher,
	cfg EngineConfig,
	logger *slog.Logger,
) *Engine {
	return &Engine{
		geoip:  geoip,
		asset:  asset,
		user:   user,
		threat: threat,
		config: cfg,
		logger: logger.With("component", "enrichment-engine"),
	}
}

// Enrich enriches a UDM event with additional context.
func (e *Engine) Enrich(ctx context.Context, event *UDMEvent) (*EnrichmentResult, error) {
	start := time.Now()
	result := &EnrichmentResult{
		EnrichedEvent: event,
		GeoIP:         make(map[string]*GeoIPResult),
		Assets:        make(map[string]*AssetInfo),
		Users:         make(map[string]*UserInfo),
		Threats:       make(map[string]*ThreatInfo),
		Errors:        []string{},
	}

	// Collect IPs, hostnames, usernames, and IOCs from the event
	ips := e.extractIPs(event)
	hostnames := e.extractHostnames(event)
	usernames := e.extractUsernames(event)
	iocs := e.extractIOCs(event)

	var wg sync.WaitGroup
	var mu sync.Mutex

	// GeoIP enrichment for external IPs
	if e.config.EnableGeoIP && e.geoip != nil {
		for _, ip := range ips {
			if e.config.SkipPrivateIPs && isPrivateIPStr(ip) {
				continue
			}
			wg.Add(1)
			go func(ipAddr string) {
				defer wg.Done()
				geoResult, err := e.geoip.Lookup(ctx, ipAddr)
				if err != nil {
					mu.Lock()
					result.Errors = append(result.Errors, "geoip:"+ipAddr+":"+err.Error())
					mu.Unlock()
					return
				}
				mu.Lock()
				result.GeoIP[ipAddr] = geoResult
				mu.Unlock()
			}(ip)
		}
	}

	// Asset enrichment for internal IPs and hostnames
	if e.config.EnableAsset && e.asset != nil {
		// Enrich by IP
		for _, ip := range ips {
			if !e.config.SkipPrivateIPs || isPrivateIPStr(ip) {
				wg.Add(1)
				go func(ipAddr string) {
					defer wg.Done()
					assetResult, err := e.asset.LookupByIP(ctx, ipAddr)
					if err != nil {
						return // Asset not found is not an error
					}
					mu.Lock()
					result.Assets[ipAddr] = assetResult
					mu.Unlock()
				}(ip)
			}
		}

		// Enrich by hostname
		for _, hostname := range hostnames {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				assetResult, err := e.asset.LookupByHostname(ctx, host)
				if err != nil {
					return
				}
				mu.Lock()
				result.Assets[host] = assetResult
				mu.Unlock()
			}(hostname)
		}
	}

	// User enrichment
	if e.config.EnableUser && e.user != nil {
		for _, username := range usernames {
			wg.Add(1)
			go func(user string) {
				defer wg.Done()
				userResult, err := e.user.LookupByUsername(ctx, user)
				if err != nil {
					return
				}
				mu.Lock()
				result.Users[user] = userResult
				mu.Unlock()
			}(username)
		}
	}

	// Threat enrichment for IPs, domains, and hashes
	if e.config.EnableThreat && e.threat != nil {
		for _, ioc := range iocs {
			wg.Add(1)
			go func(indicator IOC) {
				defer wg.Done()
				var threatResult *ThreatInfo
				var err error

				switch indicator.Type {
				case "ip":
					threatResult, err = e.threat.LookupIP(ctx, indicator.Value)
				case "domain":
					threatResult, err = e.threat.LookupDomain(ctx, indicator.Value)
				case "hash":
					threatResult, err = e.threat.LookupHash(ctx, indicator.Value)
				case "url":
					threatResult, err = e.threat.LookupURL(ctx, indicator.Value)
				}

				if err != nil || threatResult == nil {
					return
				}
				mu.Lock()
				result.Threats[indicator.Value] = threatResult
				mu.Unlock()
			}(ioc)
		}
	}

	wg.Wait()

	// Apply enrichment results to the event
	e.applyEnrichments(result)

	result.EnrichTimeMs = time.Since(start).Milliseconds()
	e.eventsEnriched.Add(1)
	e.totalEnrichTimeMs.Add(result.EnrichTimeMs)

	return result, nil
}

// IOC represents an indicator of compromise.
type IOC struct {
	Type  string // ip, domain, hash, url
	Value string
}

func (e *Engine) extractIPs(event *UDMEvent) []string {
	seen := make(map[string]bool)
	var ips []string

	addIPs := func(ipList []string) {
		for _, ip := range ipList {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	if event.Principal != nil {
		addIPs(event.Principal.IP)
	}
	if event.Target != nil {
		addIPs(event.Target.IP)
	}
	if event.Src != nil {
		addIPs(event.Src.IP)
	}
	if event.Observer != nil {
		addIPs(event.Observer.IP)
	}

	return ips
}

func (e *Engine) extractHostnames(event *UDMEvent) []string {
	seen := make(map[string]bool)
	var hostnames []string

	addHostname := func(hostname string) {
		if hostname != "" && !seen[hostname] {
			seen[hostname] = true
			hostnames = append(hostnames, hostname)
		}
	}

	if event.Principal != nil {
		addHostname(event.Principal.Hostname)
	}
	if event.Target != nil {
		addHostname(event.Target.Hostname)
	}
	if event.Src != nil {
		addHostname(event.Src.Hostname)
	}
	if event.Observer != nil {
		addHostname(event.Observer.Hostname)
	}

	return hostnames
}

func (e *Engine) extractUsernames(event *UDMEvent) []string {
	seen := make(map[string]bool)
	var usernames []string

	addUser := func(entity *Entity) {
		if entity != nil && entity.User != nil {
			username := entity.User.UserName
			if username != "" && !seen[username] {
				seen[username] = true
				usernames = append(usernames, username)
			}
		}
	}

	addUser(event.Principal)
	addUser(event.Target)
	addUser(event.Src)

	return usernames
}

func (e *Engine) extractIOCs(event *UDMEvent) []IOC {
	var iocs []IOC
	seen := make(map[string]bool)

	addIOC := func(iocType, value string) {
		key := iocType + ":" + value
		if value != "" && !seen[key] {
			seen[key] = true
			iocs = append(iocs, IOC{Type: iocType, Value: value})
		}
	}

	// Extract IPs
	ips := e.extractIPs(event)
	for _, ip := range ips {
		if !isPrivateIPStr(ip) {
			addIOC("ip", ip)
		}
	}

	// Extract domains from hostnames (external only)
	hostnames := e.extractHostnames(event)
	for _, hostname := range hostnames {
		if isDomain(hostname) {
			addIOC("domain", hostname)
		}
	}

	// Extract domains from URLs
	if event.Target != nil && event.Target.URL != "" {
		domain := extractDomainFromURL(event.Target.URL)
		if domain != "" {
			addIOC("domain", domain)
		}
		addIOC("url", event.Target.URL)
	}

	// Extract file hashes
	extractHashes := func(file *File) {
		if file != nil {
			if file.SHA256 != "" {
				addIOC("hash", file.SHA256)
			}
			if file.SHA1 != "" {
				addIOC("hash", file.SHA1)
			}
			if file.MD5 != "" {
				addIOC("hash", file.MD5)
			}
		}
	}

	if event.Principal != nil {
		extractHashes(event.Principal.File)
		if event.Principal.Process != nil {
			extractHashes(event.Principal.Process.File)
		}
	}
	if event.Target != nil {
		extractHashes(event.Target.File)
		if event.Target.Process != nil {
			extractHashes(event.Target.Process.File)
		}
	}

	return iocs
}

func (e *Engine) applyEnrichments(result *EnrichmentResult) {
	event := result.EnrichedEvent

	// Apply GeoIP enrichments to entities
	applyGeoIPToEntity := func(entity *Entity) {
		if entity == nil {
			return
		}
		for _, ip := range entity.IP {
			if geoResult, ok := result.GeoIP[ip]; ok {
				if entity.Location == nil {
					entity.Location = &Location{}
				}
				entity.Location.City = geoResult.City
				entity.Location.State = geoResult.Region
				entity.Location.CountryOrRegion = geoResult.Country
				entity.Location.RegionLatitude = geoResult.Latitude
				entity.Location.RegionLongitude = geoResult.Longitude
				entity.Location.PostalCode = geoResult.PostalCode
				entity.Location.Timezone = geoResult.Timezone
				entity.Location.ASN = geoResult.ASN
				entity.Location.ASOrg = geoResult.ASOrg
				entity.Location.IsAnonymous = geoResult.IsAnonymous
				entity.Location.IsProxy = geoResult.IsProxy
				entity.Location.IsTor = geoResult.IsTorExitNode
				break // Use first IP's location
			}
		}
	}

	applyGeoIPToEntity(event.Principal)
	applyGeoIPToEntity(event.Target)
	applyGeoIPToEntity(event.Src)

	// Apply Asset enrichments
	applyAssetToEntity := func(entity *Entity) {
		if entity == nil {
			return
		}
		// Try by IP first
		for _, ip := range entity.IP {
			if assetResult, ok := result.Assets[ip]; ok {
				if entity.Asset == nil {
					entity.Asset = &Asset{}
				}
				entity.Asset.AssetID = assetResult.AssetID
				entity.Asset.Hostname = assetResult.Hostname
				entity.Asset.FQDN = assetResult.FQDN
				entity.Asset.IPAddresses = assetResult.IPAddresses
				entity.Asset.AssetType = assetResult.AssetType
				entity.Asset.OS = assetResult.OS
				entity.Asset.Owner = assetResult.Owner
				entity.Asset.Department = assetResult.Department
				entity.Asset.Criticality = assetResult.Criticality
				entity.Asset.Classification = assetResult.Classification
				entity.Asset.Environment = assetResult.Environment
				return
			}
		}
		// Try by hostname
		if entity.Hostname != "" {
			if assetResult, ok := result.Assets[entity.Hostname]; ok {
				if entity.Asset == nil {
					entity.Asset = &Asset{}
				}
				entity.Asset.AssetID = assetResult.AssetID
				entity.Asset.Hostname = assetResult.Hostname
				entity.Asset.FQDN = assetResult.FQDN
				entity.Asset.IPAddresses = assetResult.IPAddresses
				entity.Asset.AssetType = assetResult.AssetType
				entity.Asset.OS = assetResult.OS
				entity.Asset.Owner = assetResult.Owner
				entity.Asset.Department = assetResult.Department
				entity.Asset.Criticality = assetResult.Criticality
				entity.Asset.Classification = assetResult.Classification
				entity.Asset.Environment = assetResult.Environment
			}
		}
	}

	applyAssetToEntity(event.Principal)
	applyAssetToEntity(event.Target)
	applyAssetToEntity(event.Src)

	// Apply User enrichments
	applyUserToEntity := func(entity *Entity) {
		if entity == nil || entity.User == nil || entity.User.UserName == "" {
			return
		}
		if userResult, ok := result.Users[entity.User.UserName]; ok {
			entity.User.DisplayName = userResult.DisplayName
			entity.User.Department = userResult.Department
			entity.User.Title = userResult.Title
			entity.User.Manager = userResult.Manager
			entity.User.EmployeeType = userResult.EmployeeType
			entity.User.AccountStatus = userResult.AccountStatus
			if userResult.Email != "" {
				entity.User.EmailAddresses = append(entity.User.EmailAddresses, userResult.Email)
			}
			entity.User.GroupIDs = userResult.Groups
		}
	}

	applyUserToEntity(event.Principal)
	applyUserToEntity(event.Target)
	applyUserToEntity(event.Src)

	// Apply Threat enrichments to SecurityResult
	if len(result.Threats) > 0 {
		if event.SecurityResult == nil {
			event.SecurityResult = &SecurityResult{}
		}

		// Find the highest severity threat
		var highestThreat *ThreatInfo
		for _, threat := range result.Threats {
			if highestThreat == nil || compareSeverity(threat.Severity, highestThreat.Severity) > 0 {
				highestThreat = threat
			}
		}

		if highestThreat != nil {
			event.SecurityResult.ThreatID = highestThreat.IOC
			event.SecurityResult.ThreatName = highestThreat.ThreatName
			event.SecurityResult.ThreatType = highestThreat.ThreatType
			event.SecurityResult.ThreatSeverity = highestThreat.Severity
			event.SecurityResult.Confidence = float32(highestThreat.Confidence) / 100.0

			// Collect threat sources
			var sources []string
			for _, src := range highestThreat.Sources {
				sources = append(sources, src.Name)
			}
			event.SecurityResult.ThreatSources = sources
		}
	}

	// Add enrichment labels
	if event.Metadata != nil {
		if event.Metadata.EnrichmentLabels == nil {
			event.Metadata.EnrichmentLabels = make(map[string]string)
		}
		event.Metadata.EnrichmentLabels["enriched"] = "true"
		event.Metadata.EnrichmentLabels["enriched_at"] = time.Now().UTC().Format(time.RFC3339)
		event.Metadata.EnrichmentLabels["geoip_count"] = formatInt(len(result.GeoIP))
		event.Metadata.EnrichmentLabels["asset_count"] = formatInt(len(result.Assets))
		event.Metadata.EnrichmentLabels["user_count"] = formatInt(len(result.Users))
		event.Metadata.EnrichmentLabels["threat_count"] = formatInt(len(result.Threats))
	}
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	eventsEnriched := e.eventsEnriched.Load()
	totalMs := e.totalEnrichTimeMs.Load()

	var avgMs float64
	if eventsEnriched > 0 {
		avgMs = float64(totalMs) / float64(eventsEnriched)
	}

	stats := map[string]interface{}{
		"events_enriched":      eventsEnriched,
		"enrich_errors":        e.enrichErrors.Load(),
		"total_enrich_time_ms": totalMs,
		"avg_enrich_time_ms":   avgMs,
	}

	if e.geoip != nil {
		stats["geoip"] = e.geoip.Stats()
	}
	if e.asset != nil {
		stats["asset"] = e.asset.Stats()
	}
	if e.user != nil {
		stats["user"] = e.user.Stats()
	}
	if e.threat != nil {
		stats["threat"] = e.threat.Stats()
	}

	return stats
}

// Helper functions

func isPrivateIPStr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}

func isDomain(hostname string) bool {
	// Check if hostname looks like a domain (not an IP, contains dots)
	if net.ParseIP(hostname) != nil {
		return false
	}
	return strings.Contains(hostname, ".") && !strings.HasSuffix(hostname, ".local")
}

func extractDomainFromURL(urlStr string) string {
	// Simple domain extraction
	// Remove protocol
	url := urlStr
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}
	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

func compareSeverity(a, b string) int {
	order := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"":         0,
	}
	return order[strings.ToLower(a)] - order[strings.ToLower(b)]
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}
