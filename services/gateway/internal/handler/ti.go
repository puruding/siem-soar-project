package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IOCType represents the type of indicator of compromise
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeHash   IOCType = "hash"
	IOCTypeURL    IOCType = "url"
	IOCTypeEmail  IOCType = "email"
)

// ThreatType represents the type of threat
type ThreatType string

const (
	ThreatMalware    ThreatType = "malware"
	ThreatC2         ThreatType = "c2"
	ThreatPhishing   ThreatType = "phishing"
	ThreatBotnet     ThreatType = "botnet"
	ThreatRansomware ThreatType = "ransomware"
	ThreatScanning   ThreatType = "scanning"
	ThreatAPT        ThreatType = "apt"
)

// IOCEntry represents a single IOC record
type IOCEntry struct {
	ID         string     `json:"id"`
	Type       IOCType    `json:"type"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	ThreatType ThreatType `json:"threat_type"`
	Confidence int        `json:"confidence"`
	Severity   string     `json:"severity"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Tags       []string   `json:"tags,omitempty"`
}

// IOCMatch represents a match between an IOC and text
type IOCMatch struct {
	IOC          IOCEntry `json:"ioc"`
	MatchedIn    string   `json:"matched_in"`
	MatchedValue string   `json:"matched_value"`
}

// TIMatchResult represents the TI matching result for an alert
type TIMatchResult struct {
	AlertID        string     `json:"alert_id"`
	TotalSources   int        `json:"total_sources"`
	MatchedSources int        `json:"matched_sources"`
	IOCs           []IOCMatch `json:"iocs"`
	CheckedAt      time.Time  `json:"checked_at"`
}

// In-memory IOC store
var (
	iocStore   = make(map[string]IOCEntry)
	iocStoreMu sync.RWMutex
)

// Regex patterns for IOC extraction
var (
	ipPattern     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	domainPattern = regexp.MustCompile(`\b[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b`)
	sha256Pattern = regexp.MustCompile(`\b[A-Fa-f0-9]{64}\b`)
	md5Pattern    = regexp.MustCompile(`\b[A-Fa-f0-9]{32}\b`)
	sha1Pattern   = regexp.MustCompile(`\b[A-Fa-f0-9]{40}\b`)
)

// init initializes sample IOC data
func init() {
	initSampleIOCs()
}

// initSampleIOCs populates the IOC store with sample data
func initSampleIOCs() {
	now := time.Now()
	sampleIOCs := []IOCEntry{
		// Malicious IPs
		{
			ID:         "IOC-001",
			Type:       IOCTypeIP,
			Value:      "192.168.1.100",
			Source:     "abuseipdb",
			ThreatType: ThreatScanning,
			Confidence: 85,
			Severity:   "high",
			FirstSeen:  now.Add(-72 * time.Hour),
			LastSeen:   now.Add(-1 * time.Hour),
			Tags:       []string{"brute-force", "ssh", "credential-access"},
		},
		{
			ID:         "IOC-002",
			Type:       IOCTypeIP,
			Value:      "185.234.72.10",
			Source:     "threatfox",
			ThreatType: ThreatC2,
			Confidence: 95,
			Severity:   "critical",
			FirstSeen:  now.Add(-168 * time.Hour),
			LastSeen:   now.Add(-30 * time.Minute),
			Tags:       []string{"cobalt-strike", "c2", "beacon"},
		},
		{
			ID:         "IOC-003",
			Type:       IOCTypeIP,
			Value:      "45.142.182.12",
			Source:     "misp",
			ThreatType: ThreatBotnet,
			Confidence: 90,
			Severity:   "high",
			FirstSeen:  now.Add(-240 * time.Hour),
			LastSeen:   now.Add(-2 * time.Hour),
			Tags:       []string{"emotet", "botnet", "spam"},
		},
		{
			ID:         "IOC-004",
			Type:       IOCTypeIP,
			Value:      "203.0.113.50",
			Source:     "kisa",
			ThreatType: ThreatC2,
			Confidence: 88,
			Severity:   "critical",
			FirstSeen:  now.Add(-48 * time.Hour),
			LastSeen:   now.Add(-15 * time.Minute),
			Tags:       []string{"apt", "korea", "c2-server"},
		},
		{
			ID:         "IOC-005",
			Type:       IOCTypeIP,
			Value:      "185.45.67.89",
			Source:     "threatfox",
			ThreatType: ThreatMalware,
			Confidence: 92,
			Severity:   "high",
			FirstSeen:  now.Add(-120 * time.Hour),
			LastSeen:   now.Add(-45 * time.Minute),
			Tags:       []string{"exfiltration", "data-theft"},
		},
		// Malicious domains
		{
			ID:         "IOC-006",
			Type:       IOCTypeDomain,
			Value:      "malware-c2.evil.com",
			Source:     "threatfox",
			ThreatType: ThreatC2,
			Confidence: 98,
			Severity:   "critical",
			FirstSeen:  now.Add(-96 * time.Hour),
			LastSeen:   now.Add(-20 * time.Minute),
			Tags:       []string{"c2", "malware", "beacon"},
		},
		{
			ID:         "IOC-007",
			Type:       IOCTypeDomain,
			Value:      "phishing-site.bad.net",
			Source:     "misp",
			ThreatType: ThreatPhishing,
			Confidence: 94,
			Severity:   "high",
			FirstSeen:  now.Add(-24 * time.Hour),
			LastSeen:   now.Add(-5 * time.Minute),
			Tags:       []string{"phishing", "credential-theft", "banking"},
		},
		{
			ID:         "IOC-008",
			Type:       IOCTypeDomain,
			Value:      "ransomware-drop.darknet.io",
			Source:     "kisa",
			ThreatType: ThreatRansomware,
			Confidence: 96,
			Severity:   "critical",
			FirstSeen:  now.Add(-72 * time.Hour),
			LastSeen:   now.Add(-1 * time.Hour),
			Tags:       []string{"ransomware", "lockbit", "dropper"},
		},
		// Malicious hashes
		{
			ID:         "IOC-009",
			Type:       IOCTypeHash,
			Value:      "e99a18c428cb38d5f260853678922e03afd5b0c4d0a3c3e3f5a7eb85e5fcaa78",
			Source:     "threatfox",
			ThreatType: ThreatRansomware,
			Confidence: 99,
			Severity:   "critical",
			FirstSeen:  now.Add(-48 * time.Hour),
			LastSeen:   now.Add(-10 * time.Minute),
			Tags:       []string{"lockbit", "ransomware", "encryption"},
		},
		{
			ID:         "IOC-010",
			Type:       IOCTypeHash,
			Value:      "5d41402abc4b2a76b9719d911017c592",
			Source:     "misp",
			ThreatType: ThreatMalware,
			Confidence: 87,
			Severity:   "high",
			FirstSeen:  now.Add(-168 * time.Hour),
			LastSeen:   now.Add(-3 * time.Hour),
			Tags:       []string{"trojan", "backdoor"},
		},
		{
			ID:         "IOC-011",
			Type:       IOCTypeHash,
			Value:      "098f6bcd4621d373cade4e832627b4f6",
			Source:     "abuseipdb",
			ThreatType: ThreatBotnet,
			Confidence: 82,
			Severity:   "medium",
			FirstSeen:  now.Add(-240 * time.Hour),
			LastSeen:   now.Add(-6 * time.Hour),
			Tags:       []string{"mirai", "botnet", "iot"},
		},
		// APT-related IOCs
		{
			ID:         "IOC-012",
			Type:       IOCTypeDomain,
			Value:      "apt-staging.suspicious-domain.kr",
			Source:     "kisa",
			ThreatType: ThreatAPT,
			Confidence: 91,
			Severity:   "critical",
			FirstSeen:  now.Add(-336 * time.Hour),
			LastSeen:   now.Add(-4 * time.Hour),
			Tags:       []string{"apt", "kimsuky", "korea-targeted"},
		},
		{
			ID:         "IOC-013",
			Type:       IOCTypeIP,
			Value:      "103.224.182.251",
			Source:     "kisa",
			ThreatType: ThreatAPT,
			Confidence: 89,
			Severity:   "critical",
			FirstSeen:  now.Add(-504 * time.Hour),
			LastSeen:   now.Add(-8 * time.Hour),
			Tags:       []string{"lazarus", "apt", "north-korea"},
		},
		// Additional C2 infrastructure
		{
			ID:         "IOC-014",
			Type:       IOCTypeURL,
			Value:      "https://malicious-payload.evil.com/download/stage2.exe",
			Source:     "threatfox",
			ThreatType: ThreatMalware,
			Confidence: 97,
			Severity:   "critical",
			FirstSeen:  now.Add(-12 * time.Hour),
			LastSeen:   now.Add(-30 * time.Minute),
			Tags:       []string{"payload", "dropper", "stage2"},
		},
		{
			ID:         "IOC-015",
			Type:       IOCTypeEmail,
			Value:      "attacker@phishing-campaign.com",
			Source:     "misp",
			ThreatType: ThreatPhishing,
			Confidence: 93,
			Severity:   "high",
			FirstSeen:  now.Add(-36 * time.Hour),
			LastSeen:   now.Add(-2 * time.Hour),
			Tags:       []string{"phishing", "spear-phishing", "finance"},
		},
	}

	iocStoreMu.Lock()
	for _, ioc := range sampleIOCs {
		iocStore[ioc.ID] = ioc
	}
	iocStoreMu.Unlock()
}

// extractIPs extracts IP addresses from text
func extractIPs(text string) []string {
	matches := ipPattern.FindAllString(text, -1)
	return uniqueStrings(matches)
}

// extractDomains extracts domain names from text
func extractDomains(text string) []string {
	matches := domainPattern.FindAllString(text, -1)
	// Filter out common non-domain patterns and known safe domains
	var filtered []string
	safeDomains := map[string]bool{
		"google.com": true, "microsoft.com": true, "github.com": true,
		"amazon.com": true, "cloudflare.com": true,
	}
	for _, m := range matches {
		lower := strings.ToLower(m)
		// Skip IPs masquerading as domains
		if ipPattern.MatchString(m) {
			continue
		}
		// Skip safe domains
		if safeDomains[lower] {
			continue
		}
		filtered = append(filtered, m)
	}
	return uniqueStrings(filtered)
}

// extractHashes extracts file hashes from text
func extractHashes(text string) []string {
	var hashes []string
	hashes = append(hashes, sha256Pattern.FindAllString(text, -1)...)
	hashes = append(hashes, sha1Pattern.FindAllString(text, -1)...)
	hashes = append(hashes, md5Pattern.FindAllString(text, -1)...)
	return uniqueStrings(hashes)
}

// uniqueStrings returns unique strings from a slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// MatchIOCs extracts and matches IOCs from text
func MatchIOCs(text string) []IOCMatch {
	var matches []IOCMatch

	iocStoreMu.RLock()
	defer iocStoreMu.RUnlock()

	// Extract potential IOCs from text
	ips := extractIPs(text)
	domains := extractDomains(text)
	hashes := extractHashes(text)

	// Match against IOC store
	for _, ioc := range iocStore {
		switch ioc.Type {
		case IOCTypeIP:
			for _, ip := range ips {
				if ip == ioc.Value {
					matches = append(matches, IOCMatch{
						IOC:          ioc,
						MatchedIn:    "ip_address",
						MatchedValue: ip,
					})
				}
			}
		case IOCTypeDomain:
			for _, domain := range domains {
				if strings.EqualFold(domain, ioc.Value) {
					matches = append(matches, IOCMatch{
						IOC:          ioc,
						MatchedIn:    "domain",
						MatchedValue: domain,
					})
				}
			}
		case IOCTypeHash:
			for _, hash := range hashes {
				if strings.EqualFold(hash, ioc.Value) {
					matches = append(matches, IOCMatch{
						IOC:          ioc,
						MatchedIn:    "hash",
						MatchedValue: hash,
					})
				}
			}
		}
	}

	return matches
}

// MatchAlertTI checks an alert for IOC matches
func MatchAlertTI(alert Alert) TIMatchResult {
	// Build text to search from alert fields
	var textParts []string
	textParts = append(textParts, alert.Title)
	textParts = append(textParts, alert.Description)
	textParts = append(textParts, alert.Target)
	textParts = append(textParts, alert.RawLog)

	// Add fields if present
	if alert.Fields != nil {
		for _, v := range alert.Fields {
			if s, ok := v.(string); ok {
				textParts = append(textParts, s)
			}
		}
	}

	combinedText := strings.Join(textParts, " ")
	matches := MatchIOCs(combinedText)

	// Count unique sources
	sourceSet := make(map[string]bool)
	for _, m := range matches {
		sourceSet[m.IOC.Source] = true
	}

	// Get total sources
	iocStoreMu.RLock()
	allSources := make(map[string]bool)
	for _, ioc := range iocStore {
		allSources[ioc.Source] = true
	}
	iocStoreMu.RUnlock()

	return TIMatchResult{
		AlertID:        alert.ID,
		TotalSources:   len(allSources),
		MatchedSources: len(sourceSet),
		IOCs:           matches,
		CheckedAt:      time.Now(),
	}
}

// ListIOCsHandler returns a list of IOCs
// GET /api/v1/ti/iocs?type=ip&source=threatfox&severity=critical&limit=50
func ListIOCsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse query parameters
	iocType := r.URL.Query().Get("type")
	source := r.URL.Query().Get("source")
	severity := r.URL.Query().Get("severity")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	iocStoreMu.RLock()
	defer iocStoreMu.RUnlock()

	var result []IOCEntry
	for _, ioc := range iocStore {
		// Apply filters
		if iocType != "" && string(ioc.Type) != iocType {
			continue
		}
		if source != "" && ioc.Source != source {
			continue
		}
		if severity != "" && ioc.Severity != severity {
			continue
		}

		result = append(result, ioc)
		if len(result) >= limit {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"iocs":  result,
			"total": len(result),
		},
	})
}

// GetIOCHandler returns a single IOC by ID
// GET /api/v1/ti/iocs/{id}
func GetIOCHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract IOC ID from path: /api/v1/ti/iocs/{id}
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	iocID := parts[5]

	iocStoreMu.RLock()
	ioc, exists := iocStore[iocID]
	iocStoreMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "IOC not found",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    ioc,
	})
}

// LookupIOCRequest represents the request body for IOC lookup
type LookupIOCRequest struct {
	Indicators []string `json:"indicators"`
}

// LookupIOCHandler looks up multiple indicators
// POST /api/v1/ti/lookup
func LookupIOCHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req LookupIOCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	if len(req.Indicators) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "At least one indicator is required",
		})
		return
	}

	iocStoreMu.RLock()
	defer iocStoreMu.RUnlock()

	// Build lookup results
	type LookupResult struct {
		Indicator string    `json:"indicator"`
		Found     bool      `json:"found"`
		IOC       *IOCEntry `json:"ioc,omitempty"`
	}

	results := make([]LookupResult, 0, len(req.Indicators))
	matchedCount := 0

	for _, indicator := range req.Indicators {
		indicator = strings.TrimSpace(indicator)
		if indicator == "" {
			continue
		}

		result := LookupResult{
			Indicator: indicator,
			Found:     false,
		}

		// Search for matching IOC
		for _, ioc := range iocStore {
			if strings.EqualFold(ioc.Value, indicator) {
				result.Found = true
				iocCopy := ioc
				result.IOC = &iocCopy
				matchedCount++
				break
			}
		}

		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"results":       results,
			"total_checked": len(results),
			"total_matched": matchedCount,
			"checked_at":    time.Now(),
		},
	})
}

// GetAlertTIHandler returns TI match results for an alert
// GET /api/v1/alerts/{id}/ti
func GetAlertTIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract alert ID from path: /api/v1/alerts/{id}/ti
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	alertID := parts[4]

	// Find the alert
	alertStoreMu.RLock()
	var foundAlert *Alert
	for i := range alertStore {
		if alertStore[i].ID == alertID || alertStore[i].AlertID == alertID {
			foundAlert = &alertStore[i]
			break
		}
	}
	alertStoreMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if foundAlert == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Alert not found",
		})
		return
	}

	// Get TI matches
	result := MatchAlertTI(*foundAlert)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// GetTIStatsHandler returns TI statistics
// GET /api/v1/ti/stats
func GetTIStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	iocStoreMu.RLock()
	defer iocStoreMu.RUnlock()

	// Calculate statistics
	byType := make(map[string]int)
	bySource := make(map[string]int)
	bySeverity := make(map[string]int)
	byThreat := make(map[string]int)

	for _, ioc := range iocStore {
		byType[string(ioc.Type)]++
		bySource[ioc.Source]++
		bySeverity[ioc.Severity]++
		byThreat[string(ioc.ThreatType)]++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"total":       len(iocStore),
			"by_type":     byType,
			"by_source":   bySource,
			"by_severity": bySeverity,
			"by_threat":   byThreat,
			"sources": []string{
				"threatfox",
				"abuseipdb",
				"misp",
				"kisa",
			},
		},
	})
}

// AddIOCHandler allows adding new IOCs (for demo/testing)
// POST /api/v1/ti/iocs
func AddIOCHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var ioc IOCEntry
	if err := json.NewDecoder(r.Body).Decode(&ioc); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate required fields
	if ioc.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "IOC value is required",
		})
		return
	}

	// Set defaults
	if ioc.ID == "" {
		iocStoreMu.RLock()
		ioc.ID = fmt.Sprintf("IOC-%03d", len(iocStore)+1)
		iocStoreMu.RUnlock()
	}
	if ioc.Type == "" {
		ioc.Type = detectIOCType(ioc.Value)
	}
	if ioc.Source == "" {
		ioc.Source = "manual"
	}
	if ioc.ThreatType == "" {
		ioc.ThreatType = ThreatMalware
	}
	if ioc.Confidence == 0 {
		ioc.Confidence = 50
	}
	if ioc.Severity == "" {
		ioc.Severity = "medium"
	}
	now := time.Now()
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = now
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = now
	}

	iocStoreMu.Lock()
	iocStore[ioc.ID] = ioc
	iocStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    ioc,
	})
}

// detectIOCType attempts to detect the IOC type from its value
func detectIOCType(value string) IOCType {
	if ipPattern.MatchString(value) {
		return IOCTypeIP
	}
	if sha256Pattern.MatchString(value) || md5Pattern.MatchString(value) || sha1Pattern.MatchString(value) {
		return IOCTypeHash
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return IOCTypeURL
	}
	if strings.Contains(value, "@") {
		return IOCTypeEmail
	}
	if strings.Contains(value, ".") && !strings.Contains(value, "/") {
		return IOCTypeDomain
	}
	return IOCTypeHash // Default to hash for unknown
}
