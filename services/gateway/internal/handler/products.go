package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Product represents a security product/data source
type Product struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Vendor       string                 `json:"vendor"`
	Product      string                 `json:"product"`
	Version      string                 `json:"version"`
	SourceType   string                 `json:"source_type"`
	Status       string                 `json:"status"`
	ParserType   string                 `json:"parser_type"`
	ParserConfig map[string]interface{} `json:"parser_config"`
	FieldMapping map[string]interface{} `json:"field_mapping"`
	// Additional fields for display
	Description  string    `json:"description,omitempty"`
	LogFormats   []string  `json:"log_formats,omitempty"`
	AssetCount   int       `json:"asset_count,omitempty"`
	EventsPerDay int64     `json:"events_per_day,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

var (
	productStore   = make(map[string]Product)
	productMu      sync.RWMutex
	productCounter = 0
)

func init() {
	now := time.Now()
	sampleProducts := []Product{
		{
			ID:           "prod-001",
			Name:         "Palo Alto Firewall",
			Vendor:       "Palo Alto Networks",
			Product:      "PA-5250",
			Version:      "PAN-OS 10.2",
			SourceType:   "firewall",
			Status:       "active",
			ParserType:   "cef",
			ParserConfig: map[string]interface{}{"format": "CEF"},
			FieldMapping: map[string]interface{}{"src": "source_ip", "dst": "destination_ip"},
			Description:  "Next-generation firewall with advanced threat prevention",
			LogFormats:   []string{"syslog", "CEF", "LEEF"},
			AssetCount:   3,
			EventsPerDay: 1500000,
			CreatedAt:    now.Add(-90 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-002",
			Name:         "CrowdStrike Falcon",
			Vendor:       "CrowdStrike",
			Product:      "Falcon Endpoint",
			Version:      "6.45",
			SourceType:   "edr",
			Status:       "active",
			ParserType:   "json",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"ComputerName": "hostname", "UserName": "user"},
			Description:  "Cloud-native endpoint detection and response platform",
			LogFormats:   []string{"JSON", "CEF"},
			AssetCount:   150,
			EventsPerDay: 5000000,
			CreatedAt:    now.Add(-60 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-003",
			Name:         "Microsoft Azure AD",
			Vendor:       "Microsoft",
			Product:      "Azure Active Directory",
			Version:      "2.0",
			SourceType:   "identity",
			Status:       "active",
			ParserType:   "json",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"userPrincipalName": "user", "ipAddress": "source_ip"},
			Description:  "Cloud-based identity and access management service",
			LogFormats:   []string{"JSON"},
			AssetCount:   1,
			EventsPerDay: 500000,
			CreatedAt:    now.Add(-120 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-004",
			Name:         "Cisco ASA",
			Vendor:       "Cisco",
			Product:      "ASA 5500-X",
			Version:      "9.16",
			SourceType:   "firewall",
			Status:       "active",
			ParserType:   "grok",
			ParserConfig: map[string]interface{}{"format": "syslog"},
			FieldMapping: map[string]interface{}{"device": "hostname", "severity": "severity"},
			Description:  "Adaptive Security Appliance firewall",
			LogFormats:   []string{"syslog"},
			AssetCount:   5,
			EventsPerDay: 800000,
			CreatedAt:    now.Add(-180 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-005",
			Name:         "Splunk Forwarder",
			Vendor:       "Splunk",
			Product:      "Universal Forwarder",
			Version:      "9.0",
			SourceType:   "siem",
			Status:       "active",
			ParserType:   "json",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"host": "hostname", "source": "log_source"},
			Description:  "Security Information and Event Management platform",
			LogFormats:   []string{"JSON", "syslog"},
			AssetCount:   2,
			EventsPerDay: 10000000,
			CreatedAt:    now.Add(-200 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-006",
			Name:         "AWS CloudTrail",
			Vendor:       "Amazon Web Services",
			Product:      "CloudTrail",
			Version:      "2.0",
			SourceType:   "cloud",
			Status:       "active",
			ParserType:   "json",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"eventTime": "event_time", "sourceIPAddress": "source_ip"},
			Description:  "AWS API activity logging service",
			LogFormats:   []string{"JSON"},
			AssetCount:   1,
			EventsPerDay: 2000000,
			CreatedAt:    now.Add(-150 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-007",
			Name:         "Windows Event Log",
			Vendor:       "Microsoft",
			Product:      "Windows Server",
			Version:      "2022",
			SourceType:   "endpoint",
			Status:       "active",
			ParserType:   "xml",
			ParserConfig: map[string]interface{}{"format": "EVTX"},
			FieldMapping: map[string]interface{}{"EventID": "event_id", "Computer": "hostname"},
			Description:  "Windows operating system event logging",
			LogFormats:   []string{"EVTX", "XML"},
			AssetCount:   85,
			EventsPerDay: 3000000,
			CreatedAt:    now.Add(-300 * 24 * time.Hour),
			UpdatedAt:    now,
		},
		{
			ID:           "prod-008",
			Name:         "Linux Syslog",
			Vendor:       "Open Source",
			Product:      "rsyslog",
			Version:      "8.x",
			SourceType:   "endpoint",
			Status:       "active",
			ParserType:   "grok",
			ParserConfig: map[string]interface{}{"format": "syslog"},
			FieldMapping: map[string]interface{}{"hostname": "hostname", "program": "process_name"},
			Description:  "Linux system logging via rsyslog/syslog-ng",
			LogFormats:   []string{"syslog", "JSON"},
			AssetCount:   45,
			EventsPerDay: 1200000,
			CreatedAt:    now.Add(-300 * 24 * time.Hour),
			UpdatedAt:    now,
		},
	}

	for _, product := range sampleProducts {
		productStore[product.ID] = product
	}
	productCounter = len(sampleProducts)
}

// ListProductsHandler returns all products
func ListProductsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	productMu.RLock()
	defer productMu.RUnlock()

	query := r.URL.Query()
	search := strings.ToLower(query.Get("search"))
	sourceType := query.Get("source_type")
	vendor := query.Get("vendor")
	status := query.Get("status")

	var products []Product
	for _, product := range productStore {
		if search != "" {
			if !strings.Contains(strings.ToLower(product.Name), search) &&
				!strings.Contains(strings.ToLower(product.Vendor), search) {
				continue
			}
		}
		if sourceType != "" && sourceType != "all" && product.SourceType != sourceType {
			continue
		}
		if vendor != "" && !strings.EqualFold(product.Vendor, vendor) {
			continue
		}
		if status != "" && status != "all" && product.Status != status {
			continue
		}
		products = append(products, product)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

// GetProductHandler returns a specific product
func GetProductHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	productMu.RLock()
	product, exists := productStore[id]
	productMu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"Product not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(product)
}

// CreateProductHandler creates a new product
func CreateProductHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req Product
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	productMu.Lock()
	defer productMu.Unlock()

	productCounter++
	req.ID = fmt.Sprintf("prod-%03d", productCounter)
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	if req.Status == "" {
		req.Status = "active"
	}

	productStore[req.ID] = req

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}
