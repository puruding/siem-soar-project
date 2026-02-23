package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Asset represents an asset in the system
type Asset struct {
	ID           string    `json:"id"`
	AssetID      string    `json:"asset_id"`
	DisplayName  string    `json:"display_name"`
	Hostname     string    `json:"hostname"`
	IPAddresses  []string  `json:"ip_addresses"`
	AssetType    string    `json:"asset_type"`
	OSFamily     string    `json:"os_family"`
	OSName       string    `json:"os_name"`
	Owner        string    `json:"owner"`
	Department   string    `json:"department"`
	Location     string    `json:"location"`
	Tags         []string  `json:"tags"`
	Criticality  string    `json:"criticality"`
	Status       string    `json:"status"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CreatedAt    time.Time `json:"created_at"`
	DataSourceID string    `json:"data_source_id,omitempty"`
	ProductName  string    `json:"product_name,omitempty"`
	VendorName   string    `json:"vendor_name,omitempty"`
	ParserType   string    `json:"parser_type,omitempty"`
}

var (
	assetStore   = make(map[string]Asset)
	assetMu      sync.RWMutex
	assetCounter = 0
)

func init() {
	// Initialize with sample assets including firewall-01
	now := time.Now()
	sampleAssets := []Asset{
		{
			ID:          "asset-001",
			AssetID:     "FW-001",
			DisplayName: "firewall-01",
			Hostname:    "firewall-01.corp.local",
			IPAddresses: []string{"10.0.0.1", "192.168.1.1"},
			AssetType:   "firewall",
			OSFamily:    "linux",
			OSName:      "Palo Alto PAN-OS 10.2",
			Owner:       "network-team",
			Department:  "IT Security",
			Location:    "DC-01",
			Tags:        []string{"perimeter", "critical-infra", "pci-scope"},
			Criticality: "Critical",
			Status:      "Active",
			LastSeenAt:  now,
			CreatedAt:   now.Add(-90 * 24 * time.Hour),
			VendorName:  "Palo Alto Networks",
			ProductName: "PA-5250",
			ParserType:  "paloalto_firewall",
		},
		{
			ID:          "asset-002",
			AssetID:     "SRV-001",
			DisplayName: "web-server-01",
			Hostname:    "web-server-01.corp.local",
			IPAddresses: []string{"10.0.1.10"},
			AssetType:   "server",
			OSFamily:    "linux",
			OSName:      "Ubuntu 22.04 LTS",
			Owner:       "web-team",
			Department:  "Engineering",
			Location:    "DC-01",
			Tags:        []string{"production", "web", "public-facing"},
			Criticality: "High",
			Status:      "Active",
			LastSeenAt:  now.Add(-5 * time.Minute),
			CreatedAt:   now.Add(-60 * 24 * time.Hour),
		},
		{
			ID:          "asset-003",
			AssetID:     "SRV-002",
			DisplayName: "db-server-01",
			Hostname:    "db-server-01.corp.local",
			IPAddresses: []string{"10.0.2.20"},
			AssetType:   "server",
			OSFamily:    "linux",
			OSName:      "CentOS 8",
			Owner:       "dba-team",
			Department:  "Engineering",
			Location:    "DC-01",
			Tags:        []string{"production", "database", "pci-scope"},
			Criticality: "Critical",
			Status:      "Active",
			LastSeenAt:  now.Add(-2 * time.Minute),
			CreatedAt:   now.Add(-120 * 24 * time.Hour),
		},
		{
			ID:          "asset-004",
			AssetID:     "WS-001",
			DisplayName: "admin-workstation-01",
			Hostname:    "admin-ws-01.corp.local",
			IPAddresses: []string{"192.168.1.100"},
			AssetType:   "workstation",
			OSFamily:    "windows",
			OSName:      "Windows 11 Enterprise",
			Owner:       "john.doe",
			Department:  "IT",
			Location:    "HQ-Floor2",
			Tags:        []string{"admin", "privileged"},
			Criticality: "High",
			Status:      "Active",
			LastSeenAt:  now.Add(-30 * time.Minute),
			CreatedAt:   now.Add(-30 * 24 * time.Hour),
		},
		{
			ID:          "asset-005",
			AssetID:     "SW-001",
			DisplayName: "core-switch-01",
			Hostname:    "core-sw-01.corp.local",
			IPAddresses: []string{"10.0.0.2"},
			AssetType:   "switch",
			OSFamily:    "linux",
			OSName:      "Cisco NX-OS 9.3",
			Owner:       "network-team",
			Department:  "IT",
			Location:    "DC-01",
			Tags:        []string{"core", "network", "critical-infra"},
			Criticality: "Critical",
			Status:      "Active",
			LastSeenAt:  now.Add(-1 * time.Minute),
			CreatedAt:   now.Add(-180 * 24 * time.Hour),
			VendorName:  "Cisco",
			ProductName: "Nexus 9000",
		},
		{
			ID:          "asset-006",
			AssetID:     "EDR-001",
			DisplayName: "edr-server-01",
			Hostname:    "edr-server-01.corp.local",
			IPAddresses: []string{"10.0.3.50"},
			AssetType:   "server",
			OSFamily:    "windows",
			OSName:      "Windows Server 2022",
			Owner:       "security-team",
			Department:  "IT Security",
			Location:    "DC-01",
			Tags:        []string{"security", "edr", "monitoring"},
			Criticality: "High",
			Status:      "Active",
			LastSeenAt:  now,
			CreatedAt:   now.Add(-45 * 24 * time.Hour),
			VendorName:  "CrowdStrike",
			ProductName: "Falcon",
		},
	}

	for _, asset := range sampleAssets {
		assetStore[asset.ID] = asset
	}
	assetCounter = len(sampleAssets)
}

// ListAssetsHandler returns all assets
func ListAssetsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	assetMu.RLock()
	defer assetMu.RUnlock()

	// Get query parameters for filtering
	query := r.URL.Query()
	search := strings.ToLower(query.Get("search"))
	assetType := query.Get("asset_type")
	criticality := query.Get("criticality")
	status := query.Get("status")

	var assets []Asset
	for _, asset := range assetStore {
		// Apply filters
		if search != "" {
			if !strings.Contains(strings.ToLower(asset.DisplayName), search) &&
				!strings.Contains(strings.ToLower(asset.Hostname), search) &&
				!containsIP(asset.IPAddresses, search) {
				continue
			}
		}
		if assetType != "" && assetType != "all" && asset.AssetType != assetType {
			continue
		}
		if criticality != "" && criticality != "all" && !strings.EqualFold(asset.Criticality, criticality) {
			continue
		}
		if status != "" && status != "all" && !strings.EqualFold(asset.Status, status) {
			continue
		}
		assets = append(assets, asset)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// GetAssetHandler returns a specific asset by ID
func GetAssetHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	assetMu.RLock()
	asset, exists := assetStore[id]
	assetMu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"Asset not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(asset)
}

// CreateAssetHandler creates a new asset
func CreateAssetHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req Asset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	assetMu.Lock()
	defer assetMu.Unlock()

	assetCounter++
	req.ID = fmt.Sprintf("asset-%03d", assetCounter)
	req.CreatedAt = time.Now()
	req.LastSeenAt = time.Now()
	if req.Status == "" {
		req.Status = "Active"
	}
	if req.Criticality == "" {
		req.Criticality = "Medium"
	}

	assetStore[req.ID] = req

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// UpdateAssetHandler updates an asset
func UpdateAssetHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	assetMu.Lock()
	defer assetMu.Unlock()

	asset, exists := assetStore[id]
	if !exists {
		http.Error(w, `{"error":"Asset not found"}`, http.StatusNotFound)
		return
	}

	var req Asset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Update fields
	if req.DisplayName != "" {
		asset.DisplayName = req.DisplayName
	}
	if req.Hostname != "" {
		asset.Hostname = req.Hostname
	}
	if len(req.IPAddresses) > 0 {
		asset.IPAddresses = req.IPAddresses
	}
	if req.AssetType != "" {
		asset.AssetType = req.AssetType
	}
	if req.Owner != "" {
		asset.Owner = req.Owner
	}
	if req.Department != "" {
		asset.Department = req.Department
	}
	if req.Criticality != "" {
		asset.Criticality = req.Criticality
	}
	if req.Status != "" {
		asset.Status = req.Status
	}
	if len(req.Tags) > 0 {
		asset.Tags = req.Tags
	}
	asset.LastSeenAt = time.Now()

	assetStore[id] = asset

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(asset)
}

// DeleteAssetHandler deletes an asset
func DeleteAssetHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	assetMu.Lock()
	defer assetMu.Unlock()

	if _, exists := assetStore[id]; !exists {
		http.Error(w, `{"error":"Asset not found"}`, http.StatusNotFound)
		return
	}

	delete(assetStore, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Asset deleted",
	})
}

func containsIP(ips []string, search string) bool {
	for _, ip := range ips {
		if strings.Contains(ip, search) {
			return true
		}
	}
	return false
}
