package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Parser represents a log parser configuration
type Parser struct {
	ID           string                 `json:"id"`
	DataSourceID string                 `json:"data_source_id"`
	Name         string                 `json:"name"`
	ParserType   string                 `json:"parser_type"` // grok, regex, json, cef, leef, xml
	Pattern      string                 `json:"pattern"`
	ParserConfig map[string]interface{} `json:"parser_config"`
	FieldMapping map[string]interface{} `json:"field_mapping"`
	SampleLogs   []string               `json:"sample_logs"`
	Status       string                 `json:"status"` // active, inactive, draft
	Version      int                    `json:"version"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	ProductName  string                 `json:"product_name"`
	VendorName   string                 `json:"vendor_name"`
}

var (
	parserStore   = make(map[string]Parser)
	parserMu      sync.RWMutex
	parserCounter = 0
)

func init() {
	now := time.Now()
	sampleParsers := []Parser{
		{
			ID:           "parser-001",
			DataSourceID: "prod-001",
			Name:         "Palo Alto Firewall Parser",
			ParserType:   "cef",
			Pattern:      "CEF:0|Palo Alto Networks|PAN-OS|%{VERSION}|%{THREAT_TYPE}|%{ACTION}|%{SEVERITY}|",
			ParserConfig: map[string]interface{}{"format": "CEF", "delimiter": "|"},
			FieldMapping: map[string]interface{}{"src": "source_ip", "dst": "destination_ip", "act": "action"},
			SampleLogs:   []string{"CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|block|5|src=192.168.1.100 dst=10.0.0.1 act=block"},
			Status:       "active",
			Version:      1,
			CreatedAt:    now.Add(-90 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "PA-Series Firewall",
			VendorName:   "Palo Alto Networks",
		},
		{
			ID:           "parser-002",
			DataSourceID: "prod-002",
			Name:         "CrowdStrike Falcon Parser",
			ParserType:   "json",
			Pattern:      "",
			ParserConfig: map[string]interface{}{"format": "JSON", "nested": true},
			FieldMapping: map[string]interface{}{"ComputerName": "hostname", "UserName": "user", "DetectName": "threat_name", "SeverityName": "severity"},
			SampleLogs:   []string{`{"ComputerName":"WS001","UserName":"jsmith","DetectName":"Malware","SeverityName":"High"}`},
			Status:       "active",
			Version:      2,
			CreatedAt:    now.Add(-60 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "Falcon Endpoint",
			VendorName:   "CrowdStrike",
		},
		{
			ID:           "parser-003",
			DataSourceID: "prod-003",
			Name:         "Azure AD Parser",
			ParserType:   "json",
			Pattern:      "",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"userPrincipalName": "user", "ipAddress": "source_ip", "createdDateTime": "event_time"},
			SampleLogs:   []string{`{"userPrincipalName":"user@domain.com","ipAddress":"192.168.1.100","createdDateTime":"2026-02-21T10:30:45Z"}`},
			Status:       "active",
			Version:      1,
			CreatedAt:    now.Add(-120 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "Azure Active Directory",
			VendorName:   "Microsoft",
		},
		{
			ID:           "parser-004",
			DataSourceID: "prod-004",
			Name:         "Cisco ASA Parser",
			ParserType:   "grok",
			Pattern:      `%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:device} %%ASA-%{INT:severity}-%{INT:message_id}: %{GREEDYDATA:message}`,
			ParserConfig: map[string]interface{}{"format": "syslog"},
			FieldMapping: map[string]interface{}{"device": "hostname", "severity": "severity", "message_id": "event_id"},
			SampleLogs:   []string{"Feb 21 10:30:45 fw-asa %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.100/443"},
			Status:       "active",
			Version:      3,
			CreatedAt:    now.Add(-180 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "ASA 5500-X",
			VendorName:   "Cisco",
		},
		{
			ID:           "parser-005",
			DataSourceID: "prod-005",
			Name:         "Splunk Forwarder Parser",
			ParserType:   "json",
			Pattern:      "",
			ParserConfig: map[string]interface{}{"format": "JSON"},
			FieldMapping: map[string]interface{}{"host": "hostname", "source": "log_source", "sourcetype": "log_type"},
			SampleLogs:   []string{`{"host":"server01","source":"/var/log/syslog","sourcetype":"syslog"}`},
			Status:       "active",
			Version:      1,
			CreatedAt:    now.Add(-200 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "Universal Forwarder",
			VendorName:   "Splunk",
		},
		{
			ID:           "parser-006",
			DataSourceID: "prod-006",
			Name:         "AWS CloudTrail Parser",
			ParserType:   "json",
			Pattern:      "",
			ParserConfig: map[string]interface{}{"format": "JSON", "nested": true},
			FieldMapping: map[string]interface{}{"eventTime": "event_time", "eventSource": "service", "eventName": "action", "sourceIPAddress": "source_ip"},
			SampleLogs:   []string{`{"eventTime":"2026-02-21T10:30:45Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","sourceIPAddress":"192.168.1.100"}`},
			Status:       "active",
			Version:      2,
			CreatedAt:    now.Add(-150 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "CloudTrail",
			VendorName:   "Amazon Web Services",
		},
		{
			ID:           "parser-007",
			DataSourceID: "prod-007",
			Name:         "Windows Event Parser",
			ParserType:   "xml",
			Pattern:      "",
			ParserConfig: map[string]interface{}{"format": "EVTX"},
			FieldMapping: map[string]interface{}{"EventID": "event_id", "Computer": "hostname", "SubjectUserName": "user"},
			SampleLogs:   []string{`<Event><System><EventID>4624</EventID><Computer>DC01</Computer></System></Event>`},
			Status:       "active",
			Version:      1,
			CreatedAt:    now.Add(-300 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "Windows Server",
			VendorName:   "Microsoft",
		},
		{
			ID:           "parser-008",
			DataSourceID: "prod-008",
			Name:         "Linux Syslog Parser",
			ParserType:   "grok",
			Pattern:      `%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}`,
			ParserConfig: map[string]interface{}{"format": "syslog"},
			FieldMapping: map[string]interface{}{"hostname": "hostname", "program": "process_name", "pid": "process_id"},
			SampleLogs:   []string{"Feb 21 10:30:45 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"},
			Status:       "active",
			Version:      1,
			CreatedAt:    now.Add(-300 * 24 * time.Hour),
			UpdatedAt:    now,
			ProductName:  "rsyslog",
			VendorName:   "Open Source",
		},
	}

	for _, parser := range sampleParsers {
		parserStore[parser.ID] = parser
	}
	parserCounter = len(sampleParsers)
}

// ListParsersHandler returns all parsers
func ListParsersHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	parserMu.RLock()
	defer parserMu.RUnlock()

	query := r.URL.Query()
	search := strings.ToLower(query.Get("search"))
	parserType := query.Get("parser_type")
	status := query.Get("status")

	var parsers []Parser
	for _, parser := range parserStore {
		if search != "" {
			if !strings.Contains(strings.ToLower(parser.Name), search) &&
				!strings.Contains(strings.ToLower(parser.VendorName), search) &&
				!strings.Contains(strings.ToLower(parser.ProductName), search) {
				continue
			}
		}
		if parserType != "" && parserType != "all" && parser.ParserType != parserType {
			continue
		}
		if status != "" && status != "all" && parser.Status != status {
			continue
		}
		parsers = append(parsers, parser)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parsers)
}

// GetParserHandler returns a specific parser
func GetParserHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	parserMu.RLock()
	parser, exists := parserStore[id]
	parserMu.RUnlock()

	if !exists {
		http.Error(w, `{"error":"Parser not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parser)
}

// CreateParserHandler creates a new parser
func CreateParserHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req Parser
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	parserMu.Lock()
	defer parserMu.Unlock()

	parserCounter++
	req.ID = fmt.Sprintf("parser-%03d", parserCounter)
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()
	req.Version = 1
	if req.Status == "" {
		req.Status = "active"
	}

	parserStore[req.ID] = req

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// UpdateParserHandler updates a parser
func UpdateParserHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	parserMu.Lock()
	defer parserMu.Unlock()

	parser, exists := parserStore[id]
	if !exists {
		http.Error(w, `{"error":"Parser not found"}`, http.StatusNotFound)
		return
	}

	var req Parser
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Update fields
	if req.Name != "" {
		parser.Name = req.Name
	}
	if req.Pattern != "" {
		parser.Pattern = req.Pattern
	}
	if req.ParserConfig != nil {
		parser.ParserConfig = req.ParserConfig
	}
	if req.FieldMapping != nil {
		parser.FieldMapping = req.FieldMapping
	}
	if req.SampleLogs != nil {
		parser.SampleLogs = req.SampleLogs
	}
	if req.Status != "" {
		parser.Status = req.Status
	}
	parser.Version++
	parser.UpdatedAt = time.Now()

	parserStore[id] = parser

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parser)
}

// DeleteParserHandler deletes a parser
func DeleteParserHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	parserMu.Lock()
	defer parserMu.Unlock()

	if _, exists := parserStore[id]; !exists {
		http.Error(w, `{"error":"Parser not found"}`, http.StatusNotFound)
		return
	}

	delete(parserStore, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Parser deleted",
	})
}

// TestParserHandler tests a parser with sample log
func TestParserHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req struct {
		ParserID  string `json:"parser_id"`
		SampleLog string `json:"sample_log"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Mock parsing result
	result := map[string]interface{}{
		"success": true,
		"parsed_fields": map[string]string{
			"event_time":     "2026-02-21T10:30:45Z",
			"source_ip":      "192.168.1.100",
			"destination_ip": "10.0.0.1",
			"action":         "block",
			"severity":       "high",
		},
		"matched_pattern": true,
		"parse_time_ms":   2,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
