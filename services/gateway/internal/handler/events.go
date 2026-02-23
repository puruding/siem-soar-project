package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siem-soar-platform/pkg/repository"
)

// Event represents a security event
type Event struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	EventTime     time.Time              `json:"event_time"`
	IngestTime    time.Time              `json:"ingest_time"`
	Source        string                 `json:"source"`
	SourceType    string                 `json:"source_type"`
	EventType     string                 `json:"event_type"`
	Severity      string                 `json:"severity"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	DestIP        string                 `json:"dest_ip,omitempty"`
	SourcePort    int                    `json:"source_port,omitempty"`
	DestPort      int                    `json:"dest_port,omitempty"`
	User          string                 `json:"user,omitempty"`
	Hostname      string                 `json:"hostname,omitempty"`
	Action        string                 `json:"action,omitempty"`
	Status        string                 `json:"status,omitempty"`
	Message       string                 `json:"message"`
	RawLog        string                 `json:"raw_log,omitempty"`
	ParsedFields  map[string]interface{} `json:"parsed_fields,omitempty"`
	AssetID       string                 `json:"asset_id,omitempty"`
	ProductID     string                 `json:"product_id,omitempty"`
}

var (
	eventStore   = make([]Event, 0)
	eventMu      sync.RWMutex
	eventCounter = 0
	maxEvents    = 10000 // Keep last 10000 events
	eventRepo    repository.EventRepository
	repoMu       sync.RWMutex
)

func init() {
	// Initialize with sample events
	now := time.Now()
	sampleEvents := []Event{
		{
			ID:         "evt-001",
			TenantID:   "default",
			EventTime:  now.Add(-5 * time.Minute),
			IngestTime: now.Add(-5 * time.Minute),
			Source:     "firewall-01",
			SourceType: "firewall",
			EventType:  "authentication",
			Severity:   "high",
			SourceIP:   "192.168.1.100",
			DestIP:     "10.0.0.1",
			SourcePort: 52341,
			DestPort:   22,
			User:       "admin",
			Hostname:   "firewall-01",
			Action:     "block",
			Status:     "failed",
			Message:    "Failed SSH login attempt from 192.168.1.100 - Brute Force detected",
			RawLog:     "Feb 21 10:30:45 firewall-01 sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2",
			AssetID:    "asset-001",
			ProductID:  "prod-001",
		},
		{
			ID:         "evt-002",
			TenantID:   "default",
			EventTime:  now.Add(-4 * time.Minute),
			IngestTime: now.Add(-4 * time.Minute),
			Source:     "firewall-01",
			SourceType: "firewall",
			EventType:  "authentication",
			Severity:   "high",
			SourceIP:   "192.168.1.100",
			DestIP:     "10.0.0.1",
			SourcePort: 52342,
			DestPort:   22,
			User:       "root",
			Hostname:   "firewall-01",
			Action:     "block",
			Status:     "failed",
			Message:    "Failed SSH login attempt - invalid user root",
			RawLog:     "Feb 21 10:31:45 firewall-01 sshd[12346]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2",
			AssetID:    "asset-001",
			ProductID:  "prod-001",
		},
		{
			ID:         "evt-003",
			TenantID:   "default",
			EventTime:  now.Add(-3 * time.Minute),
			IngestTime: now.Add(-3 * time.Minute),
			Source:     "web-server-01",
			SourceType: "web",
			EventType:  "web_access",
			Severity:   "low",
			SourceIP:   "10.0.0.50",
			DestIP:     "10.0.0.10",
			SourcePort: 45123,
			DestPort:   443,
			User:       "anonymous",
			Hostname:   "web-server-01",
			Action:     "allow",
			Status:     "success",
			Message:    "GET /api/v1/health HTTP/1.1 200 OK",
			RawLog:     "10.0.0.50 - - [21/Feb/2026:10:32:45 +0900] \"GET /api/v1/health HTTP/1.1\" 200 45",
			AssetID:    "asset-002",
			ProductID:  "prod-002",
		},
		{
			ID:         "evt-004",
			TenantID:   "default",
			EventTime:  now.Add(-2 * time.Minute),
			IngestTime: now.Add(-2 * time.Minute),
			Source:     "edr-agent-01",
			SourceType: "edr",
			EventType:  "process_execution",
			Severity:   "medium",
			SourceIP:   "",
			DestIP:     "",
			User:       "john.doe",
			Hostname:   "workstation-01",
			Action:     "allow",
			Status:     "success",
			Message:    "PowerShell.exe executed with encoded command",
			RawLog:     "Process: powershell.exe, CommandLine: powershell -enc ZWNobyAiaGVsbG8i, User: john.doe",
			AssetID:    "asset-004",
			ProductID:  "prod-002",
		},
		{
			ID:         "evt-005",
			TenantID:   "default",
			EventTime:  now.Add(-1 * time.Minute),
			IngestTime: now.Add(-1 * time.Minute),
			Source:     "azure-ad",
			SourceType: "identity",
			EventType:  "authentication",
			Severity:   "low",
			SourceIP:   "203.0.113.50",
			DestIP:     "",
			User:       "user@company.com",
			Hostname:   "",
			Action:     "allow",
			Status:     "success",
			Message:    "User login successful from known location",
			RawLog:     `{"userPrincipalName":"user@company.com","ipAddress":"203.0.113.50","status":{"errorCode":0},"createdDateTime":"2026-02-21T10:34:45Z"}`,
			AssetID:    "",
			ProductID:  "prod-003",
		},
	}

	eventStore = sampleEvents
	eventCounter = len(sampleEvents)
}

// SetEventRepository sets the EventRepository instance (called from main.go)
func SetEventRepository(repo repository.EventRepository) {
	repoMu.Lock()
	defer repoMu.Unlock()
	eventRepo = repo
}

// getEventRepository returns the current EventRepository (thread-safe)
func getEventRepository() repository.EventRepository {
	repoMu.RLock()
	defer repoMu.RUnlock()
	return eventRepo
}

// AddEvent adds a new event to the store
func AddEvent(event Event) {
	eventMu.Lock()
	defer eventMu.Unlock()

	eventCounter++
	event.ID = fmt.Sprintf("evt-%06d", eventCounter)
	if event.IngestTime.IsZero() {
		event.IngestTime = time.Now()
	}
	if event.TenantID == "" {
		event.TenantID = "default"
	}

	eventStore = append(eventStore, event)

	// Keep only last maxEvents
	if len(eventStore) > maxEvents {
		eventStore = eventStore[len(eventStore)-maxEvents:]
	}
}

// convertRepoEventToHandlerEvent converts repository.Event to handler.Event
func convertRepoEventToHandlerEvent(re *repository.Event) Event {
	event := Event{
		ID:           re.EventID,
		TenantID:     re.TenantID,
		EventTime:    re.Timestamp,
		IngestTime:   re.Timestamp, // Use same timestamp as ingest time
		Source:       re.VendorName,
		SourceType:   re.ProductName,
		EventType:    re.EventType,
		Severity:     re.Severity,
		User:         re.PrincipalUserID,
		Hostname:     re.PrincipalHostname,
		Action:       re.SecurityAction,
		Status:       "", // Not available in repository.Event
		Message:      re.Description,
		RawLog:       re.RawLog,
		ParsedFields: re.AdditionalFields,
	}

	// Extract first IP from arrays
	if len(re.PrincipalIP) > 0 {
		event.SourceIP = re.PrincipalIP[0]
	}
	if len(re.TargetIP) > 0 {
		event.DestIP = re.TargetIP[0]
	}

	// Generate synthetic raw log if empty
	if event.RawLog == "" {
		event.RawLog = generateSyntheticRawLog(re)
	}

	// Note: SourcePort and DestPort are not in repository.Event
	// AssetID and ProductID are also not directly mapped

	return event
}

// generateSyntheticRawLog creates a raw log string from event fields when original is missing
func generateSyntheticRawLog(re *repository.Event) string {
	var parts []string

	// Timestamp
	parts = append(parts, re.Timestamp.Format("2006-01-02T15:04:05Z07:00"))

	// Vendor/Product
	if re.VendorName != "" {
		parts = append(parts, re.VendorName)
	}
	if re.ProductName != "" {
		parts = append(parts, "["+re.ProductName+"]")
	}

	// Severity
	if re.Severity != "" && re.Severity != "UNKNOWN" {
		parts = append(parts, "severity="+re.Severity)
	}

	// Event type
	if re.EventType != "" && re.EventType != "GENERIC_EVENT" {
		parts = append(parts, "type="+re.EventType)
	}

	// Principal info
	if re.PrincipalHostname != "" {
		parts = append(parts, "host="+re.PrincipalHostname)
	}
	if re.PrincipalUserID != "" {
		parts = append(parts, "user="+re.PrincipalUserID)
	}
	if len(re.PrincipalIP) > 0 && re.PrincipalIP[0] != "" {
		parts = append(parts, "src_ip="+re.PrincipalIP[0])
	}

	// Target info
	if len(re.TargetIP) > 0 && re.TargetIP[0] != "" {
		parts = append(parts, "dst_ip="+re.TargetIP[0])
	}
	if re.TargetHostname != "" {
		parts = append(parts, "dst_host="+re.TargetHostname)
	}

	// Security info
	if re.SecurityAction != "" && re.SecurityAction != "UNKNOWN" {
		parts = append(parts, "action="+re.SecurityAction)
	}
	if re.SecurityRuleName != "" {
		parts = append(parts, "rule="+re.SecurityRuleName)
	}

	// Description
	if re.Description != "" {
		parts = append(parts, "msg=\""+re.Description+"\"")
	}

	return strings.Join(parts, " ")
}

// ListEventsHandler returns events with filtering and pagination
func ListEventsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	repo := getEventRepository()

	// If ClickHouse repository is not available, fall back to mock data
	if repo == nil {
		listEventsFromMock(w, r)
		return
	}

	query := r.URL.Query()

	// Build filter
	tenantID := query.Get("tenant_id")
	if tenantID == "" {
		tenantID = "default"
	}
	filter := repository.EventFilter{
		TenantID:    tenantID,
		SearchQuery: query.Get("search"),
	}

	// Event type filter
	if eventType := query.Get("event_type"); eventType != "" && eventType != "all" {
		filter.EventTypes = []string{eventType}
	}

	// Severity filter
	if severity := query.Get("severity"); severity != "" && severity != "all" {
		filter.Severity = []string{severity}
	}

	// Time range filtering
	if st := query.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			filter.TimeRange.Start = t
		}
	}
	if et := query.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			filter.TimeRange.End = t
		}
	}

	// Build query options
	opts := repository.NewQueryOptions()

	// Pagination
	limit := 100
	offset := 0
	if l := query.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	if o := query.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	opts.Pagination.PageSize = limit
	opts.Pagination.Page = (offset / limit) + 1

	// Sort by timestamp descending
	opts.Sorts = []repository.Sort{
		{Field: "timestamp", Order: repository.SortDesc},
	}

	// Execute search
	ctx := context.Background()
	repoEvents, total, err := repo.Search(ctx, filter, opts)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to search events: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Convert repository.Event to handler.Event
	events := make([]Event, 0, len(repoEvents))
	for _, re := range repoEvents {
		events = append(events, convertRepoEventToHandlerEvent(re))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// listEventsFromMock is the fallback function using mock data
func listEventsFromMock(w http.ResponseWriter, r *http.Request) {
	eventMu.RLock()
	defer eventMu.RUnlock()

	query := r.URL.Query()
	search := strings.ToLower(query.Get("search"))
	sourceType := query.Get("source_type")
	eventType := query.Get("event_type")
	severity := query.Get("severity")
	source := query.Get("source")

	// Pagination
	limit := 100
	offset := 0
	if l := query.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	if o := query.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	// Time range filtering
	var startTime, endTime time.Time
	if st := query.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			startTime = t
		}
	}
	if et := query.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			endTime = t
		}
	}

	// Filter events (newest first)
	var filtered []Event
	for i := len(eventStore) - 1; i >= 0; i-- {
		event := eventStore[i]

		// Time range filter
		if !startTime.IsZero() && event.EventTime.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && event.EventTime.After(endTime) {
			continue
		}

		// Search filter
		if search != "" {
			if !strings.Contains(strings.ToLower(event.Message), search) &&
				!strings.Contains(strings.ToLower(event.Source), search) &&
				!strings.Contains(strings.ToLower(event.User), search) &&
				!strings.Contains(strings.ToLower(event.SourceIP), search) {
				continue
			}
		}

		// Source type filter
		if sourceType != "" && sourceType != "all" && event.SourceType != sourceType {
			continue
		}

		// Event type filter
		if eventType != "" && eventType != "all" && event.EventType != eventType {
			continue
		}

		// Severity filter
		if severity != "" && severity != "all" && event.Severity != severity {
			continue
		}

		// Source filter
		if source != "" && event.Source != source {
			continue
		}

		filtered = append(filtered, event)
	}

	total := len(filtered)

	// Apply pagination
	if offset >= len(filtered) {
		filtered = []Event{}
	} else {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		filtered = filtered[offset:end]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": filtered,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetEventHandler returns a specific event
func GetEventHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")
	repo := getEventRepository()

	// If ClickHouse repository is not available, fall back to mock data
	if repo == nil {
		getEventFromMock(w, id)
		return
	}

	ctx := context.Background()
	repoEvent, err := repo.GetByID(ctx, "default", id)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to get event: %v"}`, err), http.StatusInternalServerError)
		return
	}

	if repoEvent == nil {
		http.Error(w, `{"error":"Event not found"}`, http.StatusNotFound)
		return
	}

	event := convertRepoEventToHandlerEvent(repoEvent)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(event)
}

// getEventFromMock is the fallback function using mock data
func getEventFromMock(w http.ResponseWriter, id string) {
	eventMu.RLock()
	defer eventMu.RUnlock()

	for _, event := range eventStore {
		if event.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(event)
			return
		}
	}

	http.Error(w, `{"error":"Event not found"}`, http.StatusNotFound)
}

// CreateEventHandler creates a new event (for log ingestion)
func CreateEventHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if event.EventTime.IsZero() {
		event.EventTime = time.Now()
	}

	AddEvent(event)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      event.ID,
	})
}

// GetEventStatsHandler returns event statistics
func GetEventStatsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	repo := getEventRepository()

	// If ClickHouse repository is not available, fall back to mock data
	if repo == nil {
		getEventStatsFromMock(w, r)
		return
	}

	query := r.URL.Query()

	// Build filter with time range
	filter := repository.EventFilter{
		TenantID: "default",
	}

	// Time range filtering (default to last 24 hours if not specified)
	now := time.Now()
	startTime := now.Add(-24 * time.Hour)
	endTime := now

	if st := query.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			startTime = t
		}
	}
	if et := query.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			endTime = t
		}
	}

	filter.TimeRange = repository.TimeRange{
		Start: startTime,
		End:   endTime,
	}

	ctx := context.Background()
	repoStats, err := repo.GetStats(ctx, filter)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to get stats: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Calculate last hour and last 24h counts
	last24hFilter := repository.EventFilter{
		TenantID: "default",
		TimeRange: repository.TimeRange{
			Start: now.Add(-24 * time.Hour),
			End:   now,
		},
	}
	last24hStats, _ := repo.GetStats(ctx, last24hFilter)

	lastHourFilter := repository.EventFilter{
		TenantID: "default",
		TimeRange: repository.TimeRange{
			Start: now.Add(-1 * time.Hour),
			End:   now,
		},
	}
	lastHourStats, _ := repo.GetStats(ctx, lastHourFilter)

	// Build response
	stats := map[string]interface{}{
		"total":          repoStats.TotalEvents,
		"by_severity":    repoStats.EventsBySeverity,
		"by_event_type":  repoStats.EventsByType,
		"by_vendor":      repoStats.EventsByVendor,
		"unique_hosts":   repoStats.UniqueHosts,
		"unique_users":   repoStats.UniqueUsers,
		"ti_matches":     repoStats.TIMatches,
	}

	if last24hStats != nil {
		stats["last_24h"] = last24hStats.TotalEvents
	}
	if lastHourStats != nil {
		stats["last_hour"] = lastHourStats.TotalEvents
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// getEventStatsFromMock is the fallback function using mock data
func getEventStatsFromMock(w http.ResponseWriter, r *http.Request) {
	eventMu.RLock()
	defer eventMu.RUnlock()

	// Calculate stats
	stats := map[string]interface{}{
		"total": len(eventStore),
	}

	// Count by severity
	severityCounts := make(map[string]int)
	sourceTypeCounts := make(map[string]int)
	eventTypeCounts := make(map[string]int)

	now := time.Now()
	last24h := 0
	lastHour := 0

	for _, event := range eventStore {
		severityCounts[event.Severity]++
		sourceTypeCounts[event.SourceType]++
		eventTypeCounts[event.EventType]++

		if event.EventTime.After(now.Add(-24 * time.Hour)) {
			last24h++
		}
		if event.EventTime.After(now.Add(-1 * time.Hour)) {
			lastHour++
		}
	}

	stats["by_severity"] = severityCounts
	stats["by_source_type"] = sourceTypeCounts
	stats["by_event_type"] = eventTypeCounts
	stats["last_24h"] = last24h
	stats["last_hour"] = lastHour

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
