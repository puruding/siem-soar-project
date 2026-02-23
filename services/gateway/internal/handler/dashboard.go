package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// DashboardStats represents the summary statistics for the dashboard
type DashboardStats struct {
	ActiveAlerts      int     `json:"activeAlerts"`
	EPS               int     `json:"eps"`
	OpenCases         int     `json:"openCases"`
	DetectionRate     float64 `json:"detectionRate"`
	MeanTimeToDetect  float64 `json:"meanTimeToDetect"`
	MeanTimeToRespond float64 `json:"meanTimeToRespond"`
}

// AlertTrendData represents alert trend data over time
type AlertTrendData struct {
	Timestamps []string `json:"timestamps"`
	Critical   []int    `json:"critical"`
	High       []int    `json:"high"`
	Medium     []int    `json:"medium"`
	Low        []int    `json:"low"`
}

// TopAlert represents a top alert entry
type TopAlert struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
	LastSeen string `json:"lastSeen"`
}

// RecentCaseResponse represents a case for dashboard display
type RecentCaseResponse struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Assignee  string `json:"assignee"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// ThreatSummary represents threat intelligence summary
type ThreatSummary struct {
	TotalThreats int `json:"totalThreats"`
	ByCategory   []struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	} `json:"byCategory"`
	ByTactic []struct {
		Tactic string `json:"tactic"`
		Count  int    `json:"count"`
	} `json:"byTactic"`
	RecentIOCs []struct {
		Type       string  `json:"type"`
		Value      string  `json:"value"`
		Confidence float64 `json:"confidence"`
	} `json:"recentIOCs"`
}

// EPSMetric represents an EPS data point
type EPSMetric struct {
	Timestamp string `json:"timestamp"`
	Value     int    `json:"value"`
}

// EPSMetricsResponse represents EPS metrics response
type EPSMetricsResponse struct {
	Metrics []EPSMetric `json:"metrics"`
	Average int         `json:"average"`
	Peak    int         `json:"peak"`
	Current int         `json:"current"`
}

// GetDashboardStatsHandler returns dashboard summary statistics
func GetDashboardStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Calculate active alerts from alertStore
	alertStoreMu.RLock()
	activeAlerts := 0
	criticalCount := 0
	highCount := 0
	for _, alert := range alertStore {
		if alert.Status == "new" || alert.Status == "investigating" {
			activeAlerts++
		}
		if alert.Severity == "CRITICAL" {
			criticalCount++
		}
		if alert.Severity == "HIGH" {
			highCount++
		}
	}
	totalAlerts := len(alertStore)
	alertStoreMu.RUnlock()

	// Calculate open cases from caseStore
	caseStoreMu.RLock()
	openCases := 0
	for _, c := range caseStore {
		if c.Status == "open" || c.Status == "investigating" {
			openCases++
		}
	}
	caseStoreMu.RUnlock()

	// Calculate events count
	eventMu.RLock()
	eventCount := len(eventStore)
	eventMu.RUnlock()

	// Calculate EPS (events per second) - simulated based on event count
	eps := eventCount * 10 // Simulate 10x the stored events as current EPS

	// Calculate detection rate (percentage of events that generated alerts)
	var detectionRate float64
	if eventCount > 0 {
		detectionRate = float64(totalAlerts) / float64(eventCount) * 100
		if detectionRate > 100 {
			detectionRate = 95.5 // Cap at realistic value
		}
	} else {
		detectionRate = 95.5 // Default value
	}

	stats := DashboardStats{
		ActiveAlerts:      activeAlerts,
		EPS:               eps,
		OpenCases:         openCases,
		DetectionRate:     detectionRate,
		MeanTimeToDetect:  3.2,  // Minutes (would be calculated from actual detection times)
		MeanTimeToRespond: 24.0, // Minutes (would be calculated from actual response times)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetAlertTrendHandler returns alert trend data over time
func GetAlertTrendHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Generate trend data for the last 24 hours
	now := time.Now()
	timestamps := make([]string, 24)
	critical := make([]int, 24)
	high := make([]int, 24)
	medium := make([]int, 24)
	low := make([]int, 24)

	alertStoreMu.RLock()
	for i := 23; i >= 0; i-- {
		hour := now.Add(-time.Duration(i) * time.Hour)
		timestamps[23-i] = hour.Format("15:00")

		// Count alerts by severity for each hour
		for _, alert := range alertStore {
			alertHour := alert.Timestamp.Hour()
			if alertHour == hour.Hour() {
				switch alert.Severity {
				case "CRITICAL":
					critical[23-i]++
				case "HIGH":
					high[23-i]++
				case "MEDIUM":
					medium[23-i]++
				case "LOW":
					low[23-i]++
				}
			}
		}
	}
	alertStoreMu.RUnlock()

	// Add some baseline data if no real alerts
	for i := range timestamps {
		if critical[i]+high[i]+medium[i]+low[i] == 0 {
			// Add simulated baseline data
			critical[i] = i%3 + 1
			high[i] = i%5 + 2
			medium[i] = i%7 + 3
			low[i] = i%4 + 1
		}
	}

	trend := AlertTrendData{
		Timestamps: timestamps,
		Critical:   critical,
		High:       high,
		Medium:     medium,
		Low:        low,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trend)
}

// GetTopAlertsHandler returns top alerts by count
func GetTopAlertsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get limit from query params
	limitStr := r.URL.Query().Get("limit")
	limit := 5
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	alertStoreMu.RLock()
	// Group alerts by rule name
	ruleCount := make(map[string]struct {
		alert Alert
		count int
	})

	for _, alert := range alertStore {
		key := alert.RuleName
		if key == "" {
			key = alert.Title
		}
		if entry, exists := ruleCount[key]; exists {
			entry.count++
			if alert.Timestamp.After(entry.alert.Timestamp) {
				entry.alert = alert
			}
			ruleCount[key] = entry
		} else {
			ruleCount[key] = struct {
				alert Alert
				count int
			}{alert: alert, count: 1}
		}
	}
	alertStoreMu.RUnlock()

	// Convert to slice and sort by count
	type alertEntry struct {
		key   string
		alert Alert
		count int
	}
	entries := make([]alertEntry, 0, len(ruleCount))
	for k, v := range ruleCount {
		entries = append(entries, alertEntry{key: k, alert: v.alert, count: v.count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	// Build response
	topAlerts := make([]TopAlert, 0, limit)
	for i := 0; i < len(entries) && i < limit; i++ {
		entry := entries[i]
		topAlerts = append(topAlerts, TopAlert{
			ID:       entry.alert.ID,
			Name:     entry.key,
			Severity: entry.alert.Severity,
			Count:    entry.count,
			LastSeen: entry.alert.Timestamp.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topAlerts)
}

// GetRecentCasesHandler returns recent cases
func GetRecentCasesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get limit from query params
	limitStr := r.URL.Query().Get("limit")
	limit := 5
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	caseStoreMu.RLock()
	recentCases := make([]RecentCaseResponse, 0, limit)
	for i := 0; i < len(caseStore) && i < limit; i++ {
		c := caseStore[i]
		recentCases = append(recentCases, RecentCaseResponse{
			ID:        c.ID,
			Title:     c.Title,
			Status:    c.Status,
			Severity:  c.Priority, // Use priority as severity
			Assignee:  c.AssignedTo,
			CreatedAt: c.CreatedAt.Format(time.RFC3339),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		})
	}
	caseStoreMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recentCases)
}

// GetThreatSummaryHandler returns threat intelligence summary
func GetThreatSummaryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Count threats from alerts
	alertStoreMu.RLock()
	tacticCount := make(map[string]int)
	categoryCount := make(map[string]int)

	for _, alert := range alertStore {
		// Count by tactic
		for _, tactic := range alert.MITRETactics {
			tacticCount[tactic]++
		}
		// Count by source type (as category)
		categoryCount[alert.SourceType]++
	}
	totalThreats := len(alertStore)
	alertStoreMu.RUnlock()

	// Build response
	summary := struct {
		TotalThreats int `json:"totalThreats"`
		ByCategory   []struct {
			Category string `json:"category"`
			Count    int    `json:"count"`
		} `json:"byCategory"`
		ByTactic []struct {
			Tactic string `json:"tactic"`
			Count  int    `json:"count"`
		} `json:"byTactic"`
		RecentIOCs []struct {
			Type       string  `json:"type"`
			Value      string  `json:"value"`
			Confidence float64 `json:"confidence"`
		} `json:"recentIOCs"`
	}{
		TotalThreats: totalThreats,
	}

	for category, count := range categoryCount {
		summary.ByCategory = append(summary.ByCategory, struct {
			Category string `json:"category"`
			Count    int    `json:"count"`
		}{Category: category, Count: count})
	}

	for tactic, count := range tacticCount {
		summary.ByTactic = append(summary.ByTactic, struct {
			Tactic string `json:"tactic"`
			Count  int    `json:"count"`
		}{Tactic: tactic, Count: count})
	}

	// Add sample IOCs
	summary.RecentIOCs = []struct {
		Type       string  `json:"type"`
		Value      string  `json:"value"`
		Confidence float64 `json:"confidence"`
	}{
		{Type: "ip", Value: "185.45.67.89", Confidence: 0.95},
		{Type: "domain", Value: "malware-c2.evil.com", Confidence: 0.98},
		{Type: "hash", Value: "a1b2c3d4e5f6789012345678901234567890abcd", Confidence: 0.90},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// GetEPSMetricsHandler returns EPS (Events Per Second) metrics
func GetEPSMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Generate EPS metrics for the last hour
	now := time.Now()
	metrics := make([]EPSMetric, 60)
	total := 0
	peak := 0

	for i := 59; i >= 0; i-- {
		minute := now.Add(-time.Duration(i) * time.Minute)
		// Generate simulated EPS data
		value := 800 + (i%20)*50 + (i%7)*30
		metrics[59-i] = EPSMetric{
			Timestamp: minute.Format("15:04"),
			Value:     value,
		}
		total += value
		if value > peak {
			peak = value
		}
	}

	// Current EPS based on events
	eventMu.RLock()
	current := len(eventStore) * 100
	if current < 500 {
		current = 850 // Baseline
	}
	eventMu.RUnlock()

	response := EPSMetricsResponse{
		Metrics: metrics,
		Average: total / 60,
		Peak:    peak,
		Current: current,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
