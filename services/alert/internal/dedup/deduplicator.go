// Package dedup provides alert deduplication capabilities.
package dedup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DedupStrategy represents a deduplication strategy.
type DedupStrategy string

const (
	StrategyExact     DedupStrategy = "exact"      // Exact fingerprint match
	StrategyKey       DedupStrategy = "key"        // Dedup key match
	StrategyWindow    DedupStrategy = "window"     // Time window based
	StrategySimilarity DedupStrategy = "similarity" // Fuzzy matching
)

// DedupAction represents the action to take for duplicates.
type DedupAction string

const (
	ActionDrop   DedupAction = "drop"   // Drop the duplicate
	ActionMerge  DedupAction = "merge"  // Merge with existing
	ActionGroup  DedupAction = "group"  // Group under existing
	ActionUpdate DedupAction = "update" // Update existing
)

// DedupConfig holds deduplication configuration.
type DedupConfig struct {
	Strategy        DedupStrategy `json:"strategy"`
	Action          DedupAction   `json:"action"`
	WindowDuration  time.Duration `json:"window_duration"`
	MaxGroupSize    int           `json:"max_group_size"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	MaxEntries      int           `json:"max_entries"`
	SimilarityThreshold float64   `json:"similarity_threshold"`
}

// DefaultDedupConfig returns default deduplication configuration.
func DefaultDedupConfig() DedupConfig {
	return DedupConfig{
		Strategy:           StrategyKey,
		Action:             ActionMerge,
		WindowDuration:     1 * time.Hour,
		MaxGroupSize:       100,
		CleanupInterval:    5 * time.Minute,
		MaxEntries:         100000,
		SimilarityThreshold: 0.85,
	}
}

// Alert interface for deduplication.
type Alert interface {
	GetID() string
	GetDedupKey() string
	GetFingerprint() string
	GetTenantID() string
	GetRuleID() string
	GetCreatedAt() time.Time
	GetEventCount() int
	SetGroupID(string)
	IncrementEventCount(int)
	SetUpdatedAt(time.Time)
}

// DedupEntry represents a deduplication entry.
type DedupEntry struct {
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	AlertID     string    `json:"alert_id"`
	TenantID    string    `json:"tenant_id"`
	RuleID      string    `json:"rule_id"`
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// DedupResult represents the result of deduplication.
type DedupResult struct {
	IsDuplicate   bool        `json:"is_duplicate"`
	Action        DedupAction `json:"action"`
	ExistingID    string      `json:"existing_id,omitempty"`
	GroupID       string      `json:"group_id,omitempty"`
	DuplicateCount int        `json:"duplicate_count"`
}

// Deduplicator provides alert deduplication.
type Deduplicator struct {
	config  DedupConfig
	entries sync.Map // map[string]*DedupEntry
	groups  sync.Map // map[string][]string (group ID -> alert IDs)
	logger  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	totalChecked   atomic.Uint64
	totalDuplicates atomic.Uint64
	totalMerged    atomic.Uint64
	totalDropped   atomic.Uint64
}

// NewDeduplicator creates a new deduplicator.
func NewDeduplicator(cfg DedupConfig, logger *slog.Logger) *Deduplicator {
	ctx, cancel := context.WithCancel(context.Background())

	d := &Deduplicator{
		config: cfg,
		logger: logger.With("component", "alert-deduplicator"),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start cleanup goroutine
	d.wg.Add(1)
	go d.cleanupLoop()

	return d
}

// Stop stops the deduplicator.
func (d *Deduplicator) Stop() {
	d.cancel()
	d.wg.Wait()
}

// Check checks if an alert is a duplicate.
func (d *Deduplicator) Check(alert Alert) *DedupResult {
	d.totalChecked.Add(1)

	switch d.config.Strategy {
	case StrategyExact:
		return d.checkExact(alert)
	case StrategyKey:
		return d.checkKey(alert)
	case StrategyWindow:
		return d.checkWindow(alert)
	case StrategySimilarity:
		return d.checkSimilarity(alert)
	default:
		return d.checkKey(alert)
	}
}

// checkExact checks for exact fingerprint match.
func (d *Deduplicator) checkExact(alert Alert) *DedupResult {
	fingerprint := alert.GetFingerprint()
	key := fmt.Sprintf("%s:%s", alert.GetTenantID(), fingerprint)

	if entry, ok := d.entries.Load(key); ok {
		e := entry.(*DedupEntry)
		if time.Now().Before(e.ExpiresAt) {
			d.totalDuplicates.Add(1)

			// Update entry
			e.Count++
			e.LastSeen = time.Now()

			return &DedupResult{
				IsDuplicate:    true,
				Action:         d.config.Action,
				ExistingID:     e.AlertID,
				DuplicateCount: e.Count,
			}
		}
		// Entry expired, remove it
		d.entries.Delete(key)
	}

	// Not a duplicate, add entry
	d.addEntry(key, alert)

	return &DedupResult{
		IsDuplicate: false,
	}
}

// checkKey checks for dedup key match.
func (d *Deduplicator) checkKey(alert Alert) *DedupResult {
	dedupKey := alert.GetDedupKey()
	key := fmt.Sprintf("%s:%s", alert.GetTenantID(), dedupKey)

	if entry, ok := d.entries.Load(key); ok {
		e := entry.(*DedupEntry)
		if time.Now().Before(e.ExpiresAt) {
			d.totalDuplicates.Add(1)

			// Update entry
			e.Count++
			e.LastSeen = time.Now()

			action := d.determineAction(e)

			result := &DedupResult{
				IsDuplicate:    true,
				Action:         action,
				ExistingID:     e.AlertID,
				DuplicateCount: e.Count,
			}

			// Handle grouping
			if action == ActionGroup {
				groupID := d.getOrCreateGroup(e.AlertID)
				d.addToGroup(groupID, alert.GetID())
				result.GroupID = groupID
			}

			return result
		}
		// Entry expired, remove it
		d.entries.Delete(key)
	}

	// Not a duplicate, add entry
	d.addEntry(key, alert)

	return &DedupResult{
		IsDuplicate: false,
	}
}

// checkWindow checks for duplicates within a time window.
func (d *Deduplicator) checkWindow(alert Alert) *DedupResult {
	ruleID := alert.GetRuleID()
	tenantID := alert.GetTenantID()

	// Check all entries for this tenant and rule within window
	var matchedEntry *DedupEntry

	d.entries.Range(func(k, v interface{}) bool {
		entry := v.(*DedupEntry)
		if entry.TenantID == tenantID && entry.RuleID == ruleID {
			if time.Now().Before(entry.ExpiresAt) {
				// Check if within window
				windowStart := time.Now().Add(-d.config.WindowDuration)
				if entry.LastSeen.After(windowStart) {
					matchedEntry = entry
					return false // Stop iteration
				}
			}
		}
		return true
	})

	if matchedEntry != nil {
		d.totalDuplicates.Add(1)
		matchedEntry.Count++
		matchedEntry.LastSeen = time.Now()

		action := d.determineAction(matchedEntry)

		result := &DedupResult{
			IsDuplicate:    true,
			Action:         action,
			ExistingID:     matchedEntry.AlertID,
			DuplicateCount: matchedEntry.Count,
		}

		if action == ActionGroup {
			groupID := d.getOrCreateGroup(matchedEntry.AlertID)
			d.addToGroup(groupID, alert.GetID())
			result.GroupID = groupID
		}

		return result
	}

	// Not a duplicate, add entry
	dedupKey := alert.GetDedupKey()
	key := fmt.Sprintf("%s:%s:%d", tenantID, dedupKey, time.Now().UnixNano())
	d.addEntry(key, alert)

	return &DedupResult{
		IsDuplicate: false,
	}
}

// checkSimilarity checks for similar alerts using fuzzy matching.
func (d *Deduplicator) checkSimilarity(alert Alert) *DedupResult {
	tenantID := alert.GetTenantID()
	ruleID := alert.GetRuleID()

	var bestMatch *DedupEntry
	var bestSimilarity float64

	d.entries.Range(func(k, v interface{}) bool {
		entry := v.(*DedupEntry)
		if entry.TenantID == tenantID && entry.RuleID == ruleID {
			if time.Now().Before(entry.ExpiresAt) {
				// Calculate similarity
				similarity := d.calculateSimilarity(alert.GetFingerprint(), entry.Fingerprint)
				if similarity >= d.config.SimilarityThreshold && similarity > bestSimilarity {
					bestMatch = entry
					bestSimilarity = similarity
				}
			}
		}
		return true
	})

	if bestMatch != nil {
		d.totalDuplicates.Add(1)
		bestMatch.Count++
		bestMatch.LastSeen = time.Now()

		action := d.determineAction(bestMatch)

		result := &DedupResult{
			IsDuplicate:    true,
			Action:         action,
			ExistingID:     bestMatch.AlertID,
			DuplicateCount: bestMatch.Count,
		}

		if action == ActionGroup {
			groupID := d.getOrCreateGroup(bestMatch.AlertID)
			d.addToGroup(groupID, alert.GetID())
			result.GroupID = groupID
		}

		return result
	}

	// Not a duplicate, add entry
	dedupKey := alert.GetDedupKey()
	key := fmt.Sprintf("%s:%s", tenantID, dedupKey)
	d.addEntry(key, alert)

	return &DedupResult{
		IsDuplicate: false,
	}
}

// addEntry adds a new dedup entry.
func (d *Deduplicator) addEntry(key string, alert Alert) {
	now := time.Now()
	entry := &DedupEntry{
		Key:         key,
		Fingerprint: alert.GetFingerprint(),
		AlertID:     alert.GetID(),
		TenantID:    alert.GetTenantID(),
		RuleID:      alert.GetRuleID(),
		Count:       1,
		FirstSeen:   now,
		LastSeen:    now,
		ExpiresAt:   now.Add(d.config.WindowDuration),
	}
	d.entries.Store(key, entry)
}

// determineAction determines the action based on entry state.
func (d *Deduplicator) determineAction(entry *DedupEntry) DedupAction {
	// If count exceeds group size, start dropping
	if entry.Count > d.config.MaxGroupSize {
		d.totalDropped.Add(1)
		return ActionDrop
	}

	// Use configured action
	if d.config.Action == ActionMerge {
		d.totalMerged.Add(1)
	}
	return d.config.Action
}

// getOrCreateGroup gets or creates a group for an alert.
func (d *Deduplicator) getOrCreateGroup(alertID string) string {
	// Generate group ID from alert ID
	h := sha256.New()
	h.Write([]byte(alertID))
	groupID := "grp_" + hex.EncodeToString(h.Sum(nil))[:16]

	// Initialize group if not exists
	if _, loaded := d.groups.LoadOrStore(groupID, []string{alertID}); !loaded {
		d.logger.Debug("created alert group", "group_id", groupID, "initial_alert", alertID)
	}

	return groupID
}

// addToGroup adds an alert to a group.
func (d *Deduplicator) addToGroup(groupID, alertID string) {
	if val, ok := d.groups.Load(groupID); ok {
		alerts := val.([]string)
		if len(alerts) < d.config.MaxGroupSize {
			alerts = append(alerts, alertID)
			d.groups.Store(groupID, alerts)
		}
	}
}

// GetGroup returns alerts in a group.
func (d *Deduplicator) GetGroup(groupID string) []string {
	if val, ok := d.groups.Load(groupID); ok {
		return val.([]string)
	}
	return nil
}

// calculateSimilarity calculates similarity between two fingerprints.
func (d *Deduplicator) calculateSimilarity(fp1, fp2 string) float64 {
	if fp1 == fp2 {
		return 1.0
	}

	// Simple character-based similarity
	len1 := len(fp1)
	len2 := len(fp2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	// Count matching characters at same positions
	matches := 0
	minLen := len1
	if len2 < minLen {
		minLen = len2
	}

	for i := 0; i < minLen; i++ {
		if fp1[i] == fp2[i] {
			matches++
		}
	}

	maxLen := len1
	if len2 > maxLen {
		maxLen = len2
	}

	return float64(matches) / float64(maxLen)
}

// cleanupLoop periodically cleans up expired entries.
func (d *Deduplicator) cleanupLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

// cleanup removes expired entries.
func (d *Deduplicator) cleanup() {
	now := time.Now()
	var expired int

	d.entries.Range(func(k, v interface{}) bool {
		entry := v.(*DedupEntry)
		if now.After(entry.ExpiresAt) {
			d.entries.Delete(k)
			expired++
		}
		return true
	})

	if expired > 0 {
		d.logger.Debug("cleaned up expired dedup entries", "count", expired)
	}
}

// Stats returns deduplicator statistics.
func (d *Deduplicator) Stats() map[string]interface{} {
	var entryCount int
	d.entries.Range(func(k, v interface{}) bool {
		entryCount++
		return true
	})

	var groupCount int
	d.groups.Range(func(k, v interface{}) bool {
		groupCount++
		return true
	})

	return map[string]interface{}{
		"total_checked":    d.totalChecked.Load(),
		"total_duplicates": d.totalDuplicates.Load(),
		"total_merged":     d.totalMerged.Load(),
		"total_dropped":    d.totalDropped.Load(),
		"entry_count":      entryCount,
		"group_count":      groupCount,
	}
}

// Clear clears all entries.
func (d *Deduplicator) Clear() {
	d.entries.Range(func(k, v interface{}) bool {
		d.entries.Delete(k)
		return true
	})
	d.groups.Range(func(k, v interface{}) bool {
		d.groups.Delete(k)
		return true
	})
}
