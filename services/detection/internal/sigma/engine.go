// Package sigma provides a high-performance Sigma rule engine.
package sigma

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EngineConfig holds configuration for the Sigma engine.
type EngineConfig struct {
	// Rule loading
	RulesDirectory     string        `json:"rules_directory"`
	AutoReload         bool          `json:"auto_reload"`
	ReloadInterval     time.Duration `json:"reload_interval"`

	// Performance
	MaxConcurrentRules int           `json:"max_concurrent_rules"`
	CacheEnabled       bool          `json:"cache_enabled"`
	CacheSize          int           `json:"cache_size"`

	// Matching
	CaseSensitive      bool          `json:"case_sensitive"`
	EnableModifiers    bool          `json:"enable_modifiers"`
}

// DefaultEngineConfig returns default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		RulesDirectory:     "./rules/sigma",
		AutoReload:         true,
		ReloadInterval:     5 * time.Minute,
		MaxConcurrentRules: 100,
		CacheEnabled:       true,
		CacheSize:          10000,
		CaseSensitive:      false,
		EnableModifiers:    true,
	}
}

// Engine is a high-performance Sigma rule engine.
type Engine struct {
	config       EngineConfig
	rules        map[string]*InternalRule
	rulesMu      sync.RWMutex
	converter    *Converter
	evaluator    *Evaluator
	logMapper    *LogSourceMapper
	logger       *slog.Logger

	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Metrics
	rulesLoaded     atomic.Int64
	eventsProcessed atomic.Uint64
	matchesFound    atomic.Uint64
	errors          atomic.Uint64
	avgMatchTime    atomic.Int64 // nanoseconds
}

// RuleMatch represents a match result.
type RuleMatch struct {
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	MatchedFields   map[string]interface{} `json:"matched_fields"`
	Score           float64                `json:"score"`
	MITRETactics    []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques []string               `json:"mitre_techniques,omitempty"`
	LogSource       LogSource              `json:"log_source"`
	Tags            []string               `json:"tags,omitempty"`
	References      []string               `json:"references,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// NewEngine creates a new Sigma engine.
func NewEngine(cfg EngineConfig, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		config:     cfg,
		rules:      make(map[string]*InternalRule),
		converter:  NewConverter(),
		evaluator:  NewEvaluator(),
		logMapper:  NewLogSourceMapper(),
		logger:     logger.With("component", "sigma-engine"),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the engine.
func (e *Engine) Start() error {
	e.logger.Info("starting sigma engine", "rules_dir", e.config.RulesDirectory)

	// Load initial rules
	if err := e.LoadRules(e.config.RulesDirectory); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Start auto-reload if enabled
	if e.config.AutoReload {
		e.wg.Add(1)
		go e.autoReloadLoop()
	}

	e.logger.Info("sigma engine started", "rules_loaded", e.rulesLoaded.Load())
	return nil
}

// Stop stops the engine.
func (e *Engine) Stop() error {
	e.logger.Info("stopping sigma engine")
	e.cancel()
	e.wg.Wait()
	e.logger.Info("sigma engine stopped")
	return nil
}

// LoadRules loads Sigma rules from a directory.
func (e *Engine) LoadRules(path string) error {
	if path == "" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path %s: %w", path, err)
	}

	var rules []*InternalRule

	if info.IsDir() {
		rules, err = e.loadDirectory(path)
	} else {
		rule, err := e.loadFile(path)
		if err != nil {
			return err
		}
		rules = []*InternalRule{rule}
	}

	if err != nil {
		return err
	}

	e.rulesMu.Lock()
	for _, rule := range rules {
		e.rules[rule.ID] = rule
	}
	e.rulesMu.Unlock()

	e.rulesLoaded.Store(int64(len(e.rules)))
	e.logger.Info("rules loaded", "count", len(rules), "total", len(e.rules))

	return nil
}

// LoadRuleYAML loads a single Sigma rule from YAML content.
func (e *Engine) LoadRuleYAML(content string) error {
	rule, err := e.converter.ConvertYAML(content)
	if err != nil {
		return err
	}

	e.rulesMu.Lock()
	e.rules[rule.ID] = rule
	e.rulesMu.Unlock()

	e.rulesLoaded.Store(int64(len(e.rules)))
	return nil
}

// RemoveRule removes a rule by ID.
func (e *Engine) RemoveRule(ruleID string) {
	e.rulesMu.Lock()
	delete(e.rules, ruleID)
	e.rulesMu.Unlock()

	e.rulesLoaded.Store(int64(len(e.rules)))
}

// Match matches an event against all loaded rules.
func (e *Engine) Match(event map[string]interface{}) ([]RuleMatch, error) {
	start := time.Now()
	e.eventsProcessed.Add(1)

	e.rulesMu.RLock()
	rules := make([]*InternalRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	e.rulesMu.RUnlock()

	var matches []RuleMatch

	for _, rule := range rules {
		result := e.evaluator.Evaluate(rule, event)
		if result.Matched {
			matches = append(matches, RuleMatch{
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Severity:        rule.Severity,
				Description:     rule.Description,
				MatchedFields:   result.MatchedFields,
				Score:           result.Score,
				MITRETactics:    rule.MITRETactics,
				MITRETechniques: rule.MITRETechniques,
				LogSource:       rule.LogSource,
				Tags:            rule.Tags,
				References:      rule.References,
				Timestamp:       time.Now(),
			})
		}
	}

	e.matchesFound.Add(uint64(len(matches)))

	// Update average match time (exponential moving average)
	elapsed := time.Since(start).Nanoseconds()
	e.updateAvgMatchTime(elapsed)

	return matches, nil
}

// MatchWithLogSource matches an event against rules for a specific log source.
func (e *Engine) MatchWithLogSource(event map[string]interface{}, logSource *LogSource) ([]RuleMatch, error) {
	start := time.Now()
	e.eventsProcessed.Add(1)

	e.rulesMu.RLock()
	rules := make([]*InternalRule, 0)
	for _, rule := range e.rules {
		if e.matchesLogSource(&rule.LogSource, logSource) {
			rules = append(rules, rule)
		}
	}
	e.rulesMu.RUnlock()

	var matches []RuleMatch

	for _, rule := range rules {
		result := e.evaluator.Evaluate(rule, event)
		if result.Matched {
			matches = append(matches, RuleMatch{
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Severity:        rule.Severity,
				Description:     rule.Description,
				MatchedFields:   result.MatchedFields,
				Score:           result.Score,
				MITRETactics:    rule.MITRETactics,
				MITRETechniques: rule.MITRETechniques,
				LogSource:       rule.LogSource,
				Tags:            rule.Tags,
				References:      rule.References,
				Timestamp:       time.Now(),
			})
		}
	}

	e.matchesFound.Add(uint64(len(matches)))
	elapsed := time.Since(start).Nanoseconds()
	e.updateAvgMatchTime(elapsed)

	return matches, nil
}

// MatchBatch matches multiple events against all rules.
func (e *Engine) MatchBatch(events []map[string]interface{}) ([][]RuleMatch, error) {
	results := make([][]RuleMatch, len(events))

	for i, event := range events {
		matches, err := e.Match(event)
		if err != nil {
			e.errors.Add(1)
			continue
		}
		results[i] = matches
	}

	return results, nil
}

// GetRule returns a rule by ID.
func (e *Engine) GetRule(ruleID string) (*InternalRule, bool) {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	rule, ok := e.rules[ruleID]
	return rule, ok
}

// GetRules returns all loaded rules.
func (e *Engine) GetRules() []*InternalRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	rules := make([]*InternalRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	return rules
}

// GetRulesByLogSource returns rules matching a log source.
func (e *Engine) GetRulesByLogSource(logSource *LogSource) []*InternalRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	var rules []*InternalRule
	for _, rule := range e.rules {
		if e.matchesLogSource(&rule.LogSource, logSource) {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRulesByTechnique returns rules matching a MITRE ATT&CK technique.
func (e *Engine) GetRulesByTechnique(techniqueID string) []*InternalRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	techniqueID = strings.ToUpper(techniqueID)
	var rules []*InternalRule

	for _, rule := range e.rules {
		for _, tech := range rule.MITRETechniques {
			if strings.ToUpper(tech) == techniqueID {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

// GetRulesByTactic returns rules matching a MITRE ATT&CK tactic.
func (e *Engine) GetRulesByTactic(tactic string) []*InternalRule {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	tactic = strings.ToLower(tactic)
	var rules []*InternalRule

	for _, rule := range e.rules {
		for _, t := range rule.MITRETactics {
			if strings.ToLower(t) == tactic {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"rules_loaded":     e.rulesLoaded.Load(),
		"events_processed": e.eventsProcessed.Load(),
		"matches_found":    e.matchesFound.Load(),
		"errors":           e.errors.Load(),
		"avg_match_time_ns": e.avgMatchTime.Load(),
	}
}

func (e *Engine) loadDirectory(dir string) ([]*InternalRule, error) {
	var rules []*InternalRule

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		rule, err := e.loadFile(path)
		if err != nil {
			e.logger.Warn("failed to load rule", "path", path, "error", err)
			return nil // Continue loading other rules
		}

		rules = append(rules, rule)
		return nil
	})

	return rules, err
}

func (e *Engine) loadFile(path string) (*InternalRule, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	rule, err := e.converter.ConvertYAML(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to convert rule: %w", err)
	}

	return rule, nil
}

func (e *Engine) matchesLogSource(ruleSource, eventSource *LogSource) bool {
	if eventSource == nil {
		return true // Match all if no filter specified
	}

	if ruleSource.Product != "" && eventSource.Product != "" {
		if !strings.EqualFold(ruleSource.Product, eventSource.Product) {
			return false
		}
	}

	if ruleSource.Category != "" && eventSource.Category != "" {
		if !strings.EqualFold(ruleSource.Category, eventSource.Category) {
			return false
		}
	}

	if ruleSource.Service != "" && eventSource.Service != "" {
		if !strings.EqualFold(ruleSource.Service, eventSource.Service) {
			return false
		}
	}

	return true
}

func (e *Engine) autoReloadLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if err := e.LoadRules(e.config.RulesDirectory); err != nil {
				e.logger.Error("failed to reload rules", "error", err)
			}
		}
	}
}

func (e *Engine) updateAvgMatchTime(elapsed int64) {
	// Exponential moving average with alpha = 0.1
	alpha := int64(10)
	for {
		old := e.avgMatchTime.Load()
		newVal := (old*(100-alpha) + elapsed*alpha) / 100
		if e.avgMatchTime.CompareAndSwap(old, newVal) {
			break
		}
	}
}
