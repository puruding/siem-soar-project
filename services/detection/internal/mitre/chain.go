// Package mitre provides attack chain analysis.
package mitre

import (
	"fmt"
	"sort"
	"time"
)

// ChainAnalyzer analyzes attack chains and progressions.
type ChainAnalyzer struct {
	mapper   *Mapper
	analyzer *AttackAnalyzer
}

// NewChainAnalyzer creates a new chain analyzer.
func NewChainAnalyzer() *ChainAnalyzer {
	mapper := NewMapper()
	return &ChainAnalyzer{
		mapper:   mapper,
		analyzer: NewAttackAnalyzerWithMapper(mapper),
	}
}

// AttackChain represents a sequence of related attack activities.
type AttackChain struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	StartTime      time.Time        `json:"start_time"`
	EndTime        time.Time        `json:"end_time"`
	Duration       time.Duration    `json:"duration"`
	Stages         []ChainStage     `json:"stages"`
	RiskScore      float64          `json:"risk_score"`
	Confidence     float64          `json:"confidence"`
	Status         ChainStatus      `json:"status"`
	Recommendation string           `json:"recommendation"`
	RelatedIOCs    []string         `json:"related_iocs,omitempty"`
}

// ChainStage represents a stage in an attack chain.
type ChainStage struct {
	Order       int          `json:"order"`
	Tactic      *Tactic      `json:"tactic"`
	Techniques  []*Technique `json:"techniques"`
	Events      []ChainEvent `json:"events"`
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Confidence  float64      `json:"confidence"`
}

// ChainEvent represents an event in a chain stage.
type ChainEvent struct {
	EventID      string                 `json:"event_id"`
	Timestamp    time.Time              `json:"timestamp"`
	TechniqueID  string                 `json:"technique_id"`
	Source       string                 `json:"source,omitempty"`
	Description  string                 `json:"description,omitempty"`
	RawData      map[string]interface{} `json:"raw_data,omitempty"`
}

// ChainStatus represents the status of an attack chain.
type ChainStatus string

const (
	ChainStatusActive    ChainStatus = "active"
	ChainStatusContained ChainStatus = "contained"
	ChainStatusComplete  ChainStatus = "complete"
	ChainStatusUnknown   ChainStatus = "unknown"
)

// ChainDetectionConfig holds configuration for chain detection.
type ChainDetectionConfig struct {
	TimeWindow       time.Duration `json:"time_window"`
	MinStages        int           `json:"min_stages"`
	MinConfidence    float64       `json:"min_confidence"`
	GroupByFields    []string      `json:"group_by_fields"`
	EnablePrediction bool          `json:"enable_prediction"`
}

// DefaultChainDetectionConfig returns default configuration.
func DefaultChainDetectionConfig() ChainDetectionConfig {
	return ChainDetectionConfig{
		TimeWindow:       24 * time.Hour,
		MinStages:        2,
		MinConfidence:    0.5,
		GroupByFields:    []string{"source.ip", "user.name", "host.name"},
		EnablePrediction: true,
	}
}

// DetectChain detects an attack chain from a sequence of events.
func (c *ChainAnalyzer) DetectChain(events []ChainEvent, config ChainDetectionConfig) *AttackChain {
	if len(events) == 0 {
		return nil
	}

	// Sort events by timestamp
	sortedEvents := make([]ChainEvent, len(events))
	copy(sortedEvents, events)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].Timestamp.Before(sortedEvents[j].Timestamp)
	})

	// Group events by tactic/stage
	stages := c.groupIntoStages(sortedEvents)

	if len(stages) < config.MinStages {
		return nil
	}

	// Calculate chain properties
	startTime := sortedEvents[0].Timestamp
	endTime := sortedEvents[len(sortedEvents)-1].Timestamp
	duration := endTime.Sub(startTime)

	if duration > config.TimeWindow {
		return nil
	}

	// Calculate risk score and confidence
	riskScore := c.calculateRiskScore(stages)
	confidence := c.calculateChainConfidence(stages, sortedEvents)

	if confidence < config.MinConfidence {
		return nil
	}

	// Determine chain status
	status := c.determineStatus(stages)

	// Generate recommendation
	recommendation := c.generateRecommendation(stages, status)

	return &AttackChain{
		ID:             fmt.Sprintf("chain-%d", startTime.Unix()),
		Name:           c.generateChainName(stages),
		Description:    c.generateChainDescription(stages),
		StartTime:      startTime,
		EndTime:        endTime,
		Duration:       duration,
		Stages:         stages,
		RiskScore:      riskScore,
		Confidence:     confidence,
		Status:         status,
		Recommendation: recommendation,
	}
}

// PredictNextStage predicts the likely next stage in an attack chain.
func (c *ChainAnalyzer) PredictNextStage(chain *AttackChain) *PredictedStage {
	if len(chain.Stages) == 0 {
		return nil
	}

	// Get the current stage's tactic
	lastStage := chain.Stages[len(chain.Stages)-1]

	// Kill chain order
	tacticOrder := []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}

	// Find current position in kill chain
	currentIdx := -1
	for i, tactic := range tacticOrder {
		if lastStage.Tactic != nil && tactic == lastStage.Tactic.ShortName {
			currentIdx = i
			break
		}
	}

	if currentIdx == -1 || currentIdx >= len(tacticOrder)-1 {
		return nil
	}

	// Predict next tactic(s)
	var predictedTactics []*Tactic
	for i := currentIdx + 1; i < len(tacticOrder) && len(predictedTactics) < 3; i++ {
		if tactic, ok := c.mapper.GetTactic(tacticOrder[i]); ok {
			predictedTactics = append(predictedTactics, tactic)
		}
	}

	if len(predictedTactics) == 0 {
		return nil
	}

	// Get likely techniques
	var likelyTechniques []*Technique
	for _, tactic := range predictedTactics {
		techs := c.mapper.GetTechniquesForTactic(tactic.ShortName)
		likelyTechniques = append(likelyTechniques, techs...)
		if len(likelyTechniques) > 10 {
			likelyTechniques = likelyTechniques[:10]
			break
		}
	}

	return &PredictedStage{
		LikelyTactics:    predictedTactics,
		LikelyTechniques: likelyTechniques,
		Probability:      0.7 - 0.1*float64(len(chain.Stages)), // Decreases with chain length
		TimeEstimate:     estimateTimeToNextStage(chain),
		Recommendations:  c.getPreventionRecommendations(predictedTactics),
	}
}

// PredictedStage represents a predicted next stage.
type PredictedStage struct {
	LikelyTactics    []*Tactic     `json:"likely_tactics"`
	LikelyTechniques []*Technique  `json:"likely_techniques"`
	Probability      float64       `json:"probability"`
	TimeEstimate     time.Duration `json:"time_estimate"`
	Recommendations  []string      `json:"recommendations"`
}

// groupIntoStages groups events into attack stages by tactic.
func (c *ChainAnalyzer) groupIntoStages(events []ChainEvent) []ChainStage {
	// Kill chain order for staging
	tacticOrder := map[string]int{
		"reconnaissance":       1,
		"resource-development": 2,
		"initial-access":       3,
		"execution":            4,
		"persistence":          5,
		"privilege-escalation": 6,
		"defense-evasion":      7,
		"credential-access":    8,
		"discovery":            9,
		"lateral-movement":     10,
		"collection":           11,
		"command-and-control":  12,
		"exfiltration":         13,
		"impact":               14,
	}

	// Group events by primary tactic
	tacticEvents := make(map[string][]ChainEvent)
	tacticTechniques := make(map[string][]*Technique)

	for _, event := range events {
		tech, ok := c.mapper.GetTechnique(event.TechniqueID)
		if !ok || len(tech.Tactics) == 0 {
			continue
		}

		// Use first tactic as primary
		primaryTactic := tech.Tactics[0]
		tacticEvents[primaryTactic] = append(tacticEvents[primaryTactic], event)
		tacticTechniques[primaryTactic] = append(tacticTechniques[primaryTactic], tech)
	}

	// Build stages
	var stages []ChainStage
	for tactic, evts := range tacticEvents {
		tacticObj, _ := c.mapper.GetTactic(tactic)

		// Deduplicate techniques
		techMap := make(map[string]*Technique)
		for _, tech := range tacticTechniques[tactic] {
			techMap[tech.ID] = tech
		}
		var techs []*Technique
		for _, tech := range techMap {
			techs = append(techs, tech)
		}

		stage := ChainStage{
			Order:      tacticOrder[tactic],
			Tactic:     tacticObj,
			Techniques: techs,
			Events:     evts,
			StartTime:  evts[0].Timestamp,
			EndTime:    evts[len(evts)-1].Timestamp,
			Duration:   evts[len(evts)-1].Timestamp.Sub(evts[0].Timestamp),
			Confidence: c.calculateStageConfidence(evts, techs),
		}
		stages = append(stages, stage)
	}

	// Sort by kill chain order
	sort.Slice(stages, func(i, j int) bool {
		return stages[i].Order < stages[j].Order
	})

	return stages
}

// calculateRiskScore calculates an overall risk score for the chain.
func (c *ChainAnalyzer) calculateRiskScore(stages []ChainStage) float64 {
	if len(stages) == 0 {
		return 0
	}

	// High-risk tactics
	highRiskTactics := map[string]float64{
		"impact":               1.0,
		"exfiltration":         0.9,
		"credential-access":    0.8,
		"privilege-escalation": 0.8,
		"lateral-movement":     0.7,
		"command-and-control":  0.7,
	}

	var maxRisk float64
	var totalRisk float64

	for _, stage := range stages {
		if stage.Tactic != nil {
			risk := highRiskTactics[stage.Tactic.ShortName]
			if risk > maxRisk {
				maxRisk = risk
			}
			totalRisk += risk
		}
	}

	// Score based on max risk and chain progression
	score := maxRisk*0.6 + (totalRisk/float64(len(stages)))*0.2 + (float64(len(stages))/14)*0.2

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// calculateChainConfidence calculates confidence in the chain detection.
func (c *ChainAnalyzer) calculateChainConfidence(stages []ChainStage, events []ChainEvent) float64 {
	if len(stages) == 0 {
		return 0
	}

	confidence := 0.5 // Base

	// More stages = higher confidence
	confidence += float64(len(stages)) * 0.1
	if confidence > 0.9 {
		confidence = 0.9
	}

	// Kill chain order maintained increases confidence
	ordered := true
	for i := 1; i < len(stages); i++ {
		if stages[i].Order < stages[i-1].Order {
			ordered = false
			break
		}
	}
	if ordered {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateStageConfidence calculates confidence for a single stage.
func (c *ChainAnalyzer) calculateStageConfidence(events []ChainEvent, techniques []*Technique) float64 {
	confidence := 0.5

	// More events = higher confidence
	if len(events) > 5 {
		confidence += 0.2
	} else if len(events) > 2 {
		confidence += 0.1
	}

	// Multiple techniques = higher confidence
	if len(techniques) > 2 {
		confidence += 0.2
	} else if len(techniques) > 1 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// determineStatus determines the current status of the attack chain.
func (c *ChainAnalyzer) determineStatus(stages []ChainStage) ChainStatus {
	if len(stages) == 0 {
		return ChainStatusUnknown
	}

	lastStage := stages[len(stages)-1]

	// Check for impact stage
	if lastStage.Tactic != nil && lastStage.Tactic.ShortName == "impact" {
		return ChainStatusComplete
	}

	// Check for exfiltration
	if lastStage.Tactic != nil && lastStage.Tactic.ShortName == "exfiltration" {
		return ChainStatusComplete
	}

	return ChainStatusActive
}

// generateChainName generates a name for the attack chain.
func (c *ChainAnalyzer) generateChainName(stages []ChainStage) string {
	if len(stages) == 0 {
		return "Unknown Attack Chain"
	}

	firstTactic := "Unknown"
	lastTactic := "Unknown"

	if stages[0].Tactic != nil {
		firstTactic = stages[0].Tactic.Name
	}
	if stages[len(stages)-1].Tactic != nil {
		lastTactic = stages[len(stages)-1].Tactic.Name
	}

	return fmt.Sprintf("%s to %s Attack Chain", firstTactic, lastTactic)
}

// generateChainDescription generates a description for the chain.
func (c *ChainAnalyzer) generateChainDescription(stages []ChainStage) string {
	if len(stages) == 0 {
		return "No attack chain detected."
	}

	var techCount int
	var eventCount int
	for _, stage := range stages {
		techCount += len(stage.Techniques)
		eventCount += len(stage.Events)
	}

	return fmt.Sprintf("Attack chain spanning %d stages with %d techniques detected across %d events.",
		len(stages), techCount, eventCount)
}

// generateRecommendation generates a recommendation based on chain status.
func (c *ChainAnalyzer) generateRecommendation(stages []ChainStage, status ChainStatus) string {
	switch status {
	case ChainStatusActive:
		if len(stages) > 3 {
			return "CRITICAL: Active multi-stage attack detected. Immediate containment recommended."
		}
		return "Active attack chain detected. Investigate and consider containment."
	case ChainStatusComplete:
		return "Attack chain appears complete. Initiate incident response and forensic investigation."
	case ChainStatusContained:
		return "Attack chain contained. Continue monitoring for related activity."
	default:
		return "Review detected activity and determine appropriate response."
	}
}

// getPreventionRecommendations gets prevention recommendations for predicted tactics.
func (c *ChainAnalyzer) getPreventionRecommendations(tactics []*Tactic) []string {
	tacticRecommendations := map[string][]string{
		"credential-access":    {"Enable MFA", "Implement Credential Guard", "Monitor authentication logs"},
		"lateral-movement":     {"Segment network", "Restrict admin shares", "Enable host-based firewall"},
		"exfiltration":         {"Enable DLP", "Monitor outbound traffic", "Restrict cloud storage access"},
		"impact":               {"Maintain offline backups", "Enable ransomware protection", "Test incident response"},
		"privilege-escalation": {"Apply least privilege", "Audit privileged accounts", "Patch systems"},
	}

	var recommendations []string
	seen := make(map[string]bool)

	for _, tactic := range tactics {
		if recs, ok := tacticRecommendations[tactic.ShortName]; ok {
			for _, rec := range recs {
				if !seen[rec] {
					recommendations = append(recommendations, rec)
					seen[rec] = true
				}
			}
		}
	}

	return recommendations
}

// estimateTimeToNextStage estimates time to next stage based on chain history.
func estimateTimeToNextStage(chain *AttackChain) time.Duration {
	if len(chain.Stages) < 2 {
		return 1 * time.Hour // Default estimate
	}

	// Calculate average time between stages
	var totalDuration time.Duration
	for i := 1; i < len(chain.Stages); i++ {
		stageDuration := chain.Stages[i].StartTime.Sub(chain.Stages[i-1].EndTime)
		totalDuration += stageDuration
	}

	return totalDuration / time.Duration(len(chain.Stages)-1)
}
