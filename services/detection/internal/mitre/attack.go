// Package mitre provides ATT&CK analysis functionality.
package mitre

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// AttackAnalyzer provides ATT&CK-based threat analysis.
type AttackAnalyzer struct {
	mapper *Mapper
}

// NewAttackAnalyzer creates a new ATT&CK analyzer.
func NewAttackAnalyzer() *AttackAnalyzer {
	return &AttackAnalyzer{
		mapper: NewMapper(),
	}
}

// NewAttackAnalyzerWithMapper creates an analyzer with a custom mapper.
func NewAttackAnalyzerWithMapper(mapper *Mapper) *AttackAnalyzer {
	return &AttackAnalyzer{
		mapper: mapper,
	}
}

// AttackPattern represents a detected attack pattern.
type AttackPattern struct {
	Techniques    []*Technique       `json:"techniques"`
	Tactics       []*Tactic          `json:"tactics"`
	Severity      string             `json:"severity"`
	Confidence    float64            `json:"confidence"`
	Description   string             `json:"description"`
	KillChain     []KillChainPhase   `json:"kill_chain"`
	Mitigations   []string           `json:"mitigations,omitempty"`
	RelatedGroups []string           `json:"related_groups,omitempty"`
	References    []string           `json:"references,omitempty"`
}

// KillChainPhase represents a phase in the cyber kill chain.
type KillChainPhase struct {
	Phase       string       `json:"phase"`
	TacticID    string       `json:"tactic_id"`
	TacticName  string       `json:"tactic_name"`
	Techniques  []*Technique `json:"techniques"`
	Order       int          `json:"order"`
}

// CoverageAnalysis represents ATT&CK coverage analysis.
type CoverageAnalysis struct {
	TotalTechniques   int                    `json:"total_techniques"`
	CoveredTechniques int                    `json:"covered_techniques"`
	CoveragePercent   float64                `json:"coverage_percent"`
	TacticCoverage    map[string]*TacticCoverage `json:"tactic_coverage"`
	GapAnalysis       []string               `json:"gap_analysis"`
	Recommendations   []string               `json:"recommendations"`
}

// TacticCoverage represents coverage for a single tactic.
type TacticCoverage struct {
	TacticID      string   `json:"tactic_id"`
	TacticName    string   `json:"tactic_name"`
	Total         int      `json:"total"`
	Covered       int      `json:"covered"`
	CoveragePercent float64 `json:"coverage_percent"`
	MissingTechniques []string `json:"missing_techniques,omitempty"`
}

// DetectionEvent represents an event for attack analysis.
type DetectionEvent struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	TechniqueID string                 `json:"technique_id,omitempty"`
	Tactics     []string               `json:"tactics,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Source      string                 `json:"source,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// AnalyzePattern analyzes technique IDs and returns an attack pattern.
func (a *AttackAnalyzer) AnalyzePattern(techniqueIDs []string) *AttackPattern {
	mapping := a.mapper.MapToATTACK(techniqueIDs, nil)

	killChain := a.buildKillChain(mapping.Techniques, mapping.Tactics)

	return &AttackPattern{
		Techniques:  mapping.Techniques,
		Tactics:     mapping.Tactics,
		Severity:    mapping.Severity,
		Confidence:  a.calculateConfidence(mapping),
		Description: a.generateDescription(mapping),
		KillChain:   killChain,
		Mitigations: a.suggestMitigations(mapping.Techniques),
	}
}

// AnalyzeEvents analyzes a sequence of events for attack patterns.
func (a *AttackAnalyzer) AnalyzeEvents(events []DetectionEvent) *AttackPattern {
	var techniqueIDs []string
	var tactics []string

	for _, event := range events {
		if event.TechniqueID != "" {
			techniqueIDs = append(techniqueIDs, event.TechniqueID)
		}
		tactics = append(tactics, event.Tactics...)
	}

	// Deduplicate
	techniqueIDs = uniqueStrings(techniqueIDs)
	tactics = uniqueStrings(tactics)

	mapping := a.mapper.MapToATTACK(techniqueIDs, tactics)
	killChain := a.buildKillChain(mapping.Techniques, mapping.Tactics)

	return &AttackPattern{
		Techniques:  mapping.Techniques,
		Tactics:     mapping.Tactics,
		Severity:    mapping.Severity,
		Confidence:  a.calculateConfidence(mapping),
		Description: a.generateDescription(mapping),
		KillChain:   killChain,
		Mitigations: a.suggestMitigations(mapping.Techniques),
	}
}

// AnalyzeCoverage analyzes detection coverage against ATT&CK.
func (a *AttackAnalyzer) AnalyzeCoverage(coveredTechniqueIDs []string) *CoverageAnalysis {
	allTechniques := a.mapper.ListAllTechniques()
	coveredSet := make(map[string]bool)
	for _, id := range coveredTechniqueIDs {
		coveredSet[strings.ToUpper(id)] = true
	}

	tacticCoverage := make(map[string]*TacticCoverage)

	// Initialize tactic coverage
	for _, tactic := range a.mapper.ListAllTactics() {
		tacticCoverage[tactic.ShortName] = &TacticCoverage{
			TacticID:   tactic.ID,
			TacticName: tactic.Name,
		}
	}

	// Calculate coverage
	for _, tech := range allTechniques {
		for _, tactic := range tech.Tactics {
			tc := tacticCoverage[tactic]
			if tc == nil {
				continue
			}
			tc.Total++
			if coveredSet[tech.ID] {
				tc.Covered++
			} else {
				tc.MissingTechniques = append(tc.MissingTechniques, tech.ID)
			}
		}
	}

	// Calculate percentages
	for _, tc := range tacticCoverage {
		if tc.Total > 0 {
			tc.CoveragePercent = float64(tc.Covered) / float64(tc.Total) * 100
		}
	}

	// Find gaps and generate recommendations
	var gaps []string
	var recommendations []string

	for _, tc := range tacticCoverage {
		if tc.CoveragePercent < 25 {
			gaps = append(gaps, fmt.Sprintf("Low coverage for %s (%d%%)", tc.TacticName, int(tc.CoveragePercent)))
			recommendations = append(recommendations,
				fmt.Sprintf("Add detection rules for %s techniques", tc.TacticName))
		}
	}

	totalCovered := len(coveredTechniqueIDs)
	totalTech := len(allTechniques)
	coveragePercent := 0.0
	if totalTech > 0 {
		coveragePercent = float64(totalCovered) / float64(totalTech) * 100
	}

	return &CoverageAnalysis{
		TotalTechniques:   totalTech,
		CoveredTechniques: totalCovered,
		CoveragePercent:   coveragePercent,
		TacticCoverage:    tacticCoverage,
		GapAnalysis:       gaps,
		Recommendations:   recommendations,
	}
}

// GetRelatedTechniques returns techniques related to the given technique.
func (a *AttackAnalyzer) GetRelatedTechniques(techniqueID string) []*Technique {
	tech, ok := a.mapper.GetTechnique(techniqueID)
	if !ok {
		return nil
	}

	related := make(map[string]*Technique)

	// Add sub-techniques
	for _, subTech := range a.mapper.GetSubTechniques(techniqueID) {
		related[subTech.ID] = subTech
	}

	// Add techniques from same tactics
	for _, tactic := range tech.Tactics {
		for _, t := range a.mapper.GetTechniquesForTactic(tactic) {
			if t.ID != techniqueID {
				related[t.ID] = t
			}
		}
	}

	var results []*Technique
	for _, t := range related {
		results = append(results, t)
	}

	return results
}

// buildKillChain builds a kill chain from techniques and tactics.
func (a *AttackAnalyzer) buildKillChain(techniques []*Technique, tactics []*Tactic) []KillChainPhase {
	phaseOrder := map[string]int{
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

	// Group techniques by tactic
	tacticTechniques := make(map[string][]*Technique)
	for _, tech := range techniques {
		for _, tactic := range tech.Tactics {
			tacticTechniques[tactic] = append(tacticTechniques[tactic], tech)
		}
	}

	var phases []KillChainPhase
	for _, tactic := range tactics {
		phase := KillChainPhase{
			Phase:      tactic.ShortName,
			TacticID:   tactic.ID,
			TacticName: tactic.Name,
			Techniques: tacticTechniques[tactic.ShortName],
			Order:      phaseOrder[tactic.ShortName],
		}
		phases = append(phases, phase)
	}

	// Sort by kill chain order
	sort.Slice(phases, func(i, j int) bool {
		return phases[i].Order < phases[j].Order
	})

	return phases
}

// calculateConfidence calculates confidence based on the mapping.
func (a *AttackAnalyzer) calculateConfidence(mapping *ATTACKMapping) float64 {
	if len(mapping.Techniques) == 0 {
		return 0.0
	}

	confidence := 0.5 // Base confidence

	// More techniques = higher confidence
	if len(mapping.Techniques) > 3 {
		confidence += 0.2
	} else if len(mapping.Techniques) > 1 {
		confidence += 0.1
	}

	// Multiple tactics = higher confidence
	if len(mapping.Tactics) > 3 {
		confidence += 0.2
	} else if len(mapping.Tactics) > 1 {
		confidence += 0.1
	}

	// Kill chain coverage = higher confidence
	if len(mapping.KillChainPhases) > 2 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// generateDescription generates a human-readable description.
func (a *AttackAnalyzer) generateDescription(mapping *ATTACKMapping) string {
	if len(mapping.Techniques) == 0 {
		return "No ATT&CK techniques identified."
	}

	var parts []string

	// Describe tactics
	if len(mapping.Tactics) > 0 {
		tacticNames := make([]string, len(mapping.Tactics))
		for i, t := range mapping.Tactics {
			tacticNames[i] = t.Name
		}
		parts = append(parts, fmt.Sprintf("Activity spans %d tactic(s): %s.",
			len(mapping.Tactics), strings.Join(tacticNames, ", ")))
	}

	// Describe techniques
	techNames := make([]string, len(mapping.Techniques))
	for i, t := range mapping.Techniques {
		techNames[i] = fmt.Sprintf("%s (%s)", t.Name, t.ID)
	}
	parts = append(parts, fmt.Sprintf("Detected technique(s): %s.",
		strings.Join(techNames, ", ")))

	return strings.Join(parts, " ")
}

// suggestMitigations suggests mitigations based on techniques.
func (a *AttackAnalyzer) suggestMitigations(techniques []*Technique) []string {
	mitigationMap := map[string][]string{
		"T1059": {"Disable unnecessary scripting interpreters", "Use application allowlisting", "Restrict PowerShell execution policy"},
		"T1078": {"Implement MFA", "Monitor account usage", "Audit privileged accounts"},
		"T1003": {"Implement Credential Guard", "Disable WDigest", "Use Protected Users group"},
		"T1055": {"Enable Attack Surface Reduction rules", "Use process integrity levels"},
		"T1021": {"Restrict remote services", "Require strong authentication", "Network segmentation"},
		"T1486": {"Maintain offline backups", "Implement network segmentation", "Use endpoint protection"},
		"T1566": {"User awareness training", "Enable email filtering", "Implement DMARC/DKIM/SPF"},
	}

	seen := make(map[string]bool)
	var mitigations []string

	for _, tech := range techniques {
		techID := tech.ID
		if tech.IsSubTechnique {
			techID = tech.ParentID
		}

		if mits, ok := mitigationMap[techID]; ok {
			for _, mit := range mits {
				if !seen[mit] {
					mitigations = append(mitigations, mit)
					seen[mit] = true
				}
			}
		}
	}

	return mitigations
}

// uniqueStrings removes duplicates from a string slice.
func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range strs {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result
}
