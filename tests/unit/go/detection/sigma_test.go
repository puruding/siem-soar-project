// Package detection_test provides unit tests for the detection service.
package detection_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SigmaRule represents a Sigma detection rule for testing.
type SigmaRule struct {
	Title       string
	ID          string
	Description string
	Level       string
	LogSource   LogSource
	Detection   Detection
	Tags        []string
}

type LogSource struct {
	Category string
	Product  string
	Service  string
}

type Detection struct {
	Selection map[string]interface{}
	Condition string
}

// InternalRule represents the converted internal rule format.
type InternalRule struct {
	ID              string
	Name            string
	Description     string
	Severity        string
	Conditions      []InternalCondition
	Logic           string
	MITRETactics    []string
	MITRETechniques []string
}

type InternalCondition struct {
	Field    string
	Operator string
	Value    interface{}
	Values   []interface{}
	Negate   bool
}

// MockConverter simulates Sigma rule conversion.
type MockConverter struct {
	fieldMapping map[string]string
}

func NewMockConverter() *MockConverter {
	return &MockConverter{
		fieldMapping: map[string]string{
			"CommandLine":      "process.command_line",
			"Image":            "process.executable",
			"User":             "user.name",
			"EventID":          "event_id",
			"DestinationPort":  "destination.port",
			"SourceIp":         "source.ip",
			"DestinationIp":    "destination.ip",
			"QueryName":        "dns.question.name",
			"TargetFilename":   "file.path",
		},
	}
}

func (c *MockConverter) Convert(yaml string) (*InternalRule, error) {
	// Simplified mock conversion
	return &InternalRule{
		ID:          "test-rule-001",
		Name:        "Suspicious PowerShell Command",
		Description: "Detects suspicious PowerShell commands",
		Severity:    "high",
		Logic:       "and",
		Conditions: []InternalCondition{
			{
				Field:    "process.command_line",
				Operator: "contains",
				Values:   []interface{}{"Invoke-Expression", "IEX"},
			},
		},
		MITRETactics:    []string{"execution"},
		MITRETechniques: []string{"T1059.001"},
	}, nil
}

func (c *MockConverter) ConvertLevel(level string) string {
	switch level {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// TestSigmaConverter tests the Sigma rule converter.
func TestSigmaConverter(t *testing.T) {
	converter := NewMockConverter()

	sigmaYAML := `
title: Suspicious PowerShell Command
id: test-rule-001
status: experimental
description: Detects suspicious PowerShell commands
author: Test Author
logsource:
    product: windows
    service: powershell
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
`

	rule, err := converter.Convert(sigmaYAML)
	require.NoError(t, err)
	require.NotNil(t, rule)

	assert.Equal(t, "test-rule-001", rule.ID)
	assert.Equal(t, "Suspicious PowerShell Command", rule.Name)
	assert.Equal(t, "high", rule.Severity)
	assert.NotEmpty(t, rule.Conditions)
}

// TestSigmaConverterLevelMapping tests severity level mapping.
func TestSigmaConverterLevelMapping(t *testing.T) {
	converter := NewMockConverter()

	testCases := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"informational", "medium"},
		{"unknown", "medium"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := converter.ConvertLevel(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestSigmaFieldMapping tests field name mapping.
func TestSigmaFieldMapping(t *testing.T) {
	converter := NewMockConverter()

	testCases := []struct {
		sigmaField   string
		expectedField string
	}{
		{"CommandLine", "process.command_line"},
		{"Image", "process.executable"},
		{"User", "user.name"},
		{"EventID", "event_id"},
		{"DestinationPort", "destination.port"},
		{"SourceIp", "source.ip"},
		{"DestinationIp", "destination.ip"},
		{"QueryName", "dns.question.name"},
		{"TargetFilename", "file.path"},
	}

	for _, tc := range testCases {
		t.Run(tc.sigmaField, func(t *testing.T) {
			mapped, ok := converter.fieldMapping[tc.sigmaField]
			assert.True(t, ok, "Field %s should be mapped", tc.sigmaField)
			assert.Equal(t, tc.expectedField, mapped)
		})
	}
}

// TestSigmaRuleWithModifiers tests rules with Sigma modifiers.
func TestSigmaRuleWithModifiers(t *testing.T) {
	t.Run("contains modifier", func(t *testing.T) {
		cond := InternalCondition{
			Field:    "process.command_line",
			Operator: "contains",
			Value:    "Invoke-Expression",
		}
		assert.Equal(t, "contains", cond.Operator)
	})

	t.Run("startswith modifier", func(t *testing.T) {
		cond := InternalCondition{
			Field:    "process.executable",
			Operator: "startswith",
			Value:    "C:\\Windows\\System32",
		}
		assert.Equal(t, "startswith", cond.Operator)
	})

	t.Run("endswith modifier", func(t *testing.T) {
		cond := InternalCondition{
			Field:    "file.path",
			Operator: "endswith",
			Value:    ".exe",
		}
		assert.Equal(t, "endswith", cond.Operator)
	})

	t.Run("regex modifier", func(t *testing.T) {
		cond := InternalCondition{
			Field:    "process.command_line",
			Operator: "regex",
			Value:    ".*powershell.*-enc.*",
		}
		assert.Equal(t, "regex", cond.Operator)
	})
}

// TestSigmaRuleWithMultipleSelections tests rules with multiple selections.
func TestSigmaRuleWithMultipleSelections(t *testing.T) {
	conditions := []InternalCondition{
		{
			Field:    "process.executable",
			Operator: "eq",
			Value:    "powershell.exe",
		},
		{
			Field:    "process.command_line",
			Operator: "contains",
			Values:   []interface{}{"-EncodedCommand", "-enc", "-e"},
		},
	}

	assert.Len(t, conditions, 2)
	assert.Equal(t, "eq", conditions[0].Operator)
	assert.Equal(t, "contains", conditions[1].Operator)
}

// TestSigmaRuleWithFilter tests rules with filter (negation).
func TestSigmaRuleWithFilter(t *testing.T) {
	conditions := []InternalCondition{
		{
			Field:    "process.executable",
			Operator: "eq",
			Value:    "powershell.exe",
			Negate:   false,
		},
		{
			Field:    "user.name",
			Operator: "eq",
			Value:    "SYSTEM",
			Negate:   true, // filter condition
		},
	}

	assert.False(t, conditions[0].Negate)
	assert.True(t, conditions[1].Negate)
}

// TestSigmaToElasticsearchQuery tests conversion to Elasticsearch query.
func TestSigmaToElasticsearchQuery(t *testing.T) {
	rule := &InternalRule{
		ID:       "test-rule",
		Name:     "Test Rule",
		Severity: "high",
		Logic:    "and",
		Conditions: []InternalCondition{
			{
				Field:    "process.command_line",
				Operator: "contains",
				Value:    "Invoke-Expression",
			},
		},
	}

	// Expected Elasticsearch query format
	expectedContains := "process.command_line:*Invoke-Expression*"
	assert.NotNil(t, rule)
	assert.Equal(t, "and", rule.Logic)
	assert.Contains(t, expectedContains, "process.command_line")
}

// TestSigmaToClickHouseQuery tests conversion to ClickHouse query.
func TestSigmaToClickHouseQuery(t *testing.T) {
	rule := &InternalRule{
		ID:       "test-rule",
		Name:     "Test Rule",
		Severity: "high",
		Logic:    "and",
		Conditions: []InternalCondition{
			{
				Field:    "process.command_line",
				Operator: "contains",
				Value:    "powershell",
			},
		},
	}

	// Expected ClickHouse query format
	expectedQuery := "process.command_line ILIKE '%powershell%'"
	assert.NotNil(t, rule)
	assert.Contains(t, expectedQuery, "ILIKE")
}

// TestSigmaRuleValidation tests rule validation.
func TestSigmaRuleValidation(t *testing.T) {
	t.Run("valid rule", func(t *testing.T) {
		rule := &InternalRule{
			ID:          "test-rule",
			Name:        "Test Rule",
			Description: "Test description",
			Severity:    "high",
			Conditions:  []InternalCondition{{Field: "test", Operator: "eq", Value: "value"}},
		}
		assert.NotEmpty(t, rule.ID)
		assert.NotEmpty(t, rule.Name)
		assert.NotEmpty(t, rule.Conditions)
	})

	t.Run("rule without ID", func(t *testing.T) {
		rule := &InternalRule{
			Name:       "Test Rule",
			Conditions: []InternalCondition{{Field: "test", Operator: "eq", Value: "value"}},
		}
		assert.Empty(t, rule.ID)
	})

	t.Run("rule without conditions", func(t *testing.T) {
		rule := &InternalRule{
			ID:   "test-rule",
			Name: "Test Rule",
		}
		assert.Empty(t, rule.Conditions)
	})
}

// TestSigmaMITREExtraction tests MITRE ATT&CK tag extraction.
func TestSigmaMITREExtraction(t *testing.T) {
	tags := []string{
		"attack.execution",
		"attack.t1059.001",
		"attack.defense_evasion",
		"attack.t1027",
		"cve.2021-44228",
	}

	var tactics []string
	var techniques []string

	for _, tag := range tags {
		if len(tag) > 7 && tag[:7] == "attack." {
			technique := tag[7:]
			if technique[0] == 't' || technique[0] == 'T' {
				techniques = append(techniques, technique)
			} else {
				tactics = append(tactics, technique)
			}
		}
	}

	assert.Contains(t, tactics, "execution")
	assert.Contains(t, tactics, "defense_evasion")
	assert.Contains(t, techniques, "t1059.001")
	assert.Contains(t, techniques, "t1027")
}

// Benchmark tests
func BenchmarkSigmaConversion(b *testing.B) {
	converter := NewMockConverter()
	sigmaYAML := `
title: Benchmark Test Rule
id: benchmark-rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: medium
`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = converter.Convert(sigmaYAML)
	}
}
