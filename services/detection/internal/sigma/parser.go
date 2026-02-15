// Package sigma provides Sigma rule parsing.
package sigma

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parser parses Sigma rules from YAML.
type Parser struct {
	strict bool
}

// NewParser creates a new Sigma parser.
func NewParser() *Parser {
	return &Parser{
		strict: false,
	}
}

// NewStrictParser creates a strict parser that fails on unknown fields.
func NewStrictParser() *Parser {
	return &Parser{
		strict: true,
	}
}

// Parse parses a Sigma rule from YAML content.
func (p *Parser) Parse(content string) (*SigmaRule, error) {
	var rule SigmaRule

	if err := yaml.Unmarshal([]byte(content), &rule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if err := p.validate(&rule); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &rule, nil
}

// ParseMultiple parses multiple Sigma rules from a multi-document YAML.
func (p *Parser) ParseMultiple(content string) ([]*SigmaRule, error) {
	var rules []*SigmaRule

	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var rule SigmaRule
		if err := decoder.Decode(&rule); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("failed to parse YAML document: %w", err)
		}

		if err := p.validate(&rule); err != nil {
			return nil, fmt.Errorf("validation failed for rule %s: %w", rule.ID, err)
		}

		rules = append(rules, &rule)
	}

	return rules, nil
}

func (p *Parser) validate(rule *SigmaRule) error {
	if rule.Title == "" && rule.ID == "" {
		return fmt.Errorf("rule must have title or id")
	}

	if rule.Detection.Condition == "" {
		return fmt.Errorf("detection condition is required")
	}

	// Validate level
	if rule.Level != "" {
		validLevels := map[string]bool{
			"critical": true, "high": true, "medium": true,
			"low": true, "informational": true,
		}
		if !validLevels[strings.ToLower(rule.Level)] {
			return fmt.Errorf("invalid level: %s", rule.Level)
		}
	}

	// Validate status
	if rule.Status != "" {
		validStatuses := map[string]bool{
			"stable": true, "test": true, "experimental": true,
			"deprecated": true, "unsupported": true,
		}
		if !validStatuses[strings.ToLower(rule.Status)] {
			return fmt.Errorf("invalid status: %s", rule.Status)
		}
	}

	return nil
}

// ConditionParser parses Sigma detection conditions.
type ConditionParser struct {
	condition string
	tokens    []token
	pos       int
}

type token struct {
	typ   tokenType
	value string
}

type tokenType int

const (
	tokenIdent tokenType = iota
	tokenAnd
	tokenOr
	tokenNot
	tokenLparen
	tokenRparen
	tokenPipe
	tokenOf
	tokenAll
	tokenOne
	tokenStar
	tokenEOF
)

// ParseCondition parses a Sigma condition string.
func ParseCondition(condition string) (*ConditionAST, error) {
	p := &ConditionParser{
		condition: condition,
	}

	p.tokenize()
	return p.parse()
}

// ConditionAST represents the parsed condition AST.
type ConditionAST struct {
	Type     string          // "and", "or", "not", "identifier", "of", "1_of", "all_of"
	Left     *ConditionAST   `json:"left,omitempty"`
	Right    *ConditionAST   `json:"right,omitempty"`
	Operand  *ConditionAST   `json:"operand,omitempty"`
	Value    string          `json:"value,omitempty"`
	Children []*ConditionAST `json:"children,omitempty"`
}

func (p *ConditionParser) tokenize() {
	var tokens []token
	condition := p.condition

	// Regex patterns for tokenization
	patterns := map[string]tokenType{
		`\band\b`:    tokenAnd,
		`\bor\b`:     tokenOr,
		`\bnot\b`:    tokenNot,
		`\bof\b`:     tokenOf,
		`\ball\b`:    tokenAll,
		`\b1\b`:      tokenOne,
		`\(`:         tokenLparen,
		`\)`:         tokenRparen,
		`\|`:         tokenPipe,
		`\*`:         tokenStar,
		`[a-zA-Z_][a-zA-Z0-9_]*`: tokenIdent,
	}

	for len(condition) > 0 {
		condition = strings.TrimLeft(condition, " \t\n")
		if len(condition) == 0 {
			break
		}

		matched := false
		for pattern, typ := range patterns {
			re := regexp.MustCompile("^(?i)" + pattern)
			if match := re.FindString(condition); match != "" {
				tokens = append(tokens, token{typ: typ, value: match})
				condition = condition[len(match):]
				matched = true
				break
			}
		}

		if !matched {
			// Skip unknown character
			condition = condition[1:]
		}
	}

	tokens = append(tokens, token{typ: tokenEOF})
	p.tokens = tokens
}

func (p *ConditionParser) current() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *ConditionParser) advance() token {
	tok := p.current()
	p.pos++
	return tok
}

func (p *ConditionParser) parse() (*ConditionAST, error) {
	return p.parseOr()
}

func (p *ConditionParser) parseOr() (*ConditionAST, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for p.current().typ == tokenOr {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &ConditionAST{
			Type:  "or",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

func (p *ConditionParser) parseAnd() (*ConditionAST, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	for p.current().typ == tokenAnd {
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &ConditionAST{
			Type:  "and",
			Left:  left,
			Right: right,
		}
	}

	return left, nil
}

func (p *ConditionParser) parseUnary() (*ConditionAST, error) {
	if p.current().typ == tokenNot {
		p.advance()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &ConditionAST{
			Type:    "not",
			Operand: operand,
		}, nil
	}

	return p.parsePrimary()
}

func (p *ConditionParser) parsePrimary() (*ConditionAST, error) {
	tok := p.current()

	switch tok.typ {
	case tokenLparen:
		p.advance()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.current().typ != tokenRparen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.advance()
		return expr, nil

	case tokenAll:
		p.advance()
		if p.current().typ == tokenOf {
			p.advance()
			// Parse "all of selection*" or "all of them"
			pattern, err := p.parseOfPattern()
			if err != nil {
				return nil, err
			}
			return &ConditionAST{
				Type:  "all_of",
				Value: pattern,
			}, nil
		}
		return nil, fmt.Errorf("expected 'of' after 'all'")

	case tokenOne:
		p.advance()
		if p.current().typ == tokenOf {
			p.advance()
			pattern, err := p.parseOfPattern()
			if err != nil {
				return nil, err
			}
			return &ConditionAST{
				Type:  "1_of",
				Value: pattern,
			}, nil
		}
		return nil, fmt.Errorf("expected 'of' after '1'")

	case tokenIdent:
		p.advance()
		return &ConditionAST{
			Type:  "identifier",
			Value: tok.value,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected token: %v", tok)
	}
}

func (p *ConditionParser) parseOfPattern() (string, error) {
	var pattern strings.Builder

	for {
		tok := p.current()
		if tok.typ == tokenIdent || tok.typ == tokenStar {
			pattern.WriteString(tok.value)
			p.advance()
		} else {
			break
		}
	}

	if pattern.Len() == 0 {
		return "", fmt.Errorf("expected pattern after 'of'")
	}

	return pattern.String(), nil
}

// ValidateSigmaRule performs comprehensive validation of a Sigma rule.
func ValidateSigmaRule(rule *SigmaRule) []string {
	var warnings []string

	// Check for recommended fields
	if rule.ID == "" {
		warnings = append(warnings, "rule should have an ID")
	}

	if rule.Status == "" {
		warnings = append(warnings, "rule should have a status")
	}

	if rule.Level == "" {
		warnings = append(warnings, "rule should have a level (severity)")
	}

	if rule.Description == "" {
		warnings = append(warnings, "rule should have a description")
	}

	if len(rule.Tags) == 0 {
		warnings = append(warnings, "rule should have tags (especially ATT&CK tags)")
	}

	// Check for MITRE ATT&CK tags
	hasAttackTag := false
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "attack.") {
			hasAttackTag = true
			break
		}
	}
	if !hasAttackTag {
		warnings = append(warnings, "rule should have MITRE ATT&CK tags")
	}

	// Check detection section
	if len(rule.Detection.RawData) == 0 {
		warnings = append(warnings, "detection section appears empty")
	}

	return warnings
}

// ExtractMITRETags extracts MITRE ATT&CK information from Sigma tags.
func ExtractMITRETags(tags []string) (tactics []string, techniques []string) {
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "attack.") {
			continue
		}

		value := strings.TrimPrefix(tag, "attack.")

		// Check if it's a technique ID (starts with t or T followed by digits)
		if len(value) > 1 && (value[0] == 't' || value[0] == 'T') {
			if isDigit(value[1]) {
				techniques = append(techniques, strings.ToUpper(value))
				continue
			}
		}

		// Otherwise it's a tactic
		tactics = append(tactics, value)
	}

	return tactics, techniques
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
