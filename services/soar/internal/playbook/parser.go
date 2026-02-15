// Package playbook provides YAML parsing for playbook definitions.
package playbook

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parser handles parsing of playbook YAML files.
type Parser struct {
	strictMode bool
	validators []ValidatorFunc
}

// ValidatorFunc is a function that validates a playbook.
type ValidatorFunc func(*Playbook) error

// ParserOption configures the parser.
type ParserOption func(*Parser)

// WithStrictMode enables strict parsing mode.
func WithStrictMode(strict bool) ParserOption {
	return func(p *Parser) {
		p.strictMode = strict
	}
}

// WithValidator adds a custom validator.
func WithValidator(v ValidatorFunc) ParserOption {
	return func(p *Parser) {
		p.validators = append(p.validators, v)
	}
}

// NewParser creates a new playbook parser.
func NewParser(opts ...ParserOption) *Parser {
	p := &Parser{
		strictMode: true,
		validators: make([]ValidatorFunc, 0),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// ParseFile parses a playbook from a file path.
func (p *Parser) ParseFile(path string) (*Playbook, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open playbook file: %w", err)
	}
	defer file.Close()

	playbook, err := p.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return playbook, nil
}

// Parse parses a playbook from a reader.
func (p *Parser) Parse(r io.Reader) (*Playbook, error) {
	var playbook Playbook

	decoder := yaml.NewDecoder(r)
	if p.strictMode {
		decoder.KnownFields(true)
	}

	if err := decoder.Decode(&playbook); err != nil {
		return nil, fmt.Errorf("yaml decode error: %w", err)
	}

	// Apply post-processing
	if err := p.postProcess(&playbook); err != nil {
		return nil, fmt.Errorf("post-processing error: %w", err)
	}

	// Run validators
	for _, validator := range p.validators {
		if err := validator(&playbook); err != nil {
			return nil, fmt.Errorf("validation error: %w", err)
		}
	}

	return &playbook, nil
}

// ParseString parses a playbook from a YAML string.
func (p *Parser) ParseString(content string) (*Playbook, error) {
	return p.Parse(strings.NewReader(content))
}

// ParseDirectory parses all playbook files in a directory.
func (p *Parser) ParseDirectory(dir string) ([]*Playbook, error) {
	var playbooks []*Playbook

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		playbook, err := p.ParseFile(path)
		if err != nil {
			return fmt.Errorf("error parsing %s: %w", path, err)
		}

		playbooks = append(playbooks, playbook)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return playbooks, nil
}

// postProcess applies post-processing to the parsed playbook.
func (p *Parser) postProcess(pb *Playbook) error {
	// Generate IDs if missing
	if pb.ID == "" && pb.Name != "" {
		pb.ID = generateID(pb.Name)
	}

	// Process steps
	if err := p.processSteps(pb.Steps, ""); err != nil {
		return err
	}

	// Set defaults
	p.setDefaults(pb)

	return nil
}

// processSteps processes steps recursively, generating IDs and validating references.
func (p *Parser) processSteps(steps []Step, prefix string) error {
	for i := range steps {
		step := &steps[i]

		// Generate step ID if missing
		if step.ID == "" {
			if step.Name != "" {
				step.ID = generateID(step.Name)
			} else {
				step.ID = fmt.Sprintf("%sstep_%d", prefix, i+1)
			}
		}

		// Process nested steps based on type
		switch step.Type {
		case StepTypeCondition:
			if step.Condition != nil {
				if err := p.processSteps(step.Condition.ThenSteps, step.ID+"_then_"); err != nil {
					return err
				}
				if err := p.processSteps(step.Condition.ElseSteps, step.ID+"_else_"); err != nil {
					return err
				}
			}

		case StepTypeParallel:
			if step.Parallel != nil {
				for j := range step.Parallel.Branches {
					branch := &step.Parallel.Branches[j]
					if branch.ID == "" {
						branch.ID = fmt.Sprintf("%s_branch_%d", step.ID, j+1)
					}
					if err := p.processSteps(branch.Steps, branch.ID+"_"); err != nil {
						return err
					}
				}
			}

		case StepTypeLoop:
			if step.Loop != nil {
				if err := p.processSteps(step.Loop.Steps, step.ID+"_iter_"); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// setDefaults sets default values for the playbook.
func (p *Parser) setDefaults(pb *Playbook) {
	if pb.Version == 0 {
		pb.Version = 1
	}

	if pb.Trigger.Type == "" {
		pb.Trigger.Type = TriggerManual
	}

	if pb.Category == "" {
		pb.Category = CategoryCustom
	}

	// Set default timeouts
	if pb.Timeout == 0 {
		pb.Timeout = Duration(24 * 60 * 60 * 1000 * 1000 * 1000) // 24 hours
	}

	// Set default retry policy
	if pb.RetryPolicy == nil {
		pb.RetryPolicy = &RetryPolicy{
			MaxAttempts:        3,
			InitialInterval:    Duration(1000 * 1000 * 1000), // 1 second
			MaxInterval:        Duration(60 * 1000 * 1000 * 1000), // 1 minute
			BackoffCoefficient: 2.0,
		}
	}
}

// generateID generates a URL-safe ID from a name.
func generateID(name string) string {
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")

	// Remove non-alphanumeric characters except underscores
	var result strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			result.WriteRune(c)
		}
	}

	return result.String()
}

// Serialize serializes a playbook to YAML.
func Serialize(pb *Playbook) ([]byte, error) {
	return yaml.Marshal(pb)
}

// SerializeToFile serializes a playbook to a YAML file.
func SerializeToFile(pb *Playbook, path string) error {
	data, err := Serialize(pb)
	if err != nil {
		return fmt.Errorf("failed to serialize playbook: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write playbook file: %w", err)
	}

	return nil
}

// MultiDocParser parses multiple playbooks from a single YAML file.
type MultiDocParser struct {
	parser *Parser
}

// NewMultiDocParser creates a parser for multi-document YAML files.
func NewMultiDocParser(opts ...ParserOption) *MultiDocParser {
	return &MultiDocParser{
		parser: NewParser(opts...),
	}
}

// ParseFile parses multiple playbooks from a single file.
func (m *MultiDocParser) ParseFile(path string) ([]*Playbook, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return m.Parse(file)
}

// Parse parses multiple playbooks from a reader.
func (m *MultiDocParser) Parse(r io.Reader) ([]*Playbook, error) {
	var playbooks []*Playbook

	decoder := yaml.NewDecoder(r)
	for {
		var playbook Playbook
		err := decoder.Decode(&playbook)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("yaml decode error: %w", err)
		}

		// Apply post-processing
		if err := m.parser.postProcess(&playbook); err != nil {
			return nil, fmt.Errorf("post-processing error: %w", err)
		}

		playbooks = append(playbooks, &playbook)
	}

	return playbooks, nil
}

// ExpressionParser parses expressions in playbook parameters.
type ExpressionParser struct{}

// ExpressionType represents the type of expression.
type ExpressionType string

const (
	ExprLiteral    ExpressionType = "literal"
	ExprVariable   ExpressionType = "variable"
	ExprOutput     ExpressionType = "output"
	ExprInput      ExpressionType = "input"
	ExprSecret     ExpressionType = "secret"
	ExprFunction   ExpressionType = "function"
	ExprJSONPath   ExpressionType = "jsonpath"
)

// ParsedExpression represents a parsed expression.
type ParsedExpression struct {
	Type     ExpressionType
	Raw      string
	Path     []string
	Function string
	Args     []string
}

// ParseExpression parses an expression string.
func (ep *ExpressionParser) ParseExpression(expr string) (*ParsedExpression, error) {
	expr = strings.TrimSpace(expr)

	// Check for variable reference: ${...}
	if strings.HasPrefix(expr, "${") && strings.HasSuffix(expr, "}") {
		inner := expr[2 : len(expr)-1]
		return ep.parseVariableExpression(inner)
	}

	// Check for output reference: $steps.stepName.output.field
	if strings.HasPrefix(expr, "$steps.") {
		return ep.parseOutputExpression(expr[7:])
	}

	// Check for input reference: $inputs.field
	if strings.HasPrefix(expr, "$inputs.") {
		return &ParsedExpression{
			Type: ExprInput,
			Raw:  expr,
			Path: strings.Split(expr[8:], "."),
		}, nil
	}

	// Check for secret reference: $secrets.name
	if strings.HasPrefix(expr, "$secrets.") {
		return &ParsedExpression{
			Type: ExprSecret,
			Raw:  expr,
			Path: strings.Split(expr[9:], "."),
		}, nil
	}

	// Literal value
	return &ParsedExpression{
		Type: ExprLiteral,
		Raw:  expr,
	}, nil
}

// parseVariableExpression parses a ${...} expression.
func (ep *ExpressionParser) parseVariableExpression(expr string) (*ParsedExpression, error) {
	// Check for function call: func(args)
	if idx := strings.Index(expr, "("); idx > 0 {
		funcName := expr[:idx]
		argsStr := expr[idx+1 : len(expr)-1]
		args := strings.Split(argsStr, ",")
		for i := range args {
			args[i] = strings.TrimSpace(args[i])
		}
		return &ParsedExpression{
			Type:     ExprFunction,
			Raw:      "${" + expr + "}",
			Function: funcName,
			Args:     args,
		}, nil
	}

	// Variable reference
	return &ParsedExpression{
		Type: ExprVariable,
		Raw:  "${" + expr + "}",
		Path: strings.Split(expr, "."),
	}, nil
}

// parseOutputExpression parses a step output expression.
func (ep *ExpressionParser) parseOutputExpression(expr string) (*ParsedExpression, error) {
	parts := strings.Split(expr, ".")

	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid output expression: $steps.%s", expr)
	}

	return &ParsedExpression{
		Type: ExprOutput,
		Raw:  "$steps." + expr,
		Path: parts,
	}, nil
}

// IsExpression checks if a string contains an expression.
func IsExpression(s string) bool {
	return strings.Contains(s, "${") ||
		strings.HasPrefix(s, "$steps.") ||
		strings.HasPrefix(s, "$inputs.") ||
		strings.HasPrefix(s, "$secrets.")
}

// ExtractExpressions extracts all expressions from a string.
func ExtractExpressions(s string) []string {
	var expressions []string

	// Find ${...} patterns
	for {
		start := strings.Index(s, "${")
		if start == -1 {
			break
		}

		// Find matching closing brace
		depth := 1
		end := start + 2
		for end < len(s) && depth > 0 {
			if s[end] == '{' {
				depth++
			} else if s[end] == '}' {
				depth--
			}
			end++
		}

		if depth == 0 {
			expressions = append(expressions, s[start:end])
			s = s[end:]
		} else {
			break
		}
	}

	return expressions
}
