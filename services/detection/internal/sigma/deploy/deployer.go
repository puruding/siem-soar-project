// Package deploy provides Sigma rule deployment to multiple SIEM platforms.
package deploy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/siem-soar-platform/pkg/connector"
)

// Deployer manages Sigma rule deployment to multiple SIEMs.
type Deployer struct {
	config     *Config
	converters map[connector.SIEMType]RuleConverter
	deployers  map[connector.SIEMType]RuleDeployer
	registry   *connector.Registry
	mu         sync.RWMutex
}

// Config holds deployer configuration.
type Config struct {
	SigmaToolsPath  string        `json:"sigmatools_path"`  // Path to sigma CLI
	PySigmaPath     string        `json:"pysigma_path"`     // Path to pySigma
	TempDir         string        `json:"temp_dir"`
	Timeout         time.Duration `json:"timeout"`
	ConcurrentDeploys int         `json:"concurrent_deploys"`
}

// DefaultConfig returns default deployer configuration.
func DefaultConfig() *Config {
	return &Config{
		SigmaToolsPath:    "sigma",
		PySigmaPath:       "sigma", // pySigma CLI
		TempDir:           "/tmp/sigma",
		Timeout:           5 * time.Minute,
		ConcurrentDeploys: 3,
	}
}

// SigmaRule represents a Sigma rule.
type SigmaRule struct {
	ID          string                 `yaml:"id" json:"id"`
	Title       string                 `yaml:"title" json:"title"`
	Status      string                 `yaml:"status" json:"status"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Author      string                 `yaml:"author,omitempty" json:"author,omitempty"`
	Date        string                 `yaml:"date,omitempty" json:"date,omitempty"`
	Modified    string                 `yaml:"modified,omitempty" json:"modified,omitempty"`
	References  []string               `yaml:"references,omitempty" json:"references,omitempty"`
	Tags        []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
	LogSource   LogSource              `yaml:"logsource" json:"logsource"`
	Detection   map[string]interface{} `yaml:"detection" json:"detection"`
	FalsePositives []string            `yaml:"falsepositives,omitempty" json:"false_positives,omitempty"`
	Level       string                 `yaml:"level,omitempty" json:"level,omitempty"`
	Fields      []string               `yaml:"fields,omitempty" json:"fields,omitempty"`
	Raw         string                 `yaml:"-" json:"raw,omitempty"` // Original YAML
}

// LogSource defines the log source for a Sigma rule.
type LogSource struct {
	Category   string `yaml:"category,omitempty" json:"category,omitempty"`
	Product    string `yaml:"product,omitempty" json:"product,omitempty"`
	Service    string `yaml:"service,omitempty" json:"service,omitempty"`
	Definition string `yaml:"definition,omitempty" json:"definition,omitempty"`
}

// ConvertedRule represents a rule converted for a specific SIEM.
type ConvertedRule struct {
	OriginalID    string             `json:"original_id"`
	SIEM          connector.SIEMType `json:"siem"`
	Query         string             `json:"query"`
	QueryLanguage string             `json:"query_language"`
	Index         string             `json:"index,omitempty"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	Severity      string             `json:"severity"`
	Tags          []string           `json:"tags,omitempty"`
	MITRE         []string           `json:"mitre,omitempty"`
	Extra         map[string]interface{} `json:"extra,omitempty"`
}

// DeploymentResult represents the result of a deployment.
type DeploymentResult struct {
	RuleID       string             `json:"rule_id"`
	SIEM         connector.SIEMType `json:"siem"`
	Success      bool               `json:"success"`
	DeployedID   string             `json:"deployed_id,omitempty"`
	Error        string             `json:"error,omitempty"`
	Duration     time.Duration      `json:"duration_ms"`
	Timestamp    time.Time          `json:"timestamp"`
}

// RuleConverter converts Sigma rules for a specific SIEM.
type RuleConverter interface {
	Convert(ctx context.Context, rule *SigmaRule) (*ConvertedRule, error)
	SIEM() connector.SIEMType
}

// RuleDeployer deploys rules to a specific SIEM.
type RuleDeployer interface {
	Deploy(ctx context.Context, rule *ConvertedRule) (*DeploymentResult, error)
	Undeploy(ctx context.Context, ruleID string) error
	List(ctx context.Context) ([]string, error)
	SIEM() connector.SIEMType
}

// NewDeployer creates a new deployer.
func NewDeployer(registry *connector.Registry, config *Config) *Deployer {
	if config == nil {
		config = DefaultConfig()
	}

	d := &Deployer{
		config:     config,
		converters: make(map[connector.SIEMType]RuleConverter),
		deployers:  make(map[connector.SIEMType]RuleDeployer),
		registry:   registry,
	}

	// Register built-in converters
	d.RegisterConverter(NewSplunkConverter(config))
	d.RegisterConverter(NewElasticConverter(config))
	d.RegisterConverter(NewSentinelConverter(config))

	return d
}

// RegisterConverter registers a rule converter.
func (d *Deployer) RegisterConverter(converter RuleConverter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.converters[converter.SIEM()] = converter
}

// RegisterDeployer registers a rule deployer.
func (d *Deployer) RegisterDeployer(deployer RuleDeployer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deployers[deployer.SIEM()] = deployer
}

// Convert converts a Sigma rule for a target SIEM.
func (d *Deployer) Convert(ctx context.Context, rule *SigmaRule, target connector.SIEMType) (*ConvertedRule, error) {
	d.mu.RLock()
	converter, ok := d.converters[target]
	d.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no converter registered for %s", target)
	}

	return converter.Convert(ctx, rule)
}

// ConvertAll converts a Sigma rule for all registered SIEMs.
func (d *Deployer) ConvertAll(ctx context.Context, rule *SigmaRule) (map[connector.SIEMType]*ConvertedRule, error) {
	d.mu.RLock()
	converters := make(map[connector.SIEMType]RuleConverter)
	for k, v := range d.converters {
		converters[k] = v
	}
	d.mu.RUnlock()

	results := make(map[connector.SIEMType]*ConvertedRule)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(converters))

	for siemType, converter := range converters {
		wg.Add(1)
		go func(st connector.SIEMType, conv RuleConverter) {
			defer wg.Done()

			converted, err := conv.Convert(ctx, rule)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", st, err)
				return
			}

			mu.Lock()
			results[st] = converted
			mu.Unlock()
		}(siemType, converter)
	}

	wg.Wait()
	close(errCh)

	// Collect errors
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 && len(results) == 0 {
		return nil, fmt.Errorf("all conversions failed: %v", errors)
	}

	return results, nil
}

// Deploy deploys a Sigma rule to a target SIEM.
func (d *Deployer) Deploy(ctx context.Context, rule *SigmaRule, target connector.SIEMType) (*DeploymentResult, error) {
	// Convert first
	converted, err := d.Convert(ctx, rule, target)
	if err != nil {
		return &DeploymentResult{
			RuleID:    rule.ID,
			SIEM:      target,
			Success:   false,
			Error:     fmt.Sprintf("conversion failed: %s", err.Error()),
			Timestamp: time.Now(),
		}, err
	}

	// Deploy
	d.mu.RLock()
	deployer, ok := d.deployers[target]
	d.mu.RUnlock()

	if !ok {
		return &DeploymentResult{
			RuleID:    rule.ID,
			SIEM:      target,
			Success:   false,
			Error:     fmt.Sprintf("no deployer registered for %s", target),
			Timestamp: time.Now(),
		}, fmt.Errorf("no deployer for %s", target)
	}

	return deployer.Deploy(ctx, converted)
}

// DeployAll deploys a Sigma rule to all registered SIEMs.
func (d *Deployer) DeployAll(ctx context.Context, rule *SigmaRule) map[connector.SIEMType]*DeploymentResult {
	results := make(map[connector.SIEMType]*DeploymentResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, d.config.ConcurrentDeploys)

	d.mu.RLock()
	siems := make([]connector.SIEMType, 0, len(d.deployers))
	for st := range d.deployers {
		siems = append(siems, st)
	}
	d.mu.RUnlock()

	for _, siemType := range siems {
		wg.Add(1)
		go func(st connector.SIEMType) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, _ := d.Deploy(ctx, rule, st)

			mu.Lock()
			results[st] = result
			mu.Unlock()
		}(siemType)
	}

	wg.Wait()
	return results
}

// Undeploy removes a rule from a target SIEM.
func (d *Deployer) Undeploy(ctx context.Context, ruleID string, target connector.SIEMType) error {
	d.mu.RLock()
	deployer, ok := d.deployers[target]
	d.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no deployer registered for %s", target)
	}

	return deployer.Undeploy(ctx, ruleID)
}

// ListDeployed lists deployed rules for a target SIEM.
func (d *Deployer) ListDeployed(ctx context.Context, target connector.SIEMType) ([]string, error) {
	d.mu.RLock()
	deployer, ok := d.deployers[target]
	d.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no deployer registered for %s", target)
	}

	return deployer.List(ctx)
}

// GetSupportedSIEMs returns the list of supported SIEMs.
func (d *Deployer) GetSupportedSIEMs() []connector.SIEMType {
	d.mu.RLock()
	defer d.mu.RUnlock()

	siems := make([]connector.SIEMType, 0, len(d.converters))
	for st := range d.converters {
		siems = append(siems, st)
	}
	return siems
}

// ConvertWithSigmaCLI converts a rule using the sigma CLI tool.
func (d *Deployer) ConvertWithSigmaCLI(ctx context.Context, ruleYAML string, target string, backend string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	defer cancel()

	// Use pySigma CLI
	cmd := exec.CommandContext(ctx, d.config.PySigmaPath, "convert",
		"--target", target,
		"--backend", backend,
		"--pipeline", getDefaultPipeline(target),
		"-",
	)

	cmd.Stdin = strings.NewReader(ruleYAML)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("sigma conversion failed: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("sigma conversion failed: %w", err)
	}

	return string(output), nil
}

// getDefaultPipeline returns the default pipeline for a target.
func getDefaultPipeline(target string) string {
	switch target {
	case "splunk":
		return "splunk_cim"
	case "elastic", "elasticsearch":
		return "ecs_windows"
	case "sentinel", "azure":
		return "azure_windows"
	default:
		return ""
	}
}

