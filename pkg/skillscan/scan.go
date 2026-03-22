package skillscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Options struct {
	Threshold string
	RulesFile string
	Locale    string
}

type Config struct {
	Input     string `yaml:"input" json:"input"`
	Output    string `yaml:"output" json:"output"`
	Threshold string `yaml:"threshold" json:"threshold"`
	RulesFile string `yaml:"rules_file" json:"rules_file"`
	Locale    string `yaml:"locale" json:"locale"`
}

type Summary struct {
	Risk        bool      `json:"risk"`
	Threshold   string    `json:"threshold"`
	RiskScore   int       `json:"risk_score"`
	RiskLabel   string    `json:"risk_label"`
	MaxSeverity string    `json:"max_severity"`
	Findings    []Finding `json:"findings"`
}

func ScanDir(path string, opts Options) (*Summary, error) {
	result, err := scanWithOptions(path, opts)
	if err != nil {
		return nil, err
	}

	threshold, err := NormalizeThreshold(opts.Threshold)
	if err != nil {
		threshold = DefaultThreshold()
	}

	summary := &Summary{
		Risk:        result.HasSeverityAtOrAbove(threshold),
		Threshold:   strings.ToUpper(threshold),
		RiskScore:   result.RiskScore,
		RiskLabel:   result.RiskLabel,
		MaxSeverity: result.MaxSeverity(),
		Findings:    result.Findings,
	}
	if isChineseLocale(opts.Locale) {
		localizeSummaryZH(summary)
	}
	return summary, nil
}

func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Input == "" {
		return nil, fmt.Errorf("config.input is required")
	}
	if cfg.Output == "" {
		return nil, fmt.Errorf("config.output is required")
	}

	baseDir := filepath.Dir(path)
	cfg.Input = resolveConfigPath(baseDir, cfg.Input)
	cfg.Output = resolveConfigPath(baseDir, cfg.Output)
	if cfg.RulesFile != "" {
		cfg.RulesFile = resolveConfigPath(baseDir, cfg.RulesFile)
	}
	return &cfg, nil
}

func ScanConfigFile(path string) (*Summary, error) {
	cfg, err := LoadConfigFile(path)
	if err != nil {
		return nil, err
	}
	return ScanDir(cfg.Input, Options{
		Threshold: cfg.Threshold,
		RulesFile: cfg.RulesFile,
		Locale:    cfg.Locale,
	})
}

func WriteSummaryJSON(path string, summary *Summary) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func scanWithOptions(path string, opts Options) (*Result, error) {
	if opts.RulesFile == "" {
		return ScanSkill(path)
	}

	rules, disabled, err := rulesWithOverlayFile(opts.RulesFile)
	if err != nil {
		return nil, err
	}
	return scanSkillImpl(path, rules, disabled, nil)
}

func resolveConfigPath(baseDir, value string) string {
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(baseDir, value)
}
