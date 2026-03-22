package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"skillscan-demo/pkg/llmscan"
	"skillscan-demo/pkg/skillscan"
)

type Config struct {
	Input         string `yaml:"input" json:"input"`
	Output        string `yaml:"output" json:"output"`
	Threshold     string `yaml:"threshold" json:"threshold"`
	RulesFile     string `yaml:"rules_file" json:"rules_file"`
	Locale        string `yaml:"locale" json:"locale"`
	EnableLLMScan bool   `yaml:"enable_llm_scan" json:"enable_llm_scan"`
}

type Result struct {
	Input    string             `json:"input"`
	RuleScan *skillscan.Summary `json:"rule_scan"`
	LLMScan  *llmscan.Summary   `json:"llm_scan,omitempty"`
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

func ScanConfigFile(path string) (*Result, error) {
	cfg, err := LoadConfigFile(path)
	if err != nil {
		return nil, err
	}
	ruleScan, err := skillscan.ScanDir(cfg.Input, skillscan.Options{
		Threshold: cfg.Threshold,
		RulesFile: cfg.RulesFile,
		Locale:    cfg.Locale,
	})
	if err != nil {
		return nil, err
	}
	result := &Result{
		Input:    cfg.Input,
		RuleScan: ruleScan,
	}
	if cfg.EnableLLMScan {
		llmResult, err := llmscan.ScanDir(cfg.Input, llmscan.Options{Locale: cfg.Locale})
		if err != nil {
			return nil, err
		}
		result.LLMScan = llmResult
	}
	return result, nil
}

func WriteJSON(path string, result *Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func resolveConfigPath(baseDir, value string) string {
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(baseDir, value)
}
