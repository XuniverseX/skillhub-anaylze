package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDemoWritesJSONReport(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	repoRoot := filepath.Join("..", "..")
	inputPath := filepath.Join("examples", "malicious-skill")

	cmd := exec.Command("go", "run", "./cmd/demo", "--input", inputPath, "--output", outputPath, "--threshold", "high")
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var report struct {
		Risk      bool   `json:"risk"`
		Findings  []any  `json:"findings"`
		Threshold string `json:"threshold"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if !report.Risk {
		t.Fatal("expected report to mark malicious skill as risky")
	}
	if report.Threshold != "HIGH" {
		t.Fatalf("expected threshold HIGH, got %q", report.Threshold)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings in report")
	}
}

func TestDemoReadsConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	repoRoot := filepath.Join("..", "..")
	outputPath := filepath.Join(tmpDir, "report.json")
	configPath := filepath.Join(tmpDir, "scan.yaml")
	inputPath, err := filepath.Abs(filepath.Join(repoRoot, "examples", "malicious-skill"))
	if err != nil {
		t.Fatalf("resolve input path: %v", err)
	}
	config := "input: " + inputPath + "\noutput: " + outputPath + "\nthreshold: high\n"

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cmd := exec.Command("go", "run", "./cmd/demo", "--config", configPath)
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run with config failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var report struct {
		Input    string `json:"input"`
		RuleScan struct {
			Risk bool `json:"risk"`
		} `json:"rule_scan"`
		LLMScan any `json:"llm_scan"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if report.Input == "" {
		t.Fatal("expected aggregated report to include input")
	}
	if !report.RuleScan.Risk {
		t.Fatal("expected aggregated report to include risky rule_scan")
	}
	if report.LLMScan != nil {
		t.Fatal("expected llm_scan to be omitted when not enabled")
	}
}

func TestDemoReadsChineseConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	repoRoot := filepath.Join("..", "..")
	outputPath := filepath.Join(tmpDir, "report.json")
	configPath := filepath.Join(tmpDir, "scan.yaml")
	inputPath, err := filepath.Abs(filepath.Join(repoRoot, "examples", "malicious-skill"))
	if err != nil {
		t.Fatalf("resolve input path: %v", err)
	}
	config := "input: " + inputPath + "\noutput: " + outputPath + "\nthreshold: high\nlocale: zh-CN\nenable_llm_scan: true\n"

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cmd := exec.Command("go", "run", "./cmd/demo", "--config", configPath)
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run with zh config failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var report struct {
		RuleScan struct {
			RiskLabel   string `json:"risk_label"`
			MaxSeverity string `json:"max_severity"`
			Findings    []struct {
				Message string `json:"message"`
			} `json:"findings"`
		} `json:"rule_scan"`
		LLMScan struct {
			RiskLabel string `json:"risk_label"`
			Summary   string `json:"summary"`
			Findings  []struct {
				Message string `json:"message"`
			} `json:"findings"`
		} `json:"llm_scan"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if report.RuleScan.RiskLabel != "严重" {
		t.Fatalf("expected localized rule risk label, got %q", report.RuleScan.RiskLabel)
	}
	if report.RuleScan.MaxSeverity != "严重" {
		t.Fatalf("expected localized max severity, got %q", report.RuleScan.MaxSeverity)
	}
	if len(report.RuleScan.Findings) == 0 {
		t.Fatal("expected rule findings")
	}
	if report.RuleScan.Findings[0].Message == "Prompt injection attempt detected" {
		t.Fatal("expected localized rule finding message")
	}
	if report.LLMScan.RiskLabel == "" || report.LLMScan.Summary == "" {
		t.Fatal("expected llm_scan to be populated")
	}
	if len(report.LLMScan.Findings) == 0 {
		t.Fatal("expected llm findings")
	}
}
