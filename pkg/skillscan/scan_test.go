package skillscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDirCleanSkill(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "clean-skill")

	result, err := ScanDir(root, Options{})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if result.Risk {
		t.Fatalf("expected clean skill to be low risk, got risk=true with findings: %+v", result.Findings)
	}
	if result.MaxSeverity != "" {
		t.Fatalf("expected no max severity, got %q", result.MaxSeverity)
	}
}

func TestScanDirMaliciousSkill(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "malicious-skill")

	result, err := ScanDir(root, Options{Threshold: "high"})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if !result.Risk {
		t.Fatalf("expected malicious skill to be risky, got risk=false")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for malicious skill")
	}
}

func TestScanDirWithRulesFile(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "malicious-skill")
	rulesPath := filepath.Join(t.TempDir(), "audit-rules.yaml")
	content := `rules:
  - pattern: prompt-injection
    enabled: false
  - id: data-exfiltration-1
    enabled: false
`
	if err := os.WriteFile(rulesPath, []byte(content), 0644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	result, err := ScanDir(root, Options{
		Threshold: "high",
		RulesFile: rulesPath,
	})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if result.Risk {
		t.Fatalf("expected custom rules file to suppress risk, got risk=true with findings: %+v", result.Findings)
	}
}

func TestScanConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	configPath := filepath.Join(tmpDir, "scan.yaml")
	root, err := filepath.Abs(filepath.Join("..", "..", "examples", "malicious-skill"))
	if err != nil {
		t.Fatalf("resolve input path: %v", err)
	}
	config := "input: " + root + "\noutput: " + outputPath + "\nthreshold: high\n"

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	summary, err := ScanConfigFile(configPath)
	if err != nil {
		t.Fatalf("ScanConfigFile returned error: %v", err)
	}

	if !summary.Risk {
		t.Fatal("expected config-driven scan to report risk=true")
	}
}

func TestScanDirChineseLocale(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "malicious-skill")

	result, err := ScanDir(root, Options{
		Threshold: "high",
		Locale:    "zh-CN",
	})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if result.RiskLabel != "critical" {
		t.Fatalf("expected risk label to stay English, got %q", result.RiskLabel)
	}
	if result.MaxSeverity != SeverityCritical {
		t.Fatalf("expected max severity to stay English, got %q", result.MaxSeverity)
	}
	if result.Threshold != "HIGH" {
		t.Fatalf("expected threshold to stay English, got %q", result.Threshold)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if result.Findings[0].Severity != SeverityCritical {
		t.Fatalf("expected finding severity to stay English, got %q", result.Findings[0].Severity)
	}
	if result.Findings[0].Pattern != "prompt-injection" {
		t.Fatalf("expected finding pattern to stay English, got %q", result.Findings[0].Pattern)
	}
	if result.Findings[0].Message == "Prompt injection attempt detected" {
		t.Fatal("expected finding message to be localized")
	}
}
