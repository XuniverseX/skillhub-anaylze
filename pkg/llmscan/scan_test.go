package llmscan

import (
	"path/filepath"
	"testing"
)

func TestScanDirMaliciousSkill(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "malicious-skill")

	result, err := ScanDir(root, Options{})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if !result.Risk {
		t.Fatal("expected llm demo scan to mark malicious skill as risky")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected llm demo findings")
	}
}

func TestScanDirChineseLocale(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "malicious-skill")

	result, err := ScanDir(root, Options{Locale: "zh-CN"})
	if err != nil {
		t.Fatalf("ScanDir returned error: %v", err)
	}

	if result.RiskLabel != "高风险" {
		t.Fatalf("expected localized llm risk label, got %q", result.RiskLabel)
	}
	if result.Summary == "" || result.Summary == "The skill contains suspicious instruction and exfiltration patterns." {
		t.Fatal("expected localized llm summary")
	}
}
