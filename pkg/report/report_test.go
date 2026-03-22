package report

import (
	"path/filepath"
	"testing"
)

func TestScanConfigFileWithLLM(t *testing.T) {
	cfgPath := filepath.Join("..", "..", "examples", "scan.yaml")

	result, err := ScanConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("ScanConfigFile returned error: %v", err)
	}

	if result.RuleScan == nil {
		t.Fatal("expected rule_scan")
	}
	if result.LLMScan == nil {
		t.Fatal("expected llm_scan from config")
	}
}
