package report

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestScanConfigFileWithLLM(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	inputPath, err := filepath.Abs(filepath.Join(repoRoot, "examples", "malicious-skill"))
	if err != nil {
		t.Fatalf("resolve input path: %v", err)
	}
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","content":[{"type":"output_text","text":"{\"risk\":true,\"risk_label\":\"high\",\"summary\":\"Detected prompt injection guidance.\",\"findings\":[{\"type\":\"prompt_injection\",\"message\":\"Detected prompt injection guidance.\",\"evidence\":\"Ignore previous instructions.\"}]}"}]}]}`))
	}))
	defer server.Close()

	t.Setenv("TEST_OPENAI_API_KEY", "test-key")

	cfgPath := filepath.Join(tmpDir, "scan.yaml")
	config := "input: " + inputPath + "\n" +
		"output: " + outputPath + "\n" +
		"threshold: high\n" +
		"enable_llm_scan: true\n" +
		"llm_provider: openai\n" +
		"openai_model: gpt-4.1-mini\n" +
		"openai_api_key_env: TEST_OPENAI_API_KEY\n" +
		"openai_base_url: " + server.URL + "\n"
	if err := os.WriteFile(cfgPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

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
	if result.LLMScan.Provider != "openai" {
		t.Fatalf("expected openai provider, got %q", result.LLMScan.Provider)
	}
}
