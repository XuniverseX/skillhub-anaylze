package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	server := startOpenAITestServer(t)
	defer server.Close()

	t.Setenv("TEST_OPENAI_API_KEY", "test-key")

	config := "input: " + inputPath + "\n" +
		"output: " + outputPath + "\n" +
		"threshold: high\n" +
		"locale: zh-CN\n" +
		"enable_llm_scan: true\n" +
		"llm_provider: openai\n" +
		"openai_model: gpt-4.1-mini\n" +
		"openai_api_key_env: TEST_OPENAI_API_KEY\n" +
		"openai_base_url: " + server.URL + "\n"

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
				Severity string `json:"severity"`
				Pattern  string `json:"pattern"`
				Message  string `json:"message"`
			} `json:"findings"`
		} `json:"rule_scan"`
		LLMScan struct {
			RiskLabel string `json:"risk_label"`
			Summary   string `json:"summary"`
			Findings  []struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"findings"`
		} `json:"llm_scan"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}

	if report.RuleScan.RiskLabel != "critical" {
		t.Fatalf("expected rule risk label to stay English, got %q", report.RuleScan.RiskLabel)
	}
	if report.RuleScan.MaxSeverity != "CRITICAL" {
		t.Fatalf("expected max severity to stay English, got %q", report.RuleScan.MaxSeverity)
	}
	if len(report.RuleScan.Findings) == 0 {
		t.Fatal("expected rule findings")
	}
	if report.RuleScan.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("expected rule severity to stay English, got %q", report.RuleScan.Findings[0].Severity)
	}
	if report.RuleScan.Findings[0].Pattern != "prompt-injection" {
		t.Fatalf("expected rule pattern to stay English, got %q", report.RuleScan.Findings[0].Pattern)
	}
	if report.RuleScan.Findings[0].Message == "Prompt injection attempt detected" {
		t.Fatal("expected localized rule finding message")
	}
	if report.LLMScan.RiskLabel != "high" || report.LLMScan.Summary == "" {
		t.Fatal("expected llm_scan to be populated")
	}
	if len(report.LLMScan.Findings) == 0 {
		t.Fatal("expected llm findings")
	}
	if report.LLMScan.Findings[0].Type != "prompt_injection" {
		t.Fatalf("expected llm finding type to stay English, got %q", report.LLMScan.Findings[0].Type)
	}
}

func startOpenAITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"type":"message","content":[{"type":"output_text","text":"{\"risk\":true,\"risk_label\":\"高风险\",\"summary\":\"检测到提示词注入与凭证外传风险。\",\"findings\":[{\"type\":\"prompt_injection\",\"message\":\"检测到提示词注入与凭证外传风险。\",\"evidence\":\"Ignore previous instructions.\"}]}"}]}]}`))
	}))
}
