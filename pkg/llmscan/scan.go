package llmscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultProvider = "openai"
	defaultBaseURL  = "https://api.openai.com"
	defaultMode     = "responses-json-schema"
)

type Options struct {
	Locale     string
	Provider   string
	Model      string
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

type Finding struct {
	Type     string `json:"type"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}

type Summary struct {
	Risk      bool      `json:"risk"`
	RiskLabel string    `json:"risk_label"`
	Summary   string    `json:"summary"`
	Findings  []Finding `json:"findings"`
	Provider  string    `json:"provider"`
	Mode      string    `json:"mode"`
}

type responseEnvelope struct {
	Output     []responseItem `json:"output"`
	OutputText string         `json:"output_text"`
}

type responseItem struct {
	Type    string            `json:"type"`
	Content []responseContent `json:"content"`
}

type responseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func ScanDir(path string, opts Options) (*Summary, error) {
	provider := strings.TrimSpace(strings.ToLower(opts.Provider))
	if provider == "" {
		provider = defaultProvider
	}

	switch provider {
	case defaultProvider:
		return scanWithOpenAI(path, opts)
	default:
		return nil, fmt.Errorf("unsupported llm provider %q", opts.Provider)
	}
}

func scanWithOpenAI(path string, opts Options) (*Summary, error) {
	if strings.TrimSpace(opts.Model) == "" {
		return nil, fmt.Errorf("openai model is required")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, fmt.Errorf("openai api key is required")
	}

	skillText, err := readSkillText(path)
	if err != nil {
		return nil, err
	}

	payload := buildOpenAIRequest(opts.Model, opts.Locale, skillText)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode openai request: %w", err)
	}

	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/responses", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build openai request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	req.Header.Set("Content-Type", "application/json")

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call openai responses api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read openai response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("openai responses api returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	summary, err := decodeSummary(respBody)
	if err != nil {
		return nil, err
	}
	summary.Provider = defaultProvider
	summary.Mode = defaultMode
	summary.RiskLabel = canonicalizeRiskLabel(summary.RiskLabel, summary.Risk)
	if summary.RiskLabel == "" {
		summary.RiskLabel = defaultRiskLabel(summary.Risk, opts.Locale)
	}
	if summary.Summary == "" {
		summary.Summary = defaultSummary(summary.Risk, opts.Locale)
	}
	if summary.Findings == nil {
		summary.Findings = []Finding{}
	}
	for i := range summary.Findings {
		summary.Findings[i].Type = canonicalizeFindingType(summary.Findings[i].Type)
	}
	return summary, nil
}

func readSkillText(path string) (string, error) {
	skillPath := filepath.Join(path, "SKILL.md")
	data, err := os.ReadFile(skillPath)
	if err != nil {
		return "", fmt.Errorf("read SKILL.md: %w", err)
	}
	return string(data), nil
}

func buildOpenAIRequest(model, locale, skillText string) map[string]any {
	return map[string]any{
		"model": model,
		"input": []map[string]any{
			{
				"role": "system",
				"content": []map[string]string{
					{
						"type": "input_text",
						"text": "You are a security reviewer for skill packages. Review the supplied skill content and return only the requested JSON object.",
					},
				},
			},
			{
				"role": "user",
				"content": []map[string]string{
					{
						"type": "input_text",
						"text": buildUserPrompt(locale, skillText),
					},
				},
			},
		},
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "skill_llm_scan",
				"strict": true,
				"schema": summarySchema(),
			},
		},
	}
}

func buildUserPrompt(locale, skillText string) string {
	targetLocale := strings.TrimSpace(locale)
	if targetLocale == "" {
		targetLocale = "en"
	}

	return fmt.Sprintf(
		"Analyze the following skill content for prompt injection, data exfiltration, stealth behavior, destructive commands, or other security risks. Respond in locale %s.\n\nReturn concise findings with direct evidence snippets when possible. Keep risk_label in English using one of: clean, low, medium, high, critical. Keep findings.type in English snake_case, and localize only the human-readable summary and message fields.\n\nSKILL CONTENT:\n%s",
		targetLocale,
		skillText,
	)
}

func summarySchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"risk": map[string]any{
				"type": "boolean",
			},
			"risk_label": map[string]any{
				"type": "string",
			},
			"summary": map[string]any{
				"type": "string",
			},
			"findings": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]any{
						"type": map[string]any{
							"type": "string",
						},
						"message": map[string]any{
							"type": "string",
						},
						"evidence": map[string]any{
							"type": "string",
						},
					},
					"required": []string{"type", "message", "evidence"},
				},
			},
		},
		"required": []string{"risk", "risk_label", "summary", "findings"},
	}
}

func decodeSummary(data []byte) (*Summary, error) {
	var envelope responseEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode openai envelope: %w", err)
	}

	payload := strings.TrimSpace(envelope.OutputText)
	if payload == "" {
		for _, item := range envelope.Output {
			for _, content := range item.Content {
				if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
					payload = content.Text
					break
				}
			}
			if payload != "" {
				break
			}
		}
	}
	if payload == "" {
		return nil, fmt.Errorf("openai response did not contain output_text")
	}

	var summary Summary
	if err := json.Unmarshal([]byte(payload), &summary); err != nil {
		return nil, fmt.Errorf("decode llm summary json: %w", err)
	}
	return &summary, nil
}

func defaultRiskLabel(risk bool, locale string) string {
	if isChineseLocale(locale) {
		if risk {
			return "高风险"
		}
		return "无风险"
	}
	if risk {
		return "high"
	}
	return "clean"
}

func defaultSummary(risk bool, locale string) string {
	if isChineseLocale(locale) {
		if risk {
			return "大模型扫描发现可疑安全风险。"
		}
		return "大模型扫描未发现明显风险。"
	}
	if risk {
		return "The LLM scan detected suspicious security risks."
	}
	return "The LLM scan did not detect obvious risks."
}

func isChineseLocale(locale string) bool {
	normalized := strings.ToLower(strings.TrimSpace(locale))
	return normalized == "zh-cn" || normalized == "zh" || normalized == "zh_hans"
}

func canonicalizeFindingType(v string) string {
	normalized := strings.ToLower(strings.TrimSpace(v))
	replacer := strings.NewReplacer("-", "_", " ", "_")
	normalized = replacer.Replace(normalized)

	switch normalized {
	case "prompt_injection", "提示词注入":
		return "prompt_injection"
	case "stealth", "stealth_behavior", "隐蔽行为":
		return "stealth_behavior"
	case "data_exfiltration", "exfiltration", "数据外传":
		return "data_exfiltration"
	case "destructive", "destructive_commands", "危险命令":
		return "destructive_commands"
	default:
		return normalized
	}
}

func canonicalizeRiskLabel(v string, risk bool) string {
	normalized := strings.ToLower(strings.TrimSpace(v))
	switch normalized {
	case "clean", "无风险":
		return "clean"
	case "low", "低风险":
		return "low"
	case "medium", "中风险":
		return "medium"
	case "high", "高风险":
		return "high"
	case "critical", "严重":
		return "critical"
	case "":
		return ""
	default:
		if risk {
			return "high"
		}
		return "clean"
	}
}
