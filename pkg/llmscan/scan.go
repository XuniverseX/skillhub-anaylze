package llmscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Options struct {
	Locale string
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

func ScanDir(path string, opts Options) (*Summary, error) {
	skillPath := filepath.Join(path, "SKILL.md")
	data, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("read SKILL.md: %w", err)
	}

	text := string(data)
	textLower := strings.ToLower(text)
	findings := make([]Finding, 0, 4)

	if strings.Contains(textLower, "ignore previous instructions") {
		findings = append(findings, Finding{
			Type:     localizeType("prompt_injection", opts.Locale),
			Message:  localizeMessage("Detected instruction override language.", opts.Locale),
			Evidence: "ignore previous instructions",
		})
	}
	if strings.Contains(textLower, "do not tell the user") {
		findings = append(findings, Finding{
			Type:     localizeType("stealth", opts.Locale),
			Message:  localizeMessage("Detected attempts to hide actions from the user.", opts.Locale),
			Evidence: "do not tell the user",
		})
	}
	if strings.Contains(textLower, "curl ") && strings.Contains(textLower, "$github_token") {
		findings = append(findings, Finding{
			Type:     localizeType("exfiltration", opts.Locale),
			Message:  localizeMessage("Detected possible credential exfiltration through network requests.", opts.Locale),
			Evidence: "curl ... $GITHUB_TOKEN",
		})
	}
	if strings.Contains(textLower, "sudo rm -rf /") {
		findings = append(findings, Finding{
			Type:     localizeType("destructive", opts.Locale),
			Message:  localizeMessage("Detected destructive privileged command guidance.", opts.Locale),
			Evidence: "sudo rm -rf /",
		})
	}

	summary := &Summary{
		Risk:      len(findings) > 0,
		RiskLabel: localizeRiskLabel(len(findings) > 0, opts.Locale),
		Summary:   localizeSummary(len(findings) > 0, opts.Locale),
		Findings:  findings,
		Provider:  "demo",
		Mode:      "heuristic-llm-demo",
	}
	return summary, nil
}

func localizeType(v, locale string) string {
	if !isChineseLocale(locale) {
		return v
	}
	switch v {
	case "prompt_injection":
		return "提示词注入"
	case "stealth":
		return "隐蔽行为"
	case "exfiltration":
		return "数据外传"
	case "destructive":
		return "危险命令"
	default:
		return v
	}
}

func localizeMessage(v, locale string) string {
	if !isChineseLocale(locale) {
		return v
	}
	switch v {
	case "Detected instruction override language.":
		return "检测到覆盖系统指令的语言。"
	case "Detected attempts to hide actions from the user.":
		return "检测到试图向用户隐藏操作的内容。"
	case "Detected possible credential exfiltration through network requests.":
		return "检测到可能通过网络请求外传凭证的行为。"
	case "Detected destructive privileged command guidance.":
		return "检测到带权限的危险命令指引。"
	default:
		return v
	}
}

func localizeRiskLabel(risk bool, locale string) string {
	if !isChineseLocale(locale) {
		if risk {
			return "high"
		}
		return "clean"
	}
	if risk {
		return "高风险"
	}
	return "无风险"
}

func localizeSummary(risk bool, locale string) string {
	if !isChineseLocale(locale) {
		if risk {
			return "The skill contains suspicious instruction and exfiltration patterns."
		}
		return "The skill content looks safe in the demo LLM scan."
	}
	if risk {
		return "该 skill 包含可疑的指令覆盖、隐蔽行为或外传模式。"
	}
	return "该 skill 在演示版 LLM 扫描中未发现明显风险。"
}

func isChineseLocale(locale string) bool {
	normalized := strings.ToLower(strings.TrimSpace(locale))
	return normalized == "zh-cn" || normalized == "zh" || normalized == "zh_hans"
}
