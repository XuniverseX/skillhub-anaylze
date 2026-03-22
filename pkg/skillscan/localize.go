package skillscan

import "strings"

var severityZH = map[string]string{
	SeverityCritical: "严重",
	SeverityHigh:     "高",
	SeverityMedium:   "中",
	SeverityLow:      "低",
	SeverityInfo:     "提示",
}

var riskLabelZH = map[string]string{
	"clean":    "无风险",
	"low":      "低风险",
	"medium":   "中风险",
	"high":     "高风险",
	"critical": "严重",
}

var patternZH = map[string]string{
	"prompt-injection":     "提示词注入",
	"data-exfiltration":    "数据外传",
	"credential-access":    "凭证访问",
	"hidden-unicode":       "隐藏Unicode",
	"invisible-payload":    "不可见载荷",
	"config-manipulation":  "配置篡改",
	"destructive-commands": "危险命令",
	"dynamic-code-exec":    "动态代码执行",
	"shell-execution":      "Shell执行",
	"obfuscation":          "混淆",
	"external-link":        "外部链接",
}

var messageZH = map[string]string{
	"Prompt injection attempt detected":                                 "检测到提示词注入尝试",
	"Output suppression directive — attempts to hide actions from user": "检测到输出抑制指令，试图向用户隐藏操作",
	"Command sends environment variables externally":                    "命令尝试向外部发送环境变量",
}

func isChineseLocale(locale string) bool {
	normalized := strings.ToLower(strings.TrimSpace(locale))
	return normalized == "zh-cn" || normalized == "zh" || normalized == "zh_hans"
}

func localizeSummaryZH(summary *Summary) {
	summary.Threshold = localizeSeverityZH(summary.Threshold)
	summary.RiskLabel = localizeRiskLabelZH(summary.RiskLabel)
	summary.MaxSeverity = localizeSeverityZH(summary.MaxSeverity)
	for i := range summary.Findings {
		summary.Findings[i].Severity = localizeSeverityZH(summary.Findings[i].Severity)
		summary.Findings[i].Pattern = localizePatternZH(summary.Findings[i].Pattern)
		summary.Findings[i].Message = localizeMessageZH(summary.Findings[i].Message)
	}
}

func localizeSeverityZH(v string) string {
	if translated, ok := severityZH[strings.ToUpper(strings.TrimSpace(v))]; ok {
		return translated
	}
	return v
}

func localizeRiskLabelZH(v string) string {
	if translated, ok := riskLabelZH[strings.ToLower(strings.TrimSpace(v))]; ok {
		return translated
	}
	return v
}

func localizePatternZH(v string) string {
	if translated, ok := patternZH[v]; ok {
		return translated
	}
	return v
}

func localizeMessageZH(v string) string {
	if translated, ok := messageZH[v]; ok {
		return translated
	}
	return v
}
