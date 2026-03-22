package skillscan

import "strings"

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
	for i := range summary.Findings {
		summary.Findings[i].Message = localizeMessageZH(summary.Findings[i].Message)
	}
}

func localizeMessageZH(v string) string {
	if translated, ok := messageZH[v]; ok {
		return translated
	}
	return v
}
