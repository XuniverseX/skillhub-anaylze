package main

import (
	"flag"
	"fmt"
	"os"

	"skillscan-demo/pkg/report"
	"skillscan-demo/pkg/skillscan"
)

func main() {
	var configPath string
	var input string
	var output string
	var threshold string
	var rulesFile string
	var locale string

	flag.StringVar(&configPath, "config", "", "path to the scan config file")
	flag.StringVar(&input, "input", "", "path to the skill directory to scan")
	flag.StringVar(&output, "output", "", "path to the JSON report file")
	flag.StringVar(&threshold, "threshold", "", "risk threshold: critical|high|medium|low|info")
	flag.StringVar(&rulesFile, "rules-file", "", "path to a YAML rules overlay file")
	flag.StringVar(&locale, "locale", "", "output locale, e.g. zh-CN")
	flag.Parse()

	if configPath != "" {
		cfg, err := report.LoadConfigFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
			os.Exit(1)
		}

		result, err := report.ScanConfigFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(1)
		}

		if err := report.WriteJSON(cfg.Output, result); err != nil {
			fmt.Fprintf(os.Stderr, "write report failed: %v\n", err)
			os.Exit(1)
		}

		ruleFindings := 0
		ruleRisk := false
		if result.RuleScan != nil {
			ruleFindings = len(result.RuleScan.Findings)
			ruleRisk = result.RuleScan.Risk
		}
		fmt.Printf("rule_risk=%t rule_findings=%d output=%s\n", ruleRisk, ruleFindings, cfg.Output)
		return
	}

	if input == "" || output == "" {
		fmt.Fprintln(os.Stderr, "usage: demo --config <file> | --input <dir> --output <file> [--threshold <level>] [--rules-file <file>]")
		os.Exit(2)
	}

	report, err := skillscan.ScanDir(input, skillscan.Options{
		Threshold: threshold,
		RulesFile: rulesFile,
		Locale:    locale,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	if err := skillscan.WriteSummaryJSON(output, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("risk=%t findings=%d output=%s\n", report.Risk, len(report.Findings), output)
}
