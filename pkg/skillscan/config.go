package skillscan

import "fmt"

func rulesWithOverlayFile(path string) ([]rule, map[string]bool, error) {
	base := builtinYAML()
	user, err := loadUserRules(path)
	if err != nil {
		return nil, nil, fmt.Errorf("load rules file: %w", err)
	}
	if user == nil {
		rules, err := loadBuiltinRules()
		if err != nil {
			return nil, nil, err
		}
		return rules, extractDisabledIDs(base), nil
	}

	merged := mergeYAMLRules(base, user)
	rules, err := compileRules(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("compile rules file: %w", err)
	}
	return rules, extractDisabledIDs(merged), nil
}
