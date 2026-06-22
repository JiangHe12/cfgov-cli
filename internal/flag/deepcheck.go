package flag

import (
	"fmt"
	"sort"
)

type IssueSeverity string

const (
	SeverityError   IssueSeverity = "error"
	SeverityWarning IssueSeverity = "warning"
)

type Issue struct {
	Severity IssueSeverity `json:"severity"`
	Code     string        `json:"code"`
	Key      string        `json:"key,omitempty"`
	Detail   string        `json:"detail,omitempty"`
}

func DeepCheck(flags []FeatureFlag) []Issue {
	issues := make([]Issue, 0, 8)
	issues = append(issues, checkDuplicateKeys(flags)...)
	issues = append(issues, checkVariants(flags)...)
	sortIssues(issues)
	return issues
}

func HasError(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == SeverityError {
			return true
		}
	}
	return false
}

func checkDuplicateKeys(flags []FeatureFlag) []Issue {
	seen := make(map[string]struct{}, len(flags))
	var issues []Issue
	for _, item := range flags {
		if _, ok := seen[item.Key]; ok {
			issues = append(issues, Issue{Severity: SeverityError, Code: "DUPLICATE_KEY", Key: item.Key})
			continue
		}
		seen[item.Key] = struct{}{}
	}
	return issues
}

func checkVariants(flags []FeatureFlag) []Issue {
	var issues []Issue
	for _, item := range flags {
		variants := variantNames(item)
		if item.Enabled && len(item.Variants) == 0 {
			issues = append(issues, Issue{Severity: SeverityWarning, Code: "ENABLED_WITHOUT_VARIANTS", Key: item.Key})
		}
		if item.DefaultVariant != "" {
			if _, ok := variants[item.DefaultVariant]; !ok {
				issues = append(issues, Issue{Severity: SeverityError, Code: "DEFAULT_VARIANT_MISSING", Key: item.Key, Detail: "defaultVariant=" + item.DefaultVariant})
			}
		}
		for _, rule := range item.Rules {
			if rule.RolloutPercent < 0 || rule.RolloutPercent > 100 {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "ROLLOUT_PERCENT_OUT_OF_RANGE",
					Key:      item.Key,
					Detail:   fmt.Sprintf("variant=%s rolloutPercent=%d", rule.Variant, rule.RolloutPercent),
				})
			}
			if _, ok := variants[rule.Variant]; !ok {
				issues = append(issues, Issue{Severity: SeverityError, Code: "RULE_VARIANT_MISSING", Key: item.Key, Detail: "variant=" + rule.Variant})
			}
		}
	}
	return issues
}

func variantNames(item FeatureFlag) map[string]struct{} {
	out := make(map[string]struct{}, len(item.Variants))
	for _, variant := range item.Variants {
		out[variant.Name] = struct{}{}
	}
	return out
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity == SeverityError
		}
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Key < issues[j].Key
	})
}
