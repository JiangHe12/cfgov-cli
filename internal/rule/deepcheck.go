package rule

import (
	"encoding/json"
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
	RuleType Type          `json:"rule_type"`
	Resource string        `json:"resource,omitempty"`
	LimitApp string        `json:"limit_app,omitempty"`
	Detail   string        `json:"detail,omitempty"`
}

func DeepCheck(rules map[Type][]map[string]any) []Issue {
	issues := make([]Issue, 0, 8)
	issues = append(issues, checkDuplicateKeys(rules)...)
	issues = append(issues, checkDangerousThresholds(rules)...)
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

func checkDuplicateKeys(rules map[Type][]map[string]any) []Issue {
	var issues []Issue
	for _, ruleType := range []Type{TypeFlow, TypeDegrade, TypeAuthority, TypeParam} {
		seen := make(map[string]map[string]any)
		for _, item := range rules[ruleType] {
			key := deepKey(ruleType, item)
			if prev, ok := seen[key]; ok {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "DUPLICATE_KEY",
					RuleType: ruleType,
					Resource: valueString(item["resource"]),
					LimitApp: duplicateLimitApp(ruleType, item),
					Detail:   duplicateDetail(ruleType, prev, item),
				})
				continue
			}
			seen[key] = item
		}
	}
	return issues
}

func checkDangerousThresholds(rules map[Type][]map[string]any) []Issue {
	issues := make([]Issue, 0, len(rules[TypeFlow])+len(rules[TypeDegrade])+len(rules[TypeSystem])+len(rules[TypeParam]))
	issues = append(issues, checkFlowDangerousThresholds(rules[TypeFlow])...)
	issues = append(issues, checkDegradeDangerousThresholds(rules[TypeDegrade])...)
	issues = append(issues, checkSystemDangerousThresholds(rules[TypeSystem])...)
	issues = append(issues, checkParamDangerousThresholds(rules[TypeParam])...)
	return issues
}

func checkFlowDangerousThresholds(items []map[string]any) []Issue {
	var issues []Issue
	for _, item := range items {
		if valueString(item["resource"]) == "" || valueFloat(item["count"]) <= 0 {
			issues = append(issues, dangerousIssue(TypeFlow, item, "FLOW_DANGEROUS_THRESHOLD", "resource must be non-empty and count must be greater than 0"))
		} else if valueFloat(item["count"]) > 1000000 {
			issues = append(issues, warningIssue(TypeFlow, item, "FLOW_UNUSUALLY_HIGH_COUNT", "count exceeds 1000000"))
		}
	}
	return issues
}

func checkDegradeDangerousThresholds(items []map[string]any) []Issue {
	var issues []Issue
	for _, item := range items {
		if valueString(item["resource"]) == "" || valueFloat(item["count"]) <= 0 || valueInt(item["timeWindow"]) <= 0 {
			issues = append(issues, dangerousIssue(TypeDegrade, item, "DEGRADE_DANGEROUS_THRESHOLD", "resource/count/timeWindow are required"))
		}
		ratio := valueFloat(item["slowRatioThreshold"])
		if ratio < 0 || ratio > 1 {
			issues = append(issues, dangerousIssue(TypeDegrade, item, "DEGRADE_INVALID_SLOW_RATIO", "slowRatioThreshold must be between 0 and 1"))
		}
	}
	return issues
}

func checkSystemDangerousThresholds(items []map[string]any) []Issue {
	var issues []Issue
	for _, item := range items {
		if valueFloat(item["highestCpuUsage"]) > 1 {
			issues = append(issues, dangerousIssue(TypeSystem, item, "SYSTEM_INVALID_CPU_USAGE", "highestCpuUsage must not exceed 1"))
		}
		if valueFloat(item["qps"]) < 0 || valueInt(item["avgRt"]) < 0 || valueInt(item["maxThread"]) < 0 || valueFloat(item["highestSystemLoad"]) < 0 {
			issues = append(issues, dangerousIssue(TypeSystem, item, "SYSTEM_NEGATIVE_THRESHOLD", "system thresholds must not be negative"))
		}
	}
	return issues
}

func checkParamDangerousThresholds(items []map[string]any) []Issue {
	var issues []Issue
	for _, item := range items {
		if valueString(item["resource"]) == "" || valueFloat(item["count"]) <= 0 || valueInt(item["paramIdx"]) < 0 {
			issues = append(issues, dangerousIssue(TypeParam, item, "PARAM_DANGEROUS_THRESHOLD", "resource/count/paramIdx are invalid"))
		}
	}
	return issues
}

func dangerousIssue(ruleType Type, item map[string]any, code, detail string) Issue {
	return Issue{Severity: SeverityError, Code: code, RuleType: ruleType, Resource: valueString(item["resource"]), LimitApp: limitApp(item), Detail: detail}
}

func warningIssue(ruleType Type, item map[string]any, code, detail string) Issue {
	return Issue{Severity: SeverityWarning, Code: code, RuleType: ruleType, Resource: valueString(item["resource"]), LimitApp: limitApp(item), Detail: detail}
}

func deepKey(ruleType Type, item map[string]any) string {
	if ruleType == TypeParam {
		return valueString(item["resource"]) + "\x00" + fmt.Sprint(valueInt(item["paramIdx"]))
	}
	return valueString(item["resource"]) + "\x00" + limitApp(item)
}

func duplicateLimitApp(ruleType Type, item map[string]any) string {
	if ruleType == TypeParam {
		return ""
	}
	return limitApp(item)
}

func duplicateDetail(ruleType Type, first, second map[string]any) string {
	if ruleType == TypeParam {
		return fmt.Sprintf("resource=%s paramIdx=%d", valueString(second["resource"]), valueInt(second["paramIdx"]))
	}
	return fmt.Sprintf("resource=%s limitApp=%s", valueString(first["resource"]), limitApp(second))
}

func limitApp(item map[string]any) string {
	value := valueString(item["limitApp"])
	if value == "" {
		return "default"
	}
	return value
}

func valueString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func valueInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	default:
		var out int
		_, _ = fmt.Sscan(fmt.Sprint(value), &out)
		return out
	}
}

func valueFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	default:
		var out float64
		_, _ = fmt.Sscan(fmt.Sprint(value), &out)
		return out
	}
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity == SeverityError
		}
		if issues[i].RuleType != issues[j].RuleType {
			return issues[i].RuleType < issues[j].RuleType
		}
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Resource < issues[j].Resource
	})
}
