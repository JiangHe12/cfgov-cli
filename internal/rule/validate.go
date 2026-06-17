package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func DecodeSet(ruleType Type, data []byte) ([]map[string]any, error) {
	if _, ok := allowedFields(ruleType); !ok {
		return nil, apperrors.New(apperrors.CodeUsageError, "unsupported rule type", nil)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		data = []byte("[]")
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, validationError("rules must be a JSON array", err)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		normalized, err := DecodeOne(ruleType, item)
		if err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	return out, nil
}

//nolint:gocyclo // Each Sentinel rule type has a distinct wire schema.
func DecodeOne(ruleType Type, data []byte) (map[string]any, error) {
	if err := rejectUnknownFieldNames(ruleType, data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var typed any
	switch ruleType {
	case TypeFlow:
		var r FlowRule
		if err := dec.Decode(&r); err != nil {
			return nil, validationError("invalid flow rule JSON", err)
		}
		if err := ValidateFlow(r); err != nil {
			return nil, err
		}
		typed = r
	case TypeDegrade:
		var r DegradeRule
		if err := dec.Decode(&r); err != nil {
			return nil, validationError("invalid degrade rule JSON", err)
		}
		if err := ValidateDegrade(r); err != nil {
			return nil, err
		}
		typed = r
	case TypeSystem:
		var r SystemRule
		if err := dec.Decode(&r); err != nil {
			return nil, validationError("invalid system rule JSON", err)
		}
		if err := ValidateSystem(r); err != nil {
			return nil, err
		}
		typed = r
	case TypeAuthority:
		var r AuthorityRule
		if err := dec.Decode(&r); err != nil {
			return nil, validationError("invalid authority rule JSON", err)
		}
		if err := ValidateAuthority(r); err != nil {
			return nil, err
		}
		typed = r
	case TypeParam:
		var r ParamFlowRule
		if err := dec.Decode(&r); err != nil {
			return nil, validationError("invalid param rule JSON", err)
		}
		if err := ValidateParamFlow(r); err != nil {
			return nil, err
		}
		typed = r
	default:
		return nil, apperrors.New(apperrors.CodeUsageError, "unsupported rule type", nil)
	}
	return marshalToNormalizedMap(typed, ruleType)
}

func rejectUnknownFieldNames(ruleType Type, data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return validationError(fmt.Sprintf("invalid %s rule JSON", ruleType), err)
	}
	allowed, ok := allowedFields(ruleType)
	if !ok {
		return apperrors.New(apperrors.CodeUsageError, "unsupported rule type", nil)
	}
	for key := range raw {
		if !allowed[key] {
			return validationError(fmt.Sprintf("json: unknown field %q", key), nil)
		}
	}
	return nil
}

func allowedFields(ruleType Type) (map[string]bool, bool) {
	switch ruleType {
	case TypeFlow:
		return fieldSet("resource", "limitApp", "grade", "count", "strategy", "refResource",
			"controlBehavior", "warmUpPeriodSec", "maxQueueingTimeMs", "clusterMode"), true
	case TypeDegrade:
		return fieldSet("resource", "limitApp", "grade", "count", "timeWindow", "minRequestAmount",
			"statIntervalMs", "slowRatioThreshold"), true
	case TypeSystem:
		return fieldSet("highestSystemLoad", "avgRt", "maxThread", "qps", "highestCpuUsage"), true
	case TypeAuthority:
		return fieldSet("resource", "limitApp", "strategy"), true
	case TypeParam:
		return fieldSet("resource", "grade", "paramIdx", "count", "controlBehavior", "maxQueueingTimeMs",
			"burstCount", "durationInSec", "paramFlowItemList"), true
	default:
		return nil, false
	}
}

func fieldSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

func marshalToNormalizedMap(typed any, ruleType Type) (map[string]any, error) {
	normalized, err := json.Marshal(typed)
	if err != nil {
		return nil, validationError("failed to normalize rule", err)
	}
	var out map[string]any
	raw := json.NewDecoder(bytes.NewReader(normalized))
	raw.UseNumber()
	if err := raw.Decode(&out); err != nil {
		return nil, validationError("invalid rule JSON", err)
	}
	if _, ok := out["limitApp"]; !ok && needsLimitApp(ruleType) {
		out["limitApp"] = "default"
	}
	return out, nil
}

func ValidateFlow(r FlowRule) error {
	if err := validateResource(r.Resource); err != nil {
		return err
	}
	if r.Count <= 0 {
		return validationError("count must be greater than 0", nil)
	}
	if !oneOf(r.Grade, 0, 1) {
		return validationError("grade must be 0 or 1", nil)
	}
	if !oneOf(r.Strategy, 0, 1, 2) {
		return validationError("strategy must be 0, 1, or 2", nil)
	}
	if (r.Strategy == 1 || r.Strategy == 2) && strings.TrimSpace(r.RefResource) == "" {
		return validationError("refResource is required when strategy is 1 or 2", nil)
	}
	if !oneOf(r.ControlBehavior, 0, 1, 2, 3) {
		return validationError("controlBehavior must be 0, 1, 2, or 3", nil)
	}
	if (r.ControlBehavior == 1 || r.ControlBehavior == 3) && r.WarmUpPeriodSec <= 0 {
		return validationError("warmUpPeriodSec must be greater than 0 for warm-up behavior", nil)
	}
	return nil
}

func ValidateDegrade(r DegradeRule) error {
	if err := validateResource(r.Resource); err != nil {
		return err
	}
	if r.Count <= 0 {
		return validationError("count must be greater than 0", nil)
	}
	if r.TimeWindow <= 0 {
		return validationError("timeWindow must be greater than 0", nil)
	}
	return nil
}

func ValidateSystem(r SystemRule) error {
	if r.HighestSystemLoad <= 0 && r.AvgRT <= 0 && r.MaxThread <= 0 && r.QPS <= 0 && r.HighestCPUUsage <= 0 {
		return validationError("at least one system threshold must be greater than 0", nil)
	}
	return nil
}

func ValidateAuthority(r AuthorityRule) error {
	if err := validateResource(r.Resource); err != nil {
		return err
	}
	if strings.TrimSpace(r.LimitApp) == "" {
		return validationError("limitApp is required", nil)
	}
	if !oneOf(r.Strategy, 0, 1) {
		return validationError("strategy must be 0 or 1", nil)
	}
	return nil
}

func ValidateParamFlow(r ParamFlowRule) error {
	if err := validateResource(r.Resource); err != nil {
		return err
	}
	if r.Count <= 0 {
		return validationError("count must be greater than 0", nil)
	}
	if r.ParamIdx < 0 {
		return validationError("paramIdx must be greater than or equal to 0", nil)
	}
	return nil
}

func validateResource(resource string) error {
	if strings.TrimSpace(resource) == "" {
		return validationError("resource must not be empty", nil)
	}
	if strings.ContainsAny(resource, "\r\n\t") {
		return validationError("resource must not contain CR, LF, or TAB", nil)
	}
	return nil
}

func validationError(message string, err error) *apperrors.AppError {
	return apperrors.New(apperrors.CodeValidationFailed, message, err)
}

func oneOf(value int, candidates ...int) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func needsLimitApp(ruleType Type) bool {
	return ruleType == TypeFlow || ruleType == TypeDegrade
}
