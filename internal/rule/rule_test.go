package rule

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestNacosKeyMatchesSentinelConvention(t *testing.T) {
	t.Parallel()
	key, err := NacosKey("order-service", TypeFlow)
	if err != nil {
		t.Fatalf("NacosKey() error = %v", err)
	}
	if key != "SENTINEL_GROUP/order-service-flow-rules" {
		t.Fatalf("key = %q", key)
	}
}

func TestNacosKeyRejectsInjectedApp(t *testing.T) {
	t.Parallel()
	if _, err := NacosKey("../prod", TypeFlow); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}

func TestDecodeSetShallowValidation(t *testing.T) {
	t.Parallel()
	rules, err := DecodeSet(TypeFlow, []byte(`[{"resource":"createOrder","grade":1,"count":10}]`))
	if err != nil {
		t.Fatalf("DecodeSet() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("count = %d, want 1", len(rules))
	}
	if _, err := DecodeSet(TypeFlow, []byte(`[{"resource":"","grade":1,"count":10}]`)); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}

func TestDecodeSetUnknownTypeFailsClosedForEmptyInput(t *testing.T) {
	t.Parallel()
	if _, err := DecodeSet(Type("bogus"), []byte("[]")); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("empty array error = %v, want usage error", err)
	}
	if _, err := DecodeSet(Type("bogus"), []byte(" ")); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("blank input error = %v, want usage error", err)
	}
	rules, err := DecodeSet(TypeFlow, []byte("[]"))
	if err != nil {
		t.Fatalf("DecodeSet(TypeFlow, []) error = %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len = %d, want 0", len(rules))
	}
}

func TestDeepValidationSurfacesDangerousRule(t *testing.T) {
	t.Parallel()
	rules, err := DecodeSet(TypeDegrade, []byte(`[{"resource":"createOrder","grade":0,"count":1,"timeWindow":10,"slowRatioThreshold":2}]`))
	if err != nil {
		t.Fatalf("DecodeSet() error = %v", err)
	}
	issues := DeepCheck(map[Type][]map[string]any{TypeDegrade: rules})
	if !HasError(issues) {
		t.Fatalf("issues = %#v, want error", issues)
	}
}

func TestDeepValidationSentinelParityChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		code     string
		severity IssueSeverity
		rules    map[Type][]map[string]any
		clean    map[Type][]map[string]any
	}{
		{
			name:     "multiple system rules",
			code:     "MULTIPLE_SYSTEM_RULES",
			severity: SeverityError,
			rules: map[Type][]map[string]any{
				TypeSystem: {
					{"qps": 100},
					{"avgRt": 20},
				},
			},
			clean: map[Type][]map[string]any{
				TypeSystem: {
					{"qps": 100},
				},
			},
		},
		{
			name:     "dangling refResource",
			code:     "FLOW_REFRESOURCE_MISSING",
			severity: SeverityError,
			rules: map[Type][]map[string]any{
				TypeFlow: {
					{"resource": "api", "grade": 1, "count": 10, "strategy": 1, "refResource": "missing"},
				},
			},
			clean: map[Type][]map[string]any{
				TypeFlow: {
					{"resource": "api", "grade": 1, "count": 10, "strategy": 1, "refResource": "base"},
					{"resource": "base", "grade": 1, "count": 10},
				},
			},
		},
		{
			name:     "param without flow",
			code:     "PARAM_WITHOUT_FLOW",
			severity: SeverityWarning,
			rules: map[Type][]map[string]any{
				TypeParam: {
					{"resource": "api", "grade": 1, "paramIdx": 0, "count": 10},
				},
			},
			clean: map[Type][]map[string]any{
				TypeFlow: {
					{"resource": "api", "grade": 1, "count": 10},
				},
				TypeParam: {
					{"resource": "api", "grade": 1, "paramIdx": 0, "count": 10},
				},
			},
		},
		{
			name:     "authority mixed strategy",
			code:     "AUTHORITY_MIXED_STRATEGY",
			severity: SeverityWarning,
			rules: map[Type][]map[string]any{
				TypeAuthority: {
					{"resource": "api", "limitApp": "caller-a", "strategy": 0},
					{"resource": "api", "limitApp": "caller-b", "strategy": 1},
				},
			},
			clean: map[Type][]map[string]any{
				TypeAuthority: {
					{"resource": "api", "limitApp": "caller-a", "strategy": 0},
					{"resource": "api", "limitApp": "caller-b", "strategy": 0},
				},
			},
		},
		{
			name:     "flow degrade grade mismatch",
			code:     "FLOW_DEGRADE_GRADE_MISMATCH",
			severity: SeverityWarning,
			rules: map[Type][]map[string]any{
				TypeFlow: {
					{"resource": "api", "grade": 1, "count": 10},
				},
				TypeDegrade: {
					{"resource": "api", "grade": 0, "count": 1, "timeWindow": 10},
				},
			},
			clean: map[Type][]map[string]any{
				TypeFlow: {
					{"resource": "api", "grade": 1, "count": 10},
				},
				TypeDegrade: {
					{"resource": "api", "grade": 1, "count": 1, "timeWindow": 10},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/trigger", func(t *testing.T) {
			t.Parallel()
			assertIssue(t, DeepCheck(tt.rules), tt.code, tt.severity)
		})
		t.Run(tt.name+"/clean", func(t *testing.T) {
			t.Parallel()
			assertNoIssue(t, DeepCheck(tt.clean), tt.code)
		})
	}
}

func TestIntraTypeDeepValidationSkipsCrossTypeWarnings(t *testing.T) {
	t.Parallel()
	paramRules := map[Type][]map[string]any{
		TypeParam: {
			{"resource": "api", "grade": 1, "paramIdx": 0, "count": 10},
		},
	}
	assertIssue(t, DeepCheck(paramRules), "PARAM_WITHOUT_FLOW", SeverityWarning)
	assertNoIssue(t, IntraTypeDeepCheck(paramRules), "PARAM_WITHOUT_FLOW")

	degradeRules := map[Type][]map[string]any{
		TypeFlow: {
			{"resource": "api", "grade": 1, "count": 10},
		},
		TypeDegrade: {
			{"resource": "api", "grade": 0, "count": 1, "timeWindow": 10},
		},
	}
	assertIssue(t, DeepCheck(degradeRules), "FLOW_DEGRADE_GRADE_MISMATCH", SeverityWarning)
	assertNoIssue(t, IntraTypeDeepCheck(map[Type][]map[string]any{TypeDegrade: degradeRules[TypeDegrade]}), "FLOW_DEGRADE_GRADE_MISMATCH")
}

func assertIssue(t *testing.T, issues []Issue, code string, severity IssueSeverity) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			if issue.Severity != severity {
				t.Fatalf("%s severity = %s, want %s; issues=%#v", code, issue.Severity, severity, issues)
			}
			return
		}
	}
	t.Fatalf("missing issue %s in %#v", code, issues)
}

func assertNoIssue(t *testing.T, issues []Issue, code string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			t.Fatalf("unexpected issue %s in %#v", code, issues)
		}
	}
}

func TestInferTypeFromPath(t *testing.T) {
	t.Parallel()
	ruleType, err := InferTypeFromPath("order-service-param-rules.json")
	if err != nil {
		t.Fatalf("InferTypeFromPath() error = %v", err)
	}
	if ruleType != TypeParam {
		t.Fatalf("type = %s, want param", ruleType)
	}
	if _, err := InferTypeFromPath("rules.json"); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}
