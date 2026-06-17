package rule

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
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
