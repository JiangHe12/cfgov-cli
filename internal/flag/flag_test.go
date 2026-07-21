package flag

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestNacosKeyMatchesFeatureFlagConvention(t *testing.T) {
	t.Parallel()
	key, err := NacosKey("order-service")
	if err != nil {
		t.Fatalf("NacosKey() error = %v", err)
	}
	if key != "FEATURE_FLAG_GROUP/order-service-flags" {
		t.Fatalf("key = %q", key)
	}
}

func TestNacosKeyRejectsInjectedApp(t *testing.T) {
	t.Parallel()
	tests := []string{"../prod", "bad/app", "bad\\app", "bad\napp", "", ".", ".."}
	for _, app := range tests {
		t.Run(app, func(t *testing.T) {
			t.Parallel()
			if _, err := NacosKey(app); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDecodeSetFailClosed(t *testing.T) {
	t.Parallel()
	valid := []byte(`[{"key":"checkout","enabled":true,"description":"new checkout","defaultVariant":"on","variants":[{"name":"on","value":"true"}],"rules":[{"variant":"on","rolloutPercent":50,"segment":"beta"}]}]`)
	flags, err := DecodeSet(valid)
	if err != nil {
		t.Fatalf("DecodeSet() error = %v", err)
	}
	if len(flags) != 1 || Key(flags[0]) != "checkout" {
		t.Fatalf("flags = %#v", flags)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "object", data: []byte(`{"key":"checkout"}`)},
		{name: "empty key", data: []byte(`[{"key":" "}]`)},
		{name: "unknown top field", data: []byte(`[{"key":"checkout","bogus":true}]`)},
		{name: "unknown nested field", data: []byte(`[{"key":"checkout","variants":[{"name":"on","value":"true","bogus":true}]}]`)},
		{name: "garbage", data: []byte(`not-json`)},
		{name: "blank", data: []byte(` `)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeSet(tt.data); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
				t.Fatalf("error = %v, want validation failed", err)
			}
		})
	}
}

func TestDeepCheck(t *testing.T) {
	t.Parallel()
	flags := []FeatureFlag{
		{Key: "checkout", Enabled: true, DefaultVariant: "missing", Variants: []Variant{{Name: "on", Value: "true"}}, Rules: []RolloutRule{{Variant: "ghost", RolloutPercent: 101}}},
		{Key: "checkout"},
		{Key: "no-variants", Enabled: true},
	}
	assertIssue(t, DeepCheck(flags), "DUPLICATE_KEY", SeverityError)
	assertIssue(t, DeepCheck(flags), "ROLLOUT_PERCENT_OUT_OF_RANGE", SeverityError)
	assertIssue(t, DeepCheck(flags), "DEFAULT_VARIANT_MISSING", SeverityError)
	assertIssue(t, DeepCheck(flags), "RULE_VARIANT_MISSING", SeverityError)
	assertIssue(t, DeepCheck(flags), "ENABLED_WITHOUT_VARIANTS", SeverityWarning)
	if !HasError(DeepCheck(flags)) {
		t.Fatal("HasError() = false, want true")
	}
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
