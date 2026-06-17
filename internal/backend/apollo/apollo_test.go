package apollo

import (
	"context"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestNewValidatesApolloPartsFailClosed(t *testing.T) {
	t.Parallel()
	_, err := New(Options{Server: "http://apollo.example", AppID: "../bad"})
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("app id error = %v, want validation failed", err)
	}
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov", Namespace: "app/config"})
	if err == nil {
		t.Fatalf("backend = %#v, want namespace validation error", backend)
	}
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("namespace error = %v, want validation failed", err)
	}
}

func TestCoordinateMappingDefaultsNamespace(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov", Env: "DEV", Cluster: "default", Namespace: "SENTINEL"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ns, key, err := backend.resolve(cfgov.Coordinate{Key: "order-service-flow-rules"})
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if ns != "SENTINEL" || key != "order-service-flow-rules" {
		t.Fatalf("mapping = %s/%s", ns, key)
	}
	ns, key, err = backend.resolve(cfgov.Coordinate{Namespace: "application", Key: "featureFlag"})
	if err != nil {
		t.Fatalf("resolve override error = %v", err)
	}
	if ns != "application" || key != "featureFlag" {
		t.Fatalf("override mapping = %s/%s", ns, key)
	}
}

func TestResolveRejectsUnsafeKey(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, _, err = backend.resolve(cfgov.Coordinate{Key: "../secret"})
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("key error = %v, want validation failed", err)
	}
}

func TestValidateKeyRejectsUnsafeKeyWithoutNacosMessage(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = backend.ValidateKey("../..")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("key error = %v, want validation failed", err)
	}
	if strings.Contains(err.Error(), "group/dataId") {
		t.Fatalf("apollo key error leaked Nacos wording: %v", err)
	}
}

func TestRedactURLHidesSensitiveQuery(t *testing.T) {
	t.Parallel()
	out := redactURL("http://apollo.example/openapi/v1/items?token=secret&accessToken=abc&key=plain")
	if strings.Contains(out, "secret") || strings.Contains(out, "abc") {
		t.Fatalf("redacted URL leaked secret: %s", out)
	}
	if !strings.Contains(out, "key=plain") {
		t.Fatalf("redacted URL lost non-sensitive query: %s", out)
	}
}

func TestCapabilitiesAndUnsupportedMethods(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	caps := backend.Capabilities()
	if caps.Backend != "apollo" || caps.SupportsHistory || caps.SupportsWatch || !caps.SupportsRules {
		t.Fatalf("capabilities = %#v", caps)
	}
	if _, _, err := backend.History(context.Background(), cfgov.Coordinate{}, cfgov.HistoryOptions{}); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("history error = %v, want not implemented", err)
	}
	if _, err := backend.Watch(context.Background(), cfgov.Coordinate{}, "", cfgov.WatchOptions{}); apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("watch error = %v, want not implemented", err)
	}
}

func TestRuleCoordinateDefaultsToSentinelNamespace(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	coord, err := backend.RuleCoordinate("order-service", "flow")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	if coord.Namespace != "SENTINEL" || coord.Key != "order-service-flow-rules" {
		t.Fatalf("coord = %#v", coord)
	}
}

func TestRuleCoordinateUsesOverrideNamespace(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov", RuleNamespace: "RULES"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	coord, err := backend.RuleCoordinate("order-service", "param")
	if err != nil {
		t.Fatalf("RuleCoordinate() error = %v", err)
	}
	if coord.Namespace != "RULES" || coord.Key != "order-service-param-rules" {
		t.Fatalf("coord = %#v", coord)
	}
}

func TestRuleCoordinateRejectsInjectedApp(t *testing.T) {
	t.Parallel()
	backend, err := New(Options{Server: "http://apollo.example", AppID: "cfgov"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = backend.RuleCoordinate("../prod", "flow")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}
