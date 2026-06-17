package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func TestRuleStoreUnsupportedBackendFailClosed(t *testing.T) {
	t.Parallel()
	backend := fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}
	if _, ok := any(backend).(cfgov.RuleStore); ok {
		t.Fatal("fake backend unexpectedly implements RuleStore")
	}
	_, _, err := ensureRuleStore(backend)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
}

func TestRuleGetExposesResourceFlagOnly(t *testing.T) {
	t.Parallel()
	root := newRootCmdWith(newDefaultFlags())
	ruleCmd, _, err := root.Find([]string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	getCmd, _, err := ruleCmd.Find([]string{"get"})
	if err != nil {
		t.Fatal(err)
	}
	if getCmd.Flags().Lookup("resource") == nil {
		t.Fatal("rule get missing --resource flag")
	}
	listCmd, _, err := ruleCmd.Find([]string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	if listCmd.Flags().Lookup("resource") != nil {
		t.Fatal("rule list must not expose --resource flag")
	}
}

func TestFilterRuleSetByResource(t *testing.T) {
	t.Parallel()
	result := ruleSetResult{
		Rules: []map[string]any{
			{"resource": "alpha", "count": 1},
			{"resource": "beta", "count": 2},
			{"count": 3},
		},
	}
	filtered := filterRuleSetByResource(result, "beta")
	if filtered.Count != 1 {
		t.Fatalf("count = %d, want 1", filtered.Count)
	}
	if len(filtered.Rules) != 1 || ruleValueString(filtered.Rules[0]["resource"]) != "beta" {
		t.Fatalf("filtered rules = %#v", filtered.Rules)
	}
}
