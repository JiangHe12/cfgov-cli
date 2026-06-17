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
