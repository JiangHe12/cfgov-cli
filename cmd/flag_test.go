package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
)

type fakeFlagBackend struct {
	fakeConfigBackend
	caps cfgov.Capabilities
}

func (f fakeFlagBackend) Capabilities() cfgov.Capabilities { return f.caps }

func (f fakeFlagBackend) FlagCoordinate(app string) (cfgov.Coordinate, error) {
	if app == "" || app == "bad/app" {
		return cfgov.Coordinate{}, apperrors.New(apperrors.CodeValidationFailed, "invalid app", nil)
	}
	return cfgov.Coordinate{Namespace: f.namespace, Key: app + "-flags"}, nil
}

func TestFlagStoreUnsupportedBackendFailClosed(t *testing.T) {
	t.Parallel()
	backend := fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}}
	if _, ok := any(backend).(cfgov.FlagStore); ok {
		t.Fatal("fake backend unexpectedly implements FlagStore")
	}
	_, _, err := ensureFlagStore(backend)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
}

func TestFlagStoreRequiresCapabilityGate(t *testing.T) {
	t.Parallel()
	backend := fakeFlagBackend{
		fakeConfigBackend: fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}},
		caps:              cfgov.Capabilities{SupportsFlags: false},
	}
	_, _, err := ensureFlagStore(backend)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
	backend.caps.SupportsFlags = true
	_, store, err := ensureFlagStore(backend)
	if err != nil {
		t.Fatalf("ensureFlagStore() error = %v", err)
	}
	if store == nil {
		t.Fatal("ensureFlagStore() returned nil store")
	}
}

func TestNacosCapabilitiesSupportFlags(t *testing.T) {
	t.Parallel()
	caps := currentBackendCapabilities(&cliFlags{Backend: "nacos"})
	if caps.Backend != "nacos" || !caps.SupportsFlags {
		t.Fatalf("nacos capabilities = %#v, want SupportsFlags=true", caps)
	}
	if !containsString(caps.ResourceTypes, "flag") {
		t.Fatalf("nacos resourceTypes = %#v, want flag", caps.ResourceTypes)
	}
}

func TestFallbackBackendsSupportFlags(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"apollo", "etcd", "k8s"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			caps := currentBackendCapabilities(&cliFlags{Backend: name})
			if !caps.SupportsFlags || !containsString(caps.ResourceTypes, "flag") {
				t.Fatalf("%s capabilities = %#v, want flag support", name, caps)
			}
		})
	}
}

func TestFlagCommandsExposeVerbsAndFlags(t *testing.T) {
	t.Parallel()
	root := newRootCmdWith(newDefaultFlags())
	flagCmd, _, err := root.Find([]string{"flag"})
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"list", "get", "export", "diff", "validate"} {
		cmd, _, err := flagCmd.Find([]string{verb})
		if err != nil {
			t.Fatalf("flag %s missing: %v", verb, err)
		}
		switch verb {
		case "list", "get", "export", "diff":
			if cmd.Flags().Lookup("app") == nil {
				t.Fatalf("flag %s missing --app", verb)
			}
		case "validate":
			if cmd.Flags().Lookup("file") == nil || cmd.Flags().Lookup("dir") == nil || cmd.Flags().Lookup("deep") == nil {
				t.Fatalf("flag validate missing expected flags")
			}
		}
	}
	for _, verb := range []string{"create", "update", "delete", "import", "rollback"} {
		cmd, _, err := flagCmd.Find([]string{verb})
		if err != nil {
			t.Fatalf("flag %s missing: %v", verb, err)
		}
		if cmd.Flags().Lookup("expected-revision") == nil {
			t.Fatalf("flag %s missing --expected-revision", verb)
		}
		if verb != "rollback" && cmd.Flags().Lookup("app") == nil {
			t.Fatalf("flag %s missing --app", verb)
		}
	}
}

func TestFilterFlagSetByKey(t *testing.T) {
	t.Parallel()
	result := flagSetResult{
		Flags: featureFlagsForTest([]flagFeatureForTest{
			{Key: "alpha"},
			{Key: "beta"},
		}),
	}
	filtered := filterFlagSetByKey(result, "beta")
	if filtered.Count != 1 || len(filtered.Flags) != 1 || filtered.Flags[0].Key != "beta" {
		t.Fatalf("filtered = %#v", filtered)
	}
}

type flagFeatureForTest struct {
	Key string
}

func featureFlagsForTest(items []flagFeatureForTest) []flag.FeatureFlag {
	out := make([]flag.FeatureFlag, 0, len(items))
	for _, item := range items {
		out = append(out, flag.FeatureFlag{Key: item.Key})
	}
	return out
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
