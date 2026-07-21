package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	etcdBackend "github.com/JiangHe12/cfgov-cli/internal/backend/etcd"
	k8sBackend "github.com/JiangHe12/cfgov-cli/internal/backend/k8s"
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

func TestRuleStoreEtcdBackendSupported(t *testing.T) {
	t.Parallel()
	backend, err := etcdBackend.New(etcdBackend.Options{Endpoints: "127.0.0.1:2379", Namespace: "ns"})
	if err != nil {
		t.Fatalf("etcd New() error = %v", err)
	}
	_, store, err := ensureRuleStore(backend)
	if err != nil {
		t.Fatalf("ensureRuleStore(etcd) error = %v", err)
	}
	if store == nil {
		t.Fatal("ensureRuleStore(etcd) returned nil store")
	}
}

func TestRuleStoreK8sBackendSupported(t *testing.T) {
	t.Parallel()
	backend, err := k8sBackend.New(k8sBackend.Options{Kubeconfig: writeTestKubeconfig(t), Context: "fake", Namespace: "default"})
	if err != nil {
		t.Fatalf("k8s New() error = %v", err)
	}
	_, store, err := ensureRuleStore(backend)
	if err != nil {
		t.Fatalf("ensureRuleStore(k8s) error = %v", err)
	}
	if store == nil {
		t.Fatal("ensureRuleStore(k8s) returned nil store")
	}
}

func TestK8sCapabilitiesSupportRules(t *testing.T) {
	t.Parallel()
	caps := currentBackendCapabilities(&cliFlags{Backend: "k8s"})
	if caps.Backend != "k8s" || !caps.SupportsRules {
		t.Fatalf("k8s capabilities = %#v, want SupportsRules=true", caps)
	}
	if !containsString(caps.ResourceTypes, "config") || !containsString(caps.ResourceTypes, "rule") || !containsString(caps.ResourceTypes, "flag") {
		t.Fatalf("k8s resourceTypes = %#v, want config/rule/flag", caps.ResourceTypes)
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

func writeTestKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig.yaml")
	data := []byte(`apiVersion: v1
kind: Config
clusters:
- name: fake
  cluster:
    server: http://127.0.0.1:6443
users:
- name: fake
  user:
    token: fake-token
contexts:
- name: fake
  context:
    cluster: fake
    user: fake
    namespace: default
current-context: fake
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func TestSelectedRuleTypes(t *testing.T) {
	t.Parallel()
	all, err := selectedRuleTypes("")
	if err != nil {
		t.Fatalf("selectedRuleTypes empty error = %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("all rule types = %#v", all)
	}
	one, err := selectedRuleTypes("flow")
	if err != nil {
		t.Fatalf("selectedRuleTypes flow error = %v", err)
	}
	if len(one) != 1 || one[0] != "flow" {
		t.Fatalf("one rule type = %#v", one)
	}
	if _, err := selectedRuleTypes("bogus"); err == nil {
		t.Fatal("selectedRuleTypes bogus expected error")
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
