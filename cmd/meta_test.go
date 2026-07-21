package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionPlain(t *testing.T) {
	SetVersionInfo("v0.0.0-test", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	out, err := runCommandForTest(t, "-o", "plain", "version")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if want := "v0.0.0-test\n"; out != want {
		t.Fatalf("unexpected version plain: %q", out)
	}
}

func TestCapabilitiesPlain(t *testing.T) {
	out, err := runCommandForTest(t, "-o", "plain", "capabilities")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	want := strings.Join(capabilityPlainCommands(), "\n") + "\n"
	if out != want {
		t.Fatalf("unexpected capabilities plain:\n%s", out)
	}
	if strings.Contains(out, "{") || strings.Contains(out, "\t") {
		t.Fatalf("capabilities plain should be a command list, got %q", out)
	}
}

func TestCapabilitiesJSONFamilySchema(t *testing.T) {
	data := buildCapabilities(newDefaultFlags(), currentBackendCapabilities(&cliFlags{Backend: "nacos"}))
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal(capabilities) error = %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("capabilities output is not JSON: %v\n%s", err, string(payload))
	}
	var env struct {
		Supported struct {
			ContextAPIVersions []string        `json:"contextApiVersions"`
			AuditAPIVersions   []string        `json:"auditApiVersions"`
			Commands           json.RawMessage `json:"commands"`
		} `json:"supported"`
		Domain struct {
			Backend       json.RawMessage `json:"backend"`
			Limits        json.RawMessage `json:"limits"`
			Features      json.RawMessage `json:"features"`
			OutputFormats []string        `json:"outputFormats"`
			ErrorCodes    []string        `json:"errorCodes"`
			ExitCodes     []int           `json:"exitCodes"`
			Environment   []string        `json:"environmentVariables"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("Unmarshal(capabilities) error = %v\n%s", err, string(payload))
	}
	if strings.Join(env.Supported.ContextAPIVersions, ",") != "cfgov-cli.io/context/v1" {
		t.Fatalf("context API versions = %#v", env.Supported.ContextAPIVersions)
	}
	if strings.Join(env.Supported.AuditAPIVersions, ",") != auditAPIVersion+","+mutationAuditAPIVersion {
		t.Fatalf("audit API versions = %#v", env.Supported.AuditAPIVersions)
	}
	if len(env.Supported.Commands) != 0 || top["backend"] != nil || top["limits"] != nil || top["features"] != nil {
		t.Fatalf("domain fields leaked outside domain: %s", string(payload))
	}
	if len(env.Domain.Backend) == 0 || len(env.Domain.Limits) == 0 || len(env.Domain.Features) == 0 {
		t.Fatalf("domain missing backend/limits/features: %+v", env.Domain)
	}
	if strings.Join(env.Domain.OutputFormats, ",") != "table,json,plain" || len(env.Domain.ErrorCodes) == 0 || len(env.Domain.ExitCodes) == 0 {
		t.Fatalf("domain metadata incomplete: %+v", env.Domain)
	}
	environment := "," + strings.Join(env.Domain.Environment, ",") + ","
	for _, name := range []string{"CFGOV_AUDIT_PRIVATE_KEY", "CFGOV_CREDENTIAL_PASSPHRASE"} {
		if !strings.Contains(environment, ","+name+",") {
			t.Fatalf("environmentVariables missing %s: %#v", name, env.Domain.Environment)
		}
	}
	for _, name := range []string{"CFGOV_OPERATOR", "CFGOV_CLI_AUDIT_PRIVATE_KEY", "CFGOV_CLI_CREDENTIAL_PASSPHRASE", "CFGOV_CLI_OPERATOR"} {
		if strings.Contains(environment, ","+name+",") {
			t.Fatalf("environmentVariables should not advertise deprecated %s: %#v", name, env.Domain.Environment)
		}
	}
}

func TestGlobalFlagsHelp(t *testing.T) {
	out, err := runCommandForTest(t, "--help")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	for _, flag := range []string{"--debug", "--trace", "--no-color", "--allow-production-reconcile"} {
		if !strings.Contains(out, flag) {
			t.Fatalf("help missing %s:\n%s", flag, out)
		}
	}
}

func TestNoOpGlobalFlagsAndCapabilitiesAreNotAdvertised(t *testing.T) {
	root := newRootCmdWith(newDefaultFlags())
	for _, name := range []string{"concurrency", "backup-keep"} {
		if flag := root.PersistentFlags().Lookup(name); flag != nil {
			t.Fatalf("global --%s still advertised without an implementation", name)
		}
	}
	data := buildCapabilities(newDefaultFlags(), currentBackendCapabilities(&cliFlags{Backend: "nacos"}))
	if data.Domain.Limits.DefaultConcurrency != 1 || data.Domain.Limits.MaxConcurrency != 1 {
		t.Fatalf("concurrency limits = %#v, want fixed single-threaded execution", data.Domain.Limits)
	}
	payload, err := json.Marshal(data.Domain.Limits)
	if err != nil {
		t.Fatalf("Marshal(limits) error = %v", err)
	}
	if strings.Contains(string(payload), "backupKeep") {
		t.Fatalf("capabilities still advertise unimplemented backup retention: %s", payload)
	}
}

func TestCapabilitiesDeclareProtectedReconcileAllowFlag(t *testing.T) {
	data := buildCapabilities(newDefaultFlags(), currentBackendCapabilities(&cliFlags{Backend: "nacos"}))
	for _, command := range data.Domain.Commands {
		if command.Noun == "config" && command.Verb == "reconcile(no prune, protected ctx)" {
			if command.Risk != "R3" || command.AllowFlag != "allow-production-reconcile" {
				t.Fatalf("protected reconcile capability = %#v", command)
			}
			return
		}
	}
	t.Fatal("protected reconcile capability is missing")
}

func TestGlobalFlagsWithVersion(t *testing.T) {
	SetVersionInfo("v0.0.0-test", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	out, err := runCommandForTest(t, "--debug", "--trace", "--no-color", "-o", "plain", "version")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if want := "v0.0.0-test\n"; out != want {
		t.Fatalf("version plain = %q, want %q", out, want)
	}
}
