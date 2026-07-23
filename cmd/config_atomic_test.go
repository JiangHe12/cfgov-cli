package cmd

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestConfigPushCreateOnlyUsesAtomicAbsencePrecondition(t *testing.T) {
	backend := &recordingConfigBackend{
		fakeConfigBackend: fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}},
		supportsCAS:       true,
	}
	f, records, configPath := atomicConfigCommandFlags(t, backend)
	out, err := executeReadAuditCommand(
		t,
		f,
		"--config", configPath,
		"--backend", "fake",
		"--server", "https://backend.example.invalid",
		"--namespace", "ns",
		"--yes",
		"--no-backup",
		"-o", "json",
		"config", "push",
		"--key", "app.yaml",
		"--content", "enabled: true",
		"--type", "yaml",
		"--create-only",
	)
	if err != nil {
		t.Fatalf("config push error = %v; out=%s", err, out)
	}
	if len(backend.puts) != 1 {
		t.Fatalf("puts = %#v, want one", backend.puts)
	}
	if !backend.puts[0].RequireAbsent || backend.puts[0].ExpectedRevision != "" {
		t.Fatalf("put preconditions = %#v, want RequireAbsent only", backend.puts[0])
	}
	if !hasMutationAction(*records, "config.write") {
		t.Fatalf("mutation records = %#v, want config.write intent/outcome", *records)
	}
}

func TestConfigPushCreateOnlyUnsupportedCASStopsBeforeMutationIntent(t *testing.T) {
	backend := &recordingConfigBackend{
		fakeConfigBackend: fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{}},
		supportsCAS:       false,
	}
	f, records, configPath := atomicConfigCommandFlags(t, backend)
	_, err := executeReadAuditCommand(
		t,
		f,
		"--config", configPath,
		"--backend", "fake",
		"--server", "https://backend.example.invalid",
		"--namespace", "ns",
		"--yes",
		"--no-backup",
		"config", "push",
		"--key", "app.yaml",
		"--content", "enabled: true",
		"--type", "yaml",
		"--create-only",
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNotImplemented {
		t.Fatalf("config push code = %s, want %s (err=%v)", got, apperrors.CodeNotImplemented, err)
	}
	if len(backend.puts) != 0 {
		t.Fatalf("puts = %#v, want none", backend.puts)
	}
	if hasMutationAction(*records, "config.write") {
		t.Fatalf("mutation records = %#v, unsupported CAS must fail before mutation intent", *records)
	}
}

func TestConfigDeleteAuthorizationAndIntentPrecedeBackendBuild(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		append     func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error)
		wantCode   apperrors.ErrorCode
		wantOutput bool
	}{
		{
			name:     "authorization denied",
			args:     []string{"--ticket", "TEST-1"},
			wantCode: apperrors.CodeAuthorizationRequired,
		},
		{
			name: "mutation intent failure",
			args: []string{"--yes", "--ticket", "TEST-1"},
			append: func(string, mutationAuditRecord, audit.Options) (audit.AppendResult, error) {
				return audit.AppendResult{State: audit.AppendCommitNotCommitted}, errors.New("injected audit failure")
			},
			wantCode: apperrors.CodeLocalIOError,
		},
		{
			name:       "plan",
			args:       []string{"--plan", "-o", "json"},
			wantOutput: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &recordingConfigBackend{
				fakeConfigBackend: fakeConfigBackend{namespace: "ns", blobs: map[string][]byte{"app.yaml": []byte("old")}},
				supportsCAS:       true,
			}
			f, _, configPath := atomicConfigCommandFlags(t, backend)
			buildCalls := 0
			f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
				buildCalls++
				return backend, nil
			}
			if test.append != nil {
				f.mutationAudit.appendRecord = test.append
			}
			args := []string{
				"--config", configPath,
				"--backend", "fake",
				"--server", "https://backend.example.invalid",
				"--namespace", "ns",
				"--no-backup",
			}
			args = append(args, test.args...)
			args = append(args, "config", "delete", "--key", "app.yaml")
			out, err := executeReadAuditCommand(t, f, args...)
			if test.wantOutput {
				if err != nil || out == "" {
					t.Fatalf("config delete plan error = %v; out=%s", err, out)
				}
			} else if got := apperrors.AsAppError(err).Code; got != test.wantCode {
				t.Fatalf("config delete code = %s, want %s (err=%v)", got, test.wantCode, err)
			}
			if buildCalls != 0 {
				t.Fatalf("backend builds = %d, want zero before authorization and durable intent", buildCalls)
			}
			if len(backend.puts) != 0 {
				t.Fatalf("backend writes = %#v, want none", backend.puts)
			}
		})
	}
}

func atomicConfigCommandFlags(t *testing.T, backend cfgov.Backend) (*cliFlags, *[]mutationAuditRecord, string) {
	t.Helper()
	root := t.TempDir()
	prepareMutationAuditTestParent(t, root)
	configPath := filepath.Join(root, "missing-config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	records := &[]mutationAuditRecord{}
	f := mutationAuditTestFlags()
	f.mutationAuditPath = filepath.Join(root, "audit.log")
	f.backendBuilder = func(*cliFlags, cfgovctx.Context, string) (cfgov.Backend, error) {
		return backend, nil
	}
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			*records = append(*records, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		appendOrdinary: func(string, any, audit.Options) error { return nil },
		now:            func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random:         bytes.NewReader(bytes.Repeat([]byte{0x71}, 128)),
	}
	return f, records, configPath
}

func hasMutationAction(records []mutationAuditRecord, action string) bool {
	for _, record := range records {
		if record.Action == action {
			return true
		}
	}
	return false
}
