package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestAuditPruneRequiresExactR3Authorization(t *testing.T) {
	tests := []struct {
		name    string
		auth    []string
		wantErr apperrors.ErrorCode
		deleted bool
	}{
		{
			name:    "missing ticket",
			auth:    []string{"--yes", "--allow-audit-prune"},
			wantErr: apperrors.CodeAuthorizationRequired,
		},
		{
			name:    "wrong allow flag",
			auth:    []string{"--yes", "--ticket", "TEST-1", "--allow-audit-repair"},
			wantErr: apperrors.CodeAuthorizationRequired,
		},
		{
			name:    "exact allow flag",
			auth:    []string{"--yes", "--ticket", "TEST-1", "--allow-audit-prune"},
			deleted: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			path, rotated := writeAuditPruneFixture(t, home)
			args := append([]string{"-o", "json"}, tt.auth...)
			args = append(args, "audit", "prune", "--path", path, "--keep-last", "0", "--confirm")
			_, err := runCommandForTestAtHome(t, home, args...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("authorized prune error = %v", err)
				}
			} else if got := apperrors.AsAppError(err).Code; got != tt.wantErr {
				t.Fatalf("error code = %q, want %q (err=%v)", got, tt.wantErr, err)
			}
			_, statErr := os.Stat(rotated)
			if tt.deleted {
				if !os.IsNotExist(statErr) {
					t.Fatalf("authorized prune kept %s: %v", rotated, statErr)
				}
			} else if statErr != nil {
				t.Fatalf("denied prune changed %s: %v", rotated, statErr)
			}
		})
	}
}

func TestAuditPruneIgnoresSpoofedOperatorAndContextOverride(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("guard", cfgovctx.Context{
		Base: corectx.Base{Roles: map[string]string{
			operator:        safety.RoleReader,
			"spoofed-admin": safety.RoleAdmin,
		}},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("override", cfgovctx.Context{
		Base:    corectx.Base{Roles: map[string]string{operator: safety.RoleAdmin}},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("guard"); err != nil {
		t.Fatal(err)
	}
	path, rotated := writeAuditPruneFixture(t, home)
	t.Setenv(cfgovOperatorEnv, "spoofed-admin")
	_, err = runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--context", "override",
		"--operator", "spoofed-admin",
		"--yes", "--ticket", "TEST-1", "--allow-audit-prune",
		"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("spoofed prune error = %v, want authorization required", err)
	}
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("spoofed prune changed evidence: %v", err)
	}
}

func TestAuditRepairRequiresExactR3Authorization(t *testing.T) {
	tests := []struct {
		name    string
		auth    []string
		wantErr apperrors.ErrorCode
		changed bool
	}{
		{
			name:    "missing ticket",
			auth:    []string{"--yes", "--allow-audit-repair"},
			wantErr: apperrors.CodeAuthorizationRequired,
		},
		{
			name:    "wrong allow flag",
			auth:    []string{"--yes", "--ticket", "TEST-1", "--allow-audit-prune"},
			wantErr: apperrors.CodeAuthorizationRequired,
		},
		{
			name:    "exact allow flag",
			auth:    []string{"--yes", "--ticket", "TEST-1", "--allow-audit-repair"},
			changed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "audit.jsonl")
			original := []byte("{malformed\n")
			writePrivateAuditFixture(t, path, original)
			args := append([]string{"-o", "json"}, tt.auth...)
			args = append(args, "audit", "verify", "--path", path, "--repair", "--confirm")
			_, err := runCommandForTestAtHome(t, home, args...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("authorized repair error = %v", err)
				}
			} else if got := apperrors.AsAppError(err).Code; got != tt.wantErr {
				t.Fatalf("error code = %q, want %q (err=%v)", got, tt.wantErr, err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tt.changed == bytes.Equal(after, original) {
				t.Fatalf("repair changed=%t, file=%q", !bytes.Equal(after, original), after)
			}
		})
	}
}

func TestAuditPruneSupportsAuthenticatedV2History(t *testing.T) {
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	path := filepath.Join(home, "audit.jsonl")
	for index := 0; index < 3; index++ {
		if err := coreaudit.AppendRecord(path, coreaudit.Event{
			Timestamp: time.Date(2026, 5, 24+index, 1, 2, 3, 0, time.UTC),
			EventType: coreaudit.EventType("test.v2"),
			Operator:  "tester",
			Status:    coreaudit.StatusSuccess,
		}, coreaudit.Options{MaxSizeBytes: 1}); err != nil {
			t.Fatal(err)
		}
	}
	rotated, err := coreaudit.RotatedFiles(path)
	if err != nil || len(rotated) == 0 {
		t.Fatalf("RotatedFiles() = %v, %v", rotated, err)
	}
	_, err = runCommandForTestAtHome(t, home,
		"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-prune",
		"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
	)
	if err != nil {
		t.Fatalf("authenticated prune error = %v", err)
	}
	remaining, err := coreaudit.RotatedFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("remaining rotations = %v, want none", remaining)
	}
	verified, err := coreaudit.Verify(path, coreaudit.VerifyOptions{})
	if err != nil || verified.HasProblems() {
		t.Fatalf("Verify() = %+v, %v", verified, err)
	}
}

func TestAuditRepairAuthenticatedHistoryFailsWithoutChangingTarget(t *testing.T) {
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	path := filepath.Join(home, "audit.jsonl")
	if err := coreaudit.AppendRecord(path, coreaudit.Event{
		Timestamp: time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC),
		EventType: coreaudit.EventType("test.v2"),
		Operator:  "tester",
		Status:    coreaudit.StatusSuccess,
	}, coreaudit.Options{}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runCommandForTestAtHome(t, home,
		"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-repair",
		"audit", "verify", "--path", path, "--repair", "--confirm",
	)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("authenticated repair error = %v, want VALIDATION_FAILED", err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, before) {
		t.Fatalf("authenticated repair changed target: %q, %v", after, readErr)
	}
	if _, statErr := os.Stat(auditControlPath(path)); statErr != nil {
		t.Fatalf("repair intent was not persisted separately: %v", statErr)
	}
}

func TestAuditPruneRejectsInvalidHistoryWithoutDeleting(t *testing.T) {
	home := t.TempDir()
	path, rotated := writeAuditPruneFixture(t, home)
	invalid := []byte(`{"timestamp":"2026-05-24T01:02:03Z","eventType":"x","eventType":"y","operator":"tester"}` + "\n")
	writePrivateAuditFixture(t, rotated, invalid)
	_, err := runCommandForTestAtHome(t, home,
		"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-prune",
		"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
	)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("invalid history prune error = %v, want VALIDATION_FAILED", err)
	}
	if after, readErr := os.ReadFile(rotated); readErr != nil || !bytes.Equal(after, invalid) {
		t.Fatalf("invalid history was changed: %q, %v", after, readErr)
	}
}

func TestAuditPruneLockAndCandidateConsistency(t *testing.T) {
	t.Run("preview does not wait for lock", func(t *testing.T) {
		home := t.TempDir()
		path, rotated := writeAuditPruneFixture(t, home)
		held := lockfile.New(path)
		if err := held.Acquire(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Release() })
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
		out, err := runCommandForTestAtHome(t, home,
			"-o", "json", "audit", "prune", "--path", path, "--keep-last", "0",
		)
		if err != nil || !strings.Contains(out, filepath.Base(rotated)) {
			t.Fatalf("locked preview = (%s, %v), want immediate candidate list", out, err)
		}
	})

	t.Run("confirmed prune waits for lock", func(t *testing.T) {
		home := t.TempDir()
		path, rotated := writeAuditPruneFixture(t, home)
		held := lockfile.New(path)
		if err := held.Acquire(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Release() })
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
		_, err := runCommandForTestAtHome(t, home,
			"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-prune",
			"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
		)
		if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
			t.Fatalf("confirmed prune lock error = %v, want LOCAL_IO_ERROR", err)
		}
		if _, statErr := os.Stat(rotated); statErr != nil {
			t.Fatalf("lock timeout changed evidence: %v", statErr)
		}
	})

	t.Run("changed prune candidates conflict", func(t *testing.T) {
		home := t.TempDir()
		path, first := writeAuditPruneFixture(t, home)
		opts := auditPruneOptions{keepLast: 0}
		preview, err := auditPruneCandidates(path, opts)
		if err != nil {
			t.Fatal(err)
		}
		second := path + ".20260525-010203.log"
		writePrivateAuditFixture(t, second, []byte("{}\n"))
		_, err = coreaudit.PruneRotatedFiles(path, preview, coreaudit.PruneOptions{Confirm: true, ExpectedRotatedFiles: []string{first}})
		if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
			t.Fatalf("candidate change error = %v, want CONFLICT", err)
		}
		for _, candidate := range []string{first, second} {
			if _, statErr := os.Stat(candidate); statErr != nil {
				t.Fatalf("candidate conflict changed %s: %v", candidate, statErr)
			}
		}
	})

	t.Run("outcome audit appends after releasing lock without raw paths", func(t *testing.T) {
		home := t.TempDir()
		path, rotated := writeAuditPruneFixture(t, home)
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
		_, err := runCommandForTestAtHome(t, home,
			"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-prune",
			"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
		)
		if err != nil {
			t.Fatalf("confirmed prune deadlocked its success audit append: %v", err)
		}
		if _, statErr := os.Stat(rotated); !os.IsNotExist(statErr) {
			t.Fatalf("confirmed prune kept %s: %v", rotated, statErr)
		}
		control, readErr := coreaudit.Query(auditControlPath(path), coreaudit.Filter{})
		if readErr != nil {
			t.Fatal(readErr)
		}
		foundOutcome := false
		for _, event := range control.Events {
			if event.EventType == coreaudit.EventType("audit.prune.outcome") {
				foundOutcome = true
			}
			if strings.Contains(event.Target.Resource, rotated) || strings.Contains(event.Diff, rotated) {
				t.Fatalf("control audit leaked deleted path: %+v", event)
			}
		}
		if !foundOutcome {
			t.Fatalf("control audit lacks prune outcome: %+v", control.Events)
		}
	})
}

func TestAuditRepairLockAndCandidateConsistency(t *testing.T) {
	t.Run("confirmed repair waits for lock", func(t *testing.T) {
		home := t.TempDir()
		path := filepath.Join(home, "audit.jsonl")
		original := []byte("{malformed\n")
		writePrivateAuditFixture(t, path, original)
		held := lockfile.New(path)
		if err := held.Acquire(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Release() })
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
		_, err := runCommandForTestAtHome(t, home,
			"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-repair",
			"audit", "verify", "--path", path, "--repair", "--confirm",
		)
		if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
			t.Fatalf("confirmed repair lock error = %v, want LOCAL_IO_ERROR", err)
		}
		after, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(after, original) {
			t.Fatalf("repair lock timeout changed evidence: %q, %v", after, readErr)
		}
	})

	t.Run("core verify owns its lock without self-deadlock", func(t *testing.T) {
		home := t.TempDir()
		path := filepath.Join(home, "audit.jsonl")
		writePrivateAuditFixture(t, path, []byte("{malformed\n"))
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
		_, err := runCommandForTestAtHome(t, home,
			"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-repair",
			"audit", "verify", "--path", path, "--repair", "--confirm",
		)
		if err != nil {
			t.Fatalf("legacy repair with core-owned lock error = %v", err)
		}
	})

	t.Run("changed repair candidates conflict", func(t *testing.T) {
		home := t.TempDir()
		path, _ := writeAuditPruneFixture(t, home)
		original := []byte("{malformed\n")
		writePrivateAuditFixture(t, path, original)
		preview, err := strictAuditRotatedFiles(path)
		if err != nil {
			t.Fatal(err)
		}
		second := path + ".20260525-010203.log"
		writePrivateAuditFixture(t, second, []byte("{}\n"))
		_, err = repairAudit(path, preview, coreaudit.VerifyOptions{Repair: true, Confirm: true})
		if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
			t.Fatalf("repair candidate change error = %v, want CONFLICT", err)
		}
		after, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(after, original) {
			t.Fatalf("repair conflict changed active evidence: %q, %v", after, readErr)
		}
	})
}

func TestAuditPrunePlanListsV2CandidateWithoutAuthorization(t *testing.T) {
	home := t.TempDir()
	path, rotated := writeAuditPruneFixture(t, home)
	envelope := []byte(`{"apiVersion":"opskit-core.io/audit/v2","kind":"AuditEnvelope"}` + "\n")
	writePrivateAuditFixture(t, rotated, envelope)
	out, err := runCommandForTestAtHome(t, home,
		"--plan", "-o", "json",
		"audit", "prune", "--path", path, "--keep-last", "0", "--confirm",
	)
	if err != nil {
		t.Fatalf("v2 prune plan error = %v; out=%s", err, out)
	}
	if !strings.Contains(out, filepath.Base(rotated)) || !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("v2 prune plan omitted candidate: %s", out)
	}
	if after, err := os.ReadFile(rotated); err != nil || !bytes.Equal(after, envelope) {
		t.Fatalf("v2 prune plan changed candidate: %q, %v", after, err)
	}
}

func TestAuditPruneCandidateOrderIsChronological(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "audit.log")
	writePrivateAuditFixture(t, path, nil)
	first := path + ".20260101-000000.log"
	second := path + ".20260201-000000.log"
	third := path + ".20260301-000000.log"
	for _, filePath := range []string{third, first, second} {
		writePrivateAuditFixture(t, filePath, nil)
	}
	got, err := auditPruneCandidates(path, auditPruneOptions{keepLast: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{first, second}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want chronological order %v", got, want)
	}
}

func TestAuditPruneCandidatesUseNumericCollisionOrder(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "audit.log")
	writePrivateAuditFixture(t, path, nil)
	for _, suffix := range []string{".20260101-000000.2.log", ".20260101-000000.10.log", ".20260101-000000.1.log"} {
		writePrivateAuditFixture(t, path+suffix, nil)
	}
	got, err := auditPruneCandidates(path, auditPruneOptions{keepLast: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		path + ".20260101-000000.1.log",
		path + ".20260101-000000.2.log",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want numeric collision order %v", got, want)
	}
}

func TestAuditPruneRejectsUnexpectedRotationFilename(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "audit.log")
	writePrivateAuditFixture(t, path, nil)
	unexpected := path + ".20260101-000000.backup.log"
	writePrivateAuditFixture(t, unexpected, nil)
	if _, err := auditPruneCandidates(path, auditPruneOptions{keepLast: 0}); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("unexpected rotation error = %v, want VALIDATION_FAILED", err)
	}
}

func writeAuditPruneFixture(t *testing.T, home string) (string, string) {
	t.Helper()
	prepareMutationAuditTestParent(t, home)
	path := filepath.Join(home, "audit.jsonl")
	writePrivateAuditFixture(t, path, []byte(`{"timestamp":"2026-05-26T01:02:03Z","eventType":"test.active","operator":"tester"}`+"\n"))
	rotated := path + ".20260524-010203.log"
	writePrivateAuditFixture(t, rotated, []byte(`{"timestamp":"2026-05-24T01:02:03Z","eventType":"test.rotated","operator":"tester"}`+"\n"))
	return path, rotated
}
