package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/cfgov-cli/internal/backup"
)

func TestBackupCleanRequestRequiresSelector(t *testing.T) {
	t.Parallel()
	_, err := backupCleanRequest(backupCleanOptions{keepLast: -1})
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestBackupCleanRequestRejectsAmbiguousSelectors(t *testing.T) {
	t.Parallel()
	_, err := backupCleanRequest(backupCleanOptions{before: "30d", keepLast: 1})
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestBackupCleanRequestKeepLast(t *testing.T) {
	t.Parallel()
	opts, err := backupCleanRequest(backupCleanOptions{keepLast: 2})
	if err != nil {
		t.Fatalf("backupCleanRequest() error = %v", err)
	}
	if opts.KeepLast == nil || *opts.KeepLast != 2 {
		t.Fatalf("KeepLast = %#v, want 2", opts.KeepLast)
	}
}

func TestBackupCleanPlanDoesNotDelete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".cfgov-cli", "backups")
	written, err := backup.Write(root, backup.Request{
		Context:   "dev",
		Namespace: "public",
		Group:     "DEFAULT_GROUP",
		DataID:    "app.yaml",
		Content:   []byte("enabled: true\n"),
		Operator:  "tester",
	})
	if err != nil {
		t.Fatalf("backup.Write() error = %v", err)
	}

	f := newDefaultFlags()
	f.Plan = true
	f.Output = "plain"
	var runErr error
	_ = captureStdout(t, func() {
		runErr = runBackupClean(f, backupCleanOptions{keepLast: 0, confirm: true})
	})
	if runErr != nil {
		t.Fatalf("runBackupClean() error = %v", runErr)
	}
	if _, err := os.Stat(written.Path); err != nil {
		t.Fatalf("planned backup clean removed %s: %v", written.Path, err)
	}
}

func TestBackupCleanRequiresFixedR3Authorization(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*cliFlags)
	}{
		{name: "missing yes", prepare: func(f *cliFlags) {
			f.Ticket = "TEST-1"
			f.AllowBackupClean = true
		}},
		{name: "missing ticket", prepare: func(f *cliFlags) {
			f.Yes = true
			f.AllowBackupClean = true
		}},
		{name: "missing allow", prepare: func(f *cliFlags) {
			f.Yes = true
			f.Ticket = "TEST-1"
			f.AllowAuditPrune = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			prepareMutationAuditTestParent(t, home)
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			root := filepath.Join(home, ".cfgov-cli", "backups")
			written, err := backup.Write(root, backup.Request{
				Context: "dev", DataID: "app.yaml", Content: []byte("enabled: true\n"), Operator: "tester",
			})
			if err != nil {
				t.Fatal(err)
			}
			f := mutationAuditTestFlags()
			f.NonInter = true
			tt.prepare(f)
			err = runBackupClean(f, backupCleanOptions{keepLast: 0, confirm: true})
			if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
				t.Fatalf("runBackupClean() error = %v, want authorization required", err)
			}
			if _, statErr := os.Stat(written.Path); statErr != nil {
				t.Fatalf("unauthorized cleanup changed backup: %v", statErr)
			}
		})
	}
}

func TestBackupCleanPartialFailureAuditsCompletedDeletionCount(t *testing.T) {
	home := t.TempDir()
	prepareMutationAuditTestParent(t, home)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".cfgov-cli", "backups")
	deleted, err := backup.Write(root, backup.Request{
		Context:   "dev",
		Namespace: "public",
		Group:     "DEFAULT_GROUP",
		DataID:    "deleted.yaml",
		Content:   []byte("deleted\n"),
		Operator:  "tester",
	})
	if err != nil {
		t.Fatalf("backup.Write() error = %v", err)
	}
	blockedPath := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blockedPath, 0o700); err != nil {
		t.Fatalf("MkdirAll(blocked) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockedPath, "child"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocked child) error = %v", err)
	}
	blocked := backup.Metadata{
		BackupID:  "ffffffffffffffffffffffffffffffff",
		Context:   "dev",
		Namespace: "public",
		Group:     "DEFAULT_GROUP",
		DataID:    "blocked.yaml",
		Operator:  "tester",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Path:      blockedPath,
	}
	line, err := json.Marshal(blocked)
	if err != nil {
		t.Fatalf("Marshal(blocked) error = %v", err)
	}
	index, err := os.OpenFile(filepath.Join(root, "index.jsonl"), os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // Test path is under t.TempDir.
	if err != nil {
		t.Fatalf("OpenFile(index) error = %v", err)
	}
	if _, err := index.Write(append(line, '\n')); err != nil {
		_ = index.Close()
		t.Fatalf("Write(index) error = %v", err)
	}
	if err := index.Close(); err != nil {
		t.Fatalf("Close(index) error = %v", err)
	}

	var records []mutationAuditRecord
	f := mutationAuditTestFlags()
	f.Output = "plain"
	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowBackupClean = true
	f.mutationAuditPath = filepath.Join(home, "audit.log")
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ audit.Options) (audit.AppendResult, error) {
			records = append(records, record)
			return audit.AppendResult{State: audit.AppendCommitCommitted}, nil
		},
		appendOrdinary: func(string, any, audit.Options) error {
			return nil
		},
		now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 16)),
	}

	err = runBackupClean(f, backupCleanOptions{keepLast: 0, confirm: true})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("runBackupClean() code = %s, want %s (err=%v)", got, apperrors.CodeLocalIOError, err)
	}
	if _, statErr := os.Stat(deleted.Path); !os.IsNotExist(statErr) {
		t.Fatalf("completed deletion still exists: %v", statErr)
	}
	if _, statErr := os.Stat(blockedPath); statErr != nil {
		t.Fatalf("failed deletion removed blocked path: %v", statErr)
	}
	if len(records) != 2 {
		t.Fatalf("mutation audit records = %d, want intent and outcome", len(records))
	}
	candidateIDs := []string{deleted.BackupID, blocked.BackupID}
	sort.Strings(candidateIDs)
	expectedMetadata := mutationValueMetadata("backup.prune.candidates", candidateIDs)
	if records[0].Phase != mutationAuditPhaseIntent ||
		records[0].Metadata.PayloadFingerprint != expectedMetadata.PayloadFingerprint ||
		records[0].Metadata.PayloadBytes != expectedMetadata.PayloadBytes {
		t.Fatalf("intent metadata = %#v, want exact candidate ID fingerprint %#v", records[0], expectedMetadata)
	}
	outcome := records[1]
	if outcome.Phase != mutationAuditPhaseOutcome || outcome.Outcome == nil {
		t.Fatalf("outcome record = %#v", outcome)
	}
	if outcome.Outcome.Status != audit.StatusPartialFailed ||
		outcome.Outcome.Succeeded != 1 ||
		outcome.Outcome.Failed != 1 ||
		outcome.Outcome.Skipped != 0 {
		t.Fatalf("partial outcome = %#v, want succeeded=1 failed=1 skipped=0", outcome.Outcome)
	}
}
