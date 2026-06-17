package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
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
