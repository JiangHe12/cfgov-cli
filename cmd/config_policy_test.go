package cmd

import (
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestValidateBackupPolicyProtectedRequiresExplicitDecision(t *testing.T) {
	f := newDefaultFlags()
	meta := cfgovctx.Context{}
	meta.Protected = true
	err := validateBackupPolicy(f, meta)
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestValidateBackupPolicyProtectedRejectsNoBackup(t *testing.T) {
	f := newDefaultFlags()
	f.NoBackup = true
	meta := cfgovctx.Context{}
	meta.Protected = true
	err := validateBackupPolicy(f, meta)
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestValidateContentRejectsMalformedJSON(t *testing.T) {
	err := validateContent([]byte(`{"bad":`), "json")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}

func TestBuildBackendRequiresContextOrServer(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	_, _, err := buildBackend(newDefaultFlags())
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestBuildBackendUnsupportedBackendFailsClosed(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	f := newDefaultFlags()
	f.Server = "http://127.0.0.1:8848"
	f.Backend = "consul"
	_, _, err := buildBackend(f)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
}
