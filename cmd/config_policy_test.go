package cmd

import (
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

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

func TestValidateContentChecksEveryYAMLDocument(t *testing.T) {
	if err := validateContent([]byte("enabled: true\n---\nname: cfgov\n"), "yaml"); err != nil {
		t.Fatalf("valid multi-document YAML rejected: %v", err)
	}
	err := validateContent([]byte("enabled: true\n---\nname: [\n"), "yaml")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("invalid later YAML document error = %v, want validation failed", err)
	}
}

func TestValidateContentRejectsMalformedXML(t *testing.T) {
	err := validateContent([]byte(`<root>`), "xml")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
	if err := validateContent([]byte(`<root/>`), "xml"); err != nil {
		t.Fatalf("valid xml rejected: %v", err)
	}
	err = validateContent([]byte(`<a/><b/>`), "xml")
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("multi-root xml error = %v, want validation failed", err)
	}
}

func TestReadConfigInputContentAndFileAreMutuallyExclusive(t *testing.T) {
	_, err := readConfigInput("inline", "file")
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestDiffSummaryIncludesLineDiff(t *testing.T) {
	result := diffSummary([]byte("a\nb\n"), []byte("a\nc\n"))
	if result.Same {
		t.Fatal("expected diff")
	}
	want := []string{"  a", "- b", "+ c", "  "}
	if len(result.Lines) != len(want) {
		t.Fatalf("lines = %#v, want %#v", result.Lines, want)
	}
	for i := range want {
		if result.Lines[i] != want[i] {
			t.Fatalf("line[%d] = %q, want %q; all=%#v", i, result.Lines[i], want[i], result.Lines)
		}
	}
}

func TestBuildBackendRequiresContextOrServer(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	err := buildBackendForTest(newDefaultFlags())
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestBuildBackendUnsupportedBackendFailsClosed(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	f := newDefaultFlags()
	f.Server = "http://127.0.0.1:8848"
	f.Backend = "unsupported"
	err := buildBackendForTest(f)
	if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
}

func buildBackendForTest(f *cliFlags) error {
	item, name, err := resolvedContext(f)
	if err != nil {
		return err
	}
	_, _, err = buildBackendForResolvedContext(f, item, name)
	return err
}
