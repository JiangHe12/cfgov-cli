package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func TestCapabilitiesDoNotDeclareBackupCleanRiskContract(t *testing.T) {
	t.Parallel()
	data := buildCapabilities(newDefaultFlags(), currentBackendCapabilities(&cliFlags{Backend: "nacos"}))
	for _, item := range data.Supported.Commands {
		if item.Noun == "backup" && item.Verb == "clean" {
			t.Fatalf("backup clean must not be in R0-R3 risk table: %#v", item)
		}
	}
	foundList := false
	for _, item := range data.Supported.Commands {
		if item.Noun == "backup" && item.Verb == "list" && item.Risk == "R0" {
			foundList = true
		}
	}
	if !foundList {
		t.Fatal("backup list R0 contract missing")
	}
}

func TestCompletionCommandSmoke(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	cmd := newRootCmdWith(f)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"completion", "powershell"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion powershell error = %v", err)
	}
	if !strings.Contains(out.String(), "cfgov") {
		t.Fatalf("completion output missing cfgov marker: %q", out.String())
	}
}

func TestRuleValidateFailOnWarnings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "flow.json")
	if err := os.WriteFile(path, []byte(`[{"resource":"api","grade":1,"count":1000001}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	f := newDefaultFlags()
	f.Output = "json"
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{"rule", "validate", "--file", path, "--deep", "--fail-on-warnings", "-o", "json"})
	err := cmd.Execute()
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}

func TestSuggestionsMinimumDistanceIsRecursive(t *testing.T) {
	t.Parallel()
	cmd := newRootCmdWith(newDefaultFlags())
	configCmd, _, err := cmd.Find([]string{"config"})
	if err != nil {
		t.Fatal(err)
	}
	if configCmd.SuggestionsMinimumDistance != 1 {
		t.Fatalf("config suggestion distance = %d, want 1", configCmd.SuggestionsMinimumDistance)
	}
}
