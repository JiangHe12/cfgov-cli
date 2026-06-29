package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

func TestCapabilitiesDoNotDeclareBackupCleanRiskContract(t *testing.T) {
	t.Parallel()
	data := buildCapabilities(newDefaultFlags(), currentBackendCapabilities(&cliFlags{Backend: "nacos"}))
	if strings.Join(data.Domain.OutputFormats, ",") != "table,json,plain" {
		t.Fatalf("outputFormats = %#v", data.Domain.OutputFormats)
	}
	for _, item := range data.Domain.Commands {
		if item.Noun == "backup" && item.Verb == "clean" {
			t.Fatalf("backup clean must not be in R0-R3 risk table: %#v", item)
		}
	}
	foundList := false
	for _, item := range data.Domain.Commands {
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

func TestRuleValidateSingleFileDeepSkipsCrossTypeWarnings(t *testing.T) {
	dir := t.TempDir()
	paramPath := filepath.Join(dir, "param.json")
	if err := os.WriteFile(paramPath, []byte(`[{"resource":"api","grade":1,"paramIdx":0,"count":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	degradePath := filepath.Join(dir, "degrade.json")
	if err := os.WriteFile(degradePath, []byte(`[{"resource":"api","grade":0,"count":1,"timeWindow":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{paramPath, degradePath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f := newDefaultFlags()
			f.Output = "json"
			cmd := newRootCmdWith(f)
			cmd.SetArgs([]string{"rule", "validate", "--file", path, "--deep", "--fail-on-warnings", "-o", "json"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("rule validate %s error = %v", path, err)
			}
		})
	}
}

func TestRuleValidateDirRunsCrossTypeWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flow.json"), []byte(`[{"resource":"api","grade":1,"count":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "degrade.json"), []byte(`[{"resource":"api","grade":0,"count":1,"timeWindow":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "param.json"), []byte(`[{"resource":"lonely","grade":1,"paramIdx":0,"count":10}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, _, _, err := readRuleValidationDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	issues := rule.DeepCheck(rules)
	assertCmdRuleIssue(t, issues, "PARAM_WITHOUT_FLOW", rule.SeverityWarning)
	assertCmdRuleIssue(t, issues, "FLOW_DEGRADE_GRADE_MISMATCH", rule.SeverityWarning)

	f := newDefaultFlags()
	f.Output = "json"
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{"rule", "validate", "--dir", dir, "--deep", "--fail-on-warnings", "-o", "json"})
	if err := cmd.Execute(); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
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

func TestParentCommandReportsSubcommands(t *testing.T) {
	t.Parallel()
	cmd := newRootCmdWith(newDefaultFlags())
	cmd.SetArgs([]string{"rule"})
	err := cmd.Execute()
	appErr := apperrors.AsAppError(err)
	if err == nil || !strings.Contains(appErr.Message, "requires a subcommand") || !strings.Contains(appErr.Suggestion, "Available subcommands") {
		t.Fatalf("error = %v, want subcommand suggestion", err)
	}
}

func assertCmdRuleIssue(t *testing.T, issues []rule.Issue, code string, severity rule.IssueSeverity) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			if issue.Severity != severity {
				t.Fatalf("%s severity = %s, want %s; issues=%#v", code, issue.Severity, severity, issues)
			}
			return
		}
	}
	t.Fatalf("missing issue %s in %#v", code, issues)
}
