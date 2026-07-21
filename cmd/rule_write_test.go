package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

func TestRuleDeleteAuthorizationLadder(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.Yes = true
	f.Ticket = "OPS-1"
	if err := authorize(f, safety.R2, cfgovctx.Context{}, allowProductionRuleDelete); err != nil {
		t.Fatalf("unprotected rule delete authorize error = %v", err)
	}

	meta := cfgovctx.Context{}
	meta.Protected = true
	if err := authorize(f, safety.R2, meta, allowProductionRuleDelete); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("protected without allow error = %v, want authorization required", err)
	}
	f.AllowDel = true
	if err := authorize(f, safety.R2, meta, allowProductionRuleDelete); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("wrong allow error = %v, want authorization required", err)
	}
	f.AllowDel = false
	f.AllowRuleDel = true
	if err := authorize(f, safety.R2, meta, allowProductionRuleDelete); err != nil {
		t.Fatalf("protected with rule allow error = %v", err)
	}
}

func TestRuleImportDeepValidationBlocksDangerousRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "degrade.json")
	if err := os.WriteFile(path, []byte(`[{"resource":"r","grade":0,"count":1,"timeWindow":10,"slowRatioThreshold":2}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readRuleDirectory(dir)
	if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("error = %v, want validation failed", err)
	}
}

func TestRuleWriteDeepValidationBlocksCrossRuleErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	flowPath := filepath.Join(dir, "flow.json")
	if err := os.WriteFile(flowPath, []byte(`{"resource":"api","grade":1,"count":10,"strategy":1,"refResource":"missing"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOneRuleForWrite(ruleWriteOptions{typeName: string(rule.TypeFlow), file: flowPath}); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("readOneRuleForWrite error = %v, want validation failed", err)
	}

	systemDir := filepath.Join(dir, "system-rules")
	if err := os.MkdirAll(systemDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(systemDir, "system.json"), []byte(`[{"qps":100},{"avgRt":20}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuleDirectory(systemDir); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("readRuleDirectory error = %v, want validation failed", err)
	}
	if _, err := readRollbackRules(systemDir); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("readRollbackRules error = %v, want validation failed", err)
	}
}

func TestMandatoryRuleBackupRejectsNoBackup(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.NoBackup = true
	err := validateMandatoryRuleBackup(f, []plannedRuleWrite{{backupBefore: true, ruleType: rule.TypeFlow}})
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestClassifyRuleChangeSkipWhenHashesMatch(t *testing.T) {
	t.Parallel()
	if got := classifyRuleChange([]map[string]any{{"resource": "r"}}, []map[string]any{{"resource": "r"}}, "abc", "abc"); got != "skip" {
		t.Fatalf("classifyRuleChange() = %q, want skip", got)
	}
}
