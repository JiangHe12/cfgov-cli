package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

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

func TestMandatoryRuleBackupRejectsNoBackup(t *testing.T) {
	t.Parallel()
	f := newDefaultFlags()
	f.NoBackup = true
	err := validateMandatoryRuleBackup(f, []plannedRuleWrite{{backupBefore: true, ruleType: rule.TypeFlow}})
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}
