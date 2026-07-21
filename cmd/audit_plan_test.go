package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditVerifyRepairPlanDoesNotRewrite(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "audit.jsonl")
	original := []byte("{malformed\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--plan", "-o", "json",
		"audit", "verify", "--path", path, "--repair", "--confirm",
	)
	if err != nil {
		t.Fatalf("planned audit repair error = %v; out=%s", err, out)
	}
	if !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("planned audit repair output missing dryRun=true: %s", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("planned audit repair rewrote log: %q", after)
	}
	matches, err := filepath.Glob(path + ".quarantine.*.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("planned audit repair created quarantine files: %v", matches)
	}

	out, err = runCommandForTestAtHome(t, home,
		"--plan", "-o", "json",
		"audit", "verify", "--path", path, "--repair",
	)
	if err != nil {
		t.Fatalf("planned audit repair without confirm error = %v; out=%s", err, out)
	}
	if !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("planned audit repair without confirm output missing dryRun=true: %s", out)
	}
}

func TestAuditPrunePreviewFlagsDoNotDelete(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "global plan", args: []string{"--plan"}},
		{name: "global dry run before command", args: []string{"--dry-run"}},
		{name: "local dry run shadows global flag", args: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "audit.jsonl")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			beforeActive, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rotated := path + ".20260524-010203.log"
			if err := os.WriteFile(rotated, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{}, tt.args...)
			args = append(args, "-o", "json", "audit", "prune", "--path", path, "--keep-last", "0", "--confirm")
			if tt.name == "local dry run shadows global flag" {
				args = append(args, "--dry-run")
			}
			out, err := runCommandForTestAtHome(t, home, args...)
			if err != nil {
				t.Fatalf("audit prune preview error = %v; out=%s", err, out)
			}
			if !strings.Contains(out, `"dryRun": true`) {
				t.Fatalf("audit prune preview output missing dryRun=true: %s", out)
			}
			if _, err := os.Stat(rotated); err != nil {
				t.Fatalf("audit prune preview deleted %s: %v", rotated, err)
			}
			afterActive, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterActive, beforeActive) {
				t.Fatalf("audit prune preview wrote active target: before=%q after=%q", beforeActive, afterActive)
			}
		})
	}
}

func TestAuditPruneConfirmStillDeletes(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rotated := path + ".20260524-010203.log"
	if err := os.WriteFile(rotated, []byte(`{"timestamp":"2026-05-24T01:02:03Z","eventType":"test.rotated","operator":"tester"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCommandForTestAtHome(t, home,
		"-o", "json", "--yes", "--ticket", "TEST-1", "--allow-audit-prune", "audit", "prune",
		"--path", path, "--keep-last", "0", "--confirm",
	)
	if err != nil {
		t.Fatalf("confirmed audit prune error = %v; out=%s", err, out)
	}
	if strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("confirmed audit prune unexpectedly reported dry-run: %s", out)
	}
	if _, err := os.Stat(rotated); !os.IsNotExist(err) {
		t.Fatalf("confirmed audit prune kept %s: %v", rotated, err)
	}
}
