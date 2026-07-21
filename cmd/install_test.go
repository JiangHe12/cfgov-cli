package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallSkillsCopiesSkillAndManifest(t *testing.T) {
	srcRoot := t.TempDir()
	srcDir := filepath.Join(srcRoot, "skills", "cfgov-cli")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "SKILL.md"), []byte("# cfgov-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFS := skillFS
	skillFS = os.DirFS(srcRoot)
	t.Cleanup(func() { skillFS = oldFS })

	target := t.TempDir()
	if err := installSkills(newDefaultFlags(), target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "cfgov-cli", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "cfgov-cli", ".installed-by")); err != nil {
		t.Fatal(err)
	}
}

func TestInstallSkillsPlanDoesNotWrite(t *testing.T) {
	srcRoot := t.TempDir()
	srcDir := filepath.Join(srcRoot, "skills", "cfgov-cli")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "SKILL.md"), []byte("# cfgov-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldFS := skillFS
	skillFS = os.DirFS(srcRoot)
	t.Cleanup(func() { skillFS = oldFS })

	home := t.TempDir()
	target := filepath.Join(home, "skills")
	out, err := runCommandForTestAtHome(t, home, "--plan", "-o", "json", "install", target, "--skills")
	if err != nil {
		t.Fatalf("planned install error = %v; out=%s", err, out)
	}
	if !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("planned install output missing dryRun=true: %s", out)
	}
	if _, err := os.Stat(filepath.Join(target, "cfgov-cli")); !os.IsNotExist(err) {
		t.Fatalf("planned install created target directory: %v", err)
	}
}
