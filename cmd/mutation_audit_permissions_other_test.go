//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMutationSpoolUnixRejectsInsecureModesAndSymlinks(t *testing.T) {
	parent := t.TempDir()
	spool := filepath.Join(parent, "audit.log"+mutationAuditSpoolSuffix)
	if err := os.Mkdir(spool, 0o755); err != nil {
		t.Fatalf("Mkdir(spool) error = %v", err)
	}
	if err := verifyMutationSpoolDirectory(spool); err == nil {
		t.Fatal("verifyMutationSpoolDirectory() error = nil for mode 0755")
	}
	if err := os.Chmod(spool, 0o700); err != nil {
		t.Fatalf("Chmod(spool) error = %v", err)
	}
	file := filepath.Join(spool, "00000000000000000001-00000000000000000000000000000001.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(spool record) error = %v", err)
	}
	if err := verifyMutationSpoolFile(file); err == nil {
		t.Fatal("verifyMutationSpoolFile() error = nil for mode 0644")
	}
	link := filepath.Join(parent, "spool-link")
	if err := os.Symlink(spool, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := verifyMutationSpoolDirectory(link); err == nil {
		t.Fatal("verifyMutationSpoolDirectory() error = nil for symlink")
	}
}

func prepareMutationAuditTestParent(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("Chmod(test parent) error = %v", err)
	}
}
