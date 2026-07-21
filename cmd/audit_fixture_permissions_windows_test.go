//go:build windows

package cmd

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func writePrivateAuditFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write private audit fixture %s: %v", path, err)
	}
	if err := setMutationSpoolACL(path, windows.NO_INHERITANCE); err != nil {
		t.Fatalf("secure private audit fixture %s: %v", path, err)
	}
	if err := verifyMutationSpoolACL(path); err != nil {
		t.Fatalf("verify private audit fixture %s: %v", path, err)
	}
}
