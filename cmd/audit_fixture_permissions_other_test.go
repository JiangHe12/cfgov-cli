//go:build !windows

package cmd

import (
	"os"
	"testing"
)

func writePrivateAuditFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write private audit fixture %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("secure private audit fixture %s: %v", path, err)
	}
}
