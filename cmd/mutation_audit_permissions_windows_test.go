//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMutationSpoolWindowsUsesOwnerOnlyACLAndRejectsReparsePoints(t *testing.T) {
	parent := t.TempDir()
	prepareMutationAuditTestParent(t, parent)
	spool := filepath.Join(parent, "audit.log"+mutationAuditSpoolSuffix)
	if err := ensureMutationSpoolDirectory(spool); err != nil {
		t.Fatalf("ensureMutationSpoolDirectory() error = %v", err)
	}
	if err := verifyMutationSpoolDirectory(spool); err != nil {
		t.Fatalf("verifyMutationSpoolDirectory() error = %v", err)
	}
	file := filepath.Join(spool, "test.tmp")
	if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := secureMutationSpoolFile(file); err != nil {
		t.Fatalf("secureMutationSpoolFile() error = %v", err)
	}
	if err := verifyMutationSpoolFile(file); err != nil {
		t.Fatalf("verifyMutationSpoolFile() error = %v", err)
	}

	link := filepath.Join(parent, "spool-link")
	if err := os.Symlink(spool, link); err != nil {
		t.Skipf("creating a Windows symlink requires Developer Mode or privilege: %v", err)
	}
	if err := verifyMutationSpoolDirectory(link); err == nil {
		t.Fatal("verifyMutationSpoolDirectory() error = nil for reparse point")
	}
}

func TestEnsureMutationSpoolDirectoryDoesNotRewriteUnsafeExistingParent(t *testing.T) {
	parent := t.TempDir()
	userSID, systemSID, adminSID, err := trustedMutationSpoolSIDs()
	if err != nil {
		t.Fatal(err)
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	fullControl := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_ALL |
			windows.FILE_GENERIC_READ |
			windows.FILE_GENERIC_WRITE |
			windows.FILE_GENERIC_EXECUTE |
			windows.DELETE,
	)
	entries := []windows.EXPLICIT_ACCESS{
		mutationSpoolExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(usersSID, windows.TRUSTEE_IS_GROUP, windows.FILE_GENERIC_WRITE, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		parent,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyMutationSpoolParent(parent); err == nil {
		t.Fatal("unsafe parent unexpectedly passed validation before initialization")
	}
	spool := filepath.Join(parent, "audit.log"+mutationAuditSpoolSuffix)
	if err := ensureMutationSpoolDirectory(spool); err == nil {
		t.Fatal("ensureMutationSpoolDirectory() error = nil for unsafe existing parent")
	}
	if err := verifyMutationSpoolParent(parent); err == nil {
		t.Fatal("initialization silently rewrote the unsafe existing parent ACL")
	}
}

func prepareMutationAuditTestParent(t *testing.T, path string) {
	t.Helper()
	for parent := filepath.Dir(path); !strings.EqualFold(parent, os.TempDir()); parent = filepath.Dir(parent) {
		if err := setMutationSpoolACL(parent, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
			t.Fatalf("setMutationSpoolACL(test ancestor %s) error = %v", parent, err)
		}
	}
	if err := setMutationSpoolACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		t.Fatalf("setMutationSpoolACL(test parent) error = %v", err)
	}
	if err := verifyMutationSpoolACL(path); err != nil {
		t.Fatalf("verifyMutationSpoolACL(test parent) error = %v", err)
	}
}
