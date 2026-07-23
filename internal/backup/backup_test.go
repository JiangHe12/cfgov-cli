package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestWriteCreatesBackupAndIndex(t *testing.T) {
	root := secureTempBackupRoot(t)
	result, err := Write(root, Request{
		Context:   "prod",
		Namespace: "public",
		Group:     "DEFAULT_GROUP",
		DataID:    "app.yaml",
		Content:   []byte("enabled: true\n"),
		Operator:  "tester",
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if result.BackupID == "" || result.SHA256 == "" || result.Size == 0 {
		t.Fatalf("result missing metadata: %#v", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(data) != "enabled: true\n" {
		t.Fatalf("backup content = %q", string(data))
	}
	items, err := List(root, Filter{Context: "prod", DataID: "app.yaml"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].BackupID != result.BackupID {
		t.Fatalf("items = %#v, want backup %q", items, result.BackupID)
	}
}

func TestWriteTraversalLikeKeyStaysUnderRoot(t *testing.T) {
	root := secureTempBackupRoot(t)
	result, err := Write(root, Request{
		Context:   "prod",
		Namespace: "controlled-ns",
		Group:     "..",
		DataID:    "..",
		Content:   []byte("safe\n"),
		Operator:  "tester",
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	pathAbs, err := filepath.Abs(result.Path)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		t.Fatalf("rel path: %v", err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		t.Fatalf("backup path escaped root: root=%q path=%q rel=%q", rootAbs, pathAbs, rel)
	}
	if !strings.Contains(rel, "%2e%2e") {
		t.Fatalf("backup path did not sanitize traversal components: rel=%q", rel)
	}
}

func TestCleanKeepLastDryRun(t *testing.T) {
	root := secureTempBackupRoot(t)
	for _, dataID := range []string{"a.yaml", "b.yaml"} {
		if _, err := Write(root, Request{Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP", DataID: dataID, Content: []byte(dataID), Operator: "tester"}); err != nil {
			t.Fatalf("Write(%s) error = %v", dataID, err)
		}
	}
	keepLast := 1
	result, err := Clean(root, CleanOptions{KeepLast: &keepLast})
	if err != nil {
		t.Fatalf("Clean() error = %v", err)
	}
	if !result.DryRun || len(result.Deleted) != 1 {
		t.Fatalf("result = %#v, want dry-run with one deletion candidate", result)
	}
	items, err := List(root, Filter{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("dry-run removed items: %#v", items)
	}
}

func TestCleanBeforeApplies(t *testing.T) {
	root := secureTempBackupRoot(t)
	if _, err := Write(root, Request{Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP", DataID: "app.yaml", Content: []byte("x"), Operator: "tester"}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	before := time.Now().Add(time.Hour)
	result, err := Clean(root, CleanOptions{Before: &before, Apply: true})
	if err != nil {
		t.Fatalf("Clean() error = %v", err)
	}
	if result.DryRun || len(result.Deleted) != 1 {
		t.Fatalf("result = %#v, want applied one deletion", result)
	}
	items, err := List(root, Filter{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("items after clean = %#v, want none", items)
	}
}

func TestApplyCleanPlanRejectsCandidateDriftBeforeDeletion(t *testing.T) {
	root := secureTempBackupRoot(t)
	first, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "first.yaml", Content: []byte("first"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(first) error = %v", err)
	}
	second, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "second.yaml", Content: []byte("second"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(second) error = %v", err)
	}
	keepLast := 1
	opts := CleanOptions{KeepLast: &keepLast}
	plan, err := PlanClean(root, opts)
	if err != nil {
		t.Fatalf("PlanClean() error = %v", err)
	}
	if len(plan.CandidateIDs()) != 1 {
		t.Fatalf("planned candidates = %v, want one", plan.CandidateIDs())
	}
	third, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "third.yaml", Content: []byte("third"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(third) error = %v", err)
	}

	result, err := ApplyCleanPlan(root, opts, plan)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
		t.Fatalf("ApplyCleanPlan() code = %s, want %s (result=%#v err=%v)", got, apperrors.CodeConflict, result, err)
	}
	for _, path := range []string{first.Path, second.Path, third.Path} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("candidate drift removed %s: %v", path, statErr)
		}
	}
	items, err := List(root, Filter{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items after conflict = %#v, want all three", items)
	}
}

func TestCleanDeleteFailureReturnsOnlyCompletedDeletions(t *testing.T) {
	root := secureTempBackupRoot(t)
	first, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "first.yaml", Content: []byte("first"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(first) error = %v", err)
	}
	second, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "second.yaml", Content: []byte("second"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(second) error = %v", err)
	}
	keepLast := 0
	writeCalled := false
	result, err := cleanLockedWithOperations(
		root,
		CleanOptions{KeepLast: &keepLast, Apply: true},
		func(path string) error {
			if path == second.Path {
				return errors.New("injected remove failure")
			}
			return os.Remove(path)
		},
		func(root string, items []Metadata) error {
			writeCalled = true
			return writeIndex(root, items)
		},
	)
	if err == nil {
		t.Fatal("cleanLockedWithOperations() error = nil, want remove failure")
	}
	if len(result.Deleted) != 1 || result.Deleted[0].Path != first.Path {
		t.Fatalf("deleted = %#v, want only completed deletion %s", result.Deleted, first.Path)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("removed = %#v, want none before index commit", result.Removed)
	}
	if writeCalled {
		t.Fatal("index write ran after deletion failure")
	}
	if _, statErr := os.Stat(first.Path); !os.IsNotExist(statErr) {
		t.Fatalf("first backup still exists after successful deletion: %v", statErr)
	}
	if _, statErr := os.Stat(second.Path); statErr != nil {
		t.Fatalf("failed deletion removed second backup: %v", statErr)
	}
}

func TestCleanIndexFailureReturnsDeletedFilesButNotUncommittedRemovals(t *testing.T) {
	root := secureTempBackupRoot(t)
	deleted, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "deleted.yaml", Content: []byte("deleted"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(deleted) error = %v", err)
	}
	missing, err := Write(root, Request{
		Context: "prod", Namespace: "public", Group: "DEFAULT_GROUP",
		DataID: "missing.yaml", Content: []byte("missing"), Operator: "tester",
	})
	if err != nil {
		t.Fatalf("Write(missing) error = %v", err)
	}
	if err := os.Remove(missing.Path); err != nil {
		t.Fatalf("Remove(missing) error = %v", err)
	}
	keepLast := 0
	result, err := cleanLockedWithOperations(
		root,
		CleanOptions{KeepLast: &keepLast, Apply: true},
		os.Remove,
		func(string, []Metadata) error {
			return errors.New("injected index write failure")
		},
	)
	if err == nil {
		t.Fatal("cleanLockedWithOperations() error = nil, want index write failure")
	}
	if len(result.Deleted) != 1 || result.Deleted[0].Path != deleted.Path {
		t.Fatalf("deleted = %#v, want completed deletion %s", result.Deleted, deleted.Path)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("removed = %#v, want no uncommitted index removals", result.Removed)
	}
	if _, statErr := os.Stat(deleted.Path); !os.IsNotExist(statErr) {
		t.Fatalf("deleted backup still exists after index failure: %v", statErr)
	}
}

func secureTempBackupRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
