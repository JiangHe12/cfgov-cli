package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func secureTempBackupRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
