package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestConfigExportNameCollisionFailsBeforeFileWrites(t *testing.T) {
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	server := newExportTestServer(t, `{
		"totalCount": 2,
		"pageNumber": 1,
		"pagesAvailable": 1,
		"pageItems": [
			{"dataId":"a:b","group":"DEFAULT_GROUP","md5":"one","type":"text"},
			{"dataId":"a_b","group":"DEFAULT_GROUP","md5":"two","type":"text"}
		]
	}`)
	defer server.Close()

	for _, plan := range []bool{false, true} {
		name := "apply"
		if plan {
			name = "plan"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "export")
			args := exportTestArgs(home, server.URL)
			if plan {
				args = append(args, "--plan")
			}
			args = append(args, "config", "export", "--dir", dir)
			_, err := runCommandForTestAtHome(t, home, args...)
			if got := apperrors.AsAppError(err).Code; got != apperrors.CodeConflict {
				t.Fatalf("config export collision code = %s, want %s (err=%v)", got, apperrors.CodeConflict, err)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("config export collision created output directory: %v", statErr)
			}
			assertNoExportMutationIntent(t, home)
		})
	}
}

func TestExportsRejectExistingTargetsWithoutOverwriteOrPartialFiles(t *testing.T) {
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	server := newExportTestServer(t, `{
		"totalCount": 1,
		"pageNumber": 1,
		"pagesAvailable": 1,
		"pageItems": [
			{"dataId":"app.yaml","group":"DEFAULT_GROUP","md5":"one","type":"yaml"}
		]
	}`)
	defer server.Close()

	tests := []struct {
		name       string
		existing   string
		mustRemain []string
		args       []string
	}{
		{
			name:       "config",
			existing:   exportManifestName,
			mustRemain: []string{"app.yaml.cfg"},
			args:       []string{"config", "export"},
		},
		{
			name:       "rule",
			existing:   "degrade.json",
			mustRemain: []string{"flow.json", "system.json", "authority.json", "param.json"},
			args:       []string{"rule", "export", "--app", "demo"},
		},
		{
			name:     "flag",
			existing: "flags.json",
			args:     []string{"flag", "export", "--app", "demo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "export")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			existingPath := filepath.Join(dir, tt.existing)
			sentinel := []byte("existing-target-must-not-change\n")
			if err := os.WriteFile(existingPath, sentinel, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append(exportTestArgs(home, server.URL), tt.args...)
			args = append(args, "--dir", dir)
			_, err := runCommandForTestAtHome(t, home, args...)
			if got := apperrors.AsAppError(err).Code; got != apperrors.CodeResourceAlreadyExists {
				t.Fatalf("%s export existing target code = %s, want %s (err=%v)", tt.name, got, apperrors.CodeResourceAlreadyExists, err)
			}
			after, readErr := os.ReadFile(existingPath)
			if readErr != nil {
				t.Fatalf("ReadFile(existing target) error = %v", readErr)
			}
			if string(after) != string(sentinel) {
				t.Fatalf("%s export overwrote existing target: %q", tt.name, after)
			}
			for _, name := range tt.mustRemain {
				if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
					t.Fatalf("%s export created %s before detecting collision: %v", tt.name, name, statErr)
				}
			}
			assertNoExportMutationIntent(t, home)
		})
	}
}

func TestExclusiveExportWriteRejectsPostPreflightCollision(t *testing.T) {
	dir := t.TempDir()
	const name = "flags.json"
	if err := preflightNewLocalFiles(dir, []string{name}); err != nil {
		t.Fatalf("preflightNewLocalFiles() error = %v", err)
	}
	path := filepath.Join(dir, name)
	sentinel := []byte("created-after-preflight\n")
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeNewLocalFile(path, []byte("must-not-overwrite\n"))
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeResourceAlreadyExists {
		t.Fatalf("writeNewLocalFile() code = %s, want %s (err=%v)", got, apperrors.CodeResourceAlreadyExists, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(sentinel) {
		t.Fatalf("post-preflight collision was overwritten: %q", after)
	}
}

func newExportTestServer(t *testing.T, listResponse string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nacos/v1/cs/configs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("pageNo") != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(listResponse))
			return
		}
		group := r.URL.Query().Get("group")
		if group == "SENTINEL_GROUP" || group == "FEATURE_FLAG_GROUP" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte("enabled: true\n"))
	}))
}

func exportTestArgs(home string, serverURL string) []string {
	return []string{
		"--config", filepath.Join(home, "config.yaml"),
		"--backend", "nacos",
		"--server", serverURL,
		"--namespace", "ns",
	}
}

func assertNoExportMutationIntent(t *testing.T, home string) {
	t.Helper()
	for _, record := range readRawAuditRecords(t, home) {
		if record["kind"] == mutationAuditKind {
			t.Fatalf("export preflight collision wrote mutation audit before validation: %#v", record)
		}
	}
}
