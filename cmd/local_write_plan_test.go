package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestPlanPreventsPullAndExportFileWrites(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nacos/v1/cs/configs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("pageNo") != "" {
			_, _ = w.Write([]byte(`{"totalCount":1,"pageNumber":1,"pagesAvailable":1,"pageItems":[{"dataId":"app.yaml","group":"DEFAULT_GROUP","md5":"rev","type":"yaml"}]}`))
			return
		}
		if r.URL.Query().Get("dataId") == "app.yaml" {
			_, _ = w.Write([]byte("enabled: true\n"))
			return
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	tests := []struct {
		name string
		path string
		args []string
	}{
		{
			name: "config pull",
			path: filepath.Join(home, "pull", "app.yaml"),
			args: []string{"config", "pull", "--key", "app.yaml", "--file", filepath.Join(home, "pull", "app.yaml")},
		},
		{
			name: "config export",
			path: filepath.Join(home, "config-export"),
			args: []string{"config", "export", "--dir", filepath.Join(home, "config-export")},
		},
		{
			name: "rule export",
			path: filepath.Join(home, "rule-export"),
			args: []string{"rule", "export", "--app", "demo", "--dir", filepath.Join(home, "rule-export")},
		},
		{
			name: "flag export",
			path: filepath.Join(home, "flag-export"),
			args: []string{"flag", "export", "--app", "demo", "--dir", filepath.Join(home, "flag-export")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{
				"--config", configPath,
				"--backend", "nacos",
				"--server", server.URL,
				"--namespace", "ns",
				"--plan",
				"-o", "json",
			}
			out, err := runCommandForTestAtHome(t, home, append(args, tt.args...)...)
			if err != nil {
				t.Fatalf("planned local write error = %v; out=%s", err, out)
			}
			if !strings.Contains(out, `"dryRun": true`) {
				t.Fatalf("planned local write output missing dryRun=true: %s", out)
			}
			if _, err := os.Stat(tt.path); !os.IsNotExist(err) {
				t.Fatalf("planned local write created %s: %v", tt.path, err)
			}
		})
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}
