package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestPlanPreventsConfigBackendMutations(t *testing.T) {
	var mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			http.NotFound(w, r)
		case http.MethodPost, http.MethodDelete:
			mutations.Add(1)
			_, _ = w.Write([]byte("true"))
		default:
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	inputDir := filepath.Join(dir, "input")
	if err := os.MkdirAll(inputDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "app.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "push",
			args: []string{"--yes", "--no-backup", "config", "push", "--key", "app.yaml", "--content", "enabled: true", "--type", "yaml"},
		},
		{
			name: "delete",
			args: []string{"--yes", "--ticket", "OPS-1", "--no-backup", "config", "delete", "--key", "app.yaml"},
		},
		{
			name: "import",
			args: []string{"config", "import", "--dir", inputDir},
		},
		{
			name: "reconcile",
			args: []string{"config", "reconcile", "--dir", inputDir},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := mutations.Load()
			args := []string{
				"--config", configFile,
				"--backend", "nacos",
				"--server", server.URL,
				"--namespace", "ns",
				"--plan",
				"-o", "json",
			}
			out, err := runCommandForTest(t, append(args, tt.args...)...)
			if err != nil {
				t.Fatalf("command error = %v; out=%s", err, out)
			}
			if got := mutations.Load(); got != before {
				t.Fatalf("backend mutation calls = %d, want %d; out=%s", got, before, out)
			}
		})
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}
