package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestCtxSetRejectsUnimplementedRemoteRolesSourceBeforeWrite(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"ctx", "set", "remote-roles",
		"--roles-source", "url",
		"--roles-url", "https://roles.example/roles.yaml",
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNotImplemented {
		t.Fatalf("ctx set error = %v, want not implemented; out=%s", err, out)
	}
	assertContextAbsent(t, configPath, "remote-roles")
}

func TestCtxImportRejectsUnimplementedRemoteRolesSourceBeforeWrite(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "remote-roles",
		Context: cfgovctx.Context{
			Base: corectx.Base{
				Server:      "http://127.0.0.1:8848",
				RolesSource: "url",
				RolesURL:    "https://roles.example/roles.yaml",
			},
			Backend: "nacos",
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "remote-roles.yaml")
	if err := os.WriteFile(importPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"ctx", "import", "--file", importPath,
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNotImplemented {
		t.Fatalf("ctx import error = %v, want not implemented; out=%s", err, out)
	}
	assertContextAbsent(t, configPath, "remote-roles")
}

func TestHistoricalRemoteRolesContextDeniesAuthorizationBeforeBackendMutationAndAudits(t *testing.T) {
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

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("remote-roles", cfgovctx.Context{
		Base: corectx.Base{
			Server:      server.URL,
			RolesSource: "url",
			RolesURL:    "https://roles.example/roles.yaml",
		},
		Backend:   "nacos",
		Namespace: "ns",
	}); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--context", "remote-roles",
		"--yes",
		"--no-backup",
		"config", "push",
		"--key", "app.yaml",
		"--content", "enabled: true",
		"--type", "yaml",
	)
	if err == nil {
		t.Fatalf("config push error = nil, want authorization required; out=%s", out)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("config push error = %v, want authorization required; out=%s", err, out)
	}
	if got := mutations.Load(); got != 0 {
		t.Fatalf("backend mutation calls = %d, want 0", got)
	}

	path, err := audit.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	result, err := audit.Query(path, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range result.Events {
		if event.EventType == audit.EventAuthorizationDenied &&
			event.Status == audit.StatusDenied &&
			event.Context.Name == "remote-roles" {
			return
		}
	}
	t.Fatalf("authorization denied audit missing: %#v", result.Events)
}

func assertContextAbsent(t *testing.T, configPath, name string) {
	t.Helper()
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Contexts[name]; exists {
		t.Fatalf("context %q was written", name)
	}
}
