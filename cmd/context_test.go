package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"
	"github.com/JiangHe12/opskit-core/safety"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestValidateRolesURLRejectsHTTPByDefault(t *testing.T) {
	t.Parallel()
	err := validateRolesURL("url", "http://roles.example/roles.yaml", false)
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
	if err := validateRolesURL("url", "http://roles.example/roles.yaml", true); err != nil {
		t.Fatalf("allow insecure roles URL error = %v", err)
	}
}

func TestCtxSetRejectsPlainCredential(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	f := newDefaultFlags()
	cmd := newRootCmdWith(f)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"--password", "secret",
		"ctx", "set", "dev",
	})
	err := cmd.Execute()
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestCtxSetStoresPasswordCredentialReference(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("CFGOV_CLI_CREDENTIAL_PASSPHRASE", "test-passphrase")

	out, err := runCommandForTest(t,
		"--config", configPath,
		"-o", "json",
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"--username", "nacos",
		"ctx", "set", "dev",
		"--password", "secret",
		"--credential-backend", "encrypted-file",
	)
	if err != nil {
		t.Fatalf("ctx set error = %v; out=%s", err, out)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatalf("context file leaked credential: %s", data)
	}
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	item := cfg.Contexts["dev"]
	if item.Username != "nacos" {
		t.Fatalf("username = %q, want nacos", item.Username)
	}
	ref := credstore.ParseRef(item.Password)
	if !ref.IsRef || ref.BackendName != "encrypted-file" {
		t.Fatalf("password ref = %#v; raw=%q", ref, item.Password)
	}
}

func TestNacosUsesCFGOVPasswordForCurrentContext(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_PASSWORD", "env-secret")
	server := nacosAuthServer(t, "nacos", "env-secret")
	defer server.Close()

	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: server.URL, Username: "nacos"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("prod"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "-o", "json", "config", "list")
	if err != nil {
		t.Fatalf("config list with CFGOV_PASSWORD error = %v; out=%s", err, out)
	}
}

func TestNacosUsesCFGOVPasswordForContextOverride(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_PASSWORD", "override-secret")
	server := nacosAuthServer(t, "prod-user", "override-secret")
	defer server.Close()

	if err := cfgovctx.Set("dev", cfgovctx.Context{
		Base:    corectx.Base{Server: "http://127.0.0.1:1", Username: "dev-user", Password: "dev-secret"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: server.URL, Username: "prod-user"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("dev"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "--context", "prod", "-o", "json", "config", "list")
	if err != nil {
		t.Fatalf("config list with --context prod and CFGOV_PASSWORD error = %v; out=%s", err, out)
	}
}

func TestNacosServerURLUserInfoStillWorks(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	server := nacosAuthServer(t, "url-user", "url-pass")
	defer server.Close()

	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: serverURLWithUserInfo(t, server.URL, "url-user", "url-pass")},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("prod"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "-o", "json", "config", "list")
	if err != nil {
		t.Fatalf("config list with URL userinfo error = %v; out=%s", err, out)
	}
}

func TestNacosExplicitCredentialsOverrideServerURLUserInfo(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_PASSWORD", "env-pass")
	server := nacosAuthServer(t, "flag-user", "env-pass")
	defer server.Close()

	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: serverURLWithUserInfo(t, server.URL, "url-user", "url-pass"), Username: "flag-user"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("prod"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "-o", "json", "config", "list")
	if err != nil {
		t.Fatalf("config list with explicit credentials over URL userinfo error = %v; out=%s", err, out)
	}
}

func TestNacosRuntimePasswordFlagOverridesServerURLUserInfo(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	server := nacosAuthServer(t, "url-user", "flag-pass")
	defer server.Close()

	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: serverURLWithUserInfo(t, server.URL, "url-user", "url-pass")},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("prod"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "--password", "flag-pass", "-o", "json", "config", "list")
	if err != nil {
		t.Fatalf("config list with runtime --password over URL userinfo error = %v; out=%s", err, out)
	}
}

func TestSharedResolvePasswordIgnoresCFGOVPassword(t *testing.T) {
	t.Setenv("CFGOV_PASSWORD", "nacos-only")
	resolved, err := cfgovctx.ResolvePassword(context.Background(), "apollo", cfgovctx.Context{Backend: "apollo"})
	if err != nil {
		t.Fatalf("ResolvePassword() error = %v", err)
	}
	if resolved != "" {
		t.Fatalf("ResolvePassword() = %q, want empty outside Nacos auth wiring", resolved)
	}
}

func TestCtxExportRedactsCredentialByDefault(t *testing.T) {
	cfgovctx.SetConfigPath(filepath.Join(t.TempDir(), "config.yaml"))
	if err := cfgovctx.Set("dev", cfgovctx.Context{
		Base:    corectx.Base{Server: "http://127.0.0.1:8848", Password: "secret", CredentialBackend: "plain-yaml"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runCtxExport(newDefaultFlags(), "dev", false); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "secret") {
		t.Fatalf("export leaked credential: %s", out)
	}
	if !strings.Contains(out, redactedCredential) {
		t.Fatalf("export missing redaction marker: %s", out)
	}
}

func TestCtxImportDoesNotOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	cfgovctx.SetConfigPath(filepath.Join(dir, "config.yaml"))
	if err := cfgovctx.Set("dev", cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848"}, Backend: "nacos"}); err != nil {
		t.Fatal(err)
	}
	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "dev",
		Context:    cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848"}, Backend: "nacos"},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ctx.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	err = runCtxImport(newDefaultFlags(), path, "", false)
	if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestCtxRoleLifecycleAndRBAC(t *testing.T) {
	dir := t.TempDir()
	cfgovctx.SetConfigPath(filepath.Join(dir, "config.yaml"))
	if err := cfgovctx.Set("dev", cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848"}, Backend: "nacos"}); err != nil {
		t.Fatal(err)
	}

	f := newDefaultFlags()
	if err := runCtxRoleSet(f, "dev", roleOptions{targetOperator: "alice", role: safety.RoleReader}); err != nil {
		t.Fatalf("runCtxRoleSet error = %v", err)
	}
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contexts["dev"].Roles["alice"] != safety.RoleReader {
		t.Fatalf("roles = %#v", cfg.Contexts["dev"].Roles)
	}
	roles := roleItems(cfg.Contexts["dev"].Roles)
	if len(roles) != 1 || roles[0].Operator != "alice" || roles[0].Role != safety.RoleReader {
		t.Fatalf("role items = %#v", roles)
	}

	writer := newDefaultFlags()
	writer.Operator = "alice"
	writer.Yes = true
	if err := authorize(writer, safety.R1, cfg.Contexts["dev"], ""); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("reader write authorize error = %v, want authorization required", err)
	}

	if err := runCtxRoleUnset(f, "dev", roleOptions{targetOperator: "alice"}); err != nil {
		t.Fatalf("runCtxRoleUnset error = %v", err)
	}
	cfg, err = cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contexts["dev"].Roles != nil {
		t.Fatalf("roles after unset = %#v, want nil", cfg.Contexts["dev"].Roles)
	}
}

func nacosAuthServer(t *testing.T, wantUser, wantPassword string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nacos/v1/auth/login":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s, want POST", r.Method)
				http.NotFound(w, r)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if gotUser, gotPassword := r.Form.Get("username"), r.Form.Get("password"); gotUser != wantUser || gotPassword != wantPassword {
				t.Errorf("login credentials = %q/%q, want %q/%q", gotUser, gotPassword, wantUser, wantPassword)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"test-token","tokenTtl":18000}`))
		case "/nacos/v1/cs/configs":
			if r.Method != http.MethodGet {
				t.Errorf("configs method = %s, want GET", r.Method)
				http.NotFound(w, r)
				return
			}
			if got := r.URL.Query().Get("accessToken"); got != "test-token" {
				t.Errorf("accessToken = %q, want test-token", got)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"totalCount":0,"pageNumber":1,"pagesAvailable":0,"pageItems":[]}`))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func serverURLWithUserInfo(t *testing.T, rawURL, username, password string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String()
}

func runCommandForTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}
	os.Stdout = writer
	runErr := cmd.Execute()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("Close(writer) error = %v", closeErr)
	}
	os.Stdout = oldStdout
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(reader); err != nil {
		t.Fatalf("ReadFrom(stdout) error = %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close(reader) error = %v", err)
	}
	return buf.String(), runErr
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
