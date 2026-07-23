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
	"sync/atomic"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/safety"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestValidateRolesURLRejectsUnimplementedRemoteSource(t *testing.T) {
	t.Parallel()
	for _, rawURL := range []string{"https://roles.example/roles.yaml", "http://roles.example/roles.yaml"} {
		err := validateRolesURL("url", rawURL, true)
		if apperrors.AsAppError(err).Code != apperrors.CodeNotImplemented {
			t.Fatalf("validateRolesURL(%q) error = %v, want not implemented", rawURL, err)
		}
	}
	if err := validateRolesURL("inline", "", false); err != nil {
		t.Fatalf("inline roles error = %v", err)
	}
}

func TestVaultCredentialBackendPrevalidationRequiresCleanHTTPSURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "https", addr: "https://vault.example:8200"},
		{name: "https base path", addr: "https://vault.example/base"},
		{name: "http", addr: "http://vault.example:8200", wantErr: true},
		{name: "relative", addr: "vault.example:8200", wantErr: true},
		{name: "userinfo", addr: "https://user:secret@vault.example", wantErr: true},
		{name: "query", addr: "https://vault.example?token=secret", wantErr: true},
		{name: "empty query", addr: "https://vault.example?", wantErr: true},
		{name: "fragment", addr: "https://vault.example/#secret", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			item := cfgovctx.Context{
				Base: corectx.Base{
					CredentialBackend: "vault",
					VaultAddr:         test.addr,
					VaultPath:         "service/prod",
					VaultRoleID:       "role-id",
				},
			}
			err := validateCredentialBackendAvailableWithFactory(item, "secret-id", func(cfgovctx.Context) (credstore.Backend, error) {
				t.Fatal("backend factory must not be called when a process secret id is supplied")
				return nil, nil
			})
			if test.wantErr && apperrors.AsAppError(err).Code != apperrors.CodeCredentialStoreError {
				t.Fatalf("validation error = %v, want credential store error", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validation error = %v", err)
			}
		})
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
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")

	out, err := runCommandForTest(t,
		"--config", configPath,
		"-o", "json",
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
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

func TestCtxMigrateCredentialsDryRun(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("literal", cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848", Password: "secret"}, Backend: "nacos"}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("ref", cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848", Password: credstore.EncodeRef("encrypted-file"), CredentialBackend: "encrypted-file"}, Backend: "nacos"}); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTest(t, "--config", configPath, "-o", "json", "ctx", "migrate-credentials", "--dry-run")
	if err != nil {
		t.Fatalf("ctx migrate-credentials --dry-run error = %v; out=%s", err, out)
	}
	for _, want := range []string{`"kind": "CredentialMigration"`, `"dryRun": true`, `"count": 1`, `"literal"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("migrate dry-run output missing %q: %s", want, out)
		}
	}
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contexts["literal"].Password != "secret" {
		t.Fatalf("dry-run mutated literal credential: %+v", cfg.Contexts["literal"].Base)
	}
}

func TestPlanPreventsContextAndCredentialMutations(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	operator, err := trustedOperator(newDefaultFlags())
	if err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("dev", cfgovctx.Context{
		Base: corectx.Base{
			Server:   "http://127.0.0.1:8848",
			Password: "literal-secret",
			Roles:    map[string]string{"alice": safety.RoleReader, operator: safety.RoleReader},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("prod", cfgovctx.Context{
		Base:    corectx.Base{Server: "http://127.0.0.1:8848"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("dev"); err != nil {
		t.Fatal(err)
	}

	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "imported",
		Context: cfgovctx.Context{
			Base: corectx.Base{
				Server:            "http://127.0.0.1:8848",
				Password:          "import-secret",
				CredentialBackend: "encrypted-file",
			},
			Backend: "nacos",
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "import.yaml")
	if err := os.WriteFile(importPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "set with credential",
			args: []string{
				"--backend", "nacos", "--server", "http://127.0.0.1:8848",
				"ctx", "set", "planned", "--password", "planned-secret", "--credential-backend", "encrypted-file",
			},
		},
		{name: "use", args: []string{"ctx", "use", "prod"}},
		{name: "delete", args: []string{"ctx", "delete", "prod"}},
		{name: "import", args: []string{"ctx", "import", "-f", importPath}},
		{name: "role set", args: []string{"ctx", "role", "set", "dev", "--target-operator", "bob", "--role", "admin"}},
		{name: "role unset", args: []string{"ctx", "role", "unset", "dev", "--target-operator", "alice"}},
		{name: "migrate credentials", args: []string{"--yes", "ctx", "migrate-credentials", "--to", "encrypted-file", "--dry-run"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--config", configPath, "--plan", "-o", "json"}
			out, err := runCommandForTestAtHome(t, home, append(args, tt.args...)...)
			if err != nil {
				t.Fatalf("planned command error = %v; out=%s", err, out)
			}
			if !strings.Contains(out, `"dryRun": true`) {
				t.Fatalf("planned command output missing dryRun=true: %s", out)
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, baseline) {
				t.Fatalf("planned command changed context config:\n%s", after)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
		t.Fatalf("planned context operations created credential file: %v", err)
	}
}

func TestCtxSetPlanRunsReadOnlyConfigAndCredentialValidation(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		home := t.TempDir()
		configPath := filepath.Join(home, "config.yaml")
		original := []byte("contexts: [\n")
		if err := os.WriteFile(configPath, original, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runCommandForTestAtHome(t, home,
			"--config", configPath,
			"--backend", "nacos",
			"--server", "http://127.0.0.1:8848",
			"--plan",
			"-o", "json",
			"ctx", "set", "planned",
		)
		if err == nil {
			t.Fatalf("ctx set plan accepted invalid config; out=%s", out)
		}
		after, readErr := os.ReadFile(configPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(after, original) {
			t.Fatalf("ctx set plan changed invalid config: %q", after)
		}
	})

	t.Run("invalid credential backend matches apply failure", func(t *testing.T) {
		planHome := t.TempDir()
		planPath := filepath.Join(planHome, "config.yaml")
		_, planErr := runCommandForTestAtHome(t, planHome,
			"--config", planPath,
			"--backend", "nacos",
			"--server", "http://127.0.0.1:8848",
			"--plan",
			"ctx", "set", "planned",
			"--credential-backend", "does-not-exist",
		)
		if planErr == nil {
			t.Fatal("ctx set plan accepted invalid credential backend")
		}

		applyHome := t.TempDir()
		applyPath := filepath.Join(applyHome, "config.yaml")
		_, applyErr := runCommandForTestAtHome(t, applyHome,
			"--config", applyPath,
			"--backend", "nacos",
			"--server", "http://127.0.0.1:8848",
			"ctx", "set", "planned",
			"--credential-backend", "does-not-exist",
		)
		if applyErr == nil {
			t.Fatal("ctx set apply accepted invalid credential backend")
		}
		if got, want := apperrors.AsAppError(planErr).Code, apperrors.AsAppError(applyErr).Code; got != want {
			t.Fatalf("plan error code = %s, apply error code = %s", got, want)
		}
		if _, err := os.Stat(planPath); !os.IsNotExist(err) {
			t.Fatalf("ctx set plan created config: %v", err)
		}
		if _, err := os.Stat(filepath.Join(planHome, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
			t.Fatalf("ctx set plan created credential file: %v", err)
		}
	})

	t.Run("unavailable credential backend", func(t *testing.T) {
		home := t.TempDir()
		configPath := filepath.Join(home, "config.yaml")
		t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "")
		_, err := runCommandForTestAtHome(t, home,
			"--config", configPath,
			"--backend", "nacos",
			"--server", "http://127.0.0.1:8848",
			"--plan",
			"ctx", "set", "planned",
			"--credential-backend", "encrypted-file",
		)
		if err == nil {
			t.Fatal("ctx set plan accepted unavailable encrypted-file backend")
		}
		if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
			t.Fatalf("ctx set plan created config: %v", statErr)
		}
		if _, statErr := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(statErr) {
			t.Fatalf("ctx set plan created credential file: %v", statErr)
		}
	})
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func TestCtxSetVaultPlanAndApplyParity(t *testing.T) {
	tests := []struct {
		name              string
		appRole           bool
		expectedRequests  int32
		expectedAuthToken string
	}{
		{name: "token", expectedRequests: 2, expectedAuthToken: "vault-token"},
		{name: "app role flag", appRole: true, expectedRequests: 3, expectedAuthToken: "client-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch r.URL.Path {
				case "/v1/auth/approle/login":
					if !tt.appRole || r.Method != http.MethodPost {
						t.Errorf("unexpected AppRole request: %s %s", r.Method, r.URL.Path)
						http.Error(w, "unexpected", http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`{"auth":{"client_token":"client-token"}}`))
				case "/v1/secret/data/team/app":
					if r.Method == http.MethodGet {
						http.NotFound(w, r)
						return
					}
					if r.Method != http.MethodPost {
						t.Errorf("secret method = %s, want GET or POST", r.Method)
						http.Error(w, "unexpected", http.StatusBadRequest)
						return
					}
					if got := r.Header.Get("X-Vault-Token"); got != tt.expectedAuthToken {
						t.Errorf("X-Vault-Token = %q, want %q", got, tt.expectedAuthToken)
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected Vault path: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			defaultTransport := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = defaultTransport }()

			home := t.TempDir()
			configPath := filepath.Join(home, "config.yaml")
			t.Setenv("VAULT_TOKEN", "")
			t.Setenv("VAULT_SECRET_ID", "")
			if !tt.appRole {
				t.Setenv("VAULT_TOKEN", "vault-token")
			}
			common := []string{
				"--config", configPath,
				"--yes",
				"--ticket", "TEST-1",
				"--allow-context-change",
				"--backend", "nacos",
				"--server", "http://127.0.0.1:8848",
				"-o", "json",
				"ctx", "set", "vault-context",
				"--password", "stored-secret",
				"--credential-backend", "vault",
				"--vault-addr", server.URL,
				"--vault-path", "team/app",
			}
			if tt.appRole {
				common = append(common, "--vault-role-id", "role-id", "--vault-secret-id", "flag-secret-id")
			}

			planArgs := append([]string{"--plan"}, common...)
			out, err := runCommandForTestAtHome(t, home, planArgs...)
			if err != nil {
				t.Fatalf("ctx set Vault plan error = %v; out=%s", err, out)
			}
			if requests.Load() != 0 {
				t.Fatalf("Vault plan requests = %d, want 0", requests.Load())
			}
			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				t.Fatalf("Vault plan created context config: %v", err)
			}
			if tt.appRole && os.Getenv("VAULT_SECRET_ID") != "" {
				t.Fatalf("Vault AppRole plan polluted VAULT_SECRET_ID: %q", os.Getenv("VAULT_SECRET_ID"))
			}

			out, err = runCommandForTestAtHome(t, home, common...)
			if err != nil {
				t.Fatalf("ctx set Vault apply error = %v; out=%s", err, out)
			}
			if requests.Load() != tt.expectedRequests {
				t.Fatalf("Vault apply requests = %d, want %d", requests.Load(), tt.expectedRequests)
			}
			if tt.appRole && os.Getenv("VAULT_SECRET_ID") != "flag-secret-id" {
				t.Fatalf("Vault AppRole apply VAULT_SECRET_ID = %q", os.Getenv("VAULT_SECRET_ID"))
			}
			cfgovctx.SetConfigPath(configPath)
			cfg, err := cfgovctx.Load()
			if err != nil {
				t.Fatal(err)
			}
			item := cfg.Contexts["vault-context"]
			ref := credstore.ParseRef(item.Password)
			if item.CredentialBackend != "vault" || !ref.IsRef || ref.BackendName != "vault" {
				t.Fatalf("stored Vault credential reference = %#v, context=%+v", ref, item)
			}
			t.Cleanup(func() { cfgovctx.SetConfigPath("") })
		})
	}
}

func TestCtxRoleLifecycleAndRBAC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	cfgovctx.SetConfigPath(filepath.Join(dir, "config.yaml"))
	f := newDefaultFlags()
	operator, err := trustedOperator(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("dev", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}

	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowRoleChange = true
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
	if len(roles) != 2 {
		t.Fatalf("role items = %#v", roles)
	}

	writer := newDefaultFlags()
	writer.Operator = "alice"
	writer.Yes = true
	spoofedMeta := cfg.Contexts["dev"]
	spoofedMeta.Roles = map[string]string{
		"alice":  safety.RoleAdmin,
		operator: safety.RoleReader,
	}
	if err := authorize(writer, safety.R1, spoofedMeta, ""); apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("reader write authorize error = %v, want authorization required", err)
	}

	if err := runCtxRoleUnset(f, "dev", roleOptions{targetOperator: "alice"}); err != nil {
		t.Fatalf("runCtxRoleUnset error = %v", err)
	}
	cfg, err = cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Contexts["dev"].Roles["alice"]; exists {
		t.Fatalf("roles after unset = %#v, want alice removed", cfg.Contexts["dev"].Roles)
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
	home := t.TempDir()
	return runCommandForTestAtHome(t, home, args...)
}

func runCommandForTestAtHome(t *testing.T, home string, args ...string) (string, error) {
	t.Helper()
	prepareMutationAuditTestParent(t, home)
	t.Setenv("NO_COLOR", "1")
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
	var buf bytes.Buffer
	readDone := make(chan error, 1)
	go func() {
		_, readErr := buf.ReadFrom(reader)
		readDone <- readErr
	}()
	runErr := cmd.Execute()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("Close(writer) error = %v", closeErr)
	}
	os.Stdout = oldStdout
	if err := <-readDone; err != nil {
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
