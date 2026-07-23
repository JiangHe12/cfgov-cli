package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/safety"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestCtxSetUsesPersistedPreChangePolicyAndIgnoresSpoofedOperator(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name        string
		target      string
		targetRoles map[string]string
		currentRole string
	}{
		{
			name:        "new target uses current context policy",
			target:      "new-target",
			currentRole: safety.RoleReader,
		},
		{
			name:        "existing target uses its own policy",
			target:      "existing-target",
			currentRole: safety.RoleAdmin,
			targetRoles: map[string]string{operator: safety.RoleReader, "spoofed-admin": safety.RoleAdmin},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			configPath := filepath.Join(home, "config.yaml")
			cfgovctx.SetConfigPath(configPath)
			t.Cleanup(func() { cfgovctx.SetConfigPath("") })
			t.Setenv(cfgovOperatorEnv, "spoofed-admin")
			current := cfgovctx.Context{
				Base: corectx.Base{
					Server: "http://127.0.0.1:8848",
					Roles: map[string]string{
						operator:        tt.currentRole,
						"spoofed-admin": safety.RoleAdmin,
					},
				},
				Backend: "nacos",
			}
			if err := cfgovctx.Set("guard", current); err != nil {
				t.Fatal(err)
			}
			if err := cfgovctx.Use("guard"); err != nil {
				t.Fatal(err)
			}
			if tt.targetRoles != nil {
				if err := cfgovctx.Set(tt.target, cfgovctx.Context{
					Base:    corectx.Base{Server: "http://127.0.0.1:8848", Roles: tt.targetRoles},
					Backend: "nacos",
				}); err != nil {
					t.Fatal(err)
				}
			}

			out, err := runCommandForTestAtHome(t, home,
				"--config", configPath,
				"--operator", "spoofed-admin",
				"--yes",
				"--ticket", "TEST-1",
				"--allow-context-change",
				"--backend", "nacos",
				"--server", "http://127.0.0.1:8848",
				"ctx", "set", tt.target,
			)
			if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
				t.Fatalf("ctx set error = %v, want authorization required; out=%s", err, out)
			}
			cfg, err := cfgovctx.Load()
			if err != nil {
				t.Fatal(err)
			}
			if tt.targetRoles == nil {
				if _, exists := cfg.Contexts[tt.target]; exists {
					t.Fatalf("denied ctx set created %q", tt.target)
				}
			} else if got := cfg.Contexts[tt.target].Roles[operator]; got != safety.RoleReader {
				t.Fatalf("denied ctx set replaced target policy: role=%q", got)
			}
		})
	}
}

func TestCtxUseCannotSwitchFromStrongPolicyToWeakPolicy(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv(cfgovOperatorEnv, "spoofed-admin")
	if err := cfgovctx.Set("strong", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles: map[string]string{
				operator:        safety.RoleReader,
				"spoofed-admin": safety.RoleAdmin,
			},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("weak", cfgovctx.Context{
		Base:    corectx.Base{Server: "http://127.0.0.1:8848"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("strong"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--plan",
		"ctx", "use", "weak",
	)
	if err != nil {
		t.Fatalf("ctx use plan error = %v; out=%s", err, out)
	}
	if current := mustLoadContexts(t).CurrentContext; current != "strong" {
		t.Fatalf("ctx use plan changed current context to %q", current)
	}

	out, err = runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--operator", "spoofed-admin",
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "use", "weak",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx use error = %v, want authorization required; out=%s", err, out)
	}
	if current := mustLoadContexts(t).CurrentContext; current != "strong" {
		t.Fatalf("denied ctx use changed current context to %q", current)
	}
}

func TestCtxUseWithoutCurrentContextUsesTargetPolicy(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleReader},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "use", "target",
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx use error = %v, want target-policy denial; out=%s", err, out)
	}
	if current := mustLoadContexts(t).CurrentContext; current != "" {
		t.Fatalf("denied ctx use set current context to %q", current)
	}
}

func TestCtxUseWithAuthorizedOldPolicyChangesCurrentContext(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("old", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Set("next", cfgovctx.Context{Base: corectx.Base{Server: "http://127.0.0.1:8848"}, Backend: "nacos"}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("old"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "use", "next",
	)
	if err != nil {
		t.Fatalf("authorized ctx use error = %v; out=%s", err, out)
	}
	if current := mustLoadContexts(t).CurrentContext; current != "next" {
		t.Fatalf("authorized ctx use current context = %q", current)
	}
}

func TestContextDeleteAndRoleChangeRequireTheirExactAllowFlags(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	item := cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}
	if err := cfgovctx.Set("prod", item); err != nil {
		t.Fatal(err)
	}

	common := []string{"--config", configPath, "--yes", "--ticket", "TEST-1"}
	out, err := runCommandForTestAtHome(t, home, append(common,
		"--allow-context-change",
		"ctx", "delete", "prod",
	)...)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx delete with wrong allow error = %v; out=%s", err, out)
	}
	if _, ok := mustLoadContexts(t).Contexts["prod"]; !ok {
		t.Fatal("ctx delete with wrong allow removed prod")
	}

	out, err = runCommandForTestAtHome(t, home, append(common,
		"--allow-context-change",
		"ctx", "role", "set", "prod",
		"--target-operator", "reader@host",
		"--role", safety.RoleReader,
	)...)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("role set with wrong allow error = %v; out=%s", err, out)
	}
	if _, ok := mustLoadContexts(t).Contexts["prod"].Roles["reader@host"]; ok {
		t.Fatal("role set with wrong allow changed roles")
	}

	out, err = runCommandForTestAtHome(t, home, append(common,
		"--allow-role-change",
		"ctx", "role", "set", "prod",
		"--target-operator", "reader@host",
		"--role", safety.RoleReader,
	)...)
	if err != nil {
		t.Fatalf("role set with exact allow error = %v; out=%s", err, out)
	}
	if got := mustLoadContexts(t).Contexts["prod"].Roles["reader@host"]; got != safety.RoleReader {
		t.Fatalf("assigned role = %q", got)
	}

	out, err = runCommandForTestAtHome(t, home, append(common,
		"--allow-context-delete",
		"ctx", "delete", "prod",
	)...)
	if err != nil {
		t.Fatalf("ctx delete with exact allow error = %v; out=%s", err, out)
	}
	if _, ok := mustLoadContexts(t).Contexts["prod"]; ok {
		t.Fatal("ctx delete with exact allow left prod")
	}
}

func TestDeniedContextImportDoesNotWriteCredentialOrContext(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	guard := cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleReader, "spoofed-admin": safety.RoleAdmin},
		},
		Backend: "nacos",
	}
	if err := cfgovctx.Set("guard", guard); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("guard"); err != nil {
		t.Fatal(err)
	}
	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "imported",
		Context: cfgovctx.Context{
			Base: corectx.Base{
				Server:            "http://127.0.0.1:8848",
				Password:          "secret",
				CredentialBackend: credentialBackendEncrypted,
			},
			Backend: "nacos",
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "context.yaml")
	if err := os.WriteFile(importPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--operator", "spoofed-admin",
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "import", "--file", importPath,
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx import error = %v, want authorization required; out=%s", err, out)
	}
	if _, ok := mustLoadContexts(t).Contexts["imported"]; ok {
		t.Fatal("denied ctx import wrote context")
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
		t.Fatalf("denied ctx import wrote credential store: %v", err)
	}
}

func TestAuthorizedContextImportStoresCredentialAfterAuthorization(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	if err := cfgovctx.Set("guard", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("guard"); err != nil {
		t.Fatal(err)
	}
	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "imported",
		Context: cfgovctx.Context{
			Base: corectx.Base{
				Server:            "http://127.0.0.1:8848",
				Password:          "secret",
				CredentialBackend: credentialBackendEncrypted,
			},
			Backend: "nacos",
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "context.yaml")
	if err := os.WriteFile(importPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "import", "--file", importPath,
	)
	if err != nil {
		t.Fatalf("authorized ctx import error = %v; out=%s", err, out)
	}
	item := mustLoadContexts(t).Contexts["imported"]
	ref := credstore.ParseRef(item.Password)
	if !ref.IsRef || ref.BackendName != credentialBackendEncrypted {
		t.Fatalf("imported credential reference = %#v", ref)
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); err != nil {
		t.Fatalf("authorized ctx import did not write credential store: %v", err)
	}
}

func TestCredentialMigrationAuthorizesAllContextsBeforeAnyWrite(t *testing.T) {
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	for name, role := range map[string]string{
		"a-authorized": safety.RoleAdmin,
		"b-denied":     safety.RoleReader,
	} {
		if err := cfgovctx.Set(name, cfgovctx.Context{
			Base: corectx.Base{
				Server:   "http://127.0.0.1:8848",
				Password: name + "-secret",
				Roles:    map[string]string{operator: role},
			},
			Backend: "nacos",
		}); err != nil {
			t.Fatal(err)
		}
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "migrate-credentials",
		"--to", credentialBackendEncrypted,
	)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("credential migration error = %v, want authorization required; out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
		t.Fatalf("denied migration wrote credential store: %v", err)
	}
	cfg := mustLoadContexts(t)
	for _, name := range []string{"a-authorized", "b-denied"} {
		if ref := credstore.ParseRef(cfg.Contexts[name].Password); ref.IsRef {
			t.Fatalf("denied migration changed %s to credential ref %#v", name, ref)
		}
	}
}

func TestCtxSetRechecksChangedPolicyInsideAtomicUpdate(t *testing.T) {
	const operator = "trusted-user@trusted-host"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://old.example:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}

	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.beforeContextUpdate = func() {
		if err := cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
			item := cfg.Contexts["target"]
			item.Roles = map[string]string{operator: safety.RoleReader}
			cfg.Contexts["target"] = item
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--config", configPath,
		"--backend", "nacos",
		"--server", "http://new.example:8848",
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-change",
		"ctx", "set", "target",
	})
	err := cmd.Execute()
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx set error = %v, want authorization required", err)
	}
	item := mustLoadContexts(t).Contexts["target"]
	if item.Server != "http://old.example:8848" || item.Roles[operator] != safety.RoleReader {
		t.Fatalf("target after denied raced update = %+v", item.Base)
	}
}

func TestCredentialMigrationRechecksAllPoliciesInsideAtomicUpdate(t *testing.T) {
	const operator = "trusted-user@trusted-host"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server:   "http://127.0.0.1:8848",
			Password: "literal-secret",
			Roles:    map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}

	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowCtxChange = true
	f.beforeContextUpdate = func() {
		if err := cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
			item := cfg.Contexts["target"]
			item.Roles = map[string]string{operator: safety.RoleReader}
			cfg.Contexts["target"] = item
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	err := runCtxMigrateCredentials(f, migrateCredentialsOptions{
		toBackend:   credentialBackendEncrypted,
		contextName: "target",
	})
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("credential migration error = %v, want authorization required", err)
	}
	item := mustLoadContexts(t).Contexts["target"]
	if item.Password != "literal-secret" || item.Roles[operator] != safety.RoleReader {
		t.Fatalf("target after denied raced migration = %+v", item.Base)
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
		t.Fatalf("denied raced migration wrote credential store: %v", err)
	}
}

func TestCtxDeleteRechecksChangedPolicyInsideAtomicUpdate(t *testing.T) {
	const operator = "trusted-user@trusted-host"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://127.0.0.1:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.beforeContextUpdate = downgradeContextRoleHook(t, "target", operator)
	cmd := newRootCmdWith(f)
	cmd.SetArgs([]string{
		"--config", configPath,
		"--yes",
		"--ticket", "TEST-1",
		"--allow-context-delete",
		"ctx", "delete", "target",
	})
	err := cmd.Execute()
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx delete error = %v, want authorization required", err)
	}
	if _, exists := mustLoadContexts(t).Contexts["target"]; !exists {
		t.Fatal("denied raced ctx delete removed target")
	}
}

func TestCtxRoleChangesRecheckChangedPolicyInsideAtomicUpdate(t *testing.T) {
	const operator = "trusted-user@trusted-host"
	for _, tt := range []struct {
		name   string
		action func(*cliFlags) error
	}{
		{
			name: "set",
			action: func(f *cliFlags) error {
				return runCtxRoleSet(f, "target", roleOptions{targetOperator: "new-reader", role: safety.RoleReader})
			},
		},
		{
			name: "unset",
			action: func(f *cliFlags) error {
				return runCtxRoleUnset(f, "target", roleOptions{targetOperator: "existing-reader"})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			configPath := filepath.Join(home, "config.yaml")
			cfgovctx.SetConfigPath(configPath)
			t.Cleanup(func() { cfgovctx.SetConfigPath("") })
			if err := cfgovctx.Set("target", cfgovctx.Context{
				Base: corectx.Base{
					Server: "http://127.0.0.1:8848",
					Roles: map[string]string{
						operator:          safety.RoleAdmin,
						"existing-reader": safety.RoleReader,
					},
				},
				Backend: "nacos",
			}); err != nil {
				t.Fatal(err)
			}
			f := newDefaultFlags()
			f.resolveOperator = func() (string, error) { return operator, nil }
			f.Yes = true
			f.Ticket = "TEST-1"
			f.AllowRoleChange = true
			f.beforeContextUpdate = func() {
				if err := cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
					item := cfg.Contexts["target"]
					item.Roles[operator] = safety.RoleReader
					cfg.Contexts["target"] = item
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := tt.action(f)
			if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
				t.Fatalf("role %s error = %v, want authorization required", tt.name, err)
			}
			roles := mustLoadContexts(t).Contexts["target"].Roles
			if _, exists := roles["new-reader"]; exists {
				t.Fatal("denied raced role set added new-reader")
			}
			if roles["existing-reader"] != safety.RoleReader {
				t.Fatal("denied raced role unset removed existing-reader")
			}
		})
	}
}

func TestCtxImportRechecksChangedPolicyInsideAtomicUpdate(t *testing.T) {
	const operator = "trusted-user@trusted-host"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	if err := cfgovctx.Set("target", cfgovctx.Context{
		Base: corectx.Base{
			Server: "http://old.example:8848",
			Roles:  map[string]string{operator: safety.RoleAdmin},
		},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	doc := contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       "target",
		Context: cfgovctx.Context{
			Base:    corectx.Base{Server: "http://new.example:8848"},
			Backend: "nacos",
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "context.yaml")
	if err := os.WriteFile(importPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f := newDefaultFlags()
	f.resolveOperator = func() (string, error) { return operator, nil }
	f.Yes = true
	f.Ticket = "TEST-1"
	f.AllowCtxChange = true
	f.beforeContextUpdate = downgradeContextRoleHook(t, "target", operator)
	err = runCtxImport(f, importPath, "", true)
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("ctx import error = %v, want authorization required", err)
	}
	item := mustLoadContexts(t).Contexts["target"]
	if item.Server != "http://old.example:8848" || item.Roles[operator] != safety.RoleReader {
		t.Fatalf("target after denied raced import = %+v", item.Base)
	}
}

func TestContextPreChangePolicyUsesTargetThenCurrentThenBootstrap(t *testing.T) {
	target := cfgovctx.Context{Backend: "target"}
	current := cfgovctx.Context{Backend: "current"}
	cfg := &corectx.Config[cfgovctx.Context]{
		CurrentContext: "guard",
		Contexts: map[string]cfgovctx.Context{
			"guard":  current,
			"target": target,
		},
	}
	if got, err := contextPreChangePolicy(cfg, "target"); err != nil || got.Backend != "target" {
		t.Fatalf("existing target policy = %+v, err=%v", got, err)
	}
	if got, err := contextPreChangePolicy(cfg, "new"); err != nil || got.Backend != "current" {
		t.Fatalf("new target policy = %+v, err=%v", got, err)
	}
	cfg.CurrentContext = ""
	if got, err := contextPreChangePolicy(cfg, "new"); err != nil || !reflect.DeepEqual(got, cfgovctx.Context{}) {
		t.Fatalf("bootstrap policy = %+v, err=%v", got, err)
	}
	cfg.CurrentContext = "missing"
	if _, err := contextPreChangePolicy(cfg, "new"); apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("missing current policy error = %v", err)
	}
}

func TestContextImportRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	valid := `apiVersion: cfgov-cli.io/ctx-export/v1
name: imported
context:
  backend: nacos
  server: http://127.0.0.1:8848
`
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "unknown top-level field",
			content: valid + `unexpected: true
`,
		},
		{
			name: "unknown context field",
			content: `apiVersion: cfgov-cli.io/ctx-export/v1
name: imported
context:
  backend: nacos
  server: http://127.0.0.1:8848
  unexpected: true
`,
		},
		{
			name:    "second document",
			content: valid + "---\n" + valid,
		},
		{
			name:    "empty second document",
			content: valid + "---\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "context.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readContextExportDocument(path)
			if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
				t.Fatalf("error = %v, want usage error", err)
			}
		})
	}
}

func TestContextImportStrictDecoderAcceptsOneKnownDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.yaml")
	content := `apiVersion: cfgov-cli.io/ctx-export/v1
name: imported
context:
  backend: nacos
  server: http://127.0.0.1:8848
# trailing comments do not create a second document
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := readContextExportDocument(path)
	if err != nil {
		t.Fatalf("readContextExportDocument() error = %v", err)
	}
	if doc.Name != "imported" || doc.Context.Backend != "nacos" {
		t.Fatalf("document = %#v", doc)
	}
}

func TestValidatePortableContextRejectsInvalidGovernanceMetadata(t *testing.T) {
	base := func() cfgovctx.Context {
		return cfgovctx.Context{
			Base:    corectx.Base{Server: "http://127.0.0.1:8848"},
			Backend: "nacos",
		}
	}
	tests := []struct {
		name   string
		mutate func(*cfgovctx.Context)
	}{
		{
			name: "unknown credential backend",
			mutate: func(item *cfgovctx.Context) {
				item.CredentialBackend = "does-not-exist"
			},
		},
		{
			name: "invalid ticket pattern",
			mutate: func(item *cfgovctx.Context) {
				item.TicketPattern = "["
			},
		},
		{
			name: "empty role operator",
			mutate: func(item *cfgovctx.Context) {
				item.Roles = map[string]string{"": safety.RoleAdmin}
			},
		},
		{
			name: "whitespace role operator",
			mutate: func(item *cfgovctx.Context) {
				item.Roles = map[string]string{"   ": safety.RoleAdmin}
			},
		},
		{
			name: "unknown role",
			mutate: func(item *cfgovctx.Context) {
				item.Roles = map[string]string{"operator@host": "owner"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := base()
			tt.mutate(&item)
			if err := validatePortableContext(item); err == nil {
				t.Fatal("validatePortableContext() error = nil, want rejection")
			}
		})
	}
}

func TestValidatePortableContextRejectsUnavailableCredentialBackend(t *testing.T) {
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "")
	item := cfgovctx.Context{
		Base: corectx.Base{
			Server:            "http://127.0.0.1:8848",
			CredentialBackend: credentialBackendEncrypted,
		},
		Backend: "nacos",
	}
	err := validatePortableContext(item)
	if apperrors.AsAppError(err).Code != apperrors.CodeCredentialStoreError {
		t.Fatalf("error = %v, want credential store error", err)
	}
}

func TestPrepareImportedCredentialRejectsEmptyReferenceBackend(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{name: "empty", password: "credstore:"},
		{name: "spaces", password: "credstore:   "},
		{name: "tab", password: "credstore:\t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := cfgovctx.Context{
				Base:    corectx.Base{Password: tt.password},
				Backend: "nacos",
			}
			_, _, err := planImportedCredential("imported", item)
			if apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
				t.Fatalf("error = %v, want usage error", err)
			}
			if item.CredentialBackend != "" {
				t.Fatalf("credential backend = %q, want unchanged empty value", item.CredentialBackend)
			}
		})
	}
}

func TestPortableContextLegalCredentialReferenceValidationDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CFGOV_CREDENTIAL_PASSPHRASE", "test-passphrase")
	item := cfgovctx.Context{
		Base: corectx.Base{
			Server:        "http://127.0.0.1:8848",
			Password:      credstore.EncodeRef(credentialBackendEncrypted),
			TicketPattern: `^OPS-\d+$`,
			Roles:         map[string]string{"operator@example": safety.RoleAdmin},
		},
		Backend: "nacos",
	}
	prepared, _, err := planImportedCredential("imported", item)
	if err != nil {
		t.Fatalf("planImportedCredential() error = %v", err)
	}
	item = prepared
	if err := validatePortableContext(item); err != nil {
		t.Fatalf("validatePortableContext() error = %v", err)
	}
	if item.CredentialBackend != credentialBackendEncrypted {
		t.Fatalf("credential backend = %q", item.CredentialBackend)
	}
	if _, err := os.Stat(filepath.Join(home, ".cfgov-cli", "credentials.enc")); !os.IsNotExist(err) {
		t.Fatalf("portable validation wrote credential store: %v", err)
	}
}

func mustLoadContexts(t *testing.T) *corectx.Config[cfgovctx.Context] {
	t.Helper()
	cfg, err := cfgovctx.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func downgradeContextRoleHook(t *testing.T, contextName, operator string) func() {
	t.Helper()
	return func() {
		if err := cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
			item := cfg.Contexts[contextName]
			item.Roles = map[string]string{operator: safety.RoleReader}
			cfg.Contexts[contextName] = item
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
