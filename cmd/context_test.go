package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
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
