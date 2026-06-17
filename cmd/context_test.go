package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	corectx "github.com/JiangHe12/opskit-core/ctx"
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
