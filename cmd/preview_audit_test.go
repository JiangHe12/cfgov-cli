package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func TestGlobalPreviewFlagsWriteOneExplicitAuditWithoutBackendMutation(t *testing.T) {
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

	for _, flag := range []string{"--plan", "--dry-run"} {
		t.Run(flag, func(t *testing.T) {
			home := t.TempDir()
			configPath := filepath.Join(home, "config.yaml")
			out, err := runCommandForTestAtHome(t, home,
				"--config", configPath,
				"--backend", "nacos",
				"--server", server.URL,
				"--namespace", "ns",
				flag,
				"-o", "json",
				"config", "push",
				"--key", "app.yaml",
				"--content", "enabled: true",
				"--type", "yaml",
			)
			if err != nil {
				t.Fatalf("config push %s error = %v; out=%s", flag, err, out)
			}
			if mutations.Load() != 0 {
				t.Fatalf("backend mutation calls = %d, want 0", mutations.Load())
			}
			assertReadPairAndPreview(t, home, "config.push.preflight", "cfgov-cli.config.push")
		})
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func TestCommandLocalDryRunsWriteExplicitPreviewAudit(t *testing.T) {
	t.Run("credential migration", func(t *testing.T) {
		home := t.TempDir()
		configPath := filepath.Join(home, "config.yaml")
		cfgovctx.SetConfigPath(configPath)
		if err := cfgovctx.Set("dev", cfgovctx.Context{Backend: "nacos"}); err != nil {
			t.Fatal(err)
		}

		out, err := runCommandForTestAtHome(t, home,
			"--config", configPath,
			"-o", "json",
			"ctx", "migrate-credentials", "--dry-run",
		)
		if err != nil {
			t.Fatalf("credential migration dry-run error = %v; out=%s", err, out)
		}
		assertSingleExplicitPreviewAudit(t, home, "cfgov-cli.ctx.migrate-credentials")
		t.Cleanup(func() { cfgovctx.SetConfigPath("") })
	})

	t.Run("audit prune", func(t *testing.T) {
		home := t.TempDir()
		targetPath := filepath.Join(home, "target-audit.log")
		if err := os.WriteFile(targetPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		rotated := targetPath + ".20260524-010203.log"
		original := []byte("{}\n")
		if err := os.WriteFile(rotated, original, 0o600); err != nil {
			t.Fatal(err)
		}

		out, err := runCommandForTestAtHome(t, home,
			"-o", "json",
			"audit", "prune",
			"--path", targetPath,
			"--keep-last", "0",
			"--confirm",
			"--dry-run",
		)
		if err != nil {
			t.Fatalf("audit prune dry-run error = %v; out=%s", err, out)
		}
		after, err := os.ReadFile(rotated)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(original) {
			t.Fatalf("audit prune dry-run changed target log: %q", after)
		}
		assertSingleExplicitPreviewAudit(t, home, "cfgov-cli.audit.prune")
	})
}

func TestDiffOnlyChangePlanWritesExplicitPreviewAudit(t *testing.T) {
	var mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte("old\n"))
		case http.MethodPost, http.MethodDelete:
			mutations.Add(1)
			_, _ = w.Write([]byte("true"))
		default:
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	home := t.TempDir()
	backupFile := filepath.Join(home, "rollback.yaml")
	if err := os.WriteFile(backupFile, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCommandForTestAtHome(t, home,
		"--config", filepath.Join(home, "config.yaml"),
		"--backend", "nacos",
		"--server", server.URL,
		"--namespace", "ns",
		"--diff",
		"-o", "json",
		"config", "rollback",
		"--key", "app.yaml",
		"--backup-file", backupFile,
	)
	if err != nil {
		t.Fatalf("config rollback --diff error = %v; out=%s", err, out)
	}
	if mutations.Load() != 0 {
		t.Fatalf("config rollback --diff mutation calls = %d, want 0", mutations.Load())
	}
	assertReadPairAndPreview(t, home, "config.rollback.plan", "cfgov-cli.config.rollback")
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func TestConfigPullPlanKeepsReadAuditAndAddsPreviewAudit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nacos/v1/cs/configs" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("remote-content"))
	}))
	defer server.Close()

	home := t.TempDir()
	targetFile := filepath.Join(home, "pulled.yaml")
	out, err := runCommandForTestAtHome(t, home,
		"--config", filepath.Join(home, "config.yaml"),
		"--backend", "nacos",
		"--server", server.URL,
		"--namespace", "ns",
		"--plan",
		"-o", "json",
		"config", "pull",
		"--key", "app.yaml",
		"--file", targetFile,
	)
	if err != nil {
		t.Fatalf("config pull plan error = %v; out=%s", err, out)
	}
	if _, err := os.Stat(targetFile); !os.IsNotExist(err) {
		t.Fatalf("config pull plan created target file: %v", err)
	}
	records := readRawAuditRecords(t, home)
	if len(records) != 3 {
		t.Fatalf("config pull plan audit count = %d, want read pair + preview: %#v", len(records), records)
	}
	assertRequiredReadPair(t, records[:2], "config.pull")
	if records[2]["eventType"] != "command.preview" || records[2]["status"] != auditStatusSkipped ||
		records[2]["preview"] != true || records[2]["dryRun"] != true {
		t.Fatalf("config pull preview audit = %#v", records[2])
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func TestExportPlansKeepReadAuditAndAddPreviewAudit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/nacos/v1/cs/configs" {
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

	tests := []struct {
		name      string
		eventType string
		args      []string
	}{
		{
			name:      "config export",
			eventType: "config.export",
			args:      []string{"config", "export", "--dir", "config-export"},
		},
		{
			name:      "rule export",
			eventType: "rule.export",
			args:      []string{"rule", "export", "--app", "demo", "--dir", "rule-export"},
		},
		{
			name:      "flag export",
			eventType: "flag.export",
			args:      []string{"flag", "export", "--app", "demo", "--dir", "flag-export"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			args := []string{
				"--config", filepath.Join(home, "config.yaml"),
				"--backend", "nacos",
				"--server", server.URL,
				"--namespace", "ns",
				"--plan",
				"-o", "json",
			}
			out, err := runCommandForTestAtHome(t, home, append(args, tt.args...)...)
			if err != nil {
				t.Fatalf("%s plan error = %v; out=%s", tt.name, err, out)
			}
			records := readRawAuditRecords(t, home)
			if len(records) != 3 {
				t.Fatalf("%s plan audit count = %d, want read pair + preview: %#v", tt.name, len(records), records)
			}
			assertRequiredReadPair(t, records[:2], tt.eventType)
			if records[2]["eventType"] != "command.preview" ||
				records[2]["status"] != auditStatusSkipped ||
				records[2]["preview"] != true ||
				records[2]["dryRun"] != true {
				t.Fatalf("%s preview audit = %#v", tt.name, records[2])
			}
		})
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func assertRequiredReadPair(t *testing.T, records []map[string]any, action string) {
	t.Helper()
	if len(records) != 2 {
		t.Fatalf("read records = %#v, want intent and outcome", records)
	}
	operationID, ok := records[0]["operationId"].(string)
	if !ok || operationID == "" ||
		records[0]["kind"] != readAuditKind ||
		records[0]["eventType"] != action+".intent" ||
		records[0]["phase"] != mutationAuditPhaseIntent ||
		records[0]["status"] != coreaudit.StatusPending {
		t.Fatalf("read intent = %#v", records[0])
	}
	if records[1]["kind"] != readAuditKind ||
		records[1]["operationId"] != operationID ||
		records[1]["eventType"] != action+".outcome" ||
		records[1]["phase"] != mutationAuditPhaseOutcome ||
		records[1]["status"] != coreaudit.StatusSuccess {
		t.Fatalf("read outcome = %#v", records[1])
	}
}

func assertReadPairAndPreview(t *testing.T, home, action, command string) {
	t.Helper()
	records := readRawAuditRecords(t, home)
	if len(records) != 3 {
		t.Fatalf("audit count = %d, want read pair + preview: %#v", len(records), records)
	}
	assertRequiredReadPair(t, records[:2], action)
	preview := records[2]
	target, _ := preview["target"].(map[string]any)
	if preview["eventType"] != "command.preview" ||
		preview["status"] != auditStatusSkipped ||
		preview["preview"] != true ||
		preview["dryRun"] != true ||
		target["resource"] != command {
		t.Fatalf("preview audit = %#v", preview)
	}
}

func TestPlanFlagOnSensitiveReadKeepsSpecificReadAudit(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	cfgovctx.SetConfigPath(configPath)
	if err := cfgovctx.Set("dev", cfgovctx.Context{
		Base:    corectx.Base{Password: "literal-secret"},
		Backend: "nacos",
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfgovctx.Use("dev"); err != nil {
		t.Fatal(err)
	}

	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--plan",
		"-o", "json",
		"ctx", "current", "--show-secrets",
	)
	if err != nil {
		t.Fatalf("ctx current sensitive read error = %v; out=%s", err, out)
	}
	records := readRawAuditRecords(t, home)
	if len(records) != 1 {
		t.Fatalf("audit record count = %d, want 1: %#v", len(records), records)
	}
	record := records[0]
	if record["eventType"] != "credential.reveal" || record["status"] != coreaudit.StatusSuccess {
		t.Fatalf("sensitive read audit = %#v", record)
	}
	if _, ok := record["preview"]; ok {
		t.Fatalf("sensitive read was mislabeled as preview: %#v", record)
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func TestPreviewAuditFailureFailsCommand(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".cfgov-cli"), []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.yaml")
	out, err := runCommandForTestAtHome(t, home,
		"--config", configPath,
		"--backend", "nacos",
		"--server", "http://127.0.0.1:8848",
		"--plan",
		"-o", "json",
		"ctx", "set", "planned",
	)
	if err == nil {
		t.Fatalf("preview succeeded without its required audit; out=%s", out)
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("preview audit error code = %s, want %s; err=%v", got, apperrors.CodeLocalIOError, err)
	}
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed preview created context config: %v", statErr)
	}
	t.Cleanup(func() { cfgovctx.SetConfigPath("") })
}

func assertSingleExplicitPreviewAudit(t *testing.T, home, command string) {
	t.Helper()
	records := readRawAuditRecords(t, home)
	if len(records) != 1 {
		t.Fatalf("preview audit record count = %d, want 1: %#v", len(records), records)
	}
	record := records[0]
	if record["eventType"] != "command.preview" {
		t.Fatalf("eventType = %#v, want command.preview", record["eventType"])
	}
	if record["status"] != auditStatusSkipped {
		t.Fatalf("status = %#v, want %q", record["status"], auditStatusSkipped)
	}
	if record["preview"] != true || record["dryRun"] != true {
		t.Fatalf("preview markers = preview:%#v dryRun:%#v", record["preview"], record["dryRun"])
	}
	target, ok := record["target"].(map[string]any)
	if !ok || target["resourceType"] != "command" || target["resource"] != command {
		t.Fatalf("target = %#v, want command %q", record["target"], command)
	}
	diff, _ := record["diff"].(string)
	if !strings.Contains(diff, "preview=true") || !strings.Contains(diff, "dryRun=true") {
		t.Fatalf("diff = %q, want explicit preview markers", diff)
	}
	path := filepath.Join(home, ".cfgov-cli", "audit.log")
	verified, err := coreaudit.Verify(path, coreaudit.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify preview audit: %v", err)
	}
	if verified.Total != 1 || verified.Valid != 1 || verified.Malformed != 0 || verified.SchemaErrors != 0 {
		t.Fatalf("preview audit verification = %+v", verified)
	}
	out, err := runCommandForTestAtHome(t, home,
		"-o", "json",
		"audit", "query",
		"--path", path,
		"--type", "command.preview",
	)
	if err != nil {
		t.Fatalf("query preview audit: %v; out=%s", err, out)
	}
	if !strings.Contains(out, `"preview": true`) || !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("audit query dropped preview markers: %s", out)
	}
}

func readRawAuditRecords(t *testing.T, home string) []map[string]any {
	t.Helper()
	path := filepath.Join(home, ".cfgov-cli", "audit.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode audit: %v\n%s", err, line)
		}
		if payload, ok := record["payload"].(map[string]any); ok {
			record = payload
		}
		records = append(records, record)
	}
	return records
}
