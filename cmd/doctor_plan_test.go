package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDoctorPlanMarksAuditWriteCheckSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	f := newDefaultFlags()
	f.Backend = "nacos"
	f.Server = server.URL
	f.Plan = true
	f.Output = "json"

	path, err := auditPath("")
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		_ = runDoctor(context.Background(), f)
	})
	if !strings.Contains(out, `"dryRun": true`) {
		t.Fatalf("planned doctor output missing dryRun=true: %s", out)
	}
	if !strings.Contains(out, `"status": "skipped"`) {
		t.Fatalf("planned doctor output does not mark audit check skipped: %s", out)
	}
	if !strings.Contains(out, `"complete": false`) {
		t.Fatalf("planned doctor output does not mark diagnostics incomplete: %s", out)
	}
	if strings.Contains(out, `"audit log writable"`) {
		t.Fatalf("planned doctor output claims audit log is writable: %s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("runDoctor plan probe created audit file: %v", err)
	}
}

func TestDoctorPlanCommandWritesPreviewAudit(t *testing.T) {
	home := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()

	out, err := runCommandForTestAtHome(t, home,
		"--backend", "nacos",
		"--server", server.URL,
		"--plan",
		"-o", "json",
		"doctor",
	)
	if err != nil {
		t.Fatalf("doctor plan error = %v; out=%s", err, out)
	}
	if !strings.Contains(out, `"status": "skipped"`) || !strings.Contains(out, `"complete": false`) {
		t.Fatalf("doctor plan output does not expose skipped audit check: %s", out)
	}
	assertSingleExplicitPreviewAudit(t, home, "cfgov-cli.doctor")
}
