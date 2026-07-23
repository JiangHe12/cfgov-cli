package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	records := readRawAuditRecords(t, home)
	if len(records) != 2 {
		t.Fatalf("doctor plan read audit count = %d, want pair: %#v", len(records), records)
	}
	assertRequiredReadPair(t, records, "doctor.ping")
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
	assertReadPairAndPreview(t, home, "doctor.ping", "cfgov-cli.doctor")
}
