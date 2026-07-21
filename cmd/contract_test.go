package cmd

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestContractJSONEnvelope(t *testing.T) {
	SetVersionInfo("v0.0.0-test", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	out, exit, err := runContractCommand(t, "-o", "json", "version")
	if err != nil {
		t.Fatalf("version error = %v; out=%s", err, out)
	}
	if exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	payload := decodeContractEnvelope(t, out)
	if payload.APIVersion != apiVersion || payload.Kind != "VersionInfo" || !payload.Success || len(payload.Data) == 0 {
		t.Fatalf("payload = %+v, out=%s", payload, out)
	}
}

func TestContractErrorJSON(t *testing.T) {
	out, exit, err := runContractCommand(t, "--context", "fake-ctx-12345", "-o", "json", "config", "list")
	if err == nil {
		t.Fatalf("expected error; out=%s", out)
	}
	if exit == 0 {
		t.Fatalf("exit = 0, want non-zero; err=%v; out=%s", err, out)
	}
	payload := decodeContractEnvelope(t, out)
	if payload.APIVersion != apiVersion || payload.Kind != "Error" || payload.Success || len(payload.Error) == 0 {
		t.Fatalf("payload = %+v, out=%s", payload, out)
	}
}

func TestContractVersionPlain(t *testing.T) {
	SetVersionInfo("v1.2.3", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	out, exit, err := runContractCommand(t, "-o", "plain", "version")
	if err != nil {
		t.Fatalf("version error = %v; out=%s", err, out)
	}
	if exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+\n$`).MatchString(out) {
		t.Fatalf("version plain = %q, want vX.Y.Z single line", out)
	}
}

func TestContractExitCodes(t *testing.T) {
	_, exit, err := runContractCommand(t, "version")
	if err != nil || exit != 0 {
		t.Fatalf("success err=%v exit=%d, want nil/0", err, exit)
	}
	_, exit, err = runContractCommand(t, "--context", "fake-ctx-12345", "config", "list")
	if err == nil || exit == 0 {
		t.Fatalf("error err=%v exit=%d, want non-nil/non-zero", err, exit)
	}
}

type contractEnvelope struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Error      json.RawMessage `json:"error"`
}

func runContractCommand(t *testing.T, args ...string) (string, int, error) {
	t.Helper()
	out, err := runCommandForTest(t, args...)
	if err == nil {
		return out, 0, nil
	}
	if outputFlagFromArgs(args) == "json" {
		var stderr bytes.Buffer
		_ = apperrors.WriteJSON(&stderr, err)
		out = stderr.String()
	}
	return out, apperrors.ExitCode(err), err
}

func decodeContractEnvelope(t *testing.T, out string) contractEnvelope {
	t.Helper()
	var payload contractEnvelope
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not JSON envelope: %v; out=%s", err, out)
	}
	return payload
}
