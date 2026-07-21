package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const canceledProcessBoundaryTestEnv = "CFGOV_TEST_CANCELED_PROCESS_BOUNDARY"

func TestCanceledCommandProcessBoundaryUsesSharedNonzeroExitCode(t *testing.T) {
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	command.Env = append(os.Environ(), canceledProcessBoundaryTestEnv+"=1", "NO_COLOR=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("canceled subprocess error = %v, want *exec.ExitError", err)
	}
	want := apperrors.ExitCode(context.Canceled)
	if want == 0 {
		t.Fatal("shared cancellation exit code unexpectedly equals zero")
	}
	if got := exitErr.ExitCode(); got != want {
		t.Fatalf("canceled subprocess exit = %d, want shared mapping %d; stderr=%q", got, want, stderr.String())
	}
	if !strings.Contains(stderr.String(), "operation canceled") {
		t.Fatalf("canceled subprocess stderr = %q, want mapped cancellation error", stderr.String())
	}
}
