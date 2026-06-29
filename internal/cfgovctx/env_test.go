package cfgovctx

import (
	"os"
	"testing"
)

func TestConfigureEnvWithDeprecatedAliasCopiesDeprecated(t *testing.T) {
	t.Setenv("CFGOVCTX_TEST_PRIMARY_ENV", "")
	t.Setenv("CFGOVCTX_TEST_DEPRECATED_ENV", "old")

	if got := configureEnvWithDeprecatedAlias("CFGOVCTX_TEST_PRIMARY_ENV", "CFGOVCTX_TEST_DEPRECATED_ENV"); got != "CFGOVCTX_TEST_PRIMARY_ENV" {
		t.Fatalf("configureEnvWithDeprecatedAlias() = %q", got)
	}
	if got := os.Getenv("CFGOVCTX_TEST_PRIMARY_ENV"); got != "old" {
		t.Fatalf("primary env = %q, want old", got)
	}
}
