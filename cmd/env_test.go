package cmd

import (
	"os"
	"testing"
)

func TestEnvWithDeprecatedAliasPrefersPrimary(t *testing.T) {
	t.Setenv("CFGOV_TEST_PRIMARY_ENV", "new")
	t.Setenv("CFGOV_TEST_DEPRECATED_ENV", "old")

	if got := envWithDeprecatedAlias("CFGOV_TEST_PRIMARY_ENV", "CFGOV_TEST_DEPRECATED_ENV"); got != "new" {
		t.Fatalf("envWithDeprecatedAlias() = %q, want new", got)
	}
}

func TestEnvWithDeprecatedAliasFallsBackToDeprecated(t *testing.T) {
	t.Setenv("CFGOV_TEST_PRIMARY_ENV", "")
	t.Setenv("CFGOV_TEST_DEPRECATED_ENV", "old")

	if got := envWithDeprecatedAlias("CFGOV_TEST_PRIMARY_ENV", "CFGOV_TEST_DEPRECATED_ENV"); got != "old" {
		t.Fatalf("envWithDeprecatedAlias() = %q, want old", got)
	}
}

func TestConfigureEnvWithDeprecatedAliasCopiesDeprecated(t *testing.T) {
	t.Setenv("CFGOV_TEST_PRIMARY_ENV", "")
	t.Setenv("CFGOV_TEST_DEPRECATED_ENV", "old")

	if got := configureEnvWithDeprecatedAlias("CFGOV_TEST_PRIMARY_ENV", "CFGOV_TEST_DEPRECATED_ENV"); got != "CFGOV_TEST_PRIMARY_ENV" {
		t.Fatalf("configureEnvWithDeprecatedAlias() = %q", got)
	}
	if got := os.Getenv("CFGOV_TEST_PRIMARY_ENV"); got != "old" {
		t.Fatalf("primary env = %q, want old", got)
	}
}
