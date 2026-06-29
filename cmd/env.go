package cmd

import "os"

const (
	cfgovAuditPrivateKeyEnv           = "CFGOV_AUDIT_PRIVATE_KEY"
	deprecatedCfgovAuditPrivateKeyEnv = "CFGOV_CLI_AUDIT_PRIVATE_KEY"
	cfgovOperatorEnv                  = "CFGOV_OPERATOR"
	deprecatedCfgovOperatorEnv        = "CFGOV_CLI_OPERATOR"
)

func envWithDeprecatedAlias(primary, deprecatedName string) string {
	if value := os.Getenv(primary); value != "" {
		return value
	}
	return os.Getenv(deprecatedName)
}

func configureEnvWithDeprecatedAlias(primary, deprecatedName string) string {
	if os.Getenv(primary) == "" {
		if value := os.Getenv(deprecatedName); value != "" {
			_ = os.Setenv(primary, value)
		}
	}
	return primary
}
