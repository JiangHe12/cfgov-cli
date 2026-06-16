package cmd

import (
	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"
)

type capabilitiesData struct {
	Tool      capTool      `json:"tool"`
	Backend   capBackend   `json:"backend"`
	Supported capSupported `json:"supported"`
}

type capTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type capBackend struct {
	Name            string   `json:"name"`
	ResourceTypes   []string `json:"resourceTypes"`
	SupportsHistory bool     `json:"supportsHistory"`
	SupportsWatch   bool     `json:"supportsWatch"`
}

type capSupported struct {
	Commands           []capCommand `json:"commands"`
	ContextAPIVersions []string     `json:"contextApiVersions"`
	AuditAPIVersions   []string     `json:"auditApiVersions"`
	ErrorCodes         []string     `json:"errorCodes"`
	ExitCodes          []int        `json:"exitCodes"`
	Kinds              []string     `json:"kinds"`
	CredentialBackends []string     `json:"credentialBackends"`
	Environment        []string     `json:"environmentVariables"`
}

type capCommand struct {
	Noun      string `json:"noun"`
	Verb      string `json:"verb"`
	Risk      string `json:"risk"`
	AllowFlag string `json:"allowFlag,omitempty"`
}

func newCapabilitiesCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "Show cfgov capabilities",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			data := buildCapabilities()
			p := newPrinter(f)
			if f.Output == "json" || f.Output == "plain" {
				return p.JSONData("Capabilities", data)
			}
			p.Table([]string{"NOUN", "VERB", "RISK", "ALLOW FLAG"}, capabilityRows(data.Supported.Commands))
			return nil
		},
	}
}

func buildCapabilities() capabilitiesData {
	v, c, _ := getVersionInfo()
	return capabilitiesData{
		Tool:    capTool{Name: "cfgov-cli", Version: v, Commit: c},
		Backend: capBackend{Name: "nacos", ResourceTypes: []string{"config"}, SupportsHistory: true, SupportsWatch: true},
		Supported: capSupported{
			Commands: []capCommand{
				{Noun: "config", Verb: "get", Risk: "R0"},
				{Noun: "config", Verb: "list", Risk: "R0"},
				{Noun: "config", Verb: "diff", Risk: "R0"},
				{Noun: "config", Verb: "validate", Risk: "R0"},
				{Noun: "config", Verb: "pull", Risk: "R0"},
				{Noun: "config", Verb: "history", Risk: "R0"},
				{Noun: "config", Verb: "listen", Risk: "R0"},
				{Noun: "config", Verb: "push", Risk: "R1"},
				{Noun: "config", Verb: "delete", Risk: "R2"},
				{Noun: "config", Verb: "delete(protected ctx)", Risk: "R3", AllowFlag: "allow-production-config-delete"},
			},
			ContextAPIVersions: []string{"cfgov-cli.io/context/v1"},
			AuditAPIVersions:   []string{auditAPIVersion},
			ErrorCodes:         errorCodeStrings(),
			ExitCodes:          apperrors.AllExitCodes(),
			Kinds:              []string{"AuditQueryResult", "AuditVerifyResult", "Capabilities", "ChangePlan", "ChangeResult", "ConfigItem", "ConfigList", "ConfigListenEvent", "ContextItem", "ContextList", "DiffResult", "Error", "HistoryList", "ValidationResult", "VersionInfo"},
			CredentialBackends: credstore.Available(),
			Environment:        []string{"CFGOV_CLI_AUDIT_PRIVATE_KEY", "CFGOV_CLI_CREDENTIAL_PASSPHRASE", "CFGOV_CLI_OPERATOR", "NACOS_SERVER", "NACOS_USERNAME", "NACOS_PASSWORD", "NACOS_NAMESPACE"},
		},
	}
}

func capabilityRows(commands []capCommand) [][]string {
	rows := make([][]string, 0, len(commands))
	for _, cmd := range commands {
		rows = append(rows, []string{cmd.Noun, cmd.Verb, cmd.Risk, cmd.AllowFlag})
	}
	return rows
}

func errorCodeStrings() []string {
	codes := apperrors.AllCodes()
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		out = append(out, string(code))
	}
	return out
}
