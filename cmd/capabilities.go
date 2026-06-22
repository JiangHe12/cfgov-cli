package cmd

import (
	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/credstore"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

type capabilitiesData struct {
	Tool      capTool      `json:"tool"`
	Backend   capBackend   `json:"backend"`
	Supported capSupported `json:"supported"`
	Limits    capLimits    `json:"limits"`
	Features  capFeatures  `json:"features"`
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
	SupportsRules   bool     `json:"supportsRules"`
	SupportsFlags   bool     `json:"supportsFlags"`
	SupportsCAS     bool     `json:"supportsCas"`
	Verbs           []string `json:"verbs"`
}

type capLimits struct {
	DefaultConcurrency int   `json:"defaultConcurrency"`
	MaxConcurrency     int   `json:"maxConcurrency"`
	TraceBodyLimit     int   `json:"traceBodyLimit"`
	AuditMaxSizeBytes  int64 `json:"auditMaxSizeBytes"`
	BackupKeep         int   `json:"backupKeep"`
}

type capFeatures struct {
	ContextOverride bool `json:"contextOverride"`
	DebugTrace      bool `json:"debugTrace"`
	AuditPrune      bool `json:"auditPrune"`
	AuditTablePlain bool `json:"auditTablePlain"`
	StrictNoChange  bool `json:"strictNoChange"`
}

type capSupported struct {
	Commands           []capCommand `json:"commands"`
	ContextAPIVersions []string     `json:"contextApiVersions"`
	AuditAPIVersions   []string     `json:"auditApiVersions"`
	OutputFormats      []string     `json:"outputFormats"`
	ErrorCodes         []string     `json:"errorCodes"`
	ExitCodes          []int        `json:"exitCodes"`
	Kinds              []string     `json:"kinds"`
	CredentialBackends []string     `json:"credentialBackends"`
	Environment        []string     `json:"environmentVariables"`
	RuleTypes          []string     `json:"ruleTypes"`
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
			data := buildCapabilities(f, currentBackendCapabilities(f))
			p := newPrinter(f)
			if f.Output == "json" || f.Output == "plain" {
				return p.JSONData("Capabilities", data)
			}
			p.Table([]string{"NOUN", "VERB", "RISK", "ALLOW FLAG"}, capabilityRows(data.Supported.Commands))
			return nil
		},
	}
}

func currentBackendCapabilities(f *cliFlags) cfgov.Capabilities {
	if backend, _, err := buildBackend(f); err == nil {
		return backend.Capabilities()
	}
	ctxMeta, _, _ := resolvedContext(f)
	name := firstNonEmpty(f.Backend, ctxMeta.Backend, "nacos")
	switch name {
	case "apollo":
		return cfgov.Capabilities{
			Backend:          "apollo",
			ResourceTypes:    []string{"config", "rule", "flag"},
			Verbs:            []string{"get", "list", "diff", "validate", "pull", "push", "delete"},
			SupportsCAS:      true,
			SupportsRevision: true,
			SupportsHistory:  false,
			SupportsWatch:    false,
			SupportsRules:    true,
			SupportsFlags:    true,
		}
	case "etcd":
		return cfgov.Capabilities{
			Backend:          "etcd",
			ResourceTypes:    []string{"config", "rule", "flag"},
			Verbs:            []string{"get", "list", "diff", "validate", "pull", "listen", "push", "delete"},
			SupportsCAS:      true,
			SupportsRevision: true,
			SupportsHistory:  false,
			SupportsWatch:    true,
			SupportsRules:    true,
			SupportsFlags:    true,
		}
	case "k8s":
		return cfgov.Capabilities{
			Backend:          "k8s",
			ResourceTypes:    []string{"config", "rule", "flag"},
			Verbs:            []string{"get", "list", "diff", "validate", "pull", "push", "delete"},
			SupportsCAS:      true,
			SupportsRevision: true,
			SupportsHistory:  false,
			SupportsWatch:    false,
			SupportsRules:    true,
			SupportsFlags:    true,
		}
	default:
		return cfgov.Capabilities{
			Backend:          "nacos",
			ResourceTypes:    []string{"config", "namespace", "service", "rule", "flag"},
			Verbs:            []string{"get", "list", "diff", "validate", "pull", "history", "listen", "push", "delete"},
			SupportsCAS:      true,
			SupportsRevision: true,
			SupportsHistory:  true,
			SupportsWatch:    true,
			SupportsRules:    true,
			SupportsFlags:    true,
		}
	}
}

func buildCapabilities(f *cliFlags, backend cfgov.Capabilities) capabilitiesData {
	v, c, _ := getVersionInfo()
	return capabilitiesData{
		Tool: capTool{Name: "cfgov-cli", Version: v, Commit: c},
		Backend: capBackend{
			Name:            backend.Backend,
			ResourceTypes:   backend.ResourceTypes,
			SupportsHistory: backend.SupportsHistory,
			SupportsWatch:   backend.SupportsWatch,
			SupportsRules:   backend.SupportsRules,
			SupportsFlags:   backend.SupportsFlags,
			SupportsCAS:     backend.SupportsCAS,
			Verbs:           backend.Verbs,
		},
		Supported: capSupported{
			Commands: []capCommand{
				{Noun: "config", Verb: "get", Risk: "R0"},
				{Noun: "config", Verb: "list", Risk: "R0"},
				{Noun: "config", Verb: "diff", Risk: "R0"},
				{Noun: "config", Verb: "validate", Risk: "R0"},
				{Noun: "config", Verb: "pull", Risk: "R0"},
				{Noun: "config", Verb: "history", Risk: "R0"},
				{Noun: "config", Verb: "listen", Risk: "R0"},
				{Noun: "config", Verb: "export", Risk: "R0"},
				{Noun: "config", Verb: "push", Risk: "R1"},
				{Noun: "config", Verb: "import", Risk: "R1"},
				{Noun: "config", Verb: "promote", Risk: "R1"},
				{Noun: "config", Verb: "rollback", Risk: "R1"},
				{Noun: "config", Verb: "delete", Risk: "R2"},
				{Noun: "config", Verb: "reconcile(no prune)", Risk: "R2"},
				{Noun: "config", Verb: "reconcile(prune)", Risk: "R3", AllowFlag: "allow-production-prune"},
				{Noun: "config", Verb: "delete(protected ctx)", Risk: "R3", AllowFlag: "allow-production-config-delete"},
				{Noun: "namespace", Verb: "list", Risk: "R0"},
				{Noun: "namespace", Verb: "create", Risk: "R1"},
				{Noun: "namespace", Verb: "update", Risk: "R1"},
				{Noun: "namespace", Verb: "delete", Risk: "R2", AllowFlag: "allow-production-namespace-delete"},
				{Noun: "namespace", Verb: "delete(protected ctx)", Risk: "R3", AllowFlag: "allow-production-namespace-delete"},
				{Noun: "service", Verb: "list", Risk: "R0"},
				{Noun: "service", Verb: "get", Risk: "R0"},
				{Noun: "service", Verb: "instances", Risk: "R0"},
				{Noun: "service", Verb: "register", Risk: "R1"},
				{Noun: "service", Verb: "deregister", Risk: "R2", AllowFlag: "allow-production-service-deregister"},
				{Noun: "service", Verb: "deregister(protected ctx)", Risk: "R3", AllowFlag: "allow-production-service-deregister"},
				{Noun: "rule", Verb: "list", Risk: "R0"},
				{Noun: "rule", Verb: "get", Risk: "R0"},
				{Noun: "rule", Verb: "export", Risk: "R0"},
				{Noun: "rule", Verb: "diff", Risk: "R0"},
				{Noun: "rule", Verb: "validate", Risk: "R0"},
				{Noun: "rule", Verb: "create", Risk: "R1"},
				{Noun: "rule", Verb: "update", Risk: "R1"},
				{Noun: "rule", Verb: "import", Risk: "R1"},
				{Noun: "rule", Verb: "rollback", Risk: "R1"},
				{Noun: "rule", Verb: "delete", Risk: "R2"},
				{Noun: "rule", Verb: "delete(protected ctx)", Risk: "R3", AllowFlag: "allow-production-rule-delete"},
				{Noun: "flag", Verb: "list", Risk: "R0"},
				{Noun: "flag", Verb: "get", Risk: "R0"},
				{Noun: "flag", Verb: "export", Risk: "R0"},
				{Noun: "flag", Verb: "diff", Risk: "R0"},
				{Noun: "flag", Verb: "validate", Risk: "R0"},
				{Noun: "flag", Verb: "create", Risk: "R1"},
				{Noun: "flag", Verb: "update", Risk: "R1"},
				{Noun: "flag", Verb: "import", Risk: "R1"},
				{Noun: "flag", Verb: "rollback", Risk: "R1"},
				{Noun: "flag", Verb: "delete", Risk: "R2"},
				{Noun: "flag", Verb: "delete(protected ctx)", Risk: "R3", AllowFlag: "allow-production-flag-delete"},
				{Noun: "backup", Verb: "list", Risk: "R0"},
			},
			ContextAPIVersions: []string{"cfgov-cli.io/context/v1"},
			AuditAPIVersions:   []string{auditAPIVersion},
			OutputFormats:      []string{"table", "json", "plain"},
			ErrorCodes:         errorCodeStrings(),
			ExitCodes:          apperrors.AllExitCodes(),
			Kinds:              []string{"AuditPruneResult", "AuditQueryResult", "AuditVerifyResult", "BackupCleanResult", "BackupList", "Capabilities", "ChangePlan", "ChangeResult", "ConfigExport", "ConfigItem", "ConfigList", "ConfigListenEvent", "ContextImportResult", "ContextItem", "ContextList", "ContextTestResult", "DiffResult", "DoctorResult", "Error", "ExportResult", "FlagDiff", "FlagExport", "FlagList", "FlagSet", "FlagValidation", "HistoryList", "NamespaceItem", "NamespaceList", "RoleList", "RuleDiff", "RuleExport", "RuleList", "RuleSet", "RuleValidation", "ServiceInstanceList", "ServiceItem", "ServiceList", "ValidationResult", "VersionInfo"},
			CredentialBackends: credstore.Available(),
			Environment:        []string{"APOLLO_APP_ID", "APOLLO_CLUSTER", "APOLLO_ENV", "APOLLO_NAMESPACE", "APOLLO_RULE_NAMESPACE", "APOLLO_SECRET", "APOLLO_SERVER", "APOLLO_TOKEN", "CFGOV_CLI_AUDIT_PRIVATE_KEY", "CFGOV_CLI_CREDENTIAL_PASSPHRASE", "CFGOV_CLI_OPERATOR", "ETCD_CACERT", "ETCD_CLIENT_CERT", "ETCD_CLIENT_KEY", "ETCD_ENDPOINTS", "ETCD_KEY_PREFIX", "ETCD_NAMESPACE", "ETCD_PASSWORD", "ETCD_RULE_NAMESPACE", "ETCD_SERVER", "ETCD_USERNAME", "KUBECONFIG", "NACOS_NAMESPACE", "NACOS_PASSWORD", "NACOS_SERVER", "NACOS_USERNAME"},
			RuleTypes:          []string{"flow", "degrade", "system", "authority", "param"},
		},
		Limits: capLimits{
			DefaultConcurrency: 1,
			MaxConcurrency:     16,
			TraceBodyLimit:     f.TraceBodyLim,
			AuditMaxSizeBytes:  firstPositiveInt64(f.AuditMaxSize, audit.DefaultMaxSizeBytes),
			BackupKeep:         f.BackupKeep,
		},
		Features: capFeatures{
			ContextOverride: true,
			DebugTrace:      true,
			AuditPrune:      true,
			AuditTablePlain: true,
			StrictNoChange:  true,
		},
	}
}

func firstPositiveInt64(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
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
