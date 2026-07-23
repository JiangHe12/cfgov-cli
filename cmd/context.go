package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/safety"

	consulBackend "github.com/JiangHe12/cfgov-cli/internal/backend/consul"
	etcdBackend "github.com/JiangHe12/cfgov-cli/internal/backend/etcd"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	ctxExportAPIVersion          = "cfgov-cli.io/ctx-export/v1"
	redactedCredential           = "<REDACTED>"
	credentialBackendEncrypted   = "encrypted-file"
	credentialBackendKeychain    = "keychain"
	credentialMigrationEventType = audit.EventType("credential.migrate")
)

type contextExportDocument struct {
	APIVersion string           `yaml:"apiVersion"`
	Name       string           `yaml:"name"`
	Context    cfgovctx.Context `yaml:"context"`
}

type contextImportResult struct {
	Name               string `json:"name"`
	CredentialRedacted bool   `json:"credentialRedacted"`
}

type contextImportRuntime struct {
	newCredentialBackend func(cfgovctx.Context) (credstore.Backend, error)
	updateContexts       func(func(*corectx.Config[cfgovctx.Context]) error) error
	rollbackTimeout      time.Duration
}

type importedCredentialPlan struct {
	backend     credstore.Backend
	backendName string
	name        string
	password    string
	context     cfgovctx.Context
}

type importedCredentialState struct {
	plan     *importedCredentialPlan
	previous string
	existed  bool
}

type contextTargetState struct {
	item   cfgovctx.Context
	exists bool
}

type mutationCommitState uint8

const (
	mutationCommitUnknown mutationCommitState = iota
	mutationCommitUnchanged
	mutationCommitCommitted
	mutationCommitDivergent
)

type roleOptions struct {
	targetOperator string
	role           string
}

type roleItem struct {
	Operator string `json:"operator"`
	Role     string `json:"role"`
}

type migrateCredentialsOptions struct {
	toBackend   string
	contextName string
	dryRun      bool
}

type migrateCredentialCandidate struct {
	name     string
	context  cfgovctx.Context
	password string
}

type credentialMigrationResult struct {
	DryRun   bool     `json:"dryRun"`
	Backend  string   `json:"backend"`
	Contexts []string `json:"contexts"`
	Count    int      `json:"count"`
}

func newContextCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "ctx", Aliases: []string{"context"}, Short: "Manage cfgov contexts", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(ctxSetCmd(f), ctxUseCmd(f), ctxListCmd(f), ctxCurrentCmd(f), ctxDeleteCmd(f), ctxExportCmd(f), ctxImportCmd(f), ctxMigrateCredentialsCmd(f), ctxTestCmd(f), ctxRoleCmd(f))
	return cmd
}

func ctxSetCmd(f *cliFlags) *cobra.Command { //nolint:gocyclo // Cobra wiring for corectx + backend-specific fields stays local to ctx set.
	var protected bool
	var credentialBackend string
	var env, ticketPattern, rolesSource, rolesURL string
	var allowInsecureRolesURL bool
	var vaultAddr, vaultPath, vaultRoleID, vaultSecretID, vaultNamespace string
	var otelEndpoint, otelMetricsEndpoint string
	var otelInsecure bool
	var apolloAppID, apolloEnv, apolloCluster, apolloNamespace, apolloRuleNamespace string
	var apolloToken, apolloSecret string
	var etcdKeyPrefix, etcdRuleNamespace, etcdCACert, etcdClientCert, etcdClientKey string
	var consulKeyPrefix, consulRuleNamespace, consulCACert, consulClientCert, consulClientKey string
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a backend-bound context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Backend == "" {
				return apperrors.New(apperrors.CodeUsageError, "--backend is required", nil)
			}
			if f.Backend != "nacos" && f.Backend != "apollo" && f.Backend != "etcd" && f.Backend != "consul" && f.Backend != "k8s" {
				return apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
			}
			switch f.Backend {
			case "etcd":
				if err := etcdBackend.ValidateEndpoints(f.Server); err != nil {
					return err
				}
				if err := etcdBackend.ValidateKeyPrefix(etcdKeyPrefix); err != nil {
					return err
				}
			case "consul":
				if err := consulBackend.ValidateServer(f.Server); err != nil {
					return err
				}
				if err := consulBackend.ValidateKeyPrefix(consulKeyPrefix); err != nil {
					return err
				}
			case "k8s":
			default:
				if err := validateServerURL(f.Server); err != nil {
					return err
				}
			}
			if err := validateRolesURL(rolesSource, rolesURL, allowInsecureRolesURL); err != nil {
				return err
			}
			if f.Backend == "apollo" && apolloAppID == "" {
				return apperrors.New(apperrors.CodeUsageError, "--apollo-app-id is required for apollo backend", nil)
			}
			if apolloToken != "" && apolloSecret != "" {
				return apperrors.New(apperrors.CodeUsageError, "--apollo-token and --apollo-secret are mutually exclusive", nil)
			}
			credential := firstNonEmpty(f.Password, apolloToken, apolloSecret)
			if err := credstore.RequireSecureBackend(credentialBackend, credential != ""); err != nil {
				return err
			}
			item := cfgovctx.Context{
				Base: corectx.Base{
					Server:                f.Server,
					Username:              f.Username,
					Env:                   env,
					Protected:             protected,
					TicketPattern:         ticketPattern,
					CredentialBackend:     credentialBackend,
					RolesSource:           rolesSource,
					RolesURL:              rolesURL,
					AllowInsecureRolesURL: allowInsecureRolesURL,
					VaultAddr:             vaultAddr,
					VaultPath:             vaultPath,
					VaultRoleID:           vaultRoleID,
					VaultNamespace:        vaultNamespace,
					OTLPEndpoint:          otelEndpoint,
					OTLPMetricsEndpoint:   otelMetricsEndpoint,
					OTLPInsecure:          otelInsecure,
					OTLPRedact:            true,
				},
				Backend:             f.Backend,
				Namespace:           f.Namespace,
				ApolloAppID:         apolloAppID,
				ApolloEnv:           apolloEnv,
				ApolloCluster:       apolloCluster,
				ApolloNamespace:     firstNonEmpty(apolloNamespace, f.Namespace),
				ApolloRuleNamespace: apolloRuleNamespace,
				EtcdKeyPrefix:       etcdKeyPrefix,
				EtcdRuleNamespace:   etcdRuleNamespace,
				EtcdCACert:          etcdCACert,
				EtcdClientCert:      etcdClientCert,
				EtcdClientKey:       etcdClientKey,
				ConsulKeyPrefix:     consulKeyPrefix,
				ConsulRuleNamespace: consulRuleNamespace,
				ConsulCACert:        consulCACert,
				ConsulClientCert:    consulClientCert,
				ConsulClientKey:     consulClientKey,
				K8sKubeconfig:       f.K8sKubeconfig,
				K8sContext:          f.K8sContext,
			}
			cfg, err := cfgovctx.Load()
			if err != nil {
				return err
			}
			if err := validateCredentialBackendConfiguration(item, vaultSecretID); err != nil {
				return err
			}
			if isPlanOnly(f) {
				item, err = prepareContextCredentialPlan(
					cmd.Context(), f, cfg, args[0], credentialBackend, credential, item, vaultSecretID,
				)
				if err != nil {
					return err
				}
				return printLocalChangePlan(f, "context", "set", args[0], map[string]any{
					"backend":            item.Backend,
					"namespace":          item.Namespace,
					"protected":          item.Protected,
					"credentialBackend":  credentialBackend,
					"credentialProvided": credential != "",
				})
			}
			runBeforeContextUpdate(f)
			var mutation *mutationAuditHandle
			var credentialTransaction *credentialMutationTransaction
			credentialWriteIndex := -1
			var original contextTargetState
			err = updateImportedContexts(f, func(cfg *corectx.Config[cfgovctx.Context]) error {
				prePolicy, err := contextPreChangePolicy(cfg, args[0])
				if err != nil {
					return err
				}
				original = captureContextTargetState(cfg, args[0])
				preflight, err := prepareContextCredentialPreflight(
					cmd.Context(),
					f,
					args[0],
					prePolicy,
					credentialBackend,
					credential,
					item,
					vaultSecretID,
				)
				if err != nil {
					return err
				}
				item = preflight.Item
				credentialTransaction = preflight.Transaction
				credentialWriteIndex = preflight.WriteIndex
				if err := authorizeForContext(f, safety.R3, prePolicy, allowContextChange, args[0]); err != nil {
					return err
				}
				metadata := mutationValueMetadata("ctx.set", item)
				metadata.Items = 1
				if _, exists := cfg.Contexts[args[0]]; exists {
					metadata.Updates = 1
				} else {
					metadata.Creates = 1
				}
				mutation, err = beginMutationAudit(f, mutationAuditSpec{
					Action:      "ctx.set",
					ContextName: args[0],
					Context:     prePolicy,
					Target:      audit.EventTarget{ResourceType: "context", Resource: args[0]},
					Metadata:    metadata,
				})
				if err != nil {
					return err
				}
				if credentialTransaction != nil {
					if err := credentialTransaction.applyWrite(cmd.Context(), credentialWriteIndex); err != nil {
						return apperrors.New(apperrors.CodeCredentialStoreError, "failed to store credential", err)
					}
				}
				cfg.Contexts[args[0]] = item
				return nil
			})
			progress := credentialMutationProgress{}
			compensationStatus := ""
			switch {
			case err == nil:
				progress.succeeded = 1
			case mutation == nil:
				progress.failed = 1
			default:
				progress, compensationStatus, err = reconcileContextSetCredentialFailure(
					commandContext(f),
					f,
					credentialTransaction,
					args[0],
					original,
					item,
					err,
				)
			}
			if mutation != nil {
				if auditErr := finishCredentialMutationAudit(mutation, 1, progress, compensationStatus, err); auditErr != nil {
					return auditErr
				}
			}
			if err != nil {
				return err
			}
			appendContextAuditWarnFor(f, audit.EventType("ctx.set"), args[0], item, audit.StatusSuccess, "", nil)
			return newPrinter(f).JSONData("ContextItem", contextView(args[0], item, false, false))
		},
	}
	cmd.Flags().BoolVar(&protected, "protected", false, "Mark context as protected")
	cmd.Flags().StringVar(&credentialBackend, "credential-backend", "plain-yaml", "Credential backend")
	cmd.Flags().StringVar(&f.Password, "password", "", "Password to store in credstore; prefer CFGOV_PASSWORD for non-interactive runs")
	cmd.Flags().StringVar(&env, "env", "", "Environment label")
	cmd.Flags().StringVar(&ticketPattern, "ticket-pattern", "", "Regex pattern for ticket validation")
	cmd.Flags().StringVar(&rolesSource, "roles-source", "", "RBAC roles source: inline (remote sources are not implemented)")
	cmd.Flags().StringVar(&rolesURL, "roles-url", "", "Reserved remote RBAC roles URL (currently rejected)")
	cmd.Flags().BoolVar(&allowInsecureRolesURL, "allow-insecure-roles-url", false, "Reserved remote roles URL option (currently rejected)")
	cmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address")
	cmd.Flags().StringVar(&vaultPath, "vault-path", "", "Vault KV v2 path under secret/data/")
	cmd.Flags().StringVar(&vaultRoleID, "vault-role-id", "", "Vault AppRole role_id")
	cmd.Flags().StringVar(&vaultSecretID, "vault-secret-id", "", "Vault AppRole secret_id; stored only in VAULT_SECRET_ID for this process")
	cmd.Flags().StringVar(&vaultNamespace, "vault-namespace", "", "Vault Enterprise namespace")
	cmd.Flags().StringVar(&otelEndpoint, "otel-endpoint", "", "OTLP trace endpoint URL")
	cmd.Flags().StringVar(&otelMetricsEndpoint, "otel-metrics-endpoint", "", "OTLP metrics endpoint URL")
	cmd.Flags().BoolVar(&otelInsecure, "otel-insecure", false, "Disable TLS for OTLP exporter")
	cmd.Flags().StringVar(&apolloAppID, "apollo-app-id", "", "Apollo OpenAPI appId")
	cmd.Flags().StringVar(&apolloEnv, "apollo-env", "", "Apollo environment")
	cmd.Flags().StringVar(&apolloCluster, "apollo-cluster", "", "Apollo cluster")
	cmd.Flags().StringVar(&apolloNamespace, "apollo-namespace", "", "Apollo namespace")
	cmd.Flags().StringVar(&apolloRuleNamespace, "apollo-rule-namespace", "", "Apollo namespace for Sentinel rules")
	cmd.Flags().StringVar(&apolloToken, "apollo-token", "", "Apollo OpenAPI token")
	cmd.Flags().StringVar(&apolloSecret, "apollo-secret", "", "Apollo OpenAPI secret")
	cmd.Flags().StringVar(&etcdKeyPrefix, "etcd-key-prefix", "", "etcd key prefix prepended before namespace")
	cmd.Flags().StringVar(&etcdRuleNamespace, "etcd-rule-namespace", "", "etcd namespace for Sentinel rules")
	cmd.Flags().StringVar(&etcdCACert, "etcd-ca-cert", "", "etcd CA certificate path")
	cmd.Flags().StringVar(&etcdClientCert, "etcd-client-cert", "", "etcd mTLS client certificate path")
	cmd.Flags().StringVar(&etcdClientKey, "etcd-client-key", "", "etcd mTLS client private key path")
	cmd.Flags().StringVar(&consulKeyPrefix, "consul-key-prefix", "", "Consul KV key prefix prepended before namespace")
	cmd.Flags().StringVar(&consulRuleNamespace, "consul-rule-namespace", "", "Consul KV namespace for Sentinel rules")
	cmd.Flags().StringVar(&consulCACert, "consul-ca-cert", "", "Consul CA certificate path")
	cmd.Flags().StringVar(&consulClientCert, "consul-client-cert", "", "Consul mTLS client certificate path")
	cmd.Flags().StringVar(&consulClientKey, "consul-client-key", "", "Consul mTLS client private key path")
	_ = cmd.Flags().MarkHidden("apollo-token")
	_ = cmd.Flags().MarkHidden("apollo-secret")
	_ = cmd.Flags().MarkHidden("vault-secret-id")
	return cmd
}

func ctxUseCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Set current context",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if isPlanOnly(f) {
				cfg, err := cfgovctx.Load()
				if err != nil {
					return err
				}
				if _, ok := cfg.Contexts[args[0]]; !ok {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
				}
				return printLocalChangePlan(f, "context", "use", args[0], map[string]any{"from": cfg.CurrentContext})
			}
			var target cfgovctx.Context
			var mutation *mutationAuditHandle
			runBeforeContextUpdate(f)
			err := cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
				var ok bool
				target, ok = cfg.Contexts[args[0]]
				if !ok {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
				}
				prePolicy, policyName, err := contextUsePreChangePolicy(cfg, args[0])
				if err != nil {
					return err
				}
				if err := authorizeForContext(f, safety.R3, prePolicy, allowContextChange, policyName); err != nil {
					return err
				}
				metadata := mutationValueMetadata("ctx.use", map[string]string{
					"from": cfg.CurrentContext,
					"to":   args[0],
				})
				metadata.Items = 1
				metadata.Updates = 1
				mutation, err = beginMutationAudit(f, mutationAuditSpec{
					Action:      "ctx.use",
					ContextName: args[0],
					Context:     prePolicy,
					Target:      audit.EventTarget{ResourceType: "context", Resource: args[0]},
					Metadata:    metadata,
				})
				if err != nil {
					return err
				}
				cfg.CurrentContext = args[0]
				return nil
			})
			if mutation != nil {
				if auditErr := finishMutationAudit(mutation, mutationAuditOutcome{}, err); auditErr != nil {
					return auditErr
				}
			}
			if err != nil {
				return err
			}
			appendContextAuditWarnFor(f, audit.EventType("ctx.use"), args[0], target, audit.StatusSuccess, "", nil)
			return newPrinter(f).JSONData("ContextItem", map[string]string{"current": args[0]})
		},
	}
}

func ctxListCmd(f *cliFlags) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List contexts",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := cfgovctx.Load()
			if err != nil {
				return err
			}
			names := make([]string, 0, len(cfg.Contexts))
			for name := range cfg.Contexts {
				names = append(names, name)
			}
			sort.Strings(names)
			items := make([]map[string]any, 0, len(names))
			rows := make([][]string, 0, len(names))
			for _, name := range names {
				item := cfg.Contexts[name]
				current := name == cfg.CurrentContext
				items = append(items, contextView(name, item, current, showSecrets))
				password := ""
				if item.Password != "" && !showSecrets {
					password = "******"
				} else if showSecrets {
					password = item.Password
				}
				rows = append(rows, []string{name, fmt.Sprint(current), item.Backend, item.Server, firstNonEmpty(item.Namespace, item.ApolloNamespace), item.Env, fmt.Sprint(item.Protected), password})
			}
			if showSecrets {
				appendContextAuditWarn(f, audit.EventType("credential.reveal"), cfgovctx.Context{}, audit.StatusSuccess, "ctx list --show-secrets", nil)
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("ContextList", items, len(items), 1, len(items), false)
			}
			return p.Table([]string{"NAME", "CURRENT", "BACKEND", "SERVER", "NAMESPACE", "ENV", "PROTECTED", "PASSWORD"}, rows)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal stored credential values")
	return cmd
}

func ctxCurrentCmd(f *cliFlags) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "current",
		Short: "Show current context",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			item, name, err := cfgovctx.Current()
			if err != nil {
				return err
			}
			if showSecrets {
				appendContextAuditWarn(f, audit.EventType("credential.reveal"), *item, audit.StatusSuccess, "ctx current --show-secrets", nil)
			}
			view := contextView(name, *item, true, showSecrets)
			view["credentialBackends"] = credstore.Available()
			return newPrinter(f).JSONData("ContextItem", view)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal stored credential value")
	return cmd
}

func ctxDeleteCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"remove", "rm"},
		Short:   "Delete a context",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, err := cfgovctx.Load()
			if err != nil {
				return err
			}
			item, ok := cfg.Contexts[args[0]]
			if !ok {
				return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
			}
			if isPlanOnly(f) {
				return printLocalChangePlan(f, "context", "delete", args[0], map[string]any{
					"backend":   item.Backend,
					"protected": item.Protected,
				})
			}
			runBeforeContextUpdate(f)
			var mutation *mutationAuditHandle
			err = cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
				lockedItem, ok := cfg.Contexts[args[0]]
				if !ok {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
				}
				if err := authorizeForContext(f, safety.R3, lockedItem, allowContextDelete, args[0]); err != nil {
					return err
				}
				mutation, err = beginMutationAudit(f, mutationAuditSpec{
					Action:      "ctx.delete",
					ContextName: args[0],
					Context:     lockedItem,
					Target:      audit.EventTarget{ResourceType: "context", Resource: args[0]},
					Metadata: mutationAuditMetadata{
						Items:   1,
						Deletes: 1,
					},
				})
				if err != nil {
					return err
				}
				item = lockedItem
				delete(cfg.Contexts, args[0])
				if cfg.CurrentContext == args[0] {
					cfg.CurrentContext = ""
				}
				return nil
			})
			if mutation != nil {
				if auditErr := finishMutationAudit(mutation, mutationAuditOutcome{}, err); auditErr != nil {
					return auditErr
				}
			}
			if err != nil {
				return err
			}
			appendContextAuditWarnFor(f, audit.EventType("ctx.delete"), args[0], item, audit.StatusSuccess, "", nil)
			return newPrinter(f).JSONData("ContextItem", map[string]string{"deleted": args[0]})
		},
	}
}

func ctxExportCmd(f *cliFlags) *cobra.Command {
	var includeCredentials bool
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export a portable context document",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxExport(f, args[0], includeCredentials)
		},
	}
	cmd.Flags().BoolVar(&includeCredentials, "include-credentials", false, "Include plaintext credentials when stored as plain-yaml")
	return cmd
}

func ctxImportCmd(f *cliFlags) *cobra.Command {
	var file, rename string
	var force bool
	cmd := &cobra.Command{
		Use:   "import -f <file>",
		Short: "Import a portable context document",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCtxImport(f, file, rename, force)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "Portable context document to import")
	cmd.Flags().StringVar(&rename, "rename", "", "Import under a different context name")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing context")
	return cmd
}

func ctxMigrateCredentialsCmd(f *cliFlags) *cobra.Command {
	opts := migrateCredentialsOptions{toBackend: credentialBackendEncrypted}
	cmd := &cobra.Command{
		Use:   "migrate-credentials",
		Short: "Move literal context credentials to a secure credential backend",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCtxMigrateCredentials(f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.toBackend, "to", credentialBackendEncrypted, "Target backend: encrypted-file or keychain")
	cmd.Flags().StringVar(&opts.contextName, "context", "", "Context to migrate")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Preview credential migration without writing")
	return cmd
}

func ctxTestCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "test [name]",
		Short: "Test backend connectivity for a context",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var ctxName string
			var meta cfgovctx.Context
			var err error
			if len(args) == 1 {
				ctxName = args[0]
				meta, err = loadNamedContext(ctxName)
				if err != nil {
					return err
				}
			} else {
				meta, ctxName, err = resolvedContext(f)
				if err != nil {
					return err
				}
			}
			spec := newReadAuditSpec(
				string(audit.EventContextTest),
				meta,
				"diagnostic",
				ctxName+"\x00"+firstNonEmpty(meta.Backend, f.Backend, "nacos"),
				map[string]string{"context": ctxName},
			)
			spec.ContextName = ctxName
			backendName, err := runMandatoryRead(
				f,
				spec,
				func() (string, error) {
					var backend cfgov.Backend
					var buildErr error
					if len(args) == 1 {
						backend, buildErr = buildBackendFromNamedContext(cmd.Context(), f, ctxName, meta)
					} else {
						backend, _, buildErr = buildBackendForResolvedContext(f, meta, ctxName)
					}
					if buildErr != nil {
						return "", buildErr
					}
					if pingErr := backend.Ping(cmd.Context()); pingErr != nil {
						return "", pingErr
					}
					return backend.Describe().Backend, nil
				},
				func(string) int { return 1 },
			)
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("ContextTestResult", map[string]any{"name": ctxName, "backend": backendName, "ok": true})
		},
	}
}

func ctxRoleCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage context RBAC roles",
		Args:  requireSubcommand,
		RunE:  runParentHelp,
	}
	cmd.AddCommand(ctxRoleSetCmd(f), ctxRoleUnsetCmd(f), ctxRoleListCmd(f))
	return cmd
}

func ctxRoleSetCmd(f *cliFlags) *cobra.Command {
	var opts roleOptions
	cmd := &cobra.Command{
		Use:   "set <context>",
		Short: "Assign an operator role for a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleSet(f, args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.targetOperator, "target-operator", "", "Operator identity to assign")
	cmd.Flags().StringVar(&opts.role, "role", "", "Role: reader, writer, admin")
	return cmd
}

func ctxRoleUnsetCmd(f *cliFlags) *cobra.Command {
	var opts roleOptions
	cmd := &cobra.Command{
		Use:   "unset <context>",
		Short: "Remove an operator role from a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleUnset(f, args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.targetOperator, "target-operator", "", "Operator identity to remove")
	return cmd
}

func ctxRoleListCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list <context>",
		Short: "List operator roles for a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleList(f, args[0])
		},
	}
}

func runCtxRoleSet(f *cliFlags, contextName string, opts roleOptions) error {
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	if !validRole(opts.role) {
		return apperrors.New(apperrors.CodeUsageError, "--role must be reader, writer, or admin", nil)
	}
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	if isPlanOnly(f) {
		return printLocalChangePlan(f, "role", "set", contextName, map[string]any{
			"operator": opts.targetOperator,
			"role":     opts.role,
		})
	}
	runBeforeContextUpdate(f)
	var mutation *mutationAuditHandle
	err = cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
		lockedItem, ok := cfg.Contexts[contextName]
		if !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		if err := authorizeForContext(f, safety.R3, lockedItem, allowRoleChange, contextName); err != nil {
			return err
		}
		metadata := mutationValueMetadata("role.assign", map[string]string{
			"operator": opts.targetOperator,
			"role":     opts.role,
		})
		metadata.Items = 1
		metadata.Updates = 1
		mutation, err = beginMutationAudit(f, mutationAuditSpec{
			Action:      "role.assign",
			ContextName: contextName,
			Context:     lockedItem,
			Target:      audit.EventTarget{ResourceType: "context", Resource: contextName},
			Metadata:    metadata,
		})
		if err != nil {
			return err
		}
		if lockedItem.Roles == nil {
			lockedItem.Roles = map[string]string{}
		}
		lockedItem.Roles[opts.targetOperator] = opts.role
		item = lockedItem
		cfg.Contexts[contextName] = item
		return nil
	})
	if mutation != nil {
		if auditErr := finishMutationAudit(mutation, mutationAuditOutcome{}, err); auditErr != nil {
			return auditErr
		}
	}
	if err != nil {
		return err
	}
	appendRoleAuditWarn(f, audit.EventRoleAssign, contextName, item, opts.targetOperator, opts.role, nil)
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextItem", map[string]any{"context": contextName, "operator": opts.targetOperator, "role": opts.role})
	}
	return newPrinter(f).Success(fmt.Sprintf("role %q assigned to %q in context %q", opts.role, opts.targetOperator, contextName))
}

func runCtxRoleUnset(f *cliFlags, contextName string, opts roleOptions) error {
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	if isPlanOnly(f) {
		return printLocalChangePlan(f, "role", "unset", contextName, map[string]any{
			"operator": opts.targetOperator,
		})
	}
	runBeforeContextUpdate(f)
	var mutation *mutationAuditHandle
	err = cfgovctx.Update(func(cfg *corectx.Config[cfgovctx.Context]) error {
		lockedItem, ok := cfg.Contexts[contextName]
		if !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		if err := authorizeForContext(f, safety.R3, lockedItem, allowRoleChange, contextName); err != nil {
			return err
		}
		metadata := mutationValueMetadata("role.revoke", map[string]string{"operator": opts.targetOperator})
		metadata.Items = 1
		metadata.Updates = 1
		mutation, err = beginMutationAudit(f, mutationAuditSpec{
			Action:      "role.revoke",
			ContextName: contextName,
			Context:     lockedItem,
			Target:      audit.EventTarget{ResourceType: "context", Resource: contextName},
			Metadata:    metadata,
		})
		if err != nil {
			return err
		}
		if lockedItem.Roles != nil {
			delete(lockedItem.Roles, opts.targetOperator)
			if len(lockedItem.Roles) == 0 {
				lockedItem.Roles = nil
			}
		}
		item = lockedItem
		cfg.Contexts[contextName] = item
		return nil
	})
	if mutation != nil {
		if auditErr := finishMutationAudit(mutation, mutationAuditOutcome{}, err); auditErr != nil {
			return auditErr
		}
	}
	if err != nil {
		return err
	}
	appendRoleAuditWarn(f, audit.EventRoleRevoke, contextName, item, opts.targetOperator, "", nil)
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextItem", map[string]any{"context": contextName, "operator": opts.targetOperator, "removed": true})
	}
	return newPrinter(f).Success(fmt.Sprintf("role removed from %q in context %q", opts.targetOperator, contextName))
}

func runCtxRoleList(f *cliFlags, contextName string) error {
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	items := roleItems(item.Roles)
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("RoleList", items, len(items), 1, len(items), false)
	}
	if len(items) == 0 {
		return p.Info("(no roles assigned)")
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.Operator, item.Role})
	}
	return p.Table([]string{"OPERATOR", "ROLE"}, rows)
}

func loadContextForRole(name string) (cfgovctx.Context, error) {
	cfg, err := cfgovctx.Load()
	if err != nil {
		return cfgovctx.Context{}, err
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return cfgovctx.Context{}, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
	}
	return item, nil
}

func contextPreChangePolicy(cfg *corectx.Config[cfgovctx.Context], targetName string) (cfgovctx.Context, error) {
	if item, ok := cfg.Contexts[targetName]; ok {
		return item, nil
	}
	currentName := strings.TrimSpace(cfg.CurrentContext)
	if currentName == "" {
		return cfgovctx.Context{}, nil
	}
	item, ok := cfg.Contexts[currentName]
	if !ok {
		return cfgovctx.Context{}, apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("current context %q is missing while resolving pre-change policy", currentName),
			nil,
		)
	}
	return item, nil
}

func contextUsePreChangePolicy(cfg *corectx.Config[cfgovctx.Context], targetName string) (cfgovctx.Context, string, error) {
	currentName := strings.TrimSpace(cfg.CurrentContext)
	if currentName != "" {
		item, ok := cfg.Contexts[currentName]
		if !ok {
			return cfgovctx.Context{}, "", apperrors.New(
				apperrors.CodeLocalIOError,
				fmt.Sprintf("current context %q is missing while resolving pre-change policy", currentName),
				nil,
			)
		}
		return item, currentName, nil
	}
	item, ok := cfg.Contexts[targetName]
	if !ok {
		return cfgovctx.Context{}, "", apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", targetName), nil)
	}
	return item, targetName, nil
}

func validRole(role string) bool {
	return role == safety.RoleReader || role == safety.RoleWriter || role == safety.RoleAdmin
}

func roleItems(roles map[string]string) []roleItem {
	operators := make([]string, 0, len(roles))
	for operator := range roles {
		operators = append(operators, operator)
	}
	sort.Strings(operators)
	items := make([]roleItem, 0, len(operators))
	for _, operator := range operators {
		items = append(items, roleItem{Operator: operator, Role: roles[operator]})
	}
	return items
}

func runCtxExport(f *cliFlags, name string, includeCredentials bool) error {
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
	}
	if includeCredentials {
		if item.CredentialBackend != "" && item.CredentialBackend != "plain-yaml" {
			return apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("credentials backed by %s cannot be exported in cleartext", item.CredentialBackend), nil)
		}
	} else if item.Password != "" {
		item.Password = redactedCredential
	}
	data, err := yaml.Marshal(contextExportDocument{APIVersion: ctxExportAPIVersion, Name: name, Context: item})
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal context export", err)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write context export", err)
	}
	appendContextAuditWarn(f, audit.EventContextExport, item, audit.StatusSuccess, "", nil)
	return nil
}

func runCtxImport(f *cliFlags, file, rename string, force bool) error { //nolint:gocyclo // Import validation, credential planning, overwrite checks, and apply stay in one transactional command flow.
	planOnly := isPlanOnly(f)
	if file == "" {
		return apperrors.New(apperrors.CodeUsageError, "-f/--file is required", nil)
	}
	doc, err := readContextExportDocument(file)
	if err != nil {
		return err
	}
	name := firstNonEmpty(rename, doc.Name)
	if name == "" {
		return apperrors.New(apperrors.CodeUsageError, "context name is required", nil)
	}
	credentialRedacted := doc.Context.Password == redactedCredential
	if credentialRedacted {
		doc.Context.Password = ""
	}
	var credentialPlan *importedCredentialPlan
	if !credentialRedacted {
		doc.Context, credentialPlan, err = planImportedCredential(name, doc.Context)
		if err != nil {
			return err
		}
	}
	if err := validatePortableContextStatic(doc.Context); err != nil {
		return err
	}
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	if _, exists := cfg.Contexts[name]; exists && !force {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q already exists; use --force to overwrite", name), nil)
	}
	if planOnly {
		return printLocalChangePlan(f, "context", "import", name, map[string]any{
			"credentialBackend":  doc.Context.CredentialBackend,
			"credentialRedacted": credentialRedacted,
			"overwrite":          force,
		})
	}
	runBeforeContextUpdate(f)
	var mutation *mutationAuditHandle
	var appliedCredential *importedCredentialState
	var original contextTargetState
	err = updateImportedContexts(f, func(lockedCfg *corectx.Config[cfgovctx.Context]) error {
		_, exists := lockedCfg.Contexts[name]
		if exists && !force {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q already exists; use --force to overwrite", name), nil)
		}
		if err := validatePortableContextStatic(doc.Context); err != nil {
			return err
		}
		prePolicy, err := contextPreChangePolicy(lockedCfg, name)
		if err != nil {
			return err
		}
		original = captureContextTargetState(lockedCfg, name)
		metadata := mutationValueMetadata("ctx.import", doc.Context)
		metadata.Items = 1
		if exists {
			metadata.Updates = 1
		} else {
			metadata.Creates = 1
		}
		var credentialState *importedCredentialState
		if credentialPlan != nil {
			credentialState, err = inspectImportedCredentialMandatory(commandContext(f), f, prePolicy, credentialPlan)
			if err != nil {
				return err
			}
		}
		if err := authorizeForContext(f, safety.R3, prePolicy, allowContextChange, name); err != nil {
			return err
		}
		mutation, err = beginMutationAudit(f, mutationAuditSpec{
			Action:      "ctx.import",
			ContextName: name,
			Context:     prePolicy,
			Target:      audit.EventTarget{ResourceType: "context", Resource: name},
			Metadata:    metadata,
		})
		if err != nil {
			return err
		}
		if credentialState != nil {
			appliedCredential = credentialState
			if err := applyImportedCredential(commandContext(f), credentialState); err != nil {
				return err
			}
		}
		lockedCfg.Contexts[name] = doc.Context
		return nil
	})
	progress := credentialMutationProgress{}
	compensationStatus := ""
	switch {
	case err == nil:
		progress.succeeded = 1
	case mutation == nil:
		progress.failed = 1
	default:
		progress, compensationStatus, err = reconcileContextImportCredentialFailure(
			commandContext(f),
			f,
			appliedCredential,
			name,
			original,
			doc.Context,
			err,
		)
	}
	if mutation != nil {
		if auditErr := finishCredentialMutationAudit(mutation, 1, progress, compensationStatus, err); auditErr != nil {
			return auditErr
		}
	}
	if err != nil {
		return err
	}
	appendContextAuditWarnFor(f, audit.EventContextImport, name, doc.Context, audit.StatusSuccess, "", nil)
	result := contextImportResult{Name: name, CredentialRedacted: credentialRedacted}
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextImportResult", result)
	}
	p := newPrinter(f)
	if err := p.Success(fmt.Sprintf("context %q imported", name)); err != nil {
		return err
	}
	if credentialRedacted {
		return p.Info(fmt.Sprintf("credential is redacted; run: cfgov ctx set %s with a credential backend", name))
	}
	return nil
}

func runCtxMigrateCredentials(f *cliFlags, opts migrateCredentialsOptions) error {
	if err := validateCredentialMigrationOptions(f, opts); err != nil {
		return err
	}
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	candidates, err := credentialMigrationCandidates(cfg, opts.contextName)
	if err != nil {
		return err
	}
	dryRun := opts.dryRun || isPlanOnly(f)
	result := credentialMigrationResult{
		DryRun:   dryRun,
		Backend:  opts.toBackend,
		Contexts: credentialMigrationContextNames(candidates),
		Count:    len(candidates),
	}
	if dryRun || len(candidates) == 0 {
		return printCredentialMigrationResult(f, result)
	}
	runBeforeContextUpdate(f)
	applyResult, err := migrateCredentialsLocked(f, opts)
	if auditErr := finishCredentialMigrationMutation(applyResult, err); auditErr != nil {
		return auditErr
	}
	if err != nil {
		return err
	}
	migrated := applyResult.migrated
	result.Contexts = credentialMigrationContextNames(migrated)
	result.Count = len(migrated)
	for _, candidate := range migrated {
		appendCredentialMigrationAuditWarn(f, candidate.name, candidate.context, opts.toBackend, nil)
	}
	return printCredentialMigrationResult(f, result)
}

type credentialMigrationApplyResult struct {
	migrated           []migrateCredentialCandidate
	mutation           *mutationAuditHandle
	total              int
	progress           credentialMutationProgress
	compensationStatus string
}

type credentialMutationProgress struct {
	succeeded int
	failed    int
	uncertain int
}

type credentialMutationWrite struct {
	name     string
	previous string
	written  string
	existed  bool
}

type credentialMutationTransaction struct {
	backend     credstore.Backend
	backendName string
	writes      []credentialMutationWrite
}

type credentialWriteState uint8

const (
	credentialWriteUnknown credentialWriteState = iota
	credentialWriteDesired
	credentialWritePrevious
	credentialWriteDivergent
)

func finishCredentialMigrationMutation(result credentialMigrationApplyResult, operationErr error) error {
	if result.mutation == nil {
		return operationErr
	}
	return finishCredentialMutationAudit(
		result.mutation,
		result.total,
		result.progress,
		result.compensationStatus,
		operationErr,
	)
}

func migrateCredentialsLocked(f *cliFlags, opts migrateCredentialsOptions) (credentialMigrationApplyResult, error) {
	var result credentialMigrationApplyResult
	var lockedCandidates []migrateCredentialCandidate
	var transaction *credentialMutationTransaction
	compensated := false
	migrationCtx := commandContext(f)
	err := updateImportedContexts(f, func(lockedCfg *corectx.Config[cfgovctx.Context]) error {
		var err error
		lockedCandidates, err = credentialMigrationCandidates(lockedCfg, opts.contextName)
		if err != nil {
			return err
		}
		preflight, err := prepareCredentialMigrationPreflight(migrationCtx, f, opts, lockedCandidates)
		if err != nil {
			return err
		}
		if err := authorizeCredentialMigrationCandidates(f, lockedCandidates); err != nil {
			return err
		}
		result.total = len(lockedCandidates)
		metadata := mutationValueMetadata("credential.migrate", map[string]any{
			"backend":  opts.toBackend,
			"contexts": credentialMigrationContextNames(lockedCandidates),
		})
		metadata.Items = len(lockedCandidates)
		metadata.Updates = len(lockedCandidates)
		result.mutation, err = beginMutationAudit(f, mutationAuditSpec{
			Action:      string(credentialMigrationEventType),
			ContextName: firstNonEmpty(opts.contextName, "multiple"),
			Target:      audit.EventTarget{ResourceType: "credential", Resource: firstNonEmpty(opts.contextName, "multiple")},
			Metadata:    metadata,
		})
		if err != nil {
			return err
		}
		transaction = &credentialMutationTransaction{backend: preflight.backend, backendName: opts.toBackend}
		for index, candidate := range lockedCandidates {
			transaction.writes = append(transaction.writes, preflight.writes[index])
			if err := transaction.applyWrite(migrationCtx, len(transaction.writes)-1); err != nil {
				result.progress.failed++
				operationErr := apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("store credential for context %q failed", candidate.name), err)
				compensated = true
				if compensationErr := transaction.compensate(migrationCtx, f); compensationErr != nil {
					result.compensationStatus = "incomplete"
					result.progress = result.progress.afterIncompleteCompensation()
					return credentialMutationUncertainError(
						"credential migration failed and credential rollback failed; credential state is uncertain",
						operationErr,
						compensationErr,
					)
				}
				result.compensationStatus = "succeeded"
				result.progress = result.progress.afterSuccessfulCompensation()
				return operationErr
			}
			result.progress.succeeded++
		}
		result.migrated = make([]migrateCredentialCandidate, 0, len(lockedCandidates))
		for _, candidate := range lockedCandidates {
			item := candidate.context
			item.Password = credstore.EncodeRef(opts.toBackend)
			item.CredentialBackend = opts.toBackend
			lockedCfg.Contexts[candidate.name] = item
			candidate.context = item
			result.migrated = append(result.migrated, candidate)
		}
		return nil
	})
	if err != nil && transaction != nil && !compensated {
		result.progress, result.compensationStatus, err = reconcileCredentialMigrationFailure(
			migrationCtx,
			f,
			transaction,
			lockedCandidates,
			opts.toBackend,
			result.progress,
			err,
		)
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func prepareCredentialMigrationPreflight(
	ctx context.Context,
	f *cliFlags,
	opts migrateCredentialsOptions,
	candidates []migrateCredentialCandidate,
) (*credentialMutationTransaction, error) {
	contextName := firstNonEmpty(opts.contextName, "multiple")
	contextMeta := cfgovctx.Context{}
	authorizations := make([]readAuditAuthorization, 0, len(candidates))
	if len(candidates) > 0 {
		contextMeta = candidates[0].context
	}
	for _, candidate := range candidates {
		authorizations = append(authorizations, readAuditAuthorization{
			ContextName: candidate.name,
			Context:     candidate.context,
		})
	}
	spec := newReadAuditSpec(
		"credential.migrate.preflight",
		contextMeta,
		"credential",
		contextName,
		map[string]any{
			"backend":  opts.toBackend,
			"contexts": credentialMigrationContextNames(candidates),
		},
	)
	spec.ContextName = contextName
	spec.Authorize = authorizations
	return runMandatoryRead(
		f,
		spec,
		func() (*credentialMutationTransaction, error) {
			backend, err := credentialMigrationBackend(f, opts.toBackend)
			if err != nil {
				return nil, err
			}
			transaction := &credentialMutationTransaction{backend: backend, backendName: opts.toBackend}
			for _, candidate := range candidates {
				if _, err := transaction.inspectPut(ctx, candidate.name, candidate.password); err != nil {
					return nil, apperrors.New(
						apperrors.CodeCredentialStoreError,
						fmt.Sprintf("inspect credential for context %q failed", candidate.name),
						err,
					)
				}
			}
			return transaction, nil
		},
		func(*credentialMutationTransaction) int { return len(candidates) },
	)
}

func finishCredentialMutationAudit(
	handle *mutationAuditHandle,
	total int,
	progress credentialMutationProgress,
	compensationStatus string,
	operationErr error,
) error {
	skipped := total - progress.succeeded - progress.failed - progress.uncertain
	if skipped < 0 {
		skipped = 0
	}
	status := audit.StatusSuccess
	if operationErr != nil {
		status = audit.StatusFailed
		if progress.succeeded > 0 {
			status = audit.StatusPartialFailed
		}
	}
	return finishMutationAudit(handle, mutationAuditOutcome{
		Status:             status,
		Succeeded:          progress.succeeded,
		Failed:             progress.failed,
		Skipped:            skipped,
		Uncertain:          progress.uncertain,
		CompensationStatus: compensationStatus,
	}, operationErr)
}

func (progress credentialMutationProgress) afterSuccessfulCompensation() credentialMutationProgress {
	progress.failed += progress.succeeded
	progress.succeeded = 0
	return progress
}

func (progress credentialMutationProgress) afterIncompleteCompensation() credentialMutationProgress {
	progress.uncertain += progress.succeeded + progress.failed
	progress.succeeded = 0
	progress.failed = 0
	return progress
}

func reconcileCredentialMigrationFailure(
	ctx context.Context,
	f *cliFlags,
	transaction *credentialMutationTransaction,
	candidates []migrateCredentialCandidate,
	backendName string,
	progress credentialMutationProgress,
	operationErr error,
) (credentialMutationProgress, string, error) {
	state, compensationErr, stateErr := reconcileCredentialMigrationState(ctx, f, transaction, candidates, backendName)
	switch state {
	case mutationCommitUnchanged:
		if compensationErr == nil {
			return progress.afterSuccessfulCompensation(), "succeeded", operationErr
		}
		return progress.afterIncompleteCompensation(), "incomplete", credentialMutationUncertainError(
			"credential migration failed and credential rollback failed; credential state is uncertain",
			operationErr,
			compensationErr,
		)
	case mutationCommitCommitted:
		return progress, "not-safe", credentialMutationUncertainError(
			"credential migration reported failure after the context and credentials were committed",
			operationErr,
			stateErr,
		)
	case mutationCommitUnknown, mutationCommitDivergent:
		return progress.afterIncompleteCompensation(), "not-safe", credentialMutationUncertainError(
			"credential migration failed and its commit state could not be reconciled; credential rollback was not safe",
			operationErr,
			errors.Join(stateErr, compensationErr),
		)
	}
	return progress.afterIncompleteCompensation(), "not-safe", credentialMutationUncertainError(
		"credential migration failed with an unknown commit state; credential rollback was not safe",
		operationErr,
		errors.Join(stateErr, compensationErr),
	)
}

func reconcileCredentialMigrationState(
	ctx context.Context,
	f *cliFlags,
	transaction *credentialMutationTransaction,
	candidates []migrateCredentialCandidate,
	backendName string,
) (state mutationCommitState, compensationErr error, retErr error) {
	state = mutationCommitUnknown
	retErr = withContextStoreLock(func(cfg *corectx.Config[cfgovctx.Context]) error {
		committed, unchanged := credentialMigrationConfigState(cfg, candidates, backendName)
		switch {
		case unchanged:
			if err := transaction.validateAutomaticCompensation(); err != nil {
				state = mutationCommitUnknown
				return err
			}
			state = mutationCommitUnchanged
			compensationErr = transaction.compensate(ctx, f)
		case committed:
			state = mutationCommitCommitted
		default:
			state = mutationCommitDivergent
		}
		return nil
	})
	if retErr != nil {
		state = mutationCommitUnknown
	}
	return state, compensationErr, retErr
}

func credentialMigrationConfigState(
	cfg *corectx.Config[cfgovctx.Context],
	candidates []migrateCredentialCandidate,
	backendName string,
) (committed bool, unchanged bool) {
	committed = true
	unchanged = true
	for _, candidate := range candidates {
		current, exists := cfg.Contexts[candidate.name]
		if !exists {
			return false, false
		}
		expected := candidate.context
		expected.Password = credstore.EncodeRef(backendName)
		expected.CredentialBackend = backendName
		committed = committed && reflect.DeepEqual(current, expected)
		unchanged = unchanged && reflect.DeepEqual(current, candidate.context)
	}
	return committed, unchanged
}

func credentialMigrationBackend(f *cliFlags, name string) (credstore.Backend, error) {
	item := cfgovctx.Context{Base: corectx.Base{CredentialBackend: name}}
	backend, err := contextImportCredentialBackend(f)(item)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeUsageError, err.Error(), err)
	}
	if err := backend.Available(); err != nil {
		return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("backend %q not available", name), err)
	}
	return backend, nil
}

func authorizeCredentialMigrationCandidates(f *cliFlags, candidates []migrateCredentialCandidate) error {
	for _, candidate := range candidates {
		if err := authorizeForContext(f, safety.R3, candidate.context, allowContextChange, candidate.name); err != nil {
			return err
		}
	}
	return nil
}

func validateCredentialMigrationOptions(f *cliFlags, opts migrateCredentialsOptions) error {
	if !validCredentialMigrationBackend(opts.toBackend) {
		return apperrors.New(apperrors.CodeUsageError, "--to must be encrypted-file or keychain", nil)
	}
	if opts.dryRun && f.Yes && !isPlanOnly(f) {
		return apperrors.New(apperrors.CodeUsageError, "ctx migrate-credentials accepts only one of --dry-run or --yes", nil)
	}
	if !opts.dryRun && !isPlanOnly(f) && !f.Yes {
		return apperrors.New(apperrors.CodeAuthorizationRequired, "ctx migrate-credentials requires --dry-run or --yes", nil)
	}
	return nil
}

func validCredentialMigrationBackend(name string) bool {
	return name == credentialBackendEncrypted || name == credentialBackendKeychain
}

func credentialMigrationCandidates(cfg *corectx.Config[cfgovctx.Context], contextName string) ([]migrateCredentialCandidate, error) {
	if contextName != "" {
		item, ok := cfg.Contexts[contextName]
		if !ok {
			return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		if isLiteralCredential(item.Password) {
			return []migrateCredentialCandidate{{name: contextName, context: item, password: item.Password}}, nil
		}
		return nil, nil
	}
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	candidates := make([]migrateCredentialCandidate, 0, len(names))
	for _, name := range names {
		item := cfg.Contexts[name]
		if isLiteralCredential(item.Password) {
			candidates = append(candidates, migrateCredentialCandidate{name: name, context: item, password: item.Password})
		}
	}
	return candidates, nil
}

func isLiteralCredential(value string) bool {
	return value != "" && value != redactedCredential && !credstore.ParseRef(value).IsRef
}

func credentialMigrationContextNames(candidates []migrateCredentialCandidate) []string {
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.name)
	}
	return names
}

func printCredentialMigrationResult(f *cliFlags, result credentialMigrationResult) error {
	if result.DryRun {
		markPreview(f)
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("CredentialMigration", result)
	}
	action := "would migrate"
	if !result.DryRun {
		action = "migrated"
	}
	return p.Success(fmt.Sprintf("%s %d context credential(s) to %s", action, result.Count, result.Backend))
}

//nolint:gocyclo // Fail-closed Vault URL and authentication preflight intentionally stays together.
func validateCredentialBackendAvailableWithFactory(
	item cfgovctx.Context,
	vaultSecretID string,
	factory func(cfgovctx.Context) (credstore.Backend, error),
) error {
	if err := validateCredentialBackendConfiguration(item, vaultSecretID); err != nil {
		return err
	}
	name := firstNonEmpty(item.CredentialBackend, "plain-yaml")
	if name == "vault" && vaultSecretID != "" {
		return nil
	}
	item.CredentialBackend = name
	backend, err := factory(item)
	if err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential backend", err)
	}
	if err := backend.Available(); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("credential backend %q is not available", name), err)
	}
	return nil
}

func validateCredentialBackendConfiguration(item cfgovctx.Context, vaultSecretID string) error {
	name := firstNonEmpty(item.CredentialBackend, "plain-yaml")
	if name != "vault" {
		return nil
	}
	vaultURL, err := url.Parse(strings.TrimSpace(item.VaultAddr))
	if err != nil || !vaultURL.IsAbs() || vaultURL.Scheme != "https" || vaultURL.Host == "" ||
		vaultURL.Opaque != "" || vaultURL.User != nil || vaultURL.RawQuery != "" || vaultURL.ForceQuery || vaultURL.Fragment != "" {
		return apperrors.New(apperrors.CodeCredentialStoreError, "credential backend \"vault\" is not available: vaultAddr must be an absolute HTTPS URL without userinfo, query, or fragment", err)
	}
	if strings.TrimSpace(item.VaultPath) == "" {
		return apperrors.New(apperrors.CodeCredentialStoreError, "credential backend \"vault\" is not available: vaultPath is required", nil)
	}
	if vaultSecretID != "" && strings.TrimSpace(item.VaultRoleID) == "" {
		return apperrors.New(apperrors.CodeCredentialStoreError, "credential backend \"vault\" is not available: vaultRoleID is required with --vault-secret-id", nil)
	}
	return nil
}

func prepareContextCredentialTransaction(
	f *cliFlags,
	backendName string,
	password string,
	item cfgovctx.Context,
) (cfgovctx.Context, *credentialMutationTransaction, error) {
	if backendName == "" || backendName == "plain-yaml" {
		item.Password = password
		item.CredentialBackend = backendName
		return item, nil, nil
	}
	item.CredentialBackend = backendName
	backend, err := contextImportCredentialBackend(f)(item)
	if err != nil {
		return item, nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential backend", err)
	}
	item.Password = credstore.EncodeRef(backendName)
	return item, &credentialMutationTransaction{backend: backend, backendName: backendName}, nil
}

type contextCredentialPreflight struct {
	Item        cfgovctx.Context
	Transaction *credentialMutationTransaction
	WriteIndex  int
}

func prepareContextCredentialPreflight(
	ctx context.Context,
	f *cliFlags,
	contextName string,
	prePolicy cfgovctx.Context,
	backendName string,
	password string,
	item cfgovctx.Context,
	vaultSecretID string,
) (contextCredentialPreflight, error) {
	if backendName == "" || backendName == "plain-yaml" {
		stored, transaction, err := prepareContextCredentialTransaction(f, backendName, password, item)
		return contextCredentialPreflight{Item: stored, Transaction: transaction, WriteIndex: -1}, err
	}
	spec := newReadAuditSpec(
		"ctx.set.credential.preflight",
		prePolicy,
		"credential",
		contextName,
		map[string]any{
			"credentialBackend":  backendName,
			"credentialProvided": password != "",
		},
	)
	spec.ContextName = contextName
	return runMandatoryRead(
		f,
		spec,
		func() (contextCredentialPreflight, error) {
			if vaultSecretID != "" {
				if err := os.Setenv("VAULT_SECRET_ID", vaultSecretID); err != nil {
					return contextCredentialPreflight{}, apperrors.New(apperrors.CodeLocalIOError, "failed to set VAULT_SECRET_ID for credential backend", err)
				}
			}
			stored, transaction, err := prepareContextCredentialTransaction(f, backendName, password, item)
			if err != nil {
				return contextCredentialPreflight{}, err
			}
			if transaction == nil || transaction.backend == nil {
				return contextCredentialPreflight{}, apperrors.New(apperrors.CodeCredentialStoreError, "credential transaction backend is required", nil)
			}
			if err := transaction.backend.Available(); err != nil {
				return contextCredentialPreflight{}, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("credential backend %q is not available", backendName), err)
			}
			index, err := transaction.inspectPut(ctx, contextName, password)
			if err != nil {
				return contextCredentialPreflight{}, err
			}
			return contextCredentialPreflight{
				Item:        stored,
				Transaction: transaction,
				WriteIndex:  index,
			}, nil
		},
		func(contextCredentialPreflight) int { return 1 },
	)
}

func prepareContextCredentialPlan(
	ctx context.Context,
	f *cliFlags,
	cfg *corectx.Config[cfgovctx.Context],
	contextName string,
	backendName string,
	password string,
	item cfgovctx.Context,
	vaultSecretID string,
) (cfgovctx.Context, error) {
	if backendName == "vault" {
		return item, nil
	}
	prePolicy, err := contextPreChangePolicy(cfg, contextName)
	if err != nil {
		return cfgovctx.Context{}, err
	}
	preflight, err := prepareContextCredentialPreflight(
		ctx,
		f,
		contextName,
		prePolicy,
		backendName,
		password,
		item,
		vaultSecretID,
	)
	if err != nil {
		return cfgovctx.Context{}, err
	}
	return preflight.Item, nil
}

func captureContextTargetState(cfg *corectx.Config[cfgovctx.Context], name string) contextTargetState {
	item, exists := cfg.Contexts[name]
	return contextTargetState{item: item, exists: exists}
}

func (transaction *credentialMutationTransaction) inspectPut(ctx context.Context, name, password string) (int, error) {
	if transaction == nil || transaction.backend == nil {
		return -1, apperrors.New(apperrors.CodeCredentialStoreError, "credential transaction backend is required", nil)
	}
	previous, err := transaction.backend.Get(ctx, name)
	existed := err == nil
	if err != nil && !errors.Is(err, credstore.ErrNotFound) {
		return -1, err
	}
	transaction.writes = append(transaction.writes, credentialMutationWrite{
		name:     name,
		previous: previous,
		written:  password,
		existed:  existed,
	})
	return len(transaction.writes) - 1, nil
}

func (transaction *credentialMutationTransaction) applyWrite(ctx context.Context, index int) error {
	if transaction == nil || transaction.backend == nil || index < 0 || index >= len(transaction.writes) {
		return apperrors.New(apperrors.CodeCredentialStoreError, "credential transaction write is required", nil)
	}
	write := transaction.writes[index]
	return transaction.backend.Put(ctx, write.name, write.written)
}

// compensate provides single-process failure compensation only. The context
// file and credential backend remain separate stores, so this is not
// crash-atomic if the process terminates between their mutations.
func (transaction *credentialMutationTransaction) compensate(parent context.Context, f *cliFlags) error {
	if transaction == nil || transaction.backend == nil {
		return nil
	}
	if err := transaction.validateAutomaticCompensation(); err != nil {
		return err
	}
	if parent == nil {
		parent = context.Background()
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), contextImportRollbackTimeout(f))
	defer cancel()
	var compensationErr error
	for index := len(transaction.writes) - 1; index >= 0; index-- {
		write := transaction.writes[index]
		writeState, err := transaction.currentWriteState(rollbackCtx, write)
		if err != nil {
			compensationErr = errors.Join(compensationErr, err)
			continue
		}
		if writeState == credentialWritePrevious {
			continue
		}
		if writeState != credentialWriteDesired {
			compensationErr = errors.Join(compensationErr, apperrors.New(
				apperrors.CodeCredentialStoreError,
				fmt.Sprintf("credential %q changed after the transaction write; refusing rollback", write.name),
				nil,
			))
			continue
		}
		if write.existed {
			err = transaction.backend.Put(rollbackCtx, write.name, write.previous)
		} else {
			err = transaction.backend.Delete(rollbackCtx, write.name)
			if errors.Is(err, credstore.ErrNotFound) {
				err = nil
			}
		}
		if err != nil {
			compensationErr = errors.Join(compensationErr, err)
		}
	}
	return compensationErr
}

func (transaction *credentialMutationTransaction) validateAutomaticCompensation() error {
	if transaction == nil || transaction.backend == nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "credential transaction backend is required", nil)
	}
	if strings.TrimSpace(transaction.backendName) == "vault" || transaction.backend.Name() == "vault" {
		return apperrors.New(
			apperrors.CodeCredentialStoreError,
			"automatic Vault credential rollback is unsafe without atomic compare-and-swap",
			nil,
		)
	}
	return nil
}

func (transaction *credentialMutationTransaction) singleWriteState(
	parent context.Context,
	f *cliFlags,
) (credentialWriteState, error) {
	if transaction == nil || transaction.backend == nil || len(transaction.writes) != 1 {
		return credentialWriteUnknown, apperrors.New(
			apperrors.CodeCredentialStoreError,
			"exactly one credential transaction write is required for context reconciliation",
			nil,
		)
	}
	if parent == nil {
		parent = context.Background()
	}
	inspectCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), contextImportRollbackTimeout(f))
	defer cancel()
	return transaction.currentWriteState(inspectCtx, transaction.writes[0])
}

func (transaction *credentialMutationTransaction) currentWriteState(
	ctx context.Context,
	write credentialMutationWrite,
) (credentialWriteState, error) {
	current, err := transaction.backend.Get(ctx, write.name)
	if err == nil {
		switch {
		case current == write.written:
			return credentialWriteDesired, nil
		case write.existed && current == write.previous:
			return credentialWritePrevious, nil
		default:
			return credentialWriteDivergent, nil
		}
	}
	if errors.Is(err, credstore.ErrNotFound) {
		if !write.existed {
			return credentialWritePrevious, nil
		}
		return credentialWriteDivergent, nil
	}
	return credentialWriteUnknown, apperrors.New(
		apperrors.CodeCredentialStoreError,
		fmt.Sprintf("failed to verify credential %q before rollback", write.name),
		err,
	)
}

func reconcileContextSetCredentialFailure(
	ctx context.Context,
	f *cliFlags,
	transaction *credentialMutationTransaction,
	name string,
	original contextTargetState,
	expected cfgovctx.Context,
	operationErr error,
) (credentialMutationProgress, string, error) {
	if transaction != nil && len(transaction.writes) == 0 {
		transaction = nil
	}
	return reconcileContextMutationFailure(
		ctx,
		f,
		name,
		original,
		expected,
		transaction,
		"context update",
		operationErr,
	)
}

func reconcileContextImportCredentialFailure(
	ctx context.Context,
	f *cliFlags,
	state *importedCredentialState,
	name string,
	original contextTargetState,
	expected cfgovctx.Context,
	operationErr error,
) (credentialMutationProgress, string, error) {
	return reconcileContextMutationFailure(
		ctx,
		f,
		name,
		original,
		expected,
		importedCredentialTransaction(state),
		"context import",
		operationErr,
	)
}

func reconcileContextMutationFailure(
	ctx context.Context,
	f *cliFlags,
	name string,
	original contextTargetState,
	expected cfgovctx.Context,
	transaction *credentialMutationTransaction,
	operation string,
	operationErr error,
) (credentialMutationProgress, string, error) {
	state, compensationErr, stateErr := reconcileContextTargetState(ctx, f, name, original, expected, transaction)
	switch state {
	case mutationCommitUnchanged:
		if transaction == nil {
			return credentialMutationProgress{failed: 1}, "", operationErr
		}
		if compensationErr == nil {
			return credentialMutationProgress{failed: 1}, "succeeded", operationErr
		}
		return credentialMutationProgress{uncertain: 1}, "incomplete", credentialMutationUncertainError(
			operation+" failed and credential rollback failed; credential state is uncertain",
			operationErr,
			compensationErr,
		)
	case mutationCommitCommitted:
		compensationStatus := ""
		if transaction != nil {
			compensationStatus = "not-safe"
		}
		return credentialMutationProgress{succeeded: 1}, compensationStatus, credentialMutationUncertainError(
			operation+" reported failure after the context was committed",
			operationErr,
			stateErr,
		)
	case mutationCommitUnknown, mutationCommitDivergent:
		return credentialMutationProgress{uncertain: 1}, "not-safe", credentialMutationUncertainError(
			operation+" failed and its commit state could not be reconciled; operation state is uncertain",
			operationErr,
			errors.Join(stateErr, compensationErr),
		)
	}
	return credentialMutationProgress{uncertain: 1}, "not-safe", credentialMutationUncertainError(
		operation+" failed with an unknown commit state; operation state is uncertain",
		operationErr,
		errors.Join(stateErr, compensationErr),
	)
}

func reconcileContextTargetState( //nolint:gocyclo // Locked commit classification and fail-closed compensation form one state machine.
	ctx context.Context,
	f *cliFlags,
	name string,
	original contextTargetState,
	expected cfgovctx.Context,
	transaction *credentialMutationTransaction,
) (state mutationCommitState, compensationErr error, retErr error) {
	state = mutationCommitUnknown
	retErr = withContextStoreLock(func(cfg *corectx.Config[cfgovctx.Context]) error {
		current, exists := cfg.Contexts[name]
		unchanged := exists == original.exists && (!exists || persistedContextsEqual(current, original.item))
		committed := exists && persistedContextsEqual(current, expected)
		if unchanged && transaction != nil {
			if err := transaction.validateAutomaticCompensation(); err != nil {
				state = mutationCommitUnknown
				return err
			}
		}
		switch {
		case unchanged && committed && transaction != nil:
			writeState, err := transaction.singleWriteState(ctx, f)
			if err != nil {
				state = mutationCommitUnknown
				return err
			}
			switch writeState {
			case credentialWriteDesired:
				state = mutationCommitCommitted
			case credentialWritePrevious:
				state = mutationCommitUnchanged
			case credentialWriteUnknown, credentialWriteDivergent:
				state = mutationCommitUnknown
				compensationErr = apperrors.New(
					apperrors.CodeCredentialStoreError,
					"credential changed after the context transaction write; commit state is uncertain",
					nil,
				)
			}
		case committed:
			state = mutationCommitCommitted
		case unchanged:
			state = mutationCommitUnchanged
			if transaction != nil {
				compensationErr = transaction.compensate(ctx, f)
			}
		default:
			state = mutationCommitDivergent
		}
		return nil
	})
	if retErr != nil {
		state = mutationCommitUnknown
	}
	return state, compensationErr, retErr
}

func persistedContextsEqual(left, right cfgovctx.Context) bool {
	return reflect.DeepEqual(normalizePersistedContext(left), normalizePersistedContext(right))
}

func normalizePersistedContext(item cfgovctx.Context) cfgovctx.Context {
	if item.OTLPEndpointSource == "" {
		item.OTLPEndpointSource = "auto"
	}
	if item.OTLPMetricsSource == "" {
		item.OTLPMetricsSource = "auto"
	}
	if len(item.Roles) == 0 {
		item.Roles = nil
	}
	return item
}

func credentialMutationUncertainError(message string, operationErr, reconciliationErr error) error {
	return apperrors.New(
		apperrors.CodePartialFailure,
		message,
		errors.Join(operationErr, reconciliationErr),
	)
}

func withContextStoreLock(action func(*corectx.Config[cfgovctx.Context]) error) (retErr error) {
	dir, err := corectx.ConfigDir()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to resolve context config directory", err)
	}
	lock := lockfile.New(filepath.Join(dir, "config"))
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(); err != nil && retErr == nil {
			retErr = apperrors.New(apperrors.CodeLocalIOError, "failed to release context config lock", err)
		}
	}()
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	return action(cfg)
}

func readContextExportDocument(path string) (contextExportDocument, error) {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "invalid context import file", nil)
	}
	info, err := os.Stat(clean)
	if err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeLocalIOError, "failed to stat context import file", err)
	}
	if info.IsDir() {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "context import file is a directory", nil)
	}
	data, err := os.ReadFile(clean) //nolint:gosec // User supplied context import path.
	if err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read context import file", err)
	}
	var doc contextExportDocument
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "context import must contain exactly one YAML document", nil)
		}
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	if doc.APIVersion != ctxExportAPIVersion {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUnsupportedProtocol, fmt.Sprintf("unsupported context export apiVersion %q", doc.APIVersion), nil)
	}
	return doc, nil
}

func planImportedCredential(name string, item cfgovctx.Context) (cfgovctx.Context, *importedCredentialPlan, error) {
	if ref := credstore.ParseRef(item.Password); ref.IsRef {
		if strings.TrimSpace(ref.BackendName) == "" {
			return item, nil, apperrors.New(apperrors.CodeUsageError, "credential reference backend must not be empty", nil)
		}
		if item.CredentialBackend != "" && item.CredentialBackend != ref.BackendName {
			return item, nil, apperrors.New(apperrors.CodeUsageError, "credential reference does not match credentialBackend", nil)
		}
		item.CredentialBackend = ref.BackendName
		item.Password = credstore.EncodeRef(ref.BackendName)
		return item, nil, nil
	}
	if item.CredentialBackend == "" || item.CredentialBackend == "plain-yaml" {
		return item, nil, nil
	}
	if item.Password == "" {
		item.Password = credstore.EncodeRef(item.CredentialBackend)
		return item, nil, nil
	}
	backendContext := item
	backendContext.Password = ""
	plan := &importedCredentialPlan{
		backendName: item.CredentialBackend,
		name:        name,
		password:    item.Password,
		context:     backendContext,
	}
	item.Password = credstore.EncodeRef(item.CredentialBackend)
	return item, plan, nil
}

func inspectImportedCredential(ctx context.Context, plan *importedCredentialPlan) (*importedCredentialState, error) {
	if plan == nil {
		return nil, nil
	}
	if plan.backend == nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "credential backend is required before import preflight", nil)
	}
	previous, err := plan.backend.Get(ctx, plan.name)
	if err == nil {
		return &importedCredentialState{plan: plan, previous: previous, existed: true}, nil
	}
	if errors.Is(err, credstore.ErrNotFound) {
		return &importedCredentialState{plan: plan}, nil
	}
	return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to inspect existing credential before import", err)
}

func inspectImportedCredentialMandatory(
	ctx context.Context,
	f *cliFlags,
	prePolicy cfgovctx.Context,
	plan *importedCredentialPlan,
) (*importedCredentialState, error) {
	if plan == nil {
		return nil, nil
	}
	spec := newReadAuditSpec(
		"ctx.import.credential.preflight",
		prePolicy,
		"credential",
		plan.name,
		map[string]string{"credentialBackend": plan.backendName},
	)
	spec.ContextName = plan.name
	return runMandatoryRead(
		f,
		spec,
		func() (*importedCredentialState, error) {
			backend, err := contextImportCredentialBackend(f)(plan.context)
			if err != nil {
				return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to initialize credential backend", err)
			}
			if err := backend.Available(); err != nil {
				return nil, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("credential backend %q is not available", plan.backendName), err)
			}
			boundPlan := *plan
			boundPlan.backend = backend
			return inspectImportedCredential(ctx, &boundPlan)
		},
		func(*importedCredentialState) int { return 1 },
	)
}

func applyImportedCredential(ctx context.Context, state *importedCredentialState) error {
	if state == nil || state.plan == nil {
		return nil
	}
	if err := state.plan.backend.Put(ctx, state.plan.name, state.plan.password); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to store imported credential", err)
	}
	return nil
}

func importedCredentialTransaction(state *importedCredentialState) *credentialMutationTransaction {
	if state == nil || state.plan == nil {
		return nil
	}
	return &credentialMutationTransaction{
		backend:     state.plan.backend,
		backendName: state.plan.backendName,
		writes: []credentialMutationWrite{{
			name:     state.plan.name,
			previous: state.previous,
			written:  state.plan.password,
			existed:  state.existed,
		}},
	}
}

func contextImportCredentialBackend(
	f *cliFlags,
) func(cfgovctx.Context) (credstore.Backend, error) {
	if f != nil && f.contextImport != nil && f.contextImport.newCredentialBackend != nil {
		return f.contextImport.newCredentialBackend
	}
	return credentialBackendForContext
}

func updateImportedContexts(
	f *cliFlags,
	update func(*corectx.Config[cfgovctx.Context]) error,
) error {
	if f != nil && f.contextImport != nil && f.contextImport.updateContexts != nil {
		return f.contextImport.updateContexts(update)
	}
	return cfgovctx.Update(update)
}

func contextImportRollbackTimeout(f *cliFlags) time.Duration {
	if f != nil && f.contextImport != nil && f.contextImport.rollbackTimeout > 0 {
		return f.contextImport.rollbackTimeout
	}
	return 5 * time.Second
}

func credentialBackendForContext(item cfgovctx.Context) (credstore.Backend, error) {
	if item.CredentialBackend == "vault" {
		return credstore.NewVault(credstore.VaultConfig{Addr: item.VaultAddr, Path: item.VaultPath, RoleID: item.VaultRoleID, Namespace: item.VaultNamespace}), nil
	}
	return credstore.New(item.CredentialBackend)
}

func validatePortableContext(item cfgovctx.Context) error {
	return validatePortableContextWithCredentialFactory(item, credentialBackendForContext)
}

func validatePortableContextWithCredentialFactory( //nolint:gocyclo // Backend-specific context and governance-policy validation is intentionally centralized.
	item cfgovctx.Context,
	factory func(cfgovctx.Context) (credstore.Backend, error),
) error {
	if err := validatePortableContextStatic(item); err != nil {
		return err
	}
	return validateCredentialBackendAvailableWithFactory(item, "", factory)
}

func validatePortableContextStatic(item cfgovctx.Context) error { //nolint:gocyclo // Backend-specific context and governance-policy validation is intentionally centralized.
	if item.Backend != "nacos" && item.Backend != "apollo" && item.Backend != "etcd" && item.Backend != "consul" && item.Backend != "k8s" {
		return apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
	}
	switch item.Backend {
	case "etcd":
		if err := etcdBackend.ValidateEndpoints(item.Server); err != nil {
			return err
		}
		if err := etcdBackend.ValidateKeyPrefix(item.EtcdKeyPrefix); err != nil {
			return err
		}
	case "consul":
		if err := consulBackend.ValidateServer(item.Server); err != nil {
			return err
		}
		if err := consulBackend.ValidateKeyPrefix(item.ConsulKeyPrefix); err != nil {
			return err
		}
	case "k8s":
	default:
		if err := validateServerURL(item.Server); err != nil {
			return err
		}
	}
	if item.Backend == "apollo" && item.ApolloAppID == "" {
		return apperrors.New(apperrors.CodeUsageError, "apollo context requires apolloAppId", nil)
	}
	if err := validateCredentialBackendConfiguration(item, ""); err != nil {
		return err
	}
	if item.TicketPattern != "" {
		if _, err := regexp.Compile(item.TicketPattern); err != nil {
			return apperrors.New(apperrors.CodeUsageError, "invalid context ticketPattern", err)
		}
	}
	for operator, role := range item.Roles {
		if strings.TrimSpace(operator) == "" {
			return apperrors.New(apperrors.CodeUsageError, "context role operator must not be empty", nil)
		}
		if !validRole(role) {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("invalid context role %q for operator %q", role, operator), nil)
		}
	}
	return validateRolesURL(item.RolesSource, item.RolesURL, item.AllowInsecureRolesURL)
}

func validateRolesURL(source, rawURL string, _ bool) error {
	if source != "" && source != "inline" && source != "url" {
		return apperrors.New(apperrors.CodeUsageError, "--roles-source must be inline or url", nil)
	}
	if source == "url" || strings.TrimSpace(rawURL) != "" {
		return apperrors.New(apperrors.CodeNotImplemented, "remote role sources are not implemented; use inline roles", nil)
	}
	return nil
}

func contextView(name string, item cfgovctx.Context, current, showSecrets bool) map[string]any {
	password := ""
	if showSecrets {
		password = item.Password
	}
	return map[string]any{
		"name":                name,
		"current":             current,
		"backend":             item.Backend,
		"server":              item.Server,
		"username":            item.Username,
		"password":            password,
		"passwordSet":         item.Password != "",
		"namespace":           item.Namespace,
		"env":                 item.Env,
		"protected":           item.Protected,
		"ticketPattern":       item.TicketPattern,
		"credentialBackend":   item.CredentialBackend,
		"rolesSource":         item.RolesSource,
		"rolesURL":            item.RolesURL,
		"otlpEndpoint":        item.OTLPEndpoint,
		"otlpMetricsEndpoint": item.OTLPMetricsEndpoint,
		"otlpInsecure":        item.OTLPInsecure,
		"vaultAddr":           item.VaultAddr,
		"vaultPath":           item.VaultPath,
		"vaultRoleID":         item.VaultRoleID,
		"vaultNamespace":      item.VaultNamespace,
		"apolloAppId":         item.ApolloAppID,
		"apolloEnv":           item.ApolloEnv,
		"apolloCluster":       item.ApolloCluster,
		"apolloNamespace":     item.ApolloNamespace,
		"apolloRuleNamespace": item.ApolloRuleNamespace,
		"etcdKeyPrefix":       item.EtcdKeyPrefix,
		"etcdRuleNamespace":   item.EtcdRuleNamespace,
		"etcdCaCert":          item.EtcdCACert,
		"etcdClientCert":      item.EtcdClientCert,
		"etcdClientKey":       item.EtcdClientKey,
		"consulKeyPrefix":     item.ConsulKeyPrefix,
		"consulRuleNamespace": item.ConsulRuleNamespace,
		"consulCaCert":        item.ConsulCACert,
		"consulClientCert":    item.ConsulClientCert,
		"consulClientKey":     item.ConsulClientKey,
		"k8sKubeconfig":       item.K8sKubeconfig,
		"k8sContext":          item.K8sContext,
	}
}

func appendContextAuditWarn(f *cliFlags, eventType audit.EventType, item cfgovctx.Context, status, diff string, err error) {
	appendContextAuditWarnFor(f, eventType, f.contextName(), item, status, diff, err)
}

func appendContextAuditWarnFor(f *cliFlags, eventType audit.EventType, contextName string, item cfgovctx.Context, status, diff string, err error) {
	appendAuditWarnForContext(
		f,
		eventType,
		contextName,
		item,
		audit.EventTarget{ResourceType: "context", Resource: contextName},
		status,
		diff,
		err,
	)
}

func appendRoleAuditWarn(f *cliFlags, eventType audit.EventType, contextName string, item cfgovctx.Context, operator, role string, err error) {
	path, pathErr := configuredAuditPath(f)
	if pathErr != nil {
		_, _ = fmt.Fprintf(diagnosticWriter(f), "warning: audit path failed: %s\n", redactedDiagnosticError(pathErr))
		return
	}
	status := audit.StatusSuccess
	if err != nil {
		status = audit.StatusFailed
	}
	evt := audit.Event{
		EventType: eventType,
		Operator:  currentOperator(f),
		Context:   audit.EventContext{Name: contextName, Env: item.Env, Protected: item.Protected},
		Target:    audit.EventTarget{ResourceType: "role", Resource: operator},
		Status:    status,
		Diff:      sanitizedAuditSummary(f, eventType, ""),
		RoleChange: &audit.EventRoleChange{
			ChangedOperator: operator,
			Role:            role,
		},
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code)}
	}
	if appendErr := appendQueuedAuditEvent(f, path, evt); appendErr != nil {
		_, _ = fmt.Fprintf(diagnosticWriter(f), "warning: audit write failed: %s\n", redactedDiagnosticError(appendErr))
	}
}

func appendCredentialMigrationAuditWarn(f *cliFlags, contextName string, item cfgovctx.Context, backendName string, err error) {
	path, pathErr := configuredAuditPath(f)
	if pathErr != nil {
		_, _ = fmt.Fprintf(diagnosticWriter(f), "warning: audit path failed: %s\n", redactedDiagnosticError(pathErr))
		return
	}
	status := audit.StatusSuccess
	if err != nil {
		status = audit.StatusFailed
	}
	evt := audit.Event{
		EventType: credentialMigrationEventType,
		Operator:  currentOperator(f),
		Context:   audit.EventContext{Name: contextName, Env: item.Env, Protected: item.Protected},
		Target:    audit.EventTarget{ResourceType: "credential", Resource: backendName},
		Status:    status,
		Diff:      sanitizedAuditSummary(f, credentialMigrationEventType, "credential backend="+backendName),
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code)}
	}
	if appendErr := appendQueuedAuditEvent(f, path, evt); appendErr != nil {
		_, _ = fmt.Fprintf(diagnosticWriter(f), "warning: audit write failed: %s\n", redactedDiagnosticError(appendErr))
	}
}
