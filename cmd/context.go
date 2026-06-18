package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"
	"github.com/JiangHe12/opskit-core/safety"

	etcdBackend "github.com/JiangHe12/cfgov-cli/internal/backend/etcd"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	ctxExportAPIVersion = "cfgov-cli.io/ctx-export/v1"
	redactedCredential  = "<REDACTED>"
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

type roleOptions struct {
	targetOperator string
	role           string
}

type roleItem struct {
	Operator string `json:"operator"`
	Role     string `json:"role"`
}

func newContextCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "ctx", Aliases: []string{"context"}, Short: "Manage cfgov contexts", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(ctxSetCmd(f), ctxUseCmd(f), ctxListCmd(f), ctxCurrentCmd(f), ctxDeleteCmd(f), ctxExportCmd(f), ctxImportCmd(f), ctxTestCmd(f), ctxRoleCmd(f))
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
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a backend-bound context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Backend == "" {
				return apperrors.New(apperrors.CodeUsageError, "--backend is required", nil)
			}
			if f.Backend != "nacos" && f.Backend != "apollo" && f.Backend != "etcd" && f.Backend != "k8s" {
				return apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
			}
			if f.Backend == "etcd" {
				if err := etcdBackend.ValidateEndpoints(f.Server); err != nil {
					return err
				}
				if err := etcdBackend.ValidateKeyPrefix(etcdKeyPrefix); err != nil {
					return err
				}
			} else if f.Backend != "k8s" {
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
			if vaultSecretID != "" {
				if err := os.Setenv("VAULT_SECRET_ID", vaultSecretID); err != nil {
					return apperrors.New(apperrors.CodeLocalIOError, "failed to set VAULT_SECRET_ID for credential backend", err)
				}
			}
			credential := firstNonEmpty(f.Password, apolloToken, apolloSecret)
			if credential != "" && (credentialBackend == "" || credentialBackend == "plain-yaml") {
				return apperrors.New(apperrors.CodeUsageError, "credentials must use a non-plain credential backend", nil)
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
				K8sKubeconfig:       f.K8sKubeconfig,
				K8sContext:          f.K8sContext,
			}
			var err error
			item, err = cfgovctx.StoreCredential(cmd.Context(), args[0], credentialBackend, credential, item)
			if err != nil {
				return apperrors.New(apperrors.CodeCredentialStoreError, "failed to store credential", err)
			}
			if err := cfgovctx.Set(args[0], item); err != nil {
				return err
			}
			return newPrinter(f).JSONData("ContextItem", contextView(args[0], item, false, false))
		},
	}
	cmd.Flags().BoolVar(&protected, "protected", false, "Mark context as protected")
	cmd.Flags().StringVar(&credentialBackend, "credential-backend", "plain-yaml", "Credential backend")
	cmd.Flags().StringVar(&env, "env", "", "Environment label")
	cmd.Flags().StringVar(&ticketPattern, "ticket-pattern", "", "Regex pattern for ticket validation")
	cmd.Flags().StringVar(&rolesSource, "roles-source", "", "RBAC roles source: inline | url")
	cmd.Flags().StringVar(&rolesURL, "roles-url", "", "Remote RBAC roles YAML/JSON URL")
	cmd.Flags().BoolVar(&allowInsecureRolesURL, "allow-insecure-roles-url", false, "Allow http:// roles-url")
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
			if err := cfgovctx.Use(args[0]); err != nil {
				return err
			}
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
			p.Table([]string{"NAME", "CURRENT", "BACKEND", "SERVER", "NAMESPACE", "ENV", "PROTECTED", "PASSWORD"}, rows)
			return nil
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
			item := cfg.Contexts[args[0]]
			if err := cfgovctx.Delete(args[0]); err != nil {
				return err
			}
			appendContextAuditWarn(f, audit.EventType("ctx.delete"), item, audit.StatusSuccess, "", nil)
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

func ctxTestCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "test [name]",
		Short: "Test backend connectivity for a context",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var backendName, ctxName string
			var meta cfgovctx.Context
			var backend cfgov.Backend
			var err error
			if len(args) == 1 {
				backend, err = buildBackendFromNamedContext(cmd.Context(), f, args[0])
				if err != nil {
					appendContextAuditWarn(f, audit.EventContextTest, cfgovctx.Context{}, audit.StatusFailed, "", err)
					return err
				}
				cfg, _ := cfgovctx.Load()
				meta = cfg.Contexts[args[0]]
				ctxName = args[0]
			} else {
				var item cfgovctx.Context
				backend, item, err = buildBackend(f)
				if err != nil {
					appendContextAuditWarn(f, audit.EventContextTest, cfgovctx.Context{}, audit.StatusFailed, "", err)
					return err
				}
				meta = item
				ctxName = f.contextName()
			}
			backendName = backend.Describe().Backend
			err = backend.Ping(cmd.Context())
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendContextAuditWarn(f, audit.EventContextTest, meta, status, "backend="+backendName, err)
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
	if item.Roles == nil {
		item.Roles = map[string]string{}
	}
	item.Roles[opts.targetOperator] = opts.role
	if err := cfgovctx.Set(contextName, item); err != nil {
		return err
	}
	appendRoleAuditWarn(f, audit.EventRoleAssign, contextName, item, opts.targetOperator, opts.role, nil)
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextItem", map[string]any{"context": contextName, "operator": opts.targetOperator, "role": opts.role})
	}
	newPrinter(f).Success(fmt.Sprintf("role %q assigned to %q in context %q", opts.role, opts.targetOperator, contextName))
	return nil
}

func runCtxRoleUnset(f *cliFlags, contextName string, opts roleOptions) error {
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	if item.Roles != nil {
		delete(item.Roles, opts.targetOperator)
		if len(item.Roles) == 0 {
			item.Roles = nil
		}
	}
	if err := cfgovctx.Set(contextName, item); err != nil {
		return err
	}
	appendRoleAuditWarn(f, audit.EventRoleRevoke, contextName, item, opts.targetOperator, "", nil)
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextItem", map[string]any{"context": contextName, "operator": opts.targetOperator, "removed": true})
	}
	newPrinter(f).Success(fmt.Sprintf("role removed from %q in context %q", opts.targetOperator, contextName))
	return nil
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
		p.Info("(no roles assigned)")
		return nil
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.Operator, item.Role})
	}
	p.Table([]string{"OPERATOR", "ROLE"}, rows)
	return nil
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

func runCtxImport(f *cliFlags, file, rename string, force bool) error {
	if f.NonInter && !f.Yes {
		return apperrors.New(apperrors.CodeAuthorizationRequired, "ctx import requires --yes in non-interactive mode", nil)
	}
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
	} else if err := prepareImportedCredential(context.Background(), name, &doc.Context); err != nil {
		return err
	}
	if err := validateImportedContext(doc.Context); err != nil {
		return err
	}
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	if _, exists := cfg.Contexts[name]; exists && !force {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q already exists; use --force to overwrite", name), nil)
	}
	if err := cfgovctx.Set(name, doc.Context); err != nil {
		return err
	}
	appendContextAuditWarn(f, audit.EventContextImport, doc.Context, audit.StatusSuccess, "", nil)
	result := contextImportResult{Name: name, CredentialRedacted: credentialRedacted}
	if f.Output == "json" {
		return newPrinter(f).JSONData("ContextImportResult", result)
	}
	p := newPrinter(f)
	p.Success(fmt.Sprintf("context %q imported", name))
	if credentialRedacted {
		p.Info(fmt.Sprintf("credential is redacted; run: cfgov ctx set %s with a credential backend", name))
	}
	return nil
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
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	if doc.APIVersion != ctxExportAPIVersion {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUnsupportedProtocol, fmt.Sprintf("unsupported context export apiVersion %q", doc.APIVersion), nil)
	}
	return doc, nil
}

func prepareImportedCredential(ctx context.Context, name string, item *cfgovctx.Context) error {
	if item.CredentialBackend == "" {
		if ref := credstore.ParseRef(item.Password); ref.IsRef {
			item.CredentialBackend = ref.BackendName
		}
	}
	if item.CredentialBackend == "" || item.CredentialBackend == "plain-yaml" {
		return nil
	}
	backend, err := credentialBackendForContext(*item)
	if err != nil {
		return err
	}
	if item.Password == "" {
		item.Password = credstore.EncodeRef(item.CredentialBackend)
		return nil
	}
	if err := backend.Put(ctx, name, item.Password); err != nil {
		return apperrors.New(apperrors.CodeCredentialStoreError, "failed to store credential", err)
	}
	item.Password = credstore.EncodeRef(item.CredentialBackend)
	return nil
}

func credentialBackendForContext(item cfgovctx.Context) (credstore.Backend, error) {
	if item.CredentialBackend == "vault" {
		return credstore.NewVault(credstore.VaultConfig{Addr: item.VaultAddr, Path: item.VaultPath, RoleID: item.VaultRoleID, Namespace: item.VaultNamespace}), nil
	}
	return credstore.New(item.CredentialBackend)
}

func validateImportedContext(item cfgovctx.Context) error {
	if item.Backend != "nacos" && item.Backend != "apollo" && item.Backend != "etcd" && item.Backend != "k8s" {
		return apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
	}
	if item.Backend == "etcd" {
		if err := etcdBackend.ValidateEndpoints(item.Server); err != nil {
			return err
		}
		if err := etcdBackend.ValidateKeyPrefix(item.EtcdKeyPrefix); err != nil {
			return err
		}
	} else if item.Backend != "k8s" {
		if err := validateServerURL(item.Server); err != nil {
			return err
		}
	}
	if item.Backend == "apollo" && item.ApolloAppID == "" {
		return apperrors.New(apperrors.CodeUsageError, "apollo context requires apolloAppId", nil)
	}
	return validateRolesURL(item.RolesSource, item.RolesURL, item.AllowInsecureRolesURL)
}

func validateRolesURL(source, rawURL string, allowInsecure bool) error {
	if source != "" && source != "inline" && source != "url" {
		return apperrors.New(apperrors.CodeUsageError, "--roles-source must be inline or url", nil)
	}
	if source == "url" && strings.TrimSpace(rawURL) == "" {
		return apperrors.New(apperrors.CodeUsageError, "--roles-url is required when --roles-source=url", nil)
	}
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return apperrors.New(apperrors.CodeUsageError, "roles-url must be an absolute URL", err)
	}
	if parsed.Scheme == "http" && !allowInsecure {
		return apperrors.New(apperrors.CodeUsageError, "roles-url must use https unless --allow-insecure-roles-url is set", nil)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return apperrors.New(apperrors.CodeUsageError, "roles-url must use http or https", nil)
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
		"k8sKubeconfig":       item.K8sKubeconfig,
		"k8sContext":          item.K8sContext,
	}
}

func appendContextAuditWarn(f *cliFlags, eventType audit.EventType, item cfgovctx.Context, status, diff string, err error) {
	appendAuditWarn(
		f,
		eventType,
		item,
		audit.EventTarget{ResourceType: "context", Resource: f.contextName()},
		status,
		diff,
		err,
	)
}

func appendRoleAuditWarn(f *cliFlags, eventType audit.EventType, contextName string, item cfgovctx.Context, operator, role string, err error) {
	path, pathErr := audit.DefaultPath()
	if pathErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit path failed: %v\n", pathErr)
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
		RoleChange: &audit.EventRoleChange{
			ChangedOperator: operator,
			Role:            role,
		},
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code), Message: appErr.Message}
	}
	if appendErr := audit.AppendWithOptions(path, evt, auditOptions(f)); appendErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", appendErr)
	}
}
