package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"

	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func newContextCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "ctx", Short: "Manage cfgov contexts"}
	cmd.AddCommand(ctxSetCmd(f), ctxUseCmd(f), ctxListCmd(f), ctxCurrentCmd(f))
	return cmd
}

func ctxSetCmd(f *cliFlags) *cobra.Command {
	var protected bool
	var credentialBackend string
	var apolloAppID string
	var apolloEnv string
	var apolloCluster string
	var apolloNamespace string
	var apolloRuleNamespace string
	var apolloToken string
	var apolloSecret string
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a backend-bound context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Backend == "" {
				return apperrors.New(apperrors.CodeUsageError, "--backend is required", nil)
			}
			if f.Backend != "nacos" && f.Backend != "apollo" {
				return apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
			}
			if err := validateServerURL(f.Server); err != nil {
				return err
			}
			if f.Backend == "apollo" && apolloAppID == "" {
				return apperrors.New(apperrors.CodeUsageError, "--apollo-app-id is required for apollo backend", nil)
			}
			if apolloToken != "" && apolloSecret != "" {
				return apperrors.New(apperrors.CodeUsageError, "--apollo-token and --apollo-secret are mutually exclusive", nil)
			}
			credential := firstNonEmpty(f.Password, apolloToken, apolloSecret)
			if f.Backend == "apollo" && credential != "" && (credentialBackend == "" || credentialBackend == "plain-yaml") {
				return apperrors.New(apperrors.CodeUsageError, "apollo token must use a non-plain credential backend", nil)
			}
			item := cfgovctx.Context{
				Base: corectx.Base{
					Server:            f.Server,
					Username:          f.Username,
					Protected:         protected,
					CredentialBackend: credentialBackend,
					OTLPRedact:        true,
				},
				Backend:             f.Backend,
				Namespace:           f.Namespace,
				ApolloAppID:         apolloAppID,
				ApolloEnv:           apolloEnv,
				ApolloCluster:       apolloCluster,
				ApolloNamespace:     firstNonEmpty(apolloNamespace, f.Namespace),
				ApolloRuleNamespace: apolloRuleNamespace,
			}
			var err error
			item, err = cfgovctx.StoreCredential(cmd.Context(), args[0], credentialBackend, credential, item)
			if err != nil {
				return apperrors.New(apperrors.CodeCredentialStoreError, "failed to store credential", err)
			}
			if err := cfgovctx.Set(args[0], item); err != nil {
				return err
			}
			p := newPrinter(f)
			return p.JSONData("ContextItem", map[string]any{
				"name":      args[0],
				"backend":   item.Backend,
				"server":    item.Server,
				"namespace": item.Namespace,
				"protected": item.Protected,
				"apollo": map[string]string{
					"appId":         item.ApolloAppID,
					"env":           item.ApolloEnv,
					"cluster":       item.ApolloCluster,
					"namespace":     item.ApolloNamespace,
					"ruleNamespace": item.ApolloRuleNamespace,
				},
			})
		},
	}
	cmd.Flags().BoolVar(&protected, "protected", false, "Mark context as protected")
	cmd.Flags().StringVar(&credentialBackend, "credential-backend", "plain-yaml", "Credential backend")
	cmd.Flags().StringVar(&apolloAppID, "apollo-app-id", "", "Apollo OpenAPI appId")
	cmd.Flags().StringVar(&apolloEnv, "apollo-env", "", "Apollo environment")
	cmd.Flags().StringVar(&apolloCluster, "apollo-cluster", "", "Apollo cluster")
	cmd.Flags().StringVar(&apolloNamespace, "apollo-namespace", "", "Apollo namespace")
	cmd.Flags().StringVar(&apolloRuleNamespace, "apollo-rule-namespace", "", "Apollo namespace for Sentinel rules")
	cmd.Flags().StringVar(&apolloToken, "apollo-token", "", "Apollo OpenAPI token")
	cmd.Flags().StringVar(&apolloSecret, "apollo-secret", "", "Apollo OpenAPI secret")
	_ = cmd.Flags().MarkHidden("apollo-token")
	_ = cmd.Flags().MarkHidden("apollo-secret")
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
	return &cobra.Command{
		Use:   "list",
		Short: "List contexts",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := cfgovctx.Load()
			if err != nil {
				return err
			}
			items := make([]map[string]any, 0, len(cfg.Contexts))
			rows := make([][]string, 0, len(cfg.Contexts))
			for name, item := range cfg.Contexts {
				current := name == cfg.CurrentContext
				items = append(items, map[string]any{
					"name":                name,
					"current":             current,
					"backend":             item.Backend,
					"server":              item.Server,
					"namespace":           item.Namespace,
					"protected":           item.Protected,
					"apolloAppId":         item.ApolloAppID,
					"apolloEnv":           item.ApolloEnv,
					"apolloCluster":       item.ApolloCluster,
					"apolloNamespace":     item.ApolloNamespace,
					"apolloRuleNamespace": item.ApolloRuleNamespace,
				})
				rows = append(rows, []string{name, fmt.Sprint(current), item.Backend, item.Server, firstNonEmpty(item.Namespace, item.ApolloNamespace), fmt.Sprint(item.Protected)})
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("ContextList", items, len(items), 1, len(items), false)
			}
			p.Table([]string{"NAME", "CURRENT", "BACKEND", "SERVER", "NAMESPACE", "PROTECTED"}, rows)
			return nil
		},
	}
}

func ctxCurrentCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show current context",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			item, name, err := cfgovctx.Current()
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("ContextItem", map[string]any{
				"name":                name,
				"backend":             item.Backend,
				"server":              item.Server,
				"namespace":           item.Namespace,
				"protected":           item.Protected,
				"apolloAppId":         item.ApolloAppID,
				"apolloEnv":           item.ApolloEnv,
				"apolloCluster":       item.ApolloCluster,
				"apolloNamespace":     item.ApolloNamespace,
				"apolloRuleNamespace": item.ApolloRuleNamespace,
				"credentialBackend":   item.CredentialBackend,
				"credentialBackends":  credstore.Available(),
			})
		},
	}
}
