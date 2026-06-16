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
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a backend-bound context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Backend == "" {
				return apperrors.New(apperrors.CodeUsageError, "--backend is required", nil)
			}
			if f.Backend != "nacos" {
				return apperrors.New(apperrors.CodeNotImplemented, "only nacos backend is supported in P0", nil)
			}
			if err := validateServerURL(f.Server); err != nil {
				return err
			}
			item := cfgovctx.Context{
				Base: corectx.Base{
					Server:            f.Server,
					Username:          f.Username,
					Protected:         protected,
					CredentialBackend: credentialBackend,
					OTLPRedact:        true,
				},
				Backend:   f.Backend,
				Namespace: f.Namespace,
			}
			var err error
			item, err = cfgovctx.StoreCredential(cmd.Context(), args[0], credentialBackend, f.Password, item)
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
			})
		},
	}
	cmd.Flags().BoolVar(&protected, "protected", false, "Mark context as protected")
	cmd.Flags().StringVar(&credentialBackend, "credential-backend", "plain-yaml", "Credential backend")
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
					"name":      name,
					"current":   current,
					"backend":   item.Backend,
					"server":    item.Server,
					"namespace": item.Namespace,
					"protected": item.Protected,
				})
				rows = append(rows, []string{name, fmt.Sprint(current), item.Backend, item.Server, item.Namespace, fmt.Sprint(item.Protected)})
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
				"name":               name,
				"backend":            item.Backend,
				"server":             item.Server,
				"namespace":          item.Namespace,
				"protected":          item.Protected,
				"credentialBackend":  item.CredentialBackend,
				"credentialBackends": credstore.Available(),
			})
		},
	}
}
