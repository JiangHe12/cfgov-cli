package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type namespacePlan struct {
	ResourceType string      `json:"resourceType"`
	Action       string      `json:"action"`
	ID           string      `json:"id"`
	Name         string      `json:"name,omitempty"`
	Description  string      `json:"description,omitempty"`
	Risk         safety.Risk `json:"risk"`
	ConfigCount  int         `json:"configCount,omitempty"`
	Impact       string      `json:"impact"`
	DryRun       bool        `json:"dryRun"`
}

func newNamespaceCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "namespace", Short: "Govern Nacos namespaces", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(namespaceListCmd(f), namespaceCreateCmd(f), namespaceUpdateCmd(f), namespaceDeleteCmd(f))
	return cmd
}

func namespaceListCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List namespaces",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			manager, ctxMeta, err := buildNamespaceManager(f)
			if err != nil {
				return err
			}
			items, err := manager.ListNamespaces(cmd.Context())
			appendNamespaceAudit(f, ctxMeta, "list", "", auditStatus(err), "", err)
			if err != nil {
				return err
			}
			target := operationTargetFromContext(f, ctxMeta)
			p := newPrinter(f)
			if f.Output == "json" {
				return targetJSONList(f, "NamespaceList", items, len(items), 1, len(items), target)
			}
			printOperationTarget(p, target, operationTargetRead)
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.ID, item.Name, fmt.Sprint(item.ConfigCount), item.Description})
			}
			p.Table([]string{"ID", "NAME", "CONFIGS", "DESCRIPTION"}, rows)
			return nil
		},
	}
}

func namespaceCreateCmd(f *cliFlags) *cobra.Command {
	return namespaceMutateCmd(f, "create", "Create a namespace", func(ctx context.Context, manager cfgov.NamespaceManager, id, name, desc string) error {
		return manager.CreateNamespace(ctx, id, name, desc)
	})
}

func namespaceUpdateCmd(f *cliFlags) *cobra.Command {
	return namespaceMutateCmd(f, "update", "Update a namespace", func(ctx context.Context, manager cfgov.NamespaceManager, id, name, desc string) error {
		return manager.UpdateNamespace(ctx, id, name, desc)
	})
}

func namespaceMutateCmd(
	f *cliFlags,
	action string,
	short string,
	mutate func(context.Context, cfgov.NamespaceManager, string, string, string) error,
) *cobra.Command {
	var id, name, desc string
	cmd := &cobra.Command{
		Use:   action + " --id <id> --name <name>",
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateNamespaceInput(id, name); err != nil {
				return err
			}
			manager, ctxMeta, err := buildNamespaceManager(f)
			if err != nil {
				return err
			}
			plan := namespacePlan{ResourceType: "namespace", Action: action, ID: id, Name: name, Description: desc, Risk: safety.R1, Impact: action + " one namespace", DryRun: f.DryRun || f.Plan}
			if f.DryRun || f.Plan {
				return targetJSONData(f, "ChangePlan", plan, operationTargetFromContext(f, ctxMeta), operationTargetWrite)
			}
			if err := authorize(f, safety.R1, ctxMeta, ""); err != nil {
				return err
			}
			err = mutate(cmd.Context(), manager, id, name, desc)
			appendNamespaceAudit(f, ctxMeta, action, id, auditStatus(err), plan.Impact, err)
			if err != nil {
				return err
			}
			return targetJSONData(f, "ChangeResult", map[string]any{"resourceType": "namespace", "action": action, "id": id, "name": name}, operationTargetFromContext(f, ctxMeta), operationTargetWrite)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Namespace id")
	cmd.Flags().StringVar(&name, "name", "", "Namespace name")
	cmd.Flags().StringVar(&desc, "desc", "", "Namespace description")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func namespaceDeleteCmd(f *cliFlags) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:     "delete --id <id>",
		Aliases: []string{"del", "rm"},
		Short:   "Delete a namespace",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateNamespaceID(id); err != nil {
				return err
			}
			manager, ctxMeta, err := buildNamespaceManager(f)
			if err != nil {
				return err
			}
			count, err := manager.NamespaceConfigCount(cmd.Context(), id)
			if err != nil {
				appendNamespaceAudit(f, ctxMeta, "delete", id, audit.StatusFailed, "", err)
				return err
			}
			impact := fmt.Sprintf("delete namespace %s; configCount=%d", id, count)
			plan := namespacePlan{ResourceType: "namespace", Action: "delete", ID: id, Risk: safety.R2, ConfigCount: count, Impact: impact, DryRun: f.DryRun || f.Plan}
			if f.DryRun || f.Plan {
				return targetJSONData(f, "ChangePlan", plan, operationTargetFromContext(f, ctxMeta), operationTargetWrite)
			}
			if err := authorizeNamespaceDelete(f, ctxMeta); err != nil {
				return err
			}
			if err := confirmNamespaceDelete(f, id); err != nil {
				return err
			}
			err = manager.DeleteNamespace(cmd.Context(), id)
			appendNamespaceAudit(f, ctxMeta, "delete", id, auditStatus(err), impact, err)
			if err != nil {
				return err
			}
			return targetJSONData(f, "ChangeResult", map[string]any{"resourceType": "namespace", "action": "delete", "id": id, "configCount": count}, operationTargetFromContext(f, ctxMeta), operationTargetWrite)
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "Namespace id")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func buildNamespaceManager(f *cliFlags) (cfgov.NamespaceManager, cfgovctx.Context, error) {
	backend, ctxMeta, err := buildBackend(f)
	if err != nil {
		return nil, cfgovctx.Context{}, err
	}
	manager, err := namespaceManager(backend)
	if err != nil {
		return nil, cfgovctx.Context{}, err
	}
	return manager, ctxMeta, nil
}

func namespaceManager(backend cfgov.Backend) (cfgov.NamespaceManager, error) {
	manager, ok := backend.(cfgov.NamespaceManager)
	if !ok {
		return nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support namespaces", nil)
	}
	return manager, nil
}

func authorizeNamespaceDelete(f *cliFlags, meta cfgovctx.Context) error {
	return authorize(f, safety.R2, meta, allowProductionNamespaceDel)
}

func confirmNamespaceDelete(f *cliFlags, id string) error {
	if f.Yes || f.NonInter {
		return nil
	}
	_, _ = fmt.Fprintf(os.Stderr, "Delete namespace %q (this cannot be undone)? [y/N] ", id)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(input) == 0 {
		if errors.Is(err, io.EOF) {
			return apperrors.New(apperrors.CodeUsageError, "no confirmation input available on stdin; use --yes or run in a TTY", nil)
		}
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read confirmation", err)
	}
	if strings.EqualFold(strings.TrimSpace(input), "y") {
		return nil
	}
	_, _ = fmt.Fprintln(os.Stderr, "canceled")
	return apperrors.New(apperrors.CodeValidationFailed, "namespace delete canceled", nil)
}

func validateNamespaceInput(id, name string) error {
	if err := validateNamespaceID(id); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return apperrors.New(apperrors.CodeUsageError, "namespace name is required", nil)
	}
	return nil
}

func validateNamespaceID(id string) error {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\`) {
		return apperrors.New(apperrors.CodeUsageError, "invalid namespace id", nil)
	}
	return nil
}

func appendNamespaceAudit(f *cliFlags, ctxMeta cfgovctx.Context, verb, id, status, impact string, err error) {
	appendAuditWarn(f, audit.EventType("namespace."+verb), ctxMeta, audit.EventTarget{ResourceType: "namespace", Resource: id}, status, impact, err)
}

func auditStatus(err error) string {
	if err == nil {
		return audit.StatusSuccess
	}
	return audit.StatusFailed
}
