package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/api"
	apolloBackend "github.com/JiangHe12/cfgov-cli/internal/backend/apollo"
	consulBackend "github.com/JiangHe12/cfgov-cli/internal/backend/consul"
	etcdBackend "github.com/JiangHe12/cfgov-cli/internal/backend/etcd"
	k8sBackend "github.com/JiangHe12/cfgov-cli/internal/backend/k8s"
	"github.com/JiangHe12/cfgov-cli/internal/backend/nacos"
	"github.com/JiangHe12/cfgov-cli/internal/backup"
	"github.com/JiangHe12/cfgov-cli/internal/cfgclass"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

const (
	exportManifestName = "manifest.json"
	defaultMaxChanges  = 1000
)

type configArchive struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Items      []configArchiveEntry `json:"items"`
}

type configArchiveEntry struct {
	Key      string `json:"key"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Bytes    int    `json:"bytes"`
	Type     string `json:"type,omitempty"`
	Revision string `json:"revision,omitempty"`
}

type configPlan struct {
	ResourceType string      `json:"resourceType"`
	Action       string      `json:"action"`
	Risk         safety.Risk `json:"risk"`
	Summary      planSummary `json:"summary"`
	Create       []planItem  `json:"create"`
	Update       []planItem  `json:"update"`
	Delete       []planItem  `json:"delete"`
	Prune        []planItem  `json:"prune"`
	Skip         []planItem  `json:"skip"`
	Conflict     []planItem  `json:"conflict"`
	DryRun       bool        `json:"dryRun"`
}

type planSummary struct {
	Create   int `json:"create"`
	Update   int `json:"update"`
	Delete   int `json:"delete"`
	Prune    int `json:"prune"`
	Skip     int `json:"skip"`
	Conflict int `json:"conflict"`
	Total    int `json:"total"`
}

type planItem struct {
	Key          string `json:"key"`
	LocalSHA256  string `json:"localSha256,omitempty"`
	RemoteSHA256 string `json:"remoteSha256,omitempty"`
	Bytes        int    `json:"bytes,omitempty"`
}

type localConfig struct {
	Key     string
	Content []byte
	Type    string
}

type upsertPlanOptions struct {
	Action       string
	SkipExisting bool
	Overwrite    bool
	Validate     bool
}

type reconcilePlanOptions struct {
	Prune       bool
	PruneScopes []string
	Overwrite   bool
}

func configExportCmd(f *cliFlags) *cobra.Command {
	var dir, group, prefix string
	var limit int
	cmd := &cobra.Command{
		Use:   "export --dir <dir>",
		Short: "Export configs from the current namespace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			items, err := backend.List(cmd.Context(), cfgov.ListOptions{Namespace: backend.Describe().Namespace, Group: group, Prefix: prefix, Limit: limit})
			if err != nil {
				appendAuditWarn(f, audit.EventType("config.export"), ctxMeta, audit.EventTarget{ResourceType: "config"}, audit.StatusFailed, "", err)
				return err
			}
			archive := configArchive{APIVersion: apiVersion, Kind: "ConfigExport"}
			for _, item := range items {
				blob, err := backend.Get(cmd.Context(), item.Coordinate)
				if err != nil {
					appendAuditWarn(f, audit.EventType("config.export"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: item.Coordinate.Key}, audit.StatusFailed, "", err)
					return err
				}
				file := archiveFileName(item.Coordinate.Key)
				if err := writeLocalFile(filepath.Join(dir, file), blob.Content); err != nil {
					return err
				}
				archive.Items = append(archive.Items, configArchiveEntry{
					Key:      item.Coordinate.Key,
					File:     file,
					SHA256:   sha256Bytes(blob.Content),
					Bytes:    len(blob.Content),
					Type:     item.Type,
					Revision: blob.Revision,
				})
			}
			if err := writeManifest(dir, archive); err != nil {
				return err
			}
			appendAuditWarn(f, audit.EventType("config.export"), ctxMeta, audit.EventTarget{ResourceType: "config"}, audit.StatusSuccess, archiveAuditSummary(archive.Items), nil)
			return newPrinter(f).JSONData("ExportResult", map[string]any{"dir": dir, "count": len(archive.Items), "items": archive.Items})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Output directory")
	cmd.Flags().StringVar(&group, "group", "", "Nacos group filter")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Key prefix/search filter")
	cmd.Flags().IntVar(&limit, "limit", 1000, "Maximum exported configs")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

func configImportCmd(f *cliFlags) *cobra.Command { //nolint:gocyclo // Cobra wiring plus plan/apply gates are kept together for this command.
	var dir string
	var skipExisting, overwrite, validate, forceLarge bool
	cmd := &cobra.Command{
		Use:   "import --dir <dir>",
		Short: "Import configs from a local directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			if skipExisting && overwrite {
				return apperrors.New(apperrors.CodeUsageError, "--skip-existing and --overwrite are mutually exclusive", nil)
			}
			locals, err := readLocalConfigs(dir)
			if err != nil {
				return err
			}
			plan, err := buildUpsertPlan(cmd.Context(), backend, backend.Describe().Namespace, locals, upsertPlanOptions{
				Action:       "import",
				SkipExisting: skipExisting,
				Overwrite:    overwrite,
				Validate:     validate,
			})
			if err != nil {
				return err
			}
			if err := enforcePlanLimit(plan, forceLarge, "import"); err != nil {
				return err
			}
			if !configPlanHasChanges(plan) && isStrictNoChange(f) {
				return apperrors.New(apperrors.CodeNoChangeRequired, "no changes to apply", nil)
			}
			if f.DryRun || f.Plan {
				plan.DryRun = true
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if len(plan.Conflict) > 0 {
				return apperrors.New(apperrors.CodeConflict, fmt.Sprintf("%d config(s) conflict; use --overwrite or --skip-existing", len(plan.Conflict)), nil)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			appendConfigSkippedAudits(f, ctxMeta, audit.EventType("config.import"), plan.Skip)
			for _, item := range localsForItems(locals, append(plan.Create, plan.Update...)) {
				if err := cmd.Context().Err(); err != nil {
					return err
				}
				class := cfgclass.Classify(cfgclass.OperationPush, item.Content, item.Type)
				if err := authorize(f, class.Risk, ctxMeta, ""); err != nil {
					return err
				}
				coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: item.Key}
				if _, err := maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord); err != nil {
					return err
				}
				if _, err := backend.Put(cmd.Context(), cfgov.PutRequest{Coordinate: coord, Content: item.Content, ContentType: item.Type}); err != nil {
					appendAuditWarn(f, audit.EventType("config.import"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusFailed, itemAudit(item), err)
					return err
				}
				appendAuditWarn(f, audit.EventType("config.import"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusSuccess, itemAudit(item), nil)
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"action": "config import", "summary": plan.Summary})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Input directory")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", false, "Skip configs that already exist on remote")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing remote configs")
	cmd.Flags().BoolVar(&validate, "validate", false, "Validate config content before importing")
	cmd.Flags().BoolVar(&forceLarge, "force-large-import", false, "Allow imports exceeding the default change limit")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

func configPromoteCmd(f *cliFlags) *cobra.Command { //nolint:gocyclo // Cobra wiring plus promote plan gates are kept together for this command.
	var sourceContext, key, prefix, contentType string
	var validateSource, overwrite bool
	cmd := &cobra.Command{
		Use:   "promote --source-context <ctx>",
		Short: "Promote configs from a source context to the current target",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if key == "" && prefix == "" {
				return apperrors.New(apperrors.CodeUsageError, "specify --key or --prefix", nil)
			}
			target, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			source, err := buildBackendFromNamedContext(cmd.Context(), f, sourceContext)
			if err != nil {
				return err
			}
			locals, err := sourceConfigs(cmd.Context(), source, key, prefix)
			if err != nil {
				return err
			}
			if contentType != "" {
				locals = withConfigType(locals, contentType)
			}
			if validateSource {
				if err := validateLocalConfigs(locals); err != nil {
					return err
				}
			}
			plan, err := buildUpsertPlan(cmd.Context(), target, target.Describe().Namespace, locals, upsertPlanOptions{Action: "promote", Overwrite: overwrite})
			if err != nil {
				return err
			}
			if !configPlanHasChanges(plan) && isStrictNoChange(f) {
				return apperrors.New(apperrors.CodeNoChangeRequired, "no changes to promote", nil)
			}
			if f.DryRun || f.Plan || f.Diff {
				plan.DryRun = f.DryRun || f.Plan
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			if len(plan.Conflict) > 0 {
				return apperrors.New(apperrors.CodeConflict, fmt.Sprintf("%d config(s) conflict; use --overwrite", len(plan.Conflict)), nil)
			}
			appendConfigSkippedAudits(f, ctxMeta, audit.EventType("config.promote"), plan.Skip)
			if err := applyUpserts(cmd.Context(), f, target, ctxMeta, localsForItems(locals, append(plan.Create, plan.Update...)), "config.promote"); err != nil {
				return err
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"action": "config promote", "summary": plan.Summary})
		},
	}
	cmd.Flags().StringVar(&sourceContext, "source-context", "", "Source context")
	cmd.Flags().StringVar(&key, "key", "", "Single key to promote")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Prefix/search filter")
	cmd.Flags().StringVar(&contentType, "type", "", "Config type: text, properties, json, yaml, xml")
	cmd.Flags().BoolVar(&validateSource, "validate", false, "Validate source config format before promoting")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing target configs")
	_ = cmd.MarkFlagRequired("source-context")
	return cmd
}

func configRollbackCmd(f *cliFlags) *cobra.Command {
	var key, backupFile, backupID, historyID string
	var validateTarget bool
	cmd := &cobra.Command{
		Use:   "rollback --key <key>",
		Short: "Rollback one config from backup or history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if countNonEmpty(backupFile, backupID, historyID) != 1 {
				return apperrors.New(apperrors.CodeUsageError, "specify exactly one of --backup-file, --backup-id, or --history-id", nil)
			}
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			content, err := rollbackContent(cmd.Context(), backend, key, backupFile, backupID, historyID)
			if err != nil {
				return err
			}
			if validateTarget {
				if err := validateContent(content, inferType(key)); err != nil {
					return err
				}
			}
			local := localConfig{Key: key, Content: content, Type: inferType(key)}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			remote, _ := backend.Get(cmd.Context(), coord)
			plan := configPlan{ResourceType: "config", Action: "rollback", Risk: safety.R1, Update: []planItem{{
				Key: key, LocalSHA256: sha256Bytes(content), RemoteSHA256: sha256Bytes(remote.Content), Bytes: len(content),
			}}}
			plan.Summary = summarizePlan(plan)
			if sha256Bytes(remote.Content) == sha256Bytes(content) && isStrictNoChange(f) {
				return apperrors.New(apperrors.CodeNoChangeRequired, "remote already matches rollback target", nil)
			}
			if f.DryRun || f.Plan || f.Diff {
				plan.DryRun = f.DryRun || f.Plan
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			if err := applyUpserts(cmd.Context(), f, backend, ctxMeta, []localConfig{local}, "config.rollback"); err != nil {
				return err
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"action": "config rollback", "summary": plan.Summary})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key")
	cmd.Flags().StringVar(&backupFile, "backup-file", "", "Local backup file")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "Local backup id")
	cmd.Flags().StringVar(&historyID, "history-id", "", "Nacos history id")
	cmd.Flags().BoolVar(&validateTarget, "validate", false, "Validate target content before rollback")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configReconcileCmd(f *cliFlags) *cobra.Command {
	var dir string
	var prune, overwrite, forceLarge bool
	var pruneScopes []string
	cmd := &cobra.Command{
		Use:   "reconcile --dir <dir>",
		Short: "Reconcile remote configs with a local directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			locals, err := readLocalConfigs(dir)
			if err != nil {
				return err
			}
			plan, err := buildReconcilePlan(cmd.Context(), backend, backend.Describe().Namespace, locals, reconcilePlanOptions{
				Prune:       prune,
				PruneScopes: pruneScopes,
				Overwrite:   overwrite,
			})
			if err != nil {
				return err
			}
			if err := enforceReconcilePlanGates(f, plan, forceLarge); err != nil {
				return err
			}
			if f.DryRun || f.Plan {
				plan.DryRun = true
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if len(plan.Conflict) > 0 {
				return apperrors.New(apperrors.CodeConflict, fmt.Sprintf("%d config(s) conflict; use --overwrite", len(plan.Conflict)), nil)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			required := safety.AllowFlag("")
			if len(plan.Prune) > 0 {
				required = allowProductionPrune
			}
			if err := authorizeReconcile(f, plan.Risk, ctxMeta, required); err != nil {
				return err
			}
			appendConfigSkippedAudits(f, ctxMeta, audit.EventType("config.reconcile"), plan.Skip)
			if err := applyUpserts(cmd.Context(), f, backend, ctxMeta, localsForItems(locals, append(plan.Create, plan.Update...)), "config.reconcile"); err != nil {
				return err
			}
			for _, item := range append(plan.Delete, plan.Prune...) {
				coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: item.Key}
				if _, err := maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord); err != nil {
					return err
				}
				if err := backend.Delete(cmd.Context(), cfgov.DeleteRequest{Coordinate: coord}); err != nil {
					appendAuditWarn(f, audit.EventType("config.reconcile"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusFailed, "delete sha256="+item.RemoteSHA256, err)
					return err
				}
				appendAuditWarn(f, audit.EventType("config.reconcile"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusSuccess, "delete sha256="+item.RemoteSHA256, nil)
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"action": "config reconcile", "summary": plan.Summary})
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "Input directory")
	cmd.Flags().BoolVar(&prune, "prune", false, "Delete remote configs missing from local directory")
	cmd.Flags().StringSliceVar(&pruneScopes, "prune-scope", nil, "Namespace[/group] scopes for prune")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing remote configs")
	cmd.Flags().BoolVar(&forceLarge, "force-large-reconcile", false, "Allow reconciles exceeding the default change limit")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

func authorizeReconcile(f *cliFlags, base safety.Risk, meta cfgovctx.Context, required safety.AllowFlag) error {
	if required != "" {
		return authorize(f, base, meta, required)
	}
	effective := safety.EffectiveRisk(base, safety.ContextMeta{Protected: meta.Protected})
	if effective == safety.R3 {
		err := safety.Authorize(safety.R2, safety.Options{
			Yes:            f.Yes,
			NonInteractive: f.NonInter,
			Ticket:         f.Ticket,
			TicketPattern:  meta.TicketPattern,
			Validator:      ticketValidator(meta.TicketValidator, f.contextName(), currentOperator(f)),
			Roles:          meta.Roles,
			Operator:       currentOperator(f),
		})
		if err != nil {
			appendAuditWarn(f, audit.EventAuthorizationDenied, meta, audit.EventTarget{ResourceType: "config"}, audit.StatusDenied, "", err)
		}
		return err
	}
	return authorize(f, base, meta, "")
}

func applyUpserts(ctx context.Context, f *cliFlags, backend cfgov.Backend, meta cfgovctx.Context, items []localConfig, eventType audit.EventType) error {
	for _, item := range orderedLocals(items) {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := validateConfigKey(backend, item.Key)
		if err != nil {
			return err
		}
		item.Key = key
		class := cfgclass.Classify(cfgclass.OperationPush, item.Content, item.Type)
		if err := authorize(f, class.Risk, meta, ""); err != nil {
			return err
		}
		coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: item.Key}
		if _, err := maybeBackupConfig(ctx, f, backend, meta, coord); err != nil {
			return err
		}
		if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: coord, Content: item.Content, ContentType: item.Type}); err != nil {
			appendAuditWarn(f, eventType, meta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusFailed, itemAudit(item), err)
			return err
		}
		appendAuditWarn(f, eventType, meta, audit.EventTarget{ResourceType: "config", Resource: item.Key}, audit.StatusSuccess, itemAudit(item), nil)
	}
	return nil
}

func appendConfigSkippedAudits(f *cliFlags, meta cfgovctx.Context, eventType audit.EventType, items []planItem) {
	for _, item := range items {
		if item.LocalSHA256 == "" || item.RemoteSHA256 != item.LocalSHA256 {
			continue
		}
		appendAuditWarn(
			f,
			eventType,
			meta,
			audit.EventTarget{ResourceType: "config", Resource: item.Key},
			auditStatusSkipped,
			"sha256="+item.LocalSHA256,
			nil,
		)
	}
}

func readLocalConfigs(dir string) ([]localConfig, error) {
	manifestPath := filepath.Join(dir, exportManifestName)
	if data, err := os.ReadFile(manifestPath); err == nil { //nolint:gosec // manifest is under the operator-selected import directory.
		return readManifestConfigs(dir, data)
	} else if !os.IsNotExist(err) {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read manifest", err)
	}
	var items []localConfig
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == exportManifestName {
			return nil
		}
		key := filepath.ToSlash(rel)
		content, err := os.ReadFile(path) //nolint:gosec // path comes from operator-selected import directory walk.
		if err != nil {
			return err
		}
		items = append(items, localConfig{Key: key, Content: content, Type: inferType(key)})
		return nil
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read config directory", err)
	}
	return items, nil
}

func readManifestConfigs(dir string, data []byte) ([]localConfig, error) {
	var archive configArchive
	if err := json.Unmarshal(data, &archive); err != nil {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "invalid config export manifest", err)
	}
	items := make([]localConfig, 0, len(archive.Items))
	for _, entry := range archive.Items {
		cleanFile := filepath.Clean(filepath.FromSlash(entry.File))
		if entry.File == "" || filepath.IsAbs(cleanFile) || cleanFile == "." || cleanFile == ".." || strings.HasPrefix(cleanFile, ".."+string(filepath.Separator)) {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "manifest contains unsafe file path", nil)
		}
		content, err := os.ReadFile(filepath.Join(dir, cleanFile)) //nolint:gosec // manifest file path is validated relative path.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read manifest entry", err)
		}
		if entry.SHA256 != "" && sha256Bytes(content) != entry.SHA256 {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "manifest sha256 mismatch for "+entry.Key, nil)
		}
		items = append(items, localConfig{Key: entry.Key, Content: content, Type: firstNonEmpty(entry.Type, inferType(entry.Key))})
	}
	return items, nil
}

func buildUpsertPlan(ctx context.Context, backend cfgov.Backend, namespace string, locals []localConfig, opts upsertPlanOptions) (configPlan, error) {
	plan := configPlan{ResourceType: "config", Action: opts.Action, Risk: safety.R1}
	for _, item := range orderedLocals(locals) {
		key, err := validateConfigKey(backend, item.Key)
		if err != nil {
			return plan, err
		}
		item.Key = key
		if opts.Validate {
			if err := validateContent(item.Content, item.Type); err != nil {
				entry := planItem{Key: key, LocalSHA256: sha256Bytes(item.Content), Bytes: len(item.Content)}
				plan.Conflict = append(plan.Conflict, entry)
				continue
			}
		}
		coord := cfgov.Coordinate{Namespace: namespace, Key: key}
		remote, err := backend.Get(ctx, coord)
		entry := planItem{Key: key, LocalSHA256: sha256Bytes(item.Content), Bytes: len(item.Content)}
		if err != nil {
			if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
				plan.Create = append(plan.Create, entry)
				continue
			}
			return plan, err
		}
		entry.RemoteSHA256 = sha256Bytes(remote.Content)
		switch {
		case entry.RemoteSHA256 == entry.LocalSHA256:
			plan.Skip = append(plan.Skip, entry)
		case opts.SkipExisting:
			plan.Skip = append(plan.Skip, entry)
		case opts.Overwrite:
			plan.Update = append(plan.Update, entry)
		default:
			plan.Conflict = append(plan.Conflict, entry)
		}
	}
	plan.Summary = summarizePlan(plan)
	return plan, nil
}

func buildReconcilePlan(ctx context.Context, backend cfgov.Backend, namespace string, locals []localConfig, opts reconcilePlanOptions) (configPlan, error) {
	scopes, err := parsePruneScopes(opts.PruneScopes, namespace, opts.Prune)
	if err != nil {
		return configPlan{}, err
	}
	plan, err := buildUpsertPlan(ctx, backend, namespace, locals, upsertPlanOptions{Action: "reconcile", Overwrite: opts.Overwrite})
	if err != nil {
		return plan, err
	}
	plan.Risk = safety.R2
	if opts.Prune {
		if err := appendPruneItems(ctx, backend, namespace, locals, scopes, &plan); err != nil {
			return plan, err
		}
	}
	plan.Summary = summarizePlan(plan)
	return plan, nil
}

func appendPruneItems(ctx context.Context, backend cfgov.Backend, namespace string, locals []localConfig, scopes []pruneScope, plan *configPlan) error {
	remote, err := backend.List(ctx, cfgov.ListOptions{Namespace: namespace, Limit: 10000})
	if err != nil {
		return err
	}
	localSet := map[string]bool{}
	for _, item := range locals {
		key, err := validateConfigKey(backend, item.Key)
		if err != nil {
			return err
		}
		localSet[key] = true
	}
	for _, item := range remote {
		if !pruneScopeContains(scopes, namespace, item.Coordinate.Key) {
			continue
		}
		if !localSet[item.Coordinate.Key] {
			plan.Prune = append(plan.Prune, planItem{Key: item.Coordinate.Key, RemoteSHA256: item.Revision})
		}
	}
	if len(plan.Prune) > 0 {
		plan.Risk = safety.R3
	}
	return nil
}

func sourceConfigs(ctx context.Context, backend cfgov.Backend, key, prefix string) ([]localConfig, error) {
	if key != "" {
		key, err := validateConfigKey(backend, key)
		if err != nil {
			return nil, err
		}
		blob, err := backend.Get(ctx, cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key})
		if err != nil {
			return nil, err
		}
		return []localConfig{{Key: key, Content: blob.Content, Type: inferType(key)}}, nil
	}
	items, err := backend.List(ctx, cfgov.ListOptions{Namespace: backend.Describe().Namespace, Prefix: prefix, Limit: 10000})
	if err != nil {
		return nil, err
	}
	locals := make([]localConfig, 0, len(items))
	for _, item := range items {
		blob, err := backend.Get(ctx, item.Coordinate)
		if err != nil {
			return nil, err
		}
		locals = append(locals, localConfig{Key: item.Coordinate.Key, Content: blob.Content, Type: firstNonEmpty(item.Type, inferType(item.Coordinate.Key))})
	}
	return locals, nil
}

func rollbackContent(ctx context.Context, backend cfgov.Backend, key, backupFile, backupID, historyID string) ([]byte, error) {
	if backupFile != "" {
		data, err := os.ReadFile(backupFile) //nolint:gosec // operator supplied backup file.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read backup file", err)
		}
		return data, nil
	}
	if backupID != "" {
		return rollbackContentFromBackupID(backupID)
	}
	if historyReader, ok := backend.(interface {
		HistoryBlob(context.Context, cfgov.Coordinate, string) (cfgov.Blob, error)
	}); ok {
		blob, err := historyReader.HistoryBlob(ctx, cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}, historyID)
		return blob.Content, err
	}
	return nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support rollback from history", nil)
}

func rollbackContentFromBackupID(backupID string) ([]byte, error) {
	root, err := backupRoot()
	if err != nil {
		return nil, err
	}
	items, err := backup.List(root, backup.Filter{})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to list backups", err)
	}
	for _, item := range items {
		if item.BackupID != backupID {
			continue
		}
		if item.Status == backup.StatusMissing {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "backup file missing", nil)
		}
		data, err := os.ReadFile(item.Path) //nolint:gosec // path comes from local backup index.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read backup", err)
		}
		if item.SHA256 != "" && sha256Bytes(data) != item.SHA256 {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "backup sha256 mismatch", nil)
		}
		return data, nil
	}
	return nil, apperrors.New(apperrors.CodeResourceNotFound, "backup-id not found", nil)
}

func buildBackendFromNamedContext(parent context.Context, f *cliFlags, name string) (cfgov.Backend, error) { //nolint:gocyclo // Backend construction branches are kept explicit and local.
	cfg, err := cfgovctx.Load()
	if err != nil {
		return nil, err
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return nil, apperrors.New(apperrors.CodeUsageError, "source context not found", nil)
	}
	if item.Backend != "" && item.Backend != "nacos" && item.Backend != "apollo" && item.Backend != "etcd" && item.Backend != "consul" && item.Backend != "k8s" {
		return nil, apperrors.New(apperrors.CodeNotImplemented, "backend is not supported", nil)
	}
	password, err := cfgovctx.ResolvePassword(parent, name, item)
	if err != nil {
		return nil, err
	}
	if item.Backend == "apollo" {
		return apolloBackend.New(apolloBackend.Options{
			Server:        item.Server,
			Token:         password,
			AppID:         item.ApolloAppID,
			Env:           item.ApolloEnv,
			Cluster:       item.ApolloCluster,
			Namespace:     firstNonEmpty(item.ApolloNamespace, item.Namespace),
			RuleNamespace: item.ApolloRuleNamespace,
			Operator:      currentOperator(f),
			Reason:        f.Reason,
			Timeout:       f.Timeout,
			Trace:         f.Debug || f.Trace,
			TraceOut:      os.Stderr,
		})
	}
	if item.Backend == "etcd" {
		return etcdBackend.New(etcdBackend.Options{
			Endpoints:     item.Server,
			KeyPrefix:     item.EtcdKeyPrefix,
			Namespace:     item.Namespace,
			RuleNamespace: item.EtcdRuleNamespace,
			Username:      item.Username,
			Password:      password,
			CACert:        item.EtcdCACert,
			ClientCert:    item.EtcdClientCert,
			ClientKey:     item.EtcdClientKey,
			Timeout:       f.Timeout,
			Trace:         f.Debug || f.Trace,
			TraceOut:      os.Stderr,
		})
	}
	if item.Backend == "consul" {
		return consulBackend.New(consulBackend.Options{
			Server:        item.Server,
			KeyPrefix:     item.ConsulKeyPrefix,
			Namespace:     item.Namespace,
			RuleNamespace: item.ConsulRuleNamespace,
			Token:         password,
			CACert:        item.ConsulCACert,
			ClientCert:    item.ConsulClientCert,
			ClientKey:     item.ConsulClientKey,
			Timeout:       f.Timeout,
			Trace:         f.Debug || f.Trace,
			TraceOut:      os.Stderr,
		})
	}
	if item.Backend == "k8s" {
		return k8sBackend.New(k8sBackend.Options{
			Kubeconfig: item.K8sKubeconfig,
			Context:    item.K8sContext,
			Namespace:  item.Namespace,
			Timeout:    f.Timeout,
			Trace:      f.Debug || f.Trace,
			TraceOut:   os.Stderr,
		})
	}
	client := api.NewClient(item.Server, item.Username, password, item.Namespace, f.Timeout)
	client.SetTrace(api.TraceOptions{Debug: f.Debug, Trace: f.Trace, BodyLimit: f.TraceBodyLim, Writer: os.Stderr})
	return nacos.New(client, item.Server), nil
}

func writeManifest(dir string, archive configArchive) error {
	data, err := json.MarshalIndent(archive, "", "  ")
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal export manifest", err)
	}
	return writeLocalFile(filepath.Join(dir, exportManifestName), append(data, '\n'))
}

func archiveFileName(key string) string {
	return strings.NewReplacer("/", "__", "\\", "__", ":", "_").Replace(key) + ".cfg"
}

func orderedLocals(items []localConfig) []localConfig {
	out := append([]localConfig(nil), items...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func localsForItems(locals []localConfig, items []planItem) []localConfig {
	needed := map[string]bool{}
	for _, item := range items {
		needed[item.Key] = true
	}
	out := make([]localConfig, 0, len(items))
	for _, local := range locals {
		if needed[local.Key] {
			out = append(out, local)
		}
	}
	return out
}

func summarizePlan(plan configPlan) planSummary {
	return planSummary{
		Create:   len(plan.Create),
		Update:   len(plan.Update),
		Delete:   len(plan.Delete),
		Prune:    len(plan.Prune),
		Skip:     len(plan.Skip),
		Conflict: len(plan.Conflict),
		Total:    len(plan.Create) + len(plan.Update) + len(plan.Delete) + len(plan.Prune) + len(plan.Skip) + len(plan.Conflict),
	}
}

func configPlanHasChanges(plan configPlan) bool {
	return len(plan.Create)+len(plan.Update)+len(plan.Delete)+len(plan.Prune) > 0
}

func strictNoChangeReconcile(f *cliFlags, plan configPlan) error {
	if isStrictNoChange(f) && !configPlanHasChanges(plan) && len(plan.Conflict) == 0 {
		return apperrors.New(apperrors.CodeNoChangeRequired, "no changes to reconcile", nil)
	}
	return nil
}

func enforceReconcilePlanGates(f *cliFlags, plan configPlan, forceLarge bool) error {
	if err := enforcePlanLimit(plan, forceLarge, "reconcile"); err != nil {
		return err
	}
	return strictNoChangeReconcile(f, plan)
}

func enforcePlanLimit(plan configPlan, forceLarge bool, operation string) error {
	if forceLarge {
		return nil
	}
	count := len(plan.Create) + len(plan.Update) + len(plan.Delete) + len(plan.Prune)
	if count > defaultMaxChanges {
		return apperrors.New(
			apperrors.CodeValidationFailed,
			fmt.Sprintf("%s actionable changes %d exceed limit %d; use --force-large-%s to override the limit only", operation, count, defaultMaxChanges, operation),
			nil,
		)
	}
	return nil
}

func validateLocalConfigs(items []localConfig) error {
	for _, item := range items {
		if err := validateContent(item.Content, item.Type); err != nil {
			return err
		}
	}
	return nil
}

func withConfigType(items []localConfig, contentType string) []localConfig {
	contentType = normalizeType(contentType)
	out := make([]localConfig, len(items))
	for i, item := range items {
		item.Type = contentType
		out[i] = item
	}
	return out
}

type pruneScope struct {
	Namespace string
	Group     string
}

func parsePruneScopes(values []string, namespace string, prune bool) ([]pruneScope, error) {
	if len(values) == 0 {
		if prune {
			return nil, apperrors.New(apperrors.CodeUsageError, "--prune-scope is required when --prune is set", nil)
		}
		return []pruneScope{{Namespace: namespace}}, nil
	}
	out := make([]pruneScope, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		parts := strings.Split(value, "/")
		if len(parts) > 2 || parts[0] == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, "invalid --prune-scope", nil)
		}
		scope := pruneScope{Namespace: parts[0]}
		if len(parts) == 2 {
			if parts[1] == "" {
				return nil, apperrors.New(apperrors.CodeUsageError, "invalid --prune-scope", nil)
			}
			scope.Group = parts[1]
		}
		if scope.Namespace != namespace {
			return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("--prune-scope namespace %q does not match current namespace %q", scope.Namespace, namespace), nil)
		}
		key := scope.Namespace + "/" + scope.Group
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, scope)
	}
	if len(out) == 0 {
		if prune {
			return nil, apperrors.New(apperrors.CodeUsageError, "--prune-scope is required when --prune is set", nil)
		}
		return []pruneScope{{Namespace: namespace}}, nil
	}
	return out, nil
}

func pruneScopeContains(scopes []pruneScope, namespace, key string) bool {
	group := ""
	if parsed, err := cfgov.ParseNacosKey(key); err == nil {
		group = parsed.Group
	}
	for _, scope := range scopes {
		if scope.Namespace != namespace {
			continue
		}
		if scope.Group == "" || scope.Group == group {
			return true
		}
	}
	return false
}

func archiveAuditSummary(items []configArchiveEntry) string {
	hashes := make([]string, 0, len(items))
	for _, item := range items {
		hashes = append(hashes, item.Key+"="+item.SHA256)
	}
	sort.Strings(hashes)
	return fmt.Sprintf("count=%d sha256=[%s]", len(items), strings.Join(hashes, ","))
}

func itemAudit(item localConfig) string {
	return fmt.Sprintf("key=%s sha256=%s bytes=%d", item.Key, sha256Bytes(item.Content), len(item.Content))
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}
