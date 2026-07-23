package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/backup"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
)

type flagWriteOptions struct {
	app              string
	file             string
	dir              string
	key              string
	backupRef        string
	force            bool
	all              bool
	expectedRevision string
	action           string
}

type flagWritePlan struct {
	ResourceType string           `json:"resourceType"`
	Action       string           `json:"action"`
	App          string           `json:"app"`
	Risk         safety.Risk      `json:"risk"`
	Coordinate   cfgov.Coordinate `json:"coordinate,omitempty"`
	Summary      flagPlanSummary  `json:"summary"`
	Items        []flagPlanItem   `json:"items"`
	Warnings     []flag.Issue     `json:"warnings,omitempty"`
	DryRun       bool             `json:"dryRun"`
}

type flagPlanSummary struct {
	Create int `json:"create"`
	Update int `json:"update"`
	Delete int `json:"delete"`
	Skip   int `json:"skip"`
	Total  int `json:"total"`
}

type flagPlanItem struct {
	Key          string           `json:"key"`
	Action       string           `json:"action"`
	RemoteSHA256 string           `json:"remoteSha256,omitempty"`
	LocalSHA256  string           `json:"localSha256,omitempty"`
	RemoteCount  int              `json:"remoteCount"`
	LocalCount   int              `json:"localCount"`
	Revision     string           `json:"revision,omitempty"`
	Coordinate   cfgov.Coordinate `json:"coordinate"`
}

type plannedFlagWrite struct {
	coord        cfgov.Coordinate
	current      flagSetResult
	next         []flag.FeatureFlag
	payload      []byte
	planItem     flagPlanItem
	backupBefore bool
	deleteBlob   bool
}

type flagWritePreflight struct {
	Plan  flagWritePlan
	Write plannedFlagWrite
}

func flagCreateCmd(f *cliFlags) *cobra.Command {
	opts := flagWriteOptions{action: "create"}
	cmd := &cobra.Command{
		Use:   "create --app <app> --file <path>",
		Short: "Create a feature flag",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlagSingleWrite(cmd.Context(), f, opts)
		},
	}
	addSingleFlagWriteFlags(cmd, &opts)
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite an existing feature flag")
	return cmd
}

func flagUpdateCmd(f *cliFlags) *cobra.Command {
	opts := flagWriteOptions{action: "update"}
	cmd := &cobra.Command{
		Use:   "update --app <app> --file <path>",
		Short: "Update a feature flag",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlagSingleWrite(cmd.Context(), f, opts)
		},
	}
	addSingleFlagWriteFlags(cmd, &opts)
	return cmd
}

func flagDeleteCmd(f *cliFlags) *cobra.Command {
	opts := flagWriteOptions{action: "delete"}
	cmd := &cobra.Command{
		Use:   "delete --app <app> (--key <key> | --all)",
		Short: "Delete feature flags",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlagDelete(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Application name")
	cmd.Flags().StringVar(&opts.key, "key", "", "Feature flag key to delete")
	cmd.Flags().BoolVar(&opts.all, "all", false, "Delete all feature flags for this app")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func flagImportCmd(f *cliFlags) *cobra.Command {
	opts := flagWriteOptions{action: "import"}
	cmd := &cobra.Command{
		Use:   "import --app <app> (--file <path>|--dir <dir>)",
		Short: "Import feature flags",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlagImport(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Application name")
	cmd.Flags().StringVar(&opts.file, "file", "", "Local feature flag file")
	cmd.Flags().StringVar(&opts.dir, "dir", "", "Directory containing flags.json")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func flagRollbackCmd(f *cliFlags) *cobra.Command {
	opts := flagWriteOptions{action: "rollback"}
	cmd := &cobra.Command{
		Use:   "rollback --app <app> --backup <ref>",
		Short: "Rollback feature flags from a local backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFlagRollback(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Application name")
	cmd.Flags().StringVar(&opts.backupRef, "backup", "", "Backup id, file, or directory")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("backup")
	return cmd
}

func addSingleFlagWriteFlags(cmd *cobra.Command, opts *flagWriteOptions) {
	cmd.Flags().StringVar(&opts.app, "app", "", "Application name")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "Feature flag JSON file")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("file")
}

func runFlagSingleWrite(ctx context.Context, f *cliFlags, opts flagWriteOptions) error {
	local, err := readOneFlagForWrite(opts.file)
	if err != nil {
		return err
	}
	backendRead, err := runFlagWritePreflight(
		ctx,
		f,
		opts,
		safety.R1,
		map[string]any{"localKey": flag.Key(local)},
		func(current flagSetResult) ([]flag.FeatureFlag, error) {
			return planSingleFlagSet(opts, current.Flags, local)
		},
	)
	if err != nil {
		return err
	}
	backend, ctxMeta := backendRead.Backend, backendRead.Context
	write, plan := backendRead.Value.Write, backendRead.Value.Plan
	applyExpectedFlagRevision(opts.expectedRevision, &write, &plan)
	write.backupBefore = opts.action == "update" || write.current.Count > 0
	return applyFlagWrites(ctx, f, backend, ctxMeta, plan, []plannedFlagWrite{write}, safety.R1, "", backendRead.ContextName)
}

func runFlagDelete(ctx context.Context, f *cliFlags, opts flagWriteOptions) error {
	if opts.all == (opts.key != "") {
		return apperrors.New(apperrors.CodeUsageError, "exactly one of --key or --all is required", nil)
	}
	backendRead, err := runFlagWritePreflight(
		ctx,
		f,
		opts,
		safety.R2,
		map[string]any{"key": opts.key, "all": opts.all},
		func(current flagSetResult) ([]flag.FeatureFlag, error) {
			return planDeleteFlagSet(opts, current.Flags)
		},
	)
	if err != nil {
		return err
	}
	backend, ctxMeta := backendRead.Backend, backendRead.Context
	write, plan := backendRead.Value.Write, backendRead.Value.Plan
	applyExpectedFlagRevision(opts.expectedRevision, &write, &plan)
	write.backupBefore = write.current.Count > 0
	write.deleteBlob = opts.all
	return applyFlagWrites(ctx, f, backend, ctxMeta, plan, []plannedFlagWrite{write}, safety.R2, allowProductionFlagDelete, backendRead.ContextName)
}

func runFlagImport(ctx context.Context, f *cliFlags, opts flagWriteOptions) error {
	local, err := readLocalFlagInput(opts.file, opts.dir)
	if err != nil {
		return err
	}
	return runFlagSetUpsert(ctx, f, opts, "import", local.Flags)
}

func runFlagRollback(ctx context.Context, f *cliFlags, opts flagWriteOptions) error {
	flags, err := readRollbackFlags(opts.backupRef)
	if err != nil {
		return err
	}
	return runFlagSetUpsert(ctx, f, opts, "rollback", flags)
}

func runFlagSetUpsert(ctx context.Context, f *cliFlags, opts flagWriteOptions, action string, next []flag.FeatureFlag) error {
	if len(next) == 0 && action == "import" {
		return apperrors.New(apperrors.CodeUsageError, "no feature flags found", nil)
	}
	backendRead, err := runFlagWritePreflight(
		ctx,
		f,
		opts,
		safety.R1,
		map[string]any{"nextCount": len(next), "nextSha256": flagSetSHA256(next)},
		func(flagSetResult) ([]flag.FeatureFlag, error) {
			return next, nil
		},
	)
	if err != nil {
		return err
	}
	backend, ctxMeta := backendRead.Backend, backendRead.Context
	write, plan := backendRead.Value.Write, backendRead.Value.Plan
	applyExpectedFlagRevision(opts.expectedRevision, &write, &plan)
	write.backupBefore = action == "rollback" || write.current.Count > 0
	return applyFlagWrites(ctx, f, backend, ctxMeta, plan, []plannedFlagWrite{write}, safety.R1, "", backendRead.ContextName)
}

func runFlagWritePreflight(
	ctx context.Context,
	f *cliFlags,
	opts flagWriteOptions,
	risk safety.Risk,
	request map[string]any,
	next func(flagSetResult) ([]flag.FeatureFlag, error),
) (mandatoryBackendReadResult[flagWritePreflight], error) {
	request["action"] = opts.action
	request["app"] = opts.app
	request["expectedRevisionSha256"] = mutationAuditFingerprint(
		"flag."+opts.action+".expected-revision",
		[]byte(opts.expectedRevision),
	)
	return runMandatoryBackendRead(
		f,
		"flag."+opts.action+".plan",
		"flag",
		opts.app,
		request,
		func(backend cfgov.Backend, _ cfgovctx.Context) (flagWritePreflight, error) {
			backend, store, err := ensureFlagStore(backend)
			if err != nil {
				return flagWritePreflight{}, err
			}
			current, err := readFlagSet(ctx, backend, store, opts.app)
			if err != nil {
				return flagWritePreflight{}, err
			}
			nextFlags, err := next(current)
			if err != nil {
				return flagWritePreflight{}, err
			}
			write, plan, err := plannedFlagSetWrite(store, opts.app, risk, opts.action, current, nextFlags)
			if err != nil {
				return flagWritePreflight{}, err
			}
			return flagWritePreflight{Plan: plan, Write: write}, nil
		},
		func(flagWritePreflight) int { return 1 },
	)
}

func flagSetSHA256(items []flag.FeatureFlag) string {
	data, err := marshalFlagSet(items)
	if err != nil {
		return ""
	}
	return sha256Bytes(data)
}

func readOneFlagForWrite(path string) (flag.FeatureFlag, error) {
	data, err := os.ReadFile(path) //nolint:gosec // Operator supplied flag file.
	if err != nil {
		return flag.FeatureFlag{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read flag file", err)
	}
	item, err := flag.DecodeOne(data)
	if err != nil {
		return flag.FeatureFlag{}, err
	}
	if err := rejectDeepFlagErrors([]flag.FeatureFlag{item}); err != nil {
		return flag.FeatureFlag{}, err
	}
	return item, nil
}

func planSingleFlagSet(opts flagWriteOptions, current []flag.FeatureFlag, local flag.FeatureFlag) ([]flag.FeatureFlag, error) {
	next := cloneFlags(current)
	key := flag.Key(local)
	for i, existing := range next {
		if flag.Key(existing) != key {
			continue
		}
		if opts.action == "create" && !opts.force {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "flag already exists", nil)
		}
		next[i] = local
		return next, nil
	}
	if opts.action == "update" {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "flag to update not found", nil)
	}
	return append(next, local), nil
}

func planDeleteFlagSet(opts flagWriteOptions, current []flag.FeatureFlag) ([]flag.FeatureFlag, error) {
	if opts.all {
		return []flag.FeatureFlag{}, nil
	}
	next := make([]flag.FeatureFlag, 0, len(current))
	deleted := 0
	for _, item := range current {
		if item.Key == opts.key {
			deleted++
			continue
		}
		next = append(next, item)
	}
	if deleted == 0 {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "flag to delete not found", nil)
	}
	return next, nil
}

func plannedFlagSetWrite(store cfgov.FlagStore, app string, risk safety.Risk, action string, current flagSetResult, next []flag.FeatureFlag) (plannedFlagWrite, flagWritePlan, error) {
	if action != "delete" {
		if err := rejectDeepFlagErrors(next); err != nil {
			return plannedFlagWrite{}, flagWritePlan{}, err
		}
	}
	coord, err := store.FlagCoordinate(app)
	if err != nil {
		return plannedFlagWrite{}, flagWritePlan{}, err
	}
	payload, err := marshalFlagSet(next)
	if err != nil {
		return plannedFlagWrite{}, flagWritePlan{}, err
	}
	localSHA256 := sha256Bytes(payload)
	itemAction := classifyFlagChange(current.Flags, next, current.SHA256, localSHA256)
	item := flagPlanItem{
		Key:          coord.Key,
		Action:       itemAction,
		RemoteSHA256: current.SHA256,
		LocalSHA256:  localSHA256,
		RemoteCount:  current.Count,
		LocalCount:   len(next),
		Revision:     current.Revision,
		Coordinate:   coord,
	}
	plan := flagWritePlan{ResourceType: "flag", Action: action, App: app, Risk: risk, Coordinate: coord, Items: []flagPlanItem{item}, Warnings: flagWarnings(next)}
	addFlagPlanSummary(&plan.Summary, itemAction)
	plan.Summary.Total = 1
	return plannedFlagWrite{coord: coord, current: current, next: next, payload: payload, planItem: item}, plan, nil
}

func applyFlagWrites(ctx context.Context, f *cliFlags, backend cfgov.Backend, ctxMeta cfgovctx.Context, plan flagWritePlan, writes []plannedFlagWrite, risk safety.Risk, required safety.AllowFlag, contextNames ...string) error { //nolint:gocyclo // Preview, policy, backup, intent/outcome, and ordered writes are one governed transaction flow.
	contextName := f.contextName()
	if len(contextNames) > 0 && contextNames[0] != "" {
		contextName = contextNames[0]
	}
	if err := validateFlagWriteCapabilities(backend.Capabilities(), writes); err != nil {
		return err
	}
	plan.DryRun = isPlanOnly(f)
	if plan.DryRun {
		markPreview(f)
		appendFlagAudit(f, ctxMeta, plan.Action, plan.App, audit.StatusSuccess, flagWriteAudit(plan), nil)
		return targetJSONData(f, "ChangePlan", plan, operationTargetFromDescription(contextName, backend.Describe()), operationTargetWrite)
	}
	if err := validateBackupPolicy(f, ctxMeta); err != nil {
		return err
	}
	if err := validateMandatoryFlagBackup(f, writes); err != nil {
		return err
	}
	if err := authorizeForContext(f, risk, ctxMeta, required, contextName); err != nil {
		return err
	}
	mutation, err := beginSchemaMutationAudit(
		f,
		ctxMeta,
		"flag",
		plan.Action,
		plan.App,
		plan.Items,
		plan.Summary.Total,
		plan.Summary.Create,
		plan.Summary.Update,
		plan.Summary.Delete,
		contextName,
	)
	if err != nil {
		return err
	}
	backups := make([]any, 0, len(writes))
	succeeded := 0
	for _, write := range writes {
		if write.planItem.Action == "skip" {
			appendFlagAudit(f, ctxMeta, plan.Action, plan.App, auditStatusSkipped, flagWriteItemAudit(plan.App, plan.Action, write.planItem), nil)
			continue
		}
		if write.backupBefore {
			result, err := backupFlagCurrent(ctx, f, backend, ctxMeta, write.coord)
			if err != nil {
				return finishBatchMutationAudit(mutation, plan.Summary.Total, succeeded, plan.Summary.Skip, err)
			}
			if result != nil {
				backups = append(backups, result)
			}
		}
		if write.deleteBlob {
			if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: write.coord, ExpectedRevision: write.current.Revision}); err != nil {
				appendFlagAudit(f, ctxMeta, plan.Action, plan.App, audit.StatusFailed, flagWriteAudit(plan), err)
				return finishBatchMutationAudit(mutation, plan.Summary.Total, succeeded, plan.Summary.Skip, err)
			}
			succeeded++
			continue
		}
		if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: write.coord, Content: write.payload, ContentType: "json", ExpectedRevision: write.current.Revision}); err != nil {
			appendFlagAudit(f, ctxMeta, plan.Action, plan.App, audit.StatusFailed, flagWriteAudit(plan), err)
			return finishBatchMutationAudit(mutation, plan.Summary.Total, succeeded, plan.Summary.Skip, err)
		}
		succeeded++
	}
	if mutation != nil {
		if err := finishBatchMutationAudit(mutation, plan.Summary.Total, succeeded, plan.Summary.Skip, nil); err != nil {
			return err
		}
	}
	appendFlagAudit(f, ctxMeta, plan.Action, plan.App, audit.StatusSuccess, flagWriteAudit(plan), nil)
	return targetJSONData(f, "ChangeResult", map[string]any{"resourceType": "flag", "action": plan.Action, "app": plan.App, "summary": plan.Summary, "items": plan.Items, "backup": backups}, operationTargetFromDescription(contextName, backend.Describe()), operationTargetWrite)
}

func validateFlagWriteCapabilities(capabilities cfgov.Capabilities, writes []plannedFlagWrite) error {
	if capabilities.SupportsCAS {
		return nil
	}
	for _, write := range writes {
		if write.planItem.Action == "skip" || write.current.Revision == "" {
			continue
		}
		return apperrors.New(
			apperrors.CodeNotImplemented,
			fmt.Sprintf("%s does not support the atomic revision precondition required to modify an existing flag set", capabilities.Backend),
			nil,
		)
	}
	return nil
}

func validateMandatoryFlagBackup(f *cliFlags, writes []plannedFlagWrite) error {
	for _, write := range writes {
		if write.backupBefore && f.NoBackup {
			return apperrors.New(apperrors.CodeUsageError, "flag overwrite/delete/rollback requires backup; --no-backup is not allowed", nil)
		}
	}
	return nil
}

func backupFlagCurrent(ctx context.Context, f *cliFlags, backend cfgov.Backend, meta cfgovctx.Context, coord cfgov.Coordinate) (*backup.Result, error) {
	blob, err := backend.Get(ctx, coord)
	if err != nil {
		if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
			return nil, nil
		}
		return nil, err
	}
	root, err := backupRoot()
	if err != nil {
		return nil, err
	}
	key, err := cfgov.ParseNacosKey(coord.Key)
	if err != nil {
		return nil, err
	}
	result, err := writeFlagBackup(root, f, coord, key.Group, key.DataID, blob.Content)
	if err != nil {
		return nil, err
	}
	appendAuditWarn(f, audit.EventType("backup.create"), meta, audit.EventTarget{ResourceType: "backup", Resource: result.BackupID}, audit.StatusSuccess, "backup current flag sha256="+result.SHA256, nil)
	return &result, nil
}

func writeFlagBackup(root string, f *cliFlags, coord cfgov.Coordinate, group, dataID string, content []byte) (backup.Result, error) {
	result, err := backup.Write(root, backup.Request{
		Context:   f.contextName(),
		Namespace: namespaceOrPublic(coord.Namespace),
		Group:     group,
		DataID:    dataID,
		Content:   content,
		Operator:  currentOperator(f),
	})
	if err != nil {
		return backup.Result{}, apperrors.New(apperrors.CodeLocalIOError, "failed to write backup", err)
	}
	return result, nil
}

func rejectDeepFlagErrors(flags []flag.FeatureFlag) error {
	issues := flag.DeepCheck(flags)
	if flag.HasError(issues) {
		data, _ := json.Marshal(issues)
		return apperrors.New(apperrors.CodeValidationFailed, "deep flag validation failed: "+string(data), nil)
	}
	return nil
}

func flagWarnings(flags []flag.FeatureFlag) []flag.Issue {
	issues := flag.DeepCheck(flags)
	warnings := make([]flag.Issue, 0, len(issues))
	for _, issue := range issues {
		if issue.Severity == flag.SeverityWarning {
			warnings = append(warnings, issue)
		}
	}
	return warnings
}

func readRollbackFlags(ref string) ([]flag.FeatureFlag, error) {
	info, err := os.Stat(ref)
	if err == nil {
		if info.IsDir() {
			local, err := readLocalFlagInput("", ref)
			return local.Flags, err
		}
		local, err := readLocalFlagInput(ref, "")
		return local.Flags, err
	}
	if !os.IsNotExist(err) {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to stat backup", err)
	}
	return readRollbackFlagsFromBackupID(ref)
}

func readRollbackFlagsFromBackupID(backupID string) ([]flag.FeatureFlag, error) {
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
		if !strings.HasSuffix(item.DataID, "-flags") {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "backup is not a feature flag set", nil)
		}
		data, err := os.ReadFile(item.Path) //nolint:gosec // Path comes from local backup index.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read backup", err)
		}
		flags, err := flag.DecodeSet(data)
		if err != nil {
			return nil, err
		}
		if err := rejectDeepFlagErrors(flags); err != nil {
			return nil, err
		}
		return flags, nil
	}
	return nil, apperrors.New(apperrors.CodeResourceNotFound, "backup not found", nil)
}

func marshalFlagSet(items []flag.FeatureFlag) ([]byte, error) {
	if items == nil {
		items = []flag.FeatureFlag{}
	}
	data, err := json.Marshal(items)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal flags", err)
	}
	return data, nil
}

func cloneFlags(items []flag.FeatureFlag) []flag.FeatureFlag {
	out := make([]flag.FeatureFlag, len(items))
	copy(out, items)
	return out
}

func classifyFlagChange(current, next []flag.FeatureFlag, remoteSHA256, localSHA256 string) string {
	if remoteSHA256 != "" && remoteSHA256 == localSHA256 {
		return "skip"
	}
	switch {
	case len(current) == 0 && len(next) > 0:
		return "create"
	case len(next) == 0 && len(current) > 0:
		return "delete"
	default:
		return "update"
	}
}

func addFlagPlanSummary(summary *flagPlanSummary, action string) {
	switch action {
	case "create":
		summary.Create++
	case "delete":
		summary.Delete++
	case "skip":
		summary.Skip++
	default:
		summary.Update++
	}
	summary.Total++
}

func applyExpectedFlagRevision(expected string, write *plannedFlagWrite, plan *flagWritePlan) {
	if expected == "" {
		return
	}
	write.current.Revision = expected
	write.planItem.Revision = expected
	if len(plan.Items) > 0 {
		plan.Items[0].Revision = expected
	}
}

func flagWriteAudit(plan flagWritePlan) string {
	parts := make([]string, 0, len(plan.Items))
	for _, item := range plan.Items {
		parts = append(parts, flagWriteItemAudit(plan.App, plan.Action, item))
	}
	return strings.Join(parts, ",")
}

func flagWriteItemAudit(app, action string, item flagPlanItem) string {
	return fmt.Sprintf("app=%s action=%s %s remote=%s/%d local=%s/%d rev=%s", app, action, item.Action, item.RemoteSHA256, item.RemoteCount, item.LocalSHA256, item.LocalCount, item.Revision)
}
