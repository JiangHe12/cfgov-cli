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

	"github.com/JiangHe12/cfgov-cli/internal/backup"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

type ruleWriteOptions struct {
	app              string
	typeName         string
	file             string
	fromDir          string
	resource         string
	backupRef        string
	force            bool
	all              bool
	expectedRevision string
	action           string
}

type ruleWritePlan struct {
	ResourceType string           `json:"resourceType"`
	Action       string           `json:"action"`
	App          string           `json:"app"`
	Type         rule.Type        `json:"type,omitempty"`
	Risk         safety.Risk      `json:"risk"`
	Coordinate   cfgov.Coordinate `json:"coordinate,omitempty"`
	Summary      rulePlanSummary  `json:"summary"`
	Items        []rulePlanItem   `json:"items"`
	Warnings     []rule.Issue     `json:"warnings,omitempty"`
	DryRun       bool             `json:"dryRun"`
}

type rulePlanSummary struct {
	Create int `json:"create"`
	Update int `json:"update"`
	Delete int `json:"delete"`
	Skip   int `json:"skip"`
	Total  int `json:"total"`
}

type rulePlanItem struct {
	Type         rule.Type        `json:"type"`
	Key          string           `json:"key"`
	Action       string           `json:"action"`
	RemoteSHA256 string           `json:"remoteSha256,omitempty"`
	LocalSHA256  string           `json:"localSha256,omitempty"`
	RemoteCount  int              `json:"remoteCount"`
	LocalCount   int              `json:"localCount"`
	Revision     string           `json:"revision,omitempty"`
	Coordinate   cfgov.Coordinate `json:"coordinate"`
}

type plannedRuleWrite struct {
	ruleType     rule.Type
	coord        cfgov.Coordinate
	current      ruleSetResult
	next         []map[string]any
	payload      []byte
	planItem     rulePlanItem
	backupBefore bool
	deleteBlob   bool
}

func ruleCreateCmd(f *cliFlags) *cobra.Command {
	opts := ruleWriteOptions{action: "create"}
	cmd := &cobra.Command{
		Use:   "create --app <app> --type <ruleType> --file <path>",
		Short: "Create a Sentinel rule",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuleSingleWrite(cmd.Context(), f, opts)
		},
	}
	addSingleRuleWriteFlags(cmd, &opts)
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite an existing resource+limitApp rule")
	return cmd
}

func ruleUpdateCmd(f *cliFlags) *cobra.Command {
	opts := ruleWriteOptions{action: "update"}
	cmd := &cobra.Command{
		Use:   "update --app <app> --type <ruleType> --file <path>",
		Short: "Update a Sentinel rule",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuleSingleWrite(cmd.Context(), f, opts)
		},
	}
	addSingleRuleWriteFlags(cmd, &opts)
	return cmd
}

func ruleDeleteCmd(f *cliFlags) *cobra.Command {
	opts := ruleWriteOptions{action: "delete"}
	cmd := &cobra.Command{
		Use:   "delete --app <app> --type <ruleType> (--resource <resource> | --all)",
		Short: "Delete Sentinel rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuleDelete(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&opts.typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
	cmd.Flags().StringVar(&opts.resource, "resource", "", "Resource to delete")
	cmd.Flags().BoolVar(&opts.all, "all", false, "Delete all rules for this app/type")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

func ruleImportCmd(f *cliFlags) *cobra.Command {
	opts := ruleWriteOptions{action: "import"}
	cmd := &cobra.Command{
		Use:   "import --app <app> --from-dir <dir>",
		Short: "Import Sentinel rule sets from a directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuleImport(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Sentinel app")
	cmd.Flags().StringVarP(&opts.fromDir, "from-dir", "f", "", "Source directory containing <type>.json files")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("from-dir")
	return cmd
}

func ruleRollbackCmd(f *cliFlags) *cobra.Command {
	opts := ruleWriteOptions{action: "rollback"}
	cmd := &cobra.Command{
		Use:   "rollback --app <app> --backup <ref>",
		Short: "Rollback Sentinel rules from a local backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRuleRollback(cmd.Context(), f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&opts.backupRef, "backup", "", "Backup id, file, or directory")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("backup")
	return cmd
}

func addSingleRuleWriteFlags(cmd *cobra.Command, opts *ruleWriteOptions) {
	cmd.Flags().StringVar(&opts.app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&opts.typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "Rule JSON file")
	cmd.Flags().StringVar(&opts.expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("file")
}

func runRuleSingleWrite(ctx context.Context, f *cliFlags, opts ruleWriteOptions) error {
	ruleType, local, err := readOneRuleForWrite(opts)
	if err != nil {
		return err
	}
	backend, store, ctxMeta, err := buildRuleStore(f)
	if err != nil {
		return err
	}
	current, err := readRuleSet(ctx, backend, store, opts.app, ruleType)
	if err != nil {
		return err
	}
	next, err := planSingleRuleSet(opts, ruleType, current.Rules, local)
	if err != nil {
		return err
	}
	write, plan, err := plannedRuleSetWrite(store, opts.app, ruleType, safety.R1, opts.action, current, next)
	if err != nil {
		return err
	}
	if opts.expectedRevision != "" {
		write.current.Revision = opts.expectedRevision
		write.planItem.Revision = opts.expectedRevision
		plan.Items[0].Revision = opts.expectedRevision
	}
	write.backupBefore = opts.action == "update" || current.Count > 0
	return applyRuleWrites(ctx, f, backend, ctxMeta, plan, []plannedRuleWrite{write}, safety.R1, "")
}

func runRuleDelete(ctx context.Context, f *cliFlags, opts ruleWriteOptions) error {
	if opts.all == (opts.resource != "") {
		return apperrors.New(apperrors.CodeUsageError, "exactly one of --resource or --all is required", nil)
	}
	ruleType, err := rule.ParseType(opts.typeName)
	if err != nil {
		return err
	}
	backend, store, ctxMeta, err := buildRuleStore(f)
	if err != nil {
		return err
	}
	current, err := readRuleSet(ctx, backend, store, opts.app, ruleType)
	if err != nil {
		return err
	}
	next, err := planDeleteRuleSet(opts, current.Rules)
	if err != nil {
		return err
	}
	write, plan, err := plannedRuleSetWrite(store, opts.app, ruleType, safety.R2, opts.action, current, next)
	if err != nil {
		return err
	}
	if opts.expectedRevision != "" {
		write.current.Revision = opts.expectedRevision
		write.planItem.Revision = opts.expectedRevision
		plan.Items[0].Revision = opts.expectedRevision
	}
	write.backupBefore = current.Count > 0
	write.deleteBlob = opts.all
	return applyRuleWrites(ctx, f, backend, ctxMeta, plan, []plannedRuleWrite{write}, safety.R2, allowProductionRuleDelete)
}

func runRuleImport(ctx context.Context, f *cliFlags, opts ruleWriteOptions) error {
	locals, err := readRuleDirectory(opts.fromDir)
	if err != nil {
		return err
	}
	return runRuleBatchUpsert(ctx, f, opts.app, "import", locals)
}

func runRuleRollback(ctx context.Context, f *cliFlags, opts ruleWriteOptions) error {
	locals, err := readRollbackRules(opts.backupRef)
	if err != nil {
		return err
	}
	return runRuleBatchUpsert(ctx, f, opts.app, "rollback", locals)
}

func runRuleBatchUpsert(ctx context.Context, f *cliFlags, app, action string, locals map[rule.Type][]map[string]any) error {
	if len(locals) == 0 {
		return apperrors.New(apperrors.CodeUsageError, "no rule files found", nil)
	}
	backend, store, ctxMeta, err := buildRuleStore(f)
	if err != nil {
		return err
	}
	risk := safety.R1
	writes := make([]plannedRuleWrite, 0, len(locals))
	plan := ruleWritePlan{ResourceType: "rule", Action: action, App: app, Risk: risk, DryRun: f.DryRun || f.Plan}
	for _, ruleType := range sortedRuleTypes(locals) {
		current, err := readRuleSet(ctx, backend, store, app, ruleType)
		if err != nil {
			return err
		}
		write, _, err := plannedRuleSetWrite(store, app, ruleType, risk, action, current, locals[ruleType])
		if err != nil {
			return err
		}
		write.backupBefore = action == "rollback" || current.Count > 0
		writes = append(writes, write)
		plan.Items = append(plan.Items, write.planItem)
		addRulePlanSummary(&plan.Summary, write.planItem.Action)
		plan.Warnings = append(plan.Warnings, ruleWarnings(map[rule.Type][]map[string]any{ruleType: locals[ruleType]})...)
	}
	return applyRuleWrites(ctx, f, backend, ctxMeta, plan, writes, risk, "")
}

func readOneRuleForWrite(opts ruleWriteOptions) (rule.Type, map[string]any, error) {
	ruleType, err := rule.ParseType(opts.typeName)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(opts.file) //nolint:gosec // Operator supplied rule file.
	if err != nil {
		return "", nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read rule file", err)
	}
	item, err := rule.DecodeOne(ruleType, data)
	if err != nil {
		return "", nil, err
	}
	if err := rejectDeepRuleErrors(map[rule.Type][]map[string]any{ruleType: {item}}); err != nil {
		return "", nil, err
	}
	return ruleType, item, nil
}

func planSingleRuleSet(opts ruleWriteOptions, ruleType rule.Type, current []map[string]any, local map[string]any) ([]map[string]any, error) {
	next := cloneRuleMaps(current)
	key := rule.Key(local, ruleType)
	for i, existing := range next {
		if rule.Key(existing, ruleType) != key {
			continue
		}
		if opts.action == "create" && !opts.force {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "rule already exists for resource+limitApp", nil)
		}
		next[i] = local
		return next, nil
	}
	if opts.action == "update" {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "rule to update was not found", nil)
	}
	return append(next, local), nil
}

func planDeleteRuleSet(opts ruleWriteOptions, current []map[string]any) ([]map[string]any, error) {
	if opts.all {
		return []map[string]any{}, nil
	}
	next := make([]map[string]any, 0, len(current))
	deleted := 0
	for _, item := range current {
		if fmt.Sprint(item["resource"]) == opts.resource {
			deleted++
			continue
		}
		next = append(next, item)
	}
	if deleted == 0 {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "rule to delete was not found", nil)
	}
	return next, nil
}

func plannedRuleSetWrite(store cfgov.RuleStore, app string, ruleType rule.Type, risk safety.Risk, action string, current ruleSetResult, next []map[string]any) (plannedRuleWrite, ruleWritePlan, error) {
	if action != "delete" {
		if err := rejectDeepRuleErrors(map[rule.Type][]map[string]any{ruleType: next}); err != nil {
			return plannedRuleWrite{}, ruleWritePlan{}, err
		}
	}
	coord, err := store.RuleCoordinate(app, string(ruleType))
	if err != nil {
		return plannedRuleWrite{}, ruleWritePlan{}, err
	}
	payload, err := marshalRuleSet(next)
	if err != nil {
		return plannedRuleWrite{}, ruleWritePlan{}, err
	}
	localSHA256 := sha256Bytes(payload)
	itemAction := classifyRuleChange(current.Rules, next, current.SHA256, localSHA256)
	item := rulePlanItem{
		Type:         ruleType,
		Key:          coord.Key,
		Action:       itemAction,
		RemoteSHA256: current.SHA256,
		LocalSHA256:  localSHA256,
		RemoteCount:  current.Count,
		LocalCount:   len(next),
		Revision:     current.Revision,
		Coordinate:   coord,
	}
	plan := ruleWritePlan{ResourceType: "rule", Action: action, App: app, Type: ruleType, Risk: risk, Coordinate: coord, Items: []rulePlanItem{item}}
	addRulePlanSummary(&plan.Summary, itemAction)
	plan.Summary.Total = 1
	return plannedRuleWrite{ruleType: ruleType, coord: coord, current: current, next: next, payload: payload, planItem: item}, plan, nil
}

func applyRuleWrites(ctx context.Context, f *cliFlags, backend cfgov.Backend, ctxMeta cfgovctx.Context, plan ruleWritePlan, writes []plannedRuleWrite, risk safety.Risk, required safety.AllowFlag) error {
	plan.DryRun = f.DryRun || f.Plan
	if plan.DryRun {
		appendRuleAudit(f, ctxMeta, plan.Action, plan.App, plan.Type, audit.StatusSuccess, ruleWriteAudit(plan), nil)
		return newPrinter(f).JSONData("ChangePlan", plan)
	}
	if err := validateBackupPolicy(f, ctxMeta); err != nil {
		return err
	}
	if err := validateMandatoryRuleBackup(f, writes); err != nil {
		return err
	}
	if err := authorize(f, risk, ctxMeta, required); err != nil {
		return err
	}
	backups := make([]any, 0, len(writes))
	for _, write := range writes {
		if write.planItem.Action == "skip" {
			appendRuleAudit(f, ctxMeta, plan.Action, plan.App, write.ruleType, auditStatusSkipped, ruleWriteItemAudit(plan.App, plan.Action, write.planItem), nil)
			continue
		}
		if write.backupBefore {
			result, err := backupRuleCurrent(ctx, f, backend, ctxMeta, write.coord)
			if err != nil {
				return err
			}
			if result != nil {
				backups = append(backups, result)
			}
		}
		if write.deleteBlob {
			if err := backend.Delete(ctx, cfgov.DeleteRequest{Coordinate: write.coord, ExpectedRevision: write.current.Revision}); err != nil {
				appendRuleAudit(f, ctxMeta, plan.Action, plan.App, write.ruleType, audit.StatusFailed, ruleWriteAudit(plan), err)
				return err
			}
			continue
		}
		expected := write.current.Revision
		if _, err := backend.Put(ctx, cfgov.PutRequest{Coordinate: write.coord, Content: write.payload, ContentType: "json", ExpectedRevision: expected}); err != nil {
			appendRuleAudit(f, ctxMeta, plan.Action, plan.App, write.ruleType, audit.StatusFailed, ruleWriteAudit(plan), err)
			return err
		}
	}
	appendRuleAudit(f, ctxMeta, plan.Action, plan.App, plan.Type, audit.StatusSuccess, ruleWriteAudit(plan), nil)
	return newPrinter(f).JSONData("ChangeResult", map[string]any{"resourceType": "rule", "action": plan.Action, "app": plan.App, "summary": plan.Summary, "items": plan.Items, "backup": backups})
}

func validateMandatoryRuleBackup(f *cliFlags, writes []plannedRuleWrite) error {
	for _, write := range writes {
		if write.backupBefore && f.NoBackup {
			return apperrors.New(apperrors.CodeUsageError, "rule overwrite/delete/rollback requires backup; --no-backup is not allowed", nil)
		}
	}
	return nil
}

func backupRuleCurrent(ctx context.Context, f *cliFlags, backend cfgov.Backend, meta cfgovctx.Context, coord cfgov.Coordinate) (*backup.Result, error) {
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
	result, err := backup.Write(root, backup.Request{
		Context:   f.contextName(),
		Namespace: namespaceOrPublic(coord.Namespace),
		Group:     key.Group,
		DataID:    key.DataID,
		Content:   blob.Content,
		Operator:  currentOperator(f),
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to write backup", err)
	}
	appendAuditWarn(f, audit.EventType("backup.create"), meta, audit.EventTarget{ResourceType: "backup", Resource: result.BackupID}, audit.StatusSuccess, "backup current rule sha256="+result.SHA256, nil)
	return &result, nil
}

func rejectDeepRuleErrors(rules map[rule.Type][]map[string]any) error {
	issues := rule.DeepCheck(rules)
	if rule.HasError(issues) {
		data, _ := json.Marshal(issues)
		return apperrors.New(apperrors.CodeValidationFailed, "deep rule validation failed: "+string(data), nil)
	}
	return nil
}

func ruleWarnings(rules map[rule.Type][]map[string]any) []rule.Issue {
	issues := rule.DeepCheck(rules)
	warnings := make([]rule.Issue, 0, len(issues))
	for _, issue := range issues {
		if issue.Severity == rule.SeverityWarning {
			warnings = append(warnings, issue)
		}
	}
	return warnings
}

func readRuleDirectory(dir string) (map[rule.Type][]map[string]any, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to stat rule directory", err)
	}
	if !info.IsDir() {
		return nil, apperrors.New(apperrors.CodeUsageError, "--from-dir must be a directory", nil)
	}
	out := map[rule.Type][]map[string]any{}
	for _, ruleType := range rule.AllTypes {
		path := filepath.Join(dir, string(ruleType)+".json")
		content, err := os.ReadFile(path) //nolint:gosec // Path is constrained to operator supplied import directory.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read rule file", err)
		}
		items, err := rule.DecodeSet(ruleType, content)
		if err != nil {
			return nil, err
		}
		if err := rejectDeepRuleErrors(map[rule.Type][]map[string]any{ruleType: items}); err != nil {
			return nil, err
		}
		out[ruleType] = items
	}
	return out, nil
}

func readRollbackRules(ref string) (map[rule.Type][]map[string]any, error) {
	info, err := os.Stat(ref)
	if err == nil {
		if info.IsDir() {
			return readRuleDirectory(ref)
		}
		ruleType, err := rule.InferTypeFromPath(ref)
		if err != nil {
			return nil, err
		}
		local, err := readLocalRuleFile(ref, ruleType)
		if err != nil {
			return nil, err
		}
		return map[rule.Type][]map[string]any{ruleType: local.Rules}, nil
	}
	if !os.IsNotExist(err) {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to stat backup", err)
	}
	return readRollbackRulesFromBackupID(ref)
}

func readRollbackRulesFromBackupID(backupID string) (map[rule.Type][]map[string]any, error) {
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
		ruleType, err := rule.TypeFromDataID(item.DataID)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(item.Path) //nolint:gosec // Path comes from local backup index.
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read backup", err)
		}
		rules, err := rule.DecodeSet(ruleType, data)
		if err != nil {
			return nil, err
		}
		if err := rejectDeepRuleErrors(map[rule.Type][]map[string]any{ruleType: rules}); err != nil {
			return nil, err
		}
		return map[rule.Type][]map[string]any{ruleType: rules}, nil
	}
	return nil, apperrors.New(apperrors.CodeResourceNotFound, "backup not found", nil)
}

func marshalRuleSet(items []map[string]any) ([]byte, error) {
	if items == nil {
		items = []map[string]any{}
	}
	data, err := json.Marshal(items)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal rules", err)
	}
	return data, nil
}

func cloneRuleMaps(items []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		cloned := make(map[string]any, len(item))
		for key, value := range item {
			cloned[key] = value
		}
		out = append(out, cloned)
	}
	return out
}

func classifyRuleChange(current, next []map[string]any, remoteSHA256, localSHA256 string) string {
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

func addRulePlanSummary(summary *rulePlanSummary, action string) {
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

func sortedRuleTypes(items map[rule.Type][]map[string]any) []rule.Type {
	out := make([]rule.Type, 0, len(items))
	for ruleType := range items {
		out = append(out, ruleType)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ruleWriteAudit(plan ruleWritePlan) string {
	parts := make([]string, 0, len(plan.Items))
	for _, item := range plan.Items {
		parts = append(parts, ruleWriteItemAudit(plan.App, plan.Action, item))
	}
	return strings.Join(parts, ",")
}

func ruleWriteItemAudit(app, action string, item rulePlanItem) string {
	return fmt.Sprintf("app=%s action=%s %s:%s remote=%s/%d local=%s/%d rev=%s", app, action, item.Type, item.Action, item.RemoteSHA256, item.RemoteCount, item.LocalSHA256, item.LocalCount, item.Revision)
}
