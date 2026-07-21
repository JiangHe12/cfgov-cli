package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type auditQueryOptions struct {
	since        string
	until        string
	operator     string
	contextName  string
	namespace    string
	env          string
	protectedStr string
	eventType    string
	ticket       string
	app          string
	dataID       string
	group        string
	ruleType     string
	resource     string
	status       string
	path         string
	limit        int
	reverse      bool
}

type auditVerifyOptions struct {
	path    string
	strict  bool
	repair  bool
	confirm bool
	decrypt bool
}

type auditPruneOptions struct {
	path      string
	before    string
	keepLast  int
	dryRun    bool
	dryRunSet bool
	confirm   bool
}

type auditPruneResult struct {
	DryRun          bool                       `json:"dryRun"`
	DeletedFiles    []string                   `json:"deletedFiles"`
	Count           int                        `json:"count"`
	Started         bool                       `json:"started"`
	CheckpointState audit.PruneCheckpointState `json:"checkpointState,omitempty"`
}

func newAuditCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect cfgov audit log", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(auditQueryCmd(f), auditVerifyCmd(f), auditPruneCmd(f))
	return cmd
}

func auditQueryCmd(f *cliFlags) *cobra.Command {
	var opts auditQueryOptions
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query audit events",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAuditQuery(f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.since, "since", "", "Start time: 24h or RFC3339")
	cmd.Flags().StringVar(&opts.until, "until", "", "End time: 24h or RFC3339")
	cmd.Flags().StringVar(&opts.operator, "operator", "", "Match operator exactly")
	cmd.Flags().StringVar(&opts.contextName, "context-filter", "", "Match audit context name exactly")
	cmd.Flags().StringVar(&opts.namespace, "namespace-filter", "", "Match namespace metadata exactly")
	cmd.Flags().StringVar(&opts.env, "env", "", "Match audit context environment exactly")
	cmd.Flags().StringVar(&opts.protectedStr, "protected", "", "Filter by protected: true | false")
	cmd.Flags().StringVar(&opts.eventType, "type", "", "Match event type exactly")
	cmd.Flags().StringVar(&opts.ticket, "ticket", "", "Match ticket exactly")
	cmd.Flags().StringVar(&opts.app, "app", "", "Match application exactly")
	cmd.Flags().StringVar(&opts.dataID, "data-id", "", "Match config dataId exactly")
	cmd.Flags().StringVar(&opts.group, "group", "", "Match Nacos config group exactly")
	cmd.Flags().StringVar(&opts.ruleType, "rule-type", "", "Match Sentinel rule type exactly")
	cmd.Flags().StringVar(&opts.resource, "resource", "", "Match target resource exactly")
	cmd.Flags().StringVar(&opts.status, "status", "", "Match status exactly")
	cmd.Flags().StringVar(&opts.path, "path", "", "Override audit log path")
	cmd.Flags().IntVar(&opts.limit, "limit", 100, "Maximum events (0 = unlimited)")
	cmd.Flags().BoolVar(&opts.reverse, "reverse", false, "Sort newest-first")
	return cmd
}

func runAuditQuery(f *cliFlags, opts auditQueryOptions) error {
	filter := audit.Filter{
		EventType:   opts.eventType,
		Operator:    opts.operator,
		ContextName: opts.contextName,
		Env:         opts.env,
		Ticket:      opts.ticket,
		App:         opts.app,
		Resource:    firstNonEmpty(opts.resource, opts.dataID),
		Status:      opts.status,
		Limit:       opts.limit,
		Reverse:     opts.reverse,
		PrivateKey:  envWithDeprecatedAlias(cfgovAuditPrivateKeyEnv, deprecatedCfgovAuditPrivateKeyEnv),
	}
	now := time.Now().UTC()
	if opts.since != "" {
		t, err := audit.ParseTime(opts.since, now)
		if err != nil {
			return apperrors.New(apperrors.CodeUsageError, "invalid --since", err)
		}
		filter.Since = &t
	}
	if opts.until != "" {
		t, err := audit.ParseTime(opts.until, now)
		if err != nil {
			return apperrors.New(apperrors.CodeUsageError, "invalid --until", err)
		}
		filter.Until = &t
	}
	if opts.protectedStr != "" {
		v, err := parseAuditProtected(opts.protectedStr)
		if err != nil {
			return err
		}
		filter.Protected = &v
	}
	if opts.ruleType != "" {
		filter.ResourceType = "rule"
	}
	path, err := auditPath(opts.path)
	if err != nil {
		return err
	}
	result, err := audit.Query(path, filter)
	if err != nil {
		return err
	}
	result.Events = filterAuditEvents(result.Events, opts)
	return printAuditQueryResult(f, result)
}

func parseAuditProtected(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, apperrors.New(apperrors.CodeUsageError, "invalid --protected: expected true or false", nil)
	}
}

func filterAuditEvents(events []audit.Event, opts auditQueryOptions) []audit.Event {
	if opts.group == "" && opts.ruleType == "" && opts.app == "" && opts.namespace == "" {
		return events
	}
	out := make([]audit.Event, 0, len(events))
	for _, event := range events {
		if auditEventMatchesExtraFilters(event, opts) {
			out = append(out, event)
		}
	}
	return out
}

func auditEventMatchesExtraFilters(event audit.Event, opts auditQueryOptions) bool {
	if opts.group != "" && !auditEventMatchesGroup(event, opts.group) {
		return false
	}
	if opts.ruleType != "" && !strings.HasSuffix(event.Target.Resource, "/"+opts.ruleType) {
		return false
	}
	if opts.app != "" && event.Target.App == "" && !strings.HasPrefix(event.Target.Resource, opts.app+"/") && event.Target.Resource != opts.app {
		return false
	}
	if opts.namespace != "" && !auditEventContains(event, opts.namespace) {
		return false
	}
	return true
}

func auditEventContains(event audit.Event, value string) bool {
	return event.Target.Resource == value || event.Target.App == value || strings.Contains(event.Diff, value)
}

func auditEventMatchesGroup(event audit.Event, group string) bool {
	parsed, err := cfgov.ParseNacosKey(event.Target.Resource)
	return err == nil && parsed.Group == group
}

func printAuditQueryResult(f *cliFlags, result audit.Result) error {
	p := newPrinter(f)
	switch f.Output {
	case "json":
		return p.JSONData("AuditQueryResult", map[string]any{
			"apiVersion":       auditAPIVersion,
			"events":           auditEventsForOutput(result.Events),
			"malformedEntries": result.MalformedEntries,
		})
	case "plain":
		for _, event := range result.Events {
			data, err := json.Marshal(auditEventForOutput(event))
			if err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit event", err)
			}
			if err := p.Info(string(data)); err != nil {
				return err
			}
		}
		return nil
	default:
		rows := make([][]string, 0, len(result.Events))
		for _, event := range result.Events {
			rows = append(rows, []string{
				auditTime(event.Timestamp),
				auditDashIfEmpty(string(event.EventType)),
				auditDashIfEmpty(event.Operator),
				auditDashIfEmpty(event.Context.Name),
				auditDashIfEmpty(event.Context.Env),
				truncateAuditTableValue(event.Target.Resource),
				auditDashIfEmpty(event.Status),
			})
		}
		if err := p.Table([]string{"TIMESTAMP", "TYPE", "OPERATOR", "CONTEXT", "ENV", "RESOURCE", "STATUS"}, rows); err != nil {
			return err
		}
		if result.MalformedEntries > 0 {
			return p.Info(fmt.Sprintf("(skipped %d malformed audit entries)", result.MalformedEntries))
		}
		return nil
	}
}

func auditEventsForOutput(events []audit.Event) []any {
	out := make([]any, 0, len(events))
	for _, event := range events {
		out = append(out, auditEventForOutput(event))
	}
	return out
}

func auditEventForOutput(event audit.Event) any {
	event = sanitizeHistoricalAuditEvent(event)
	if event.EventType == audit.EventType("command.preview") {
		return previewAuditRecord{Event: event, Preview: true, DryRun: true}
	}
	return event
}

func sanitizeHistoricalAuditEvent(event audit.Event) audit.Event {
	event.Ticket = ""
	event.Reason = ""
	event.Diff = ""
	if event.Error != nil {
		event.Error = &audit.EventError{Code: event.Error.Code}
	}
	return event
}

func auditVerifyCmd(f *cliFlags) *cobra.Command {
	var opts auditVerifyOptions
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit log integrity",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAuditVerify(f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "Override audit log path")
	cmd.Flags().BoolVar(&opts.strict, "strict", false, "Exit non-zero on malformed entries or invariant violations")
	cmd.Flags().BoolVar(&opts.repair, "repair", false, "Quarantine malformed entries and rewrite audit log")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "Confirm audit repair; R3 authorization is also required")
	cmd.Flags().BoolVar(&opts.decrypt, "decrypt", false, "Decrypt audit entries using CFGOV_AUDIT_PRIVATE_KEY")
	return cmd
}

func runAuditVerify(f *cliFlags, opts auditVerifyOptions) error { //nolint:gocyclo,nestif // Verification, optional repair preview, mutation audit, printing, and strict-mode handling form one command flow.
	confirm := opts.confirm
	planRepair := opts.repair && isPlanOnly(f)
	if opts.repair && !confirm && !planRepair {
		return apperrors.New(apperrors.CodeUsageError, "audit verify --repair requires --confirm", nil)
	}
	path, err := auditPath(opts.path)
	if err != nil {
		return err
	}
	privateKey := ""
	if opts.decrypt {
		privateKey = envWithDeprecatedAlias(cfgovAuditPrivateKeyEnv, deprecatedCfgovAuditPrivateKeyEnv)
	}
	verifyOptions := audit.VerifyOptions{
		Decrypt:    opts.decrypt,
		PrivateKey: privateKey,
		Repair:     opts.repair && !planRepair,
		Confirm:    confirm && !planRepair,
	}
	var result audit.VerifyResult
	//nolint:nestif // Repair keeps preview binding, R3 authorization, intent, apply, and outcome in one ordered branch.
	if opts.repair && !planRepair {
		var previewCandidates []string
		previewCandidates, err = strictAuditRotatedFiles(path)
		if err != nil {
			return err
		}
		err = withAuditControlPolicyLock(f, allowAuditRepair, func() error {
			metadata := mutationValueMetadata("audit.repair", previewCandidates)
			metadata.Items = len(previewCandidates) + 1
			metadata.Updates = metadata.Items
			mutation, auditErr := beginMutationAudit(f, mutationAuditSpec{
				Action:    "audit.repair",
				Target:    audit.EventTarget{ResourceType: "audit", Resource: path},
				Metadata:  metadata,
				AuditPath: auditControlPath(path),
			})
			if auditErr != nil {
				return auditErr
			}
			var operationErr error
			result, operationErr = repairAudit(path, previewCandidates, verifyOptions)
			repaired := 0
			for _, file := range result.Files {
				if file.Repaired {
					repaired++
				}
			}
			return finishBatchMutationAudit(mutation, len(result.Files), repaired, 0, operationErr)
		})
		if err != nil {
			return err
		}
	} else {
		result, err = audit.Verify(path, verifyOptions)
	}
	if err != nil {
		return err
	}
	if planRepair {
		if err := printLocalChangePlan(f, "audit", "repair", path, map[string]any{"verification": result}); err != nil {
			return err
		}
	} else {
		if err := printAuditVerifyResult(f, result); err != nil {
			return err
		}
	}
	if opts.strict && auditVerifyHasProblems(result) {
		return apperrors.New(apperrors.CodeValidationFailed, "audit verification failed", nil)
	}
	return nil
}

func auditVerifyHasProblems(result audit.VerifyResult) bool {
	return result.HasProblems()
}

func printAuditVerifyResult(f *cliFlags, result audit.VerifyResult) error {
	p := newPrinter(f)
	switch f.Output {
	case "json":
		return p.JSONData("AuditVerifyResult", result)
	case "plain":
		return p.Info(fmt.Sprintf("total=%d valid=%d malformed=%d schemaErrors=%d timestampOrderViolations=%d authenticated=%d legacyUnauthenticated=%d encryptedOpaque=%d integrityErrors=%d sequenceViolations=%d checkpointViolations=%d truncationDetected=%t lockPresent=%t",
			result.Total, result.Valid, result.Malformed, result.SchemaErrors, result.TimestampOrderViolations,
			result.Authenticated, result.LegacyUnauthenticated, result.EncryptedOpaque, result.IntegrityErrors,
			result.SequenceViolations, result.CheckpointViolations, result.TruncationDetected, result.Lock.Present))
	default:
		rows := make([][]string, 0, len(result.Files))
		for _, file := range result.Files {
			rows = append(rows, []string{
				file.Path,
				fmt.Sprintf("%d", file.Total),
				fmt.Sprintf("%d", file.Valid),
				fmt.Sprintf("%d", file.Malformed),
				fmt.Sprintf("%d", file.SchemaError),
				fmt.Sprintf("%d", file.TimestampOrderViolations),
				fmt.Sprintf("%d", file.Authenticated),
				fmt.Sprintf("%d", file.LegacyUnauthenticated),
				fmt.Sprintf("%d", file.EncryptedOpaque),
				fmt.Sprintf("%d", file.IntegrityErrors),
				fmt.Sprintf("%d", file.SequenceViolations),
				auditDashIfEmpty(file.Quarantine),
				fmt.Sprintf("%t", file.Repaired),
			})
		}
		if err := p.Table([]string{"PATH", "TOTAL", "VALID", "MALFORMED", "SCHEMA_ERRORS", "TIMESTAMP_ORDER_VIOLATIONS", "AUTHENTICATED", "LEGACY_UNAUTHENTICATED", "ENCRYPTED_OPAQUE", "INTEGRITY_ERRORS", "SEQUENCE_VIOLATIONS", "QUARANTINE", "REPAIRED"}, rows); err != nil {
			return err
		}
		return p.Info(fmt.Sprintf("total=%d valid=%d malformed=%d schemaErrors=%d timestampOrderViolations=%d authenticated=%d legacyUnauthenticated=%d encryptedOpaque=%d integrityErrors=%d sequenceViolations=%d checkpointViolations=%d truncationDetected=%t lockPresent=%t",
			result.Total, result.Valid, result.Malformed, result.SchemaErrors, result.TimestampOrderViolations,
			result.Authenticated, result.LegacyUnauthenticated, result.EncryptedOpaque, result.IntegrityErrors,
			result.SequenceViolations, result.CheckpointViolations, result.TruncationDetected, result.Lock.Present))
	}
}

func auditPruneCmd(f *cliFlags) *cobra.Command {
	opts := auditPruneOptions{keepLast: -1, dryRun: true}
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune rotated audit logs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.dryRunSet = cmd.Flags().Changed("dry-run")
			return runAuditPrune(f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "Override audit log path")
	cmd.Flags().StringVar(&opts.before, "before", "", "Prune rotated logs before this time (30d / RFC3339 / YYYY-MM-DD)")
	cmd.Flags().IntVar(&opts.keepLast, "keep-last", -1, "Keep the newest N rotated logs (0 = delete all rotated logs)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", true, "Preview matched rotated logs without deleting")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "Confirm deletion; R3 authorization is also required")
	return cmd
}

func runAuditPrune(f *cliFlags, opts auditPruneOptions) error { //nolint:gocyclo // Selector validation, preview precedence, deletion, audit, and output form one command flow.
	if opts.before == "" && opts.keepLast < 0 {
		return apperrors.New(apperrors.CodeUsageError, "audit prune requires --before or --keep-last", nil)
	}
	if opts.before != "" && opts.keepLast >= 0 {
		return apperrors.New(apperrors.CodeUsageError, "audit prune accepts only one of --before or --keep-last", nil)
	}
	if opts.keepLast < -1 {
		return apperrors.New(apperrors.CodeUsageError, "--keep-last must be >= 0", nil)
	}
	path, err := auditPath(opts.path)
	if err != nil {
		return err
	}
	expectedRotated, err := strictAuditRotatedFiles(path)
	if err != nil {
		return err
	}
	candidates, err := auditPruneCandidatesFrom(path, opts, expectedRotated, time.Now().UTC())
	if err != nil {
		return err
	}
	preview := !opts.confirm || isPlanOnly(f) || (opts.dryRunSet && opts.dryRun)
	if preview {
		return printAuditPruneResult(f, auditPruneResult{DryRun: true, DeletedFiles: candidates, Count: len(candidates)})
	}
	var pruneResult audit.PruneResult
	err = withAuditControlPolicyLock(f, allowAuditPrune, func() error {
		if len(candidates) == 0 {
			return nil
		}
		metadata := mutationValueMetadata("audit.prune", candidates)
		metadata.Items = len(candidates)
		metadata.Deletes = len(candidates)
		mutation, auditErr := beginMutationAudit(f, mutationAuditSpec{
			Action:    "audit.prune",
			Target:    audit.EventTarget{ResourceType: "audit", Resource: path},
			Metadata:  metadata,
			AuditPath: auditControlPath(path),
		})
		if auditErr != nil {
			return auditErr
		}
		var operationErr error
		pruneResult, operationErr = audit.PruneRotatedFiles(path, candidates, audit.PruneOptions{
			Confirm:              true,
			ExpectedRotatedFiles: append([]string{}, expectedRotated...),
		})
		return finishBatchMutationAudit(mutation, len(candidates), len(pruneResult.DeletedFiles), 0, operationErr)
	})
	if err != nil {
		return err
	}
	return printAuditPruneResult(f, auditPruneResult{
		DryRun:          false,
		DeletedFiles:    pruneResult.DeletedFiles,
		Count:           len(pruneResult.DeletedFiles),
		Started:         pruneResult.Started,
		CheckpointState: pruneResult.CheckpointState,
	})
}

func repairAudit(
	path string,
	previewCandidates []string,
	verifyOptions audit.VerifyOptions,
) (audit.VerifyResult, error) {
	verifyOptions.ExpectedRotatedFiles = append([]string{}, previewCandidates...)
	return audit.Verify(path, verifyOptions)
}

func authorizeAuditControlConfig(
	f *cliFlags,
	cfg *corectx.Config[cfgovctx.Context],
	required safety.AllowFlag,
) error {
	if cfg == nil {
		return apperrors.New(apperrors.CodeLocalIOError, "audit control policy is unavailable", nil)
	}
	contextName := strings.TrimSpace(cfg.CurrentContext)
	if contextName == "" {
		return authorizeForContext(f, safety.R3, cfgovctx.Context{}, required, "")
	}
	policy, ok := cfg.Contexts[contextName]
	if !ok {
		return apperrors.New(
			apperrors.CodeAuthorizationRequired,
			fmt.Sprintf("current context %q has no persisted policy; refusing audit evidence mutation", contextName),
			nil,
		)
	}
	return authorizeForContext(f, safety.R3, policy, required, contextName)
}

func withAuditControlPolicyLock(
	f *cliFlags,
	required safety.AllowFlag,
	action func() error,
) (retErr error) {
	dir, err := corectx.ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create context directory for audit control", err)
	}
	lock := lockfile.New(filepath.Join(dir, "config"))
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(); retErr == nil && err != nil {
			retErr = apperrors.New(apperrors.CodeLocalIOError, "failed to release audit control policy lock", err)
		}
	}()
	cfg, err := cfgovctx.Load()
	if err != nil {
		return err
	}
	if err := authorizeAuditControlConfig(f, cfg, required); err != nil {
		return err
	}
	return action()
}

func auditPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	path, err := audit.DefaultPath()
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve default audit log path", err)
	}
	return path, nil
}

func auditControlPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"-control")
}

func auditPruneCandidates(path string, opts auditPruneOptions) ([]string, error) {
	rotated, err := strictAuditRotatedFiles(path)
	if err != nil {
		return nil, err
	}
	return auditPruneCandidatesFrom(path, opts, rotated, time.Now().UTC())
}

func auditPruneCandidatesFrom(
	path string,
	opts auditPruneOptions,
	rotated []string,
	now time.Time,
) ([]string, error) {
	if opts.keepLast >= 0 {
		if opts.keepLast >= len(rotated) {
			return []string{}, nil
		}
		return append([]string{}, rotated[:len(rotated)-opts.keepLast]...), nil
	}
	cutoff, err := parseAuditPruneBefore(opts.before, now)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rotated))
	for _, filePath := range rotated {
		ts, _, ok := strictAuditRotatedFileOrder(path, filePath)
		if ok && ts.Before(cutoff) {
			out = append(out, filePath)
		}
	}
	return out, nil
}

func parseAuditPruneBefore(value string, now time.Time) (time.Time, error) {
	if t, err := audit.ParseTime(value, now); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, apperrors.New(apperrors.CodeUsageError, "invalid --before: expected relative (30d), RFC3339, or YYYY-MM-DD", nil)
	}
	return t, nil
}

func printAuditPruneResult(f *cliFlags, result auditPruneResult) error {
	if result.DryRun {
		markPreview(f)
	}
	p := newPrinter(f)
	switch f.Output {
	case "json":
		return p.JSONData("AuditPruneResult", result)
	case "plain":
		for _, filePath := range result.DeletedFiles {
			if err := p.Info(filePath); err != nil {
				return err
			}
		}
		return nil
	default:
		rows := make([][]string, 0, len(result.DeletedFiles))
		action := "would-delete"
		if !result.DryRun {
			action = "deleted"
		}
		for _, filePath := range result.DeletedFiles {
			rows = append(rows, []string{action, filepath.Base(filePath), filePath})
		}
		if len(rows) == 0 {
			return p.Info("(no rotated audit logs matched)")
		}
		if err := p.Table([]string{"ACTION", "FILE", "PATH"}, rows); err != nil {
			return err
		}
		if result.DryRun {
			return p.Info(fmt.Sprintf("(dry-run: deleting %d rotated audit logs requires --confirm --yes --ticket <ticket> --allow-audit-prune)", result.Count))
		}
		return nil
	}
}

func auditTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func auditDashIfEmpty(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

func truncateAuditTableValue(value string) string {
	const maxRunes = 40
	const prefixRunes = 36
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return auditDashIfEmpty(value)
	}
	return string(runes[:prefixRunes]) + "..."
}
