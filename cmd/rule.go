package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/rule"
)

type ruleSetResult struct {
	App      string           `json:"app"`
	Type     rule.Type        `json:"type"`
	Count    int              `json:"count"`
	Key      string           `json:"key"`
	Revision string           `json:"revision,omitempty"`
	SHA256   string           `json:"sha256"`
	Rules    []map[string]any `json:"rules,omitempty"`
}

type ruleDiffResult struct {
	App          string    `json:"app"`
	Type         rule.Type `json:"type"`
	Same         bool      `json:"same"`
	RemoteSHA256 string    `json:"remoteSha256"`
	LocalSHA256  string    `json:"localSha256"`
	RemoteCount  int       `json:"remoteCount"`
	LocalCount   int       `json:"localCount"`
}

type ruleValidationResult struct {
	File     string            `json:"file,omitempty"`
	Dir      string            `json:"dir,omitempty"`
	Type     rule.Type         `json:"type,omitempty"`
	Deep     bool              `json:"deep"`
	Valid    bool              `json:"valid"`
	Count    int               `json:"count"`
	Counts   map[rule.Type]int `json:"counts,omitempty"`
	SHA256   string            `json:"sha256,omitempty"`
	Errors   int               `json:"errors"`
	Warnings int               `json:"warnings"`
	Issues   []rule.Issue      `json:"issues,omitempty"`
}

func newRuleCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Read and validate Sentinel rules", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(
		ruleListCmd(f),
		ruleGetCmd(f),
		ruleExportCmd(f),
		ruleDiffCmd(f),
		ruleValidateCmd(f),
		ruleCreateCmd(f),
		ruleUpdateCmd(f),
		ruleImportCmd(f),
		ruleDeleteCmd(f),
		ruleRollbackCmd(f),
	)
	return cmd
}

func ruleListCmd(f *cliFlags) *cobra.Command {
	var app, typeName string
	cmd := &cobra.Command{
		Use:   "list --app <app>",
		Short: "List Sentinel rule counts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, store, ctxMeta, err := buildRuleStore(f)
			if err != nil {
				return err
			}
			ruleTypes, err := selectedRuleTypes(typeName)
			if err != nil {
				return err
			}
			items := make([]ruleSetResult, 0, len(ruleTypes))
			for _, ruleType := range ruleTypes {
				result, err := readRuleSet(cmd.Context(), backend, store, app, ruleType)
				if err != nil {
					appendRuleAudit(f, ctxMeta, "list", app, ruleType, audit.StatusFailed, "", err)
					return err
				}
				result.Rules = nil
				items = append(items, result)
			}
			appendRuleAudit(f, ctxMeta, "list", app, "", audit.StatusSuccess, ruleAuditSummary(items), nil)
			if f.Output == "json" {
				return newPrinter(f).JSONList("RuleList", items, len(items), 1, len(items), false)
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{string(item.Type), item.Key, item.Revision, item.SHA256, intString(item.Count)})
			}
			newPrinter(f).Table([]string{"TYPE", "KEY", "REVISION", "SHA256", "COUNT"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func ruleGetCmd(f *cliFlags) *cobra.Command {
	var app, typeName, resource string
	cmd := &cobra.Command{
		Use:   "get --app <app> --type <ruleType>",
		Short: "Get one Sentinel rule set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ruleType, err := rule.ParseType(typeName)
			if err != nil {
				return err
			}
			backend, store, ctxMeta, err := buildRuleStore(f)
			if err != nil {
				return err
			}
			result, err := readRuleSet(cmd.Context(), backend, store, app, ruleType)
			appendRuleAudit(f, ctxMeta, "get", app, ruleType, auditStatus(err), ruleSetAudit(result), err)
			if err != nil {
				return err
			}
			if resource != "" {
				result = filterRuleSetByResource(result, resource)
			}
			return newPrinter(f).JSONData("RuleSet", result)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
	cmd.Flags().StringVar(&resource, "resource", "", "Filter by resource")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

func ruleExportCmd(f *cliFlags) *cobra.Command {
	var app, dir string
	cmd := &cobra.Command{
		Use:   "export --app <app> --dir <dir>",
		Short: "Export Sentinel rule sets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, store, ctxMeta, err := buildRuleStore(f)
			if err != nil {
				return err
			}
			items := make([]ruleSetResult, 0, len(rule.AllTypes))
			for _, ruleType := range rule.AllTypes {
				result, err := readRuleSet(cmd.Context(), backend, store, app, ruleType)
				if err != nil {
					appendRuleAudit(f, ctxMeta, "export", app, ruleType, audit.StatusFailed, "", err)
					return err
				}
				content, err := json.MarshalIndent(result.Rules, "", "  ")
				if err != nil {
					return apperrors.New(apperrors.CodeLocalIOError, "failed to encode rules", err)
				}
				if err := writeLocalFile(filepath.Join(dir, string(ruleType)+".json"), append(content, '\n')); err != nil {
					return err
				}
				result.Rules = nil
				items = append(items, result)
			}
			appendRuleAudit(f, ctxMeta, "export", app, "", audit.StatusSuccess, ruleAuditSummary(items), nil)
			return newPrinter(f).JSONData("RuleExport", map[string]any{"app": app, "dir": dir, "items": items})
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&dir, "dir", "", "Output directory")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

func ruleDiffCmd(f *cliFlags) *cobra.Command {
	var app, typeName, file, dir string
	cmd := &cobra.Command{
		Use:   "diff --app <app> (--type <ruleType> --file <path>|--dir <dir>)",
		Short: "Compare remote and local Sentinel rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir != "" {
				if file != "" {
					return apperrors.New(apperrors.CodeUsageError, "--dir and --file are mutually exclusive", nil)
				}
				return ruleDiffDir(cmd.Context(), f, app, typeName, dir)
			}
			if file == "" {
				return apperrors.New(apperrors.CodeUsageError, "--file is required unless --dir is specified", nil)
			}
			ruleType, err := rule.ParseType(typeName)
			if err != nil {
				return err
			}
			local, err := readLocalRuleFile(file, ruleType)
			if err != nil {
				return err
			}
			backend, store, ctxMeta, err := buildRuleStore(f)
			if err != nil {
				return err
			}
			remote, err := readRuleSet(cmd.Context(), backend, store, app, ruleType)
			appendRuleAudit(f, ctxMeta, "diff", app, ruleType, auditStatus(err), ruleSetAudit(remote), err)
			if err != nil {
				return err
			}
			result := ruleDiffResult{
				App:          app,
				Type:         ruleType,
				RemoteSHA256: remote.SHA256,
				LocalSHA256:  local.SHA256,
				RemoteCount:  remote.Count,
				LocalCount:   local.Count,
			}
			result.Same = result.RemoteSHA256 == result.LocalSHA256 && result.RemoteCount == result.LocalCount
			return newPrinter(f).JSONData("RuleDiff", result)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
	cmd.Flags().StringVar(&file, "file", "", "Local rule file")
	cmd.Flags().StringVar(&dir, "dir", "", "Directory containing <type>.json files")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func ruleDiffDir(ctx context.Context, f *cliFlags, app, typeName, dir string) error {
	ruleTypes, err := selectedRuleTypes(typeName)
	if err != nil {
		return err
	}
	locals, _, _, err := readRuleValidationDirectory(dir)
	if err != nil {
		return err
	}
	backend, store, ctxMeta, err := buildRuleStore(f)
	if err != nil {
		return err
	}
	items := make([]ruleDiffResult, 0, len(ruleTypes))
	for _, ruleType := range ruleTypes {
		localRules, ok := locals[ruleType]
		if !ok {
			continue
		}
		remote, err := readRuleSet(ctx, backend, store, app, ruleType)
		appendRuleAudit(f, ctxMeta, "diff", app, ruleType, auditStatus(err), ruleSetAudit(remote), err)
		if err != nil {
			return err
		}
		localPayload, err := json.Marshal(localRules)
		if err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal local rules", err)
		}
		item := ruleDiffResult{
			App:          app,
			Type:         ruleType,
			RemoteSHA256: remote.SHA256,
			LocalSHA256:  sha256Bytes(localPayload),
			RemoteCount:  remote.Count,
			LocalCount:   len(localRules),
		}
		item.Same = item.RemoteSHA256 == item.LocalSHA256 && item.RemoteCount == item.LocalCount
		items = append(items, item)
	}
	same := true
	for _, item := range items {
		if !item.Same {
			same = false
			break
		}
	}
	return newPrinter(f).JSONData("RuleDiff", map[string]any{"app": app, "dir": dir, "same": same, "items": items})
}

func ruleValidateCmd(f *cliFlags) *cobra.Command {
	var file, dir string
	var deep bool
	var failOnWarnings bool
	cmd := &cobra.Command{
		Use:   "validate (--file <path>|--dir <dir>)",
		Short: "Validate local Sentinel rule files",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if (file == "") == (dir == "") {
				return apperrors.New(apperrors.CodeUsageError, "specify exactly one of --file or --dir", nil)
			}
			if dir != "" {
				return runRuleValidateDir(f, dir, deep, failOnWarnings)
			}
			ruleType, err := rule.InferTypeFromPath(file)
			if err != nil {
				return err
			}
			local, err := readLocalRuleFile(file, ruleType)
			if err != nil {
				return err
			}
			result := ruleValidationResult{File: file, Type: ruleType, Deep: deep, Valid: true, Count: local.Count, SHA256: local.SHA256}
			if deep {
				issues := rule.IntraTypeDeepCheck(map[rule.Type][]map[string]any{ruleType: local.Rules})
				result = applyRuleValidationIssues(result, issues)
			}
			return finishRuleValidation(f, result, failOnWarnings)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Local rule file")
	cmd.Flags().StringVar(&dir, "dir", "", "Directory containing <type>.json files")
	cmd.Flags().BoolVar(&deep, "deep", false, "Run deep semantic checks")
	cmd.Flags().BoolVar(&failOnWarnings, "fail-on-warnings", false, "Exit non-zero when deep validation reports warnings")
	return cmd
}

func runRuleValidateDir(f *cliFlags, dir string, deep bool, failOnWarnings bool) error {
	rules, counts, total, err := readRuleValidationDirectory(dir)
	if err != nil {
		return err
	}
	result := ruleValidationResult{Dir: dir, Deep: deep, Valid: true, Count: total, Counts: counts}
	if deep {
		result = applyRuleValidationIssues(result, rule.DeepCheck(rules))
	}
	return finishRuleValidation(f, result, failOnWarnings)
}

func readRuleValidationDirectory(dir string) (map[rule.Type][]map[string]any, map[rule.Type]int, int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, 0, apperrors.New(apperrors.CodeLocalIOError, "failed to stat rule directory", err)
	}
	if !info.IsDir() {
		return nil, nil, 0, apperrors.New(apperrors.CodeUsageError, "--dir must be a directory", nil)
	}
	out := make(map[rule.Type][]map[string]any, len(rule.AllTypes))
	counts := make(map[rule.Type]int, len(rule.AllTypes))
	total := 0
	for _, ruleType := range rule.AllTypes {
		path := filepath.Join(dir, string(ruleType)+".json")
		content, err := os.ReadFile(path) //nolint:gosec // Path is constrained to operator supplied validation directory.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, nil, 0, apperrors.New(apperrors.CodeLocalIOError, "failed to read rule file", err)
		}
		items, err := rule.DecodeSet(ruleType, content)
		if err != nil {
			return nil, nil, 0, err
		}
		out[ruleType] = items
		counts[ruleType] = len(items)
		total += len(items)
	}
	return out, counts, total, nil
}

func applyRuleValidationIssues(result ruleValidationResult, issues []rule.Issue) ruleValidationResult {
	result.Issues = issues
	result.Errors, result.Warnings = countRuleIssues(issues)
	result.Valid = result.Errors == 0
	return result
}

func finishRuleValidation(f *cliFlags, result ruleValidationResult, failOnWarnings bool) error {
	if err := newPrinter(f).JSONData("RuleValidation", result); err != nil {
		return err
	}
	if result.Errors > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "deep rule validation failed", nil)
	}
	if failOnWarnings && result.Warnings > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "deep rule validation warnings found", nil)
	}
	return nil
}

func countRuleIssues(issues []rule.Issue) (int, int) {
	errorsCount := 0
	warningsCount := 0
	for _, issue := range issues {
		if issue.Severity == rule.SeverityError {
			errorsCount++
		} else {
			warningsCount++
		}
	}
	return errorsCount, warningsCount
}

func selectedRuleTypes(typeName string) ([]rule.Type, error) {
	if strings.TrimSpace(typeName) == "" {
		return append([]rule.Type{}, rule.AllTypes...), nil
	}
	ruleType, err := rule.ParseType(typeName)
	if err != nil {
		return nil, err
	}
	return []rule.Type{ruleType}, nil
}

func buildRuleStore(f *cliFlags) (cfgov.Backend, cfgov.RuleStore, cfgovctx.Context, error) {
	backend, ctxMeta, err := buildBackend(f)
	if err != nil {
		return nil, nil, cfgovctx.Context{}, err
	}
	backend, store, err := ensureRuleStore(backend)
	if err != nil {
		return nil, nil, cfgovctx.Context{}, err
	}
	return backend, store, ctxMeta, nil
}

func ensureRuleStore(backend cfgov.Backend) (cfgov.Backend, cfgov.RuleStore, error) {
	store, ok := backend.(cfgov.RuleStore)
	if !ok || !backend.Capabilities().SupportsRules {
		return nil, nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support Sentinel rules", nil)
	}
	return backend, store, nil
}

func readRuleSet(ctx context.Context, backend cfgov.Backend, store cfgov.RuleStore, app string, ruleType rule.Type) (ruleSetResult, error) {
	coord, err := store.RuleCoordinate(app, string(ruleType))
	if err != nil {
		return ruleSetResult{}, err
	}
	blob, err := backend.Get(ctx, coord)
	if err != nil {
		if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
			return emptyRuleSet(app, ruleType, coord), nil
		}
		return ruleSetResult{}, err
	}
	rules, err := rule.DecodeSet(ruleType, blob.Content)
	if err != nil {
		return ruleSetResult{}, err
	}
	return ruleSetResult{App: app, Type: ruleType, Count: len(rules), Key: coord.Key, Revision: blob.Revision, SHA256: sha256Bytes(blob.Content), Rules: rules}, nil
}

func emptyRuleSet(app string, ruleType rule.Type, coord cfgov.Coordinate) ruleSetResult {
	return ruleSetResult{App: app, Type: ruleType, Key: coord.Key, SHA256: sha256Bytes([]byte("[]")), Rules: []map[string]any{}}
}

func readLocalRuleFile(path string, ruleType rule.Type) (ruleSetResult, error) {
	content, err := os.ReadFile(path) //nolint:gosec // Operator supplied rule file.
	if err != nil {
		return ruleSetResult{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read rule file", err)
	}
	rules, err := rule.DecodeSet(ruleType, content)
	if err != nil {
		return ruleSetResult{}, err
	}
	return ruleSetResult{Type: ruleType, Count: len(rules), SHA256: sha256Bytes(content), Rules: rules}, nil
}

func appendRuleAudit(f *cliFlags, ctxMeta cfgovctx.Context, verb, app string, ruleType rule.Type, status, diff string, err error) {
	resource := app
	if ruleType != "" {
		resource += "/" + string(ruleType)
	}
	appendAuditWarn(f, audit.EventType("rule."+verb), ctxMeta, audit.EventTarget{ResourceType: "rule", Resource: resource}, status, diff, err)
}

func ruleSetAudit(result ruleSetResult) string {
	if result.App == "" && result.Type == "" {
		return ""
	}
	return "app=" + result.App + " type=" + string(result.Type) + " sha256=" + result.SHA256 + " count=" + intString(result.Count)
}

func ruleAuditSummary(items []ruleSetResult) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, string(item.Type)+"="+item.SHA256+"/"+intString(item.Count))
	}
	return "ruleSets=" + intString(len(items)) + " " + strings.Join(parts, ",")
}

func filterRuleSetByResource(result ruleSetResult, resource string) ruleSetResult {
	if resource == "" {
		return result
	}
	filtered := make([]map[string]any, 0, len(result.Rules))
	for _, item := range result.Rules {
		if ruleValueString(item["resource"]) == resource {
			filtered = append(filtered, item)
		}
	}
	result.Rules = filtered
	result.Count = len(filtered)
	if data, err := json.Marshal(filtered); err == nil {
		result.SHA256 = sha256Bytes(data)
	}
	return result
}

func ruleValueString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func intString(value int) string {
	return strconv.Itoa(value)
}
