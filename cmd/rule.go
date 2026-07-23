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

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"

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

type ruleExportReadResult struct {
	Items       []ruleSetResult
	ExportFiles map[string][]byte
	ExportNames []string
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
			ruleTypes, err := selectedRuleTypes(typeName)
			if err != nil {
				return err
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"rule.list",
				"rule",
				app,
				map[string]any{
					"app":   app,
					"types": ruleTypes,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) ([]ruleSetResult, error) {
					_, store, storeErr := ensureRuleStore(backend)
					if storeErr != nil {
						return nil, storeErr
					}
					items := make([]ruleSetResult, 0, len(ruleTypes))
					for _, ruleType := range ruleTypes {
						result, readErr := readRuleSet(cmd.Context(), backend, store, app, ruleType)
						if readErr != nil {
							return nil, readErr
						}
						result.Rules = nil
						items = append(items, result)
					}
					return items, nil
				},
				func(items []ruleSetResult) int { return len(items) },
			)
			if err != nil {
				return err
			}
			items := readResult.Value
			target := readResult.operationTarget()
			if f.Output == "json" {
				return targetJSONList(f, "RuleList", items, len(items), 1, len(items), target)
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{string(item.Type), item.Key, item.Revision, item.SHA256, intString(item.Count)})
			}
			p := newPrinter(f)
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			return p.Table([]string{"TYPE", "KEY", "REVISION", "SHA256", "COUNT"}, rows)
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
			readResult, err := runMandatoryBackendRead(
				f,
				"rule.get",
				"rule",
				app+"/"+string(ruleType),
				map[string]any{
					"app":      app,
					"type":     ruleType,
					"resource": resource,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (ruleSetResult, error) {
					_, store, storeErr := ensureRuleStore(backend)
					if storeErr != nil {
						return ruleSetResult{}, storeErr
					}
					result, readErr := readRuleSet(cmd.Context(), backend, store, app, ruleType)
					if readErr != nil {
						return ruleSetResult{}, readErr
					}
					return filterRuleSetByResource(result, resource), nil
				},
				func(result ruleSetResult) int { return result.Count },
			)
			if err != nil {
				return err
			}
			return targetJSONData(f, "RuleSet", readResult.Value, readResult.operationTarget(), operationTargetRead)
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
			planOnly := isPlanOnly(f)
			backendRead, err := runMandatoryBackendRead(
				f,
				"rule.export",
				"rule",
				app,
				map[string]any{
					"app":   app,
					"types": rule.AllTypes,
					"dir":   dir,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (ruleExportReadResult, error) {
					_, store, storeErr := ensureRuleStore(backend)
					if storeErr != nil {
						return ruleExportReadResult{}, storeErr
					}
					result := ruleExportReadResult{
						Items:       make([]ruleSetResult, 0, len(rule.AllTypes)),
						ExportFiles: make(map[string][]byte, len(rule.AllTypes)),
						ExportNames: make([]string, 0, len(rule.AllTypes)),
					}
					for _, ruleType := range rule.AllTypes {
						item, readErr := readRuleSet(cmd.Context(), backend, store, app, ruleType)
						if readErr != nil {
							return ruleExportReadResult{}, readErr
						}
						content, marshalErr := json.MarshalIndent(item.Rules, "", "  ")
						if marshalErr != nil {
							return ruleExportReadResult{}, apperrors.New(apperrors.CodeLocalIOError, "failed to encode rules", marshalErr)
						}
						name := string(ruleType) + ".json"
						result.ExportFiles[name] = append(content, '\n')
						result.ExportNames = append(result.ExportNames, name)
						item.Rules = nil
						result.Items = append(result.Items, item)
					}
					if preflightErr := preflightNewLocalFiles(dir, result.ExportNames); preflightErr != nil {
						return ruleExportReadResult{}, preflightErr
					}
					return result, nil
				},
				func(result ruleExportReadResult) int { return len(result.Items) },
			)
			if err != nil {
				return err
			}
			readResult := backendRead.Value
			ctxMeta := backendRead.Context
			target := backendRead.operationTarget()
			items := readResult.Items
			exportFiles := readResult.ExportFiles
			exportNames := readResult.ExportNames
			if planOnly {
				markPreview(f)
				return targetJSONData(f, "ChangePlan", map[string]any{
					"resourceType": "file",
					"action":       "rule export",
					"app":          app,
					"dir":          dir,
					"items":        items,
					"dryRun":       true,
				}, target, operationTargetRead)
			}
			metadata := mutationValueMetadata("rule.export", items)
			metadata.Items = len(exportFiles)
			metadata.Creates = len(exportFiles)
			mutation, err := beginMutationAudit(f, mutationAuditSpec{
				Action:  "rule.export",
				Context: ctxMeta,
				Target: audit.EventTarget{
					App:          app,
					ResourceType: "file",
					Resource:     dir,
				},
				Metadata: metadata,
			})
			if err != nil {
				return err
			}
			succeeded := 0
			for _, name := range exportNames {
				writeErr := writeNewLocalFile(filepath.Join(dir, name), exportFiles[name])
				if writeErr != nil {
					return finishMutationAudit(mutation, mutationAuditOutcome{
						Status:    audit.StatusPartialFailed,
						Succeeded: succeeded,
						Failed:    1,
						Skipped:   len(exportFiles) - succeeded - 1,
					}, writeErr)
				}
				succeeded++
			}
			if err := finishMutationAudit(mutation, mutationAuditOutcome{Succeeded: succeeded}, nil); err != nil {
				return err
			}
			return targetJSONData(f, "RuleExport", map[string]any{"app": app, "dir": dir, "items": items}, target, operationTargetRead)
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
			readResult, err := runMandatoryBackendRead(
				f,
				"rule.diff",
				"rule",
				app+"/"+string(ruleType),
				map[string]any{
					"app":         app,
					"type":        ruleType,
					"localSha256": local.SHA256,
					"localCount":  local.Count,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (ruleDiffResult, error) {
					_, store, storeErr := ensureRuleStore(backend)
					if storeErr != nil {
						return ruleDiffResult{}, storeErr
					}
					remote, readErr := readRuleSet(cmd.Context(), backend, store, app, ruleType)
					if readErr != nil {
						return ruleDiffResult{}, readErr
					}
					result := ruleDiffResult{
						App:          app,
						Type:         ruleType,
						RemoteSHA256: remote.SHA256,
						LocalSHA256:  local.SHA256,
						RemoteCount:  remote.Count,
						LocalCount:   local.Count,
					}
					result.Same = result.RemoteSHA256 == result.LocalSHA256 &&
						result.RemoteCount == result.LocalCount
					return result, nil
				},
				func(ruleDiffResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			return targetJSONData(f, "RuleDiff", readResult.Value, readResult.operationTarget(), operationTargetRead)
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
	readResult, err := runMandatoryBackendRead(
		f,
		"rule.diff",
		"rule",
		app,
		map[string]any{
			"app":   app,
			"dir":   dir,
			"types": ruleTypes,
		},
		func(backend cfgov.Backend, _ cfgovctx.Context) ([]ruleDiffResult, error) {
			_, store, storeErr := ensureRuleStore(backend)
			if storeErr != nil {
				return nil, storeErr
			}
			items := make([]ruleDiffResult, 0, len(ruleTypes))
			for _, ruleType := range ruleTypes {
				localRules, ok := locals[ruleType]
				if !ok {
					continue
				}
				remote, readErr := readRuleSet(ctx, backend, store, app, ruleType)
				if readErr != nil {
					return nil, readErr
				}
				localPayload, marshalErr := json.Marshal(localRules)
				if marshalErr != nil {
					return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal local rules", marshalErr)
				}
				item := ruleDiffResult{
					App:          app,
					Type:         ruleType,
					RemoteSHA256: remote.SHA256,
					LocalSHA256:  sha256Bytes(localPayload),
					RemoteCount:  remote.Count,
					LocalCount:   len(localRules),
				}
				item.Same = item.RemoteSHA256 == item.LocalSHA256 &&
					item.RemoteCount == item.LocalCount
				items = append(items, item)
			}
			return items, nil
		},
		func(items []ruleDiffResult) int { return len(items) },
	)
	if err != nil {
		return err
	}
	items := readResult.Value
	same := true
	for _, item := range items {
		if !item.Same {
			same = false
			break
		}
	}
	return targetJSONData(f, "RuleDiff", map[string]any{"app": app, "dir": dir, "same": same, "items": items}, readResult.operationTarget(), operationTargetRead)
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
