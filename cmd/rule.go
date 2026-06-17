package cmd

import (
	"context"
	"encoding/json"
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
	File   string       `json:"file"`
	Type   rule.Type    `json:"type"`
	Deep   bool         `json:"deep"`
	Valid  bool         `json:"valid"`
	Count  int          `json:"count"`
	SHA256 string       `json:"sha256"`
	Issues []rule.Issue `json:"issues,omitempty"`
}

func newRuleCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Read and validate Sentinel rules"}
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
	var app string
	cmd := &cobra.Command{
		Use:   "list --app <app>",
		Short: "List Sentinel rule counts",
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
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func ruleGetCmd(f *cliFlags) *cobra.Command {
	var app, typeName string
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
			return newPrinter(f).JSONData("RuleSet", result)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Sentinel app")
	cmd.Flags().StringVar(&typeName, "type", "", "Rule type: flow, degrade, system, authority, param")
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
	var app, typeName, file string
	cmd := &cobra.Command{
		Use:   "diff --app <app> --type <ruleType> --file <path>",
		Short: "Compare remote and local Sentinel rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func ruleValidateCmd(f *cliFlags) *cobra.Command {
	var file string
	var deep bool
	cmd := &cobra.Command{
		Use:   "validate --file <path>",
		Short: "Validate a local Sentinel rule file",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
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
				issues := rule.DeepCheck(map[rule.Type][]map[string]any{ruleType: local.Rules})
				result.Issues = issues
				result.Valid = !rule.HasError(issues)
				if !result.Valid {
					_ = newPrinter(f).JSONData("RuleValidation", result)
					return apperrors.New(apperrors.CodeValidationFailed, "deep rule validation failed", nil)
				}
			}
			return newPrinter(f).JSONData("RuleValidation", result)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Local rule file")
	cmd.Flags().BoolVar(&deep, "deep", false, "Run deep semantic checks")
	_ = cmd.MarkFlagRequired("file")
	return cmd
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

func intString(value int) string {
	return strconv.Itoa(value)
}
