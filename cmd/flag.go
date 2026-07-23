package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
	"github.com/JiangHe12/cfgov-cli/internal/flag"
)

type flagSetResult struct {
	App      string             `json:"app"`
	Count    int                `json:"count"`
	Key      string             `json:"key"`
	Revision string             `json:"revision,omitempty"`
	SHA256   string             `json:"sha256"`
	Flags    []flag.FeatureFlag `json:"flags,omitempty"`
}

type flagDiffResult struct {
	App          string `json:"app"`
	Same         bool   `json:"same"`
	RemoteSHA256 string `json:"remoteSha256"`
	LocalSHA256  string `json:"localSha256"`
	RemoteCount  int    `json:"remoteCount"`
	LocalCount   int    `json:"localCount"`
}

type flagValidationResult struct {
	File     string       `json:"file,omitempty"`
	Dir      string       `json:"dir,omitempty"`
	Deep     bool         `json:"deep"`
	Valid    bool         `json:"valid"`
	Count    int          `json:"count"`
	SHA256   string       `json:"sha256,omitempty"`
	Errors   int          `json:"errors"`
	Warnings int          `json:"warnings"`
	Issues   []flag.Issue `json:"issues,omitempty"`
}

type flagExportReadResult struct {
	Result  flagSetResult
	Payload []byte
}

func newFlagCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "flag", Short: "Read and validate feature flags", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(
		flagListCmd(f),
		flagGetCmd(f),
		flagExportCmd(f),
		flagDiffCmd(f),
		flagValidateCmd(f),
		flagCreateCmd(f),
		flagUpdateCmd(f),
		flagDeleteCmd(f),
		flagImportCmd(f),
		flagRollbackCmd(f),
	)
	return cmd
}

func flagListCmd(f *cliFlags) *cobra.Command {
	var app string
	cmd := &cobra.Command{
		Use:   "list --app <app>",
		Short: "List feature flag count",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"flag.list",
				"flag",
				app,
				map[string]any{"app": app},
				func(backend cfgov.Backend, _ cfgovctx.Context) (flagSetResult, error) {
					_, store, storeErr := ensureFlagStore(backend)
					if storeErr != nil {
						return flagSetResult{}, storeErr
					}
					return readFlagSet(cmd.Context(), backend, store, app)
				},
				func(result flagSetResult) int { return result.Count },
			)
			if err != nil {
				return err
			}
			result := readResult.Value
			result.Flags = nil
			items := []flagSetResult{result}
			target := readResult.operationTarget()
			if f.Output == "json" {
				return targetJSONList(f, "FlagList", items, len(items), 1, len(items), target)
			}
			p := newPrinter(f)
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			return p.Table([]string{"KEY", "REVISION", "SHA256", "COUNT"}, [][]string{{result.Key, result.Revision, result.SHA256, intString(result.Count)}})
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application name")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func flagGetCmd(f *cliFlags) *cobra.Command {
	var app, key string
	cmd := &cobra.Command{
		Use:   "get --app <app>",
		Short: "Get one feature flag set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"flag.get",
				"flag",
				app,
				map[string]any{
					"app": app,
					"key": key,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (flagSetResult, error) {
					_, store, storeErr := ensureFlagStore(backend)
					if storeErr != nil {
						return flagSetResult{}, storeErr
					}
					result, readErr := readFlagSet(cmd.Context(), backend, store, app)
					if readErr != nil {
						return flagSetResult{}, readErr
					}
					return filterFlagSetByKey(result, key), nil
				},
				func(result flagSetResult) int { return result.Count },
			)
			if err != nil {
				return err
			}
			return targetJSONData(f, "FlagSet", readResult.Value, readResult.operationTarget(), operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application name")
	cmd.Flags().StringVar(&key, "key", "", "Filter by feature flag key")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func flagExportCmd(f *cliFlags) *cobra.Command {
	var app, dir string
	cmd := &cobra.Command{
		Use:   "export --app <app> --dir <dir>",
		Short: "Export feature flag set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			planOnly := isPlanOnly(f)
			backendRead, err := runMandatoryBackendRead(
				f,
				"flag.export",
				"flag",
				app,
				map[string]any{"app": app, "dir": dir},
				func(backend cfgov.Backend, _ cfgovctx.Context) (flagExportReadResult, error) {
					_, store, storeErr := ensureFlagStore(backend)
					if storeErr != nil {
						return flagExportReadResult{}, storeErr
					}
					result, readErr := readFlagSet(cmd.Context(), backend, store, app)
					if readErr != nil {
						return flagExportReadResult{}, readErr
					}
					content, marshalErr := json.MarshalIndent(result.Flags, "", "  ")
					if marshalErr != nil {
						return flagExportReadResult{}, apperrors.New(apperrors.CodeLocalIOError, "failed to encode flags", marshalErr)
					}
					result.Flags = nil
					payload := append(append(make([]byte, 0, len(content)+1), content...), '\n')
					if preflightErr := preflightNewLocalFiles(dir, []string{"flags.json"}); preflightErr != nil {
						return flagExportReadResult{}, preflightErr
					}
					return flagExportReadResult{Result: result, Payload: payload}, nil
				},
				func(result flagExportReadResult) int { return result.Result.Count },
			)
			if err != nil {
				return err
			}
			readResult := backendRead.Value
			ctxMeta := backendRead.Context
			target := backendRead.operationTarget()
			result := readResult.Result
			payload := readResult.Payload
			if planOnly {
				markPreview(f)
				return targetJSONData(f, "ChangePlan", map[string]any{
					"resourceType": "file",
					"action":       "flag export",
					"app":          app,
					"dir":          dir,
					"items":        []flagSetResult{result},
					"dryRun":       true,
				}, target, operationTargetRead)
			}
			metadata := mutationPayloadMetadata("flag.export", payload)
			metadata.Items = 1
			metadata.Creates = 1
			metadata.Revision = result.Revision
			mutation, err := beginMutationAudit(f, mutationAuditSpec{
				Action:  "flag.export",
				Context: ctxMeta,
				Target: audit.EventTarget{
					App:          app,
					ResourceType: "file",
					Resource:     filepath.Join(dir, "flags.json"),
				},
				Metadata: metadata,
			})
			if err != nil {
				return err
			}
			writeErr := writeNewLocalFile(filepath.Join(dir, "flags.json"), payload)
			if auditErr := finishMutationAudit(
				mutation,
				mutationAuditOutcome{Revision: result.Revision},
				writeErr,
			); auditErr != nil {
				return auditErr
			}
			return targetJSONData(f, "FlagExport", map[string]any{"app": app, "dir": dir, "items": []flagSetResult{result}}, target, operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application name")
	cmd.Flags().StringVar(&dir, "dir", "", "Output directory")
	_ = cmd.MarkFlagRequired("app")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}

func flagDiffCmd(f *cliFlags) *cobra.Command {
	var app, file, dir string
	cmd := &cobra.Command{
		Use:   "diff --app <app> (--file <path>|--dir <dir>)",
		Short: "Compare remote and local feature flags",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			local, err := readLocalFlagInput(file, dir)
			if err != nil {
				return err
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"flag.diff",
				"flag",
				app,
				map[string]any{
					"app":         app,
					"localSha256": local.SHA256,
					"localCount":  local.Count,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (flagDiffResult, error) {
					_, store, storeErr := ensureFlagStore(backend)
					if storeErr != nil {
						return flagDiffResult{}, storeErr
					}
					remote, readErr := readFlagSet(cmd.Context(), backend, store, app)
					if readErr != nil {
						return flagDiffResult{}, readErr
					}
					result := flagDiffResult{
						App:          app,
						RemoteSHA256: remote.SHA256,
						LocalSHA256:  local.SHA256,
						RemoteCount:  remote.Count,
						LocalCount:   local.Count,
					}
					result.Same = result.RemoteSHA256 == result.LocalSHA256 &&
						result.RemoteCount == result.LocalCount
					return result, nil
				},
				func(flagDiffResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			return targetJSONData(f, "FlagDiff", readResult.Value, readResult.operationTarget(), operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application name")
	cmd.Flags().StringVar(&file, "file", "", "Local feature flag file")
	cmd.Flags().StringVar(&dir, "dir", "", "Directory containing flags.json")
	_ = cmd.MarkFlagRequired("app")
	return cmd
}

func flagValidateCmd(f *cliFlags) *cobra.Command {
	var file, dir string
	var deep bool
	var failOnWarnings bool
	cmd := &cobra.Command{
		Use:   "validate (--file <path>|--dir <dir>)",
		Short: "Validate local feature flag files",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			local, err := readLocalFlagInput(file, dir)
			if err != nil {
				return err
			}
			result := flagValidationResult{File: file, Dir: dir, Deep: deep, Valid: true, Count: local.Count, SHA256: local.SHA256}
			if deep {
				result = applyFlagValidationIssues(result, flag.DeepCheck(local.Flags))
			}
			return finishFlagValidation(f, result, failOnWarnings)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Local feature flag file")
	cmd.Flags().StringVar(&dir, "dir", "", "Directory containing flags.json")
	cmd.Flags().BoolVar(&deep, "deep", false, "Run deep semantic checks")
	cmd.Flags().BoolVar(&failOnWarnings, "fail-on-warnings", false, "Exit non-zero when deep validation reports warnings")
	return cmd
}

func ensureFlagStore(backend cfgov.Backend) (cfgov.Backend, cfgov.FlagStore, error) {
	store, ok := backend.(cfgov.FlagStore)
	if !ok || !backend.Capabilities().SupportsFlags {
		return nil, nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support feature flags", nil)
	}
	return backend, store, nil
}

func readFlagSet(ctx context.Context, backend cfgov.Backend, store cfgov.FlagStore, app string) (flagSetResult, error) {
	coord, err := store.FlagCoordinate(app)
	if err != nil {
		return flagSetResult{}, err
	}
	blob, err := backend.Get(ctx, coord)
	if err != nil {
		if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
			return emptyFlagSet(app, coord), nil
		}
		return flagSetResult{}, err
	}
	flags, err := flag.DecodeSet(blob.Content)
	if err != nil {
		return flagSetResult{}, err
	}
	return flagSetResult{App: app, Count: len(flags), Key: coord.Key, Revision: blob.Revision, SHA256: sha256Bytes(blob.Content), Flags: flags}, nil
}

func emptyFlagSet(app string, coord cfgov.Coordinate) flagSetResult {
	return flagSetResult{App: app, Key: coord.Key, SHA256: sha256Bytes([]byte("[]")), Flags: []flag.FeatureFlag{}}
}

func readLocalFlagInput(file, dir string) (flagSetResult, error) {
	if (file == "") == (dir == "") {
		return flagSetResult{}, apperrors.New(apperrors.CodeUsageError, "specify exactly one of --file or --dir", nil)
	}
	path := file
	if dir != "" {
		info, err := os.Stat(dir)
		if err != nil {
			return flagSetResult{}, apperrors.New(apperrors.CodeLocalIOError, "failed to stat flag directory", err)
		}
		if !info.IsDir() {
			return flagSetResult{}, apperrors.New(apperrors.CodeUsageError, "--dir must be a directory", nil)
		}
		path = filepath.Join(dir, "flags.json")
	}
	content, err := os.ReadFile(path) //nolint:gosec // Operator supplied flag file or validation directory.
	if err != nil {
		return flagSetResult{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read flag file", err)
	}
	flags, err := flag.DecodeSet(content)
	if err != nil {
		return flagSetResult{}, err
	}
	return flagSetResult{Count: len(flags), SHA256: sha256Bytes(content), Flags: flags}, nil
}

func applyFlagValidationIssues(result flagValidationResult, issues []flag.Issue) flagValidationResult {
	result.Issues = issues
	result.Errors, result.Warnings = countFlagIssues(issues)
	result.Valid = result.Errors == 0
	return result
}

func finishFlagValidation(f *cliFlags, result flagValidationResult, failOnWarnings bool) error {
	if err := newPrinter(f).JSONData("FlagValidation", result); err != nil {
		return err
	}
	if result.Errors > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "deep flag validation failed", nil)
	}
	if failOnWarnings && result.Warnings > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "deep flag validation warnings found", nil)
	}
	return nil
}

func countFlagIssues(issues []flag.Issue) (int, int) {
	errorsCount := 0
	warningsCount := 0
	for _, issue := range issues {
		if issue.Severity == flag.SeverityError {
			errorsCount++
		} else {
			warningsCount++
		}
	}
	return errorsCount, warningsCount
}

func appendFlagAudit(f *cliFlags, ctxMeta cfgovctx.Context, verb, app, status, diff string, err error) {
	appendAuditWarn(f, audit.EventType("flag."+verb), ctxMeta, audit.EventTarget{ResourceType: "flag", Resource: app}, status, diff, err)
}

func filterFlagSetByKey(result flagSetResult, key string) flagSetResult {
	if key == "" {
		return result
	}
	filtered := make([]flag.FeatureFlag, 0, len(result.Flags))
	for _, item := range result.Flags {
		if item.Key == key {
			filtered = append(filtered, item)
		}
	}
	result.Flags = filtered
	result.Count = len(filtered)
	if data, err := json.Marshal(filtered); err == nil {
		result.SHA256 = sha256Bytes(data)
	}
	return result
}
