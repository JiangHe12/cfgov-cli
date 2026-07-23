package cmd

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Nacos revision fingerprints are MD5.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/cfgov-cli/internal/backup"
	"github.com/JiangHe12/cfgov-cli/internal/cfgclass"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

type configHistoryReadResult struct {
	Items []cfgov.HistoryItem
	Total int
}

type configBlobReadResult struct {
	Blob       cfgov.Blob
	Coordinate cfgov.Coordinate
	Key        string
}

type configContextDiffReadResult struct {
	Diff              diffResult
	TargetDescription cfgov.Description
}

const maxConfigListenEvents = 1_000

func newConfigCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Govern config blobs", Args: requireSubcommand, RunE: runParentHelp}
	cmd.AddCommand(
		configGetCmd(f),
		configListCmd(f),
		configDiffCmd(f),
		configValidateCmd(f),
		configPullCmd(f),
		configHistoryCmd(f),
		configListenCmd(f),
		configExportCmd(f),
		configImportCmd(f),
		configPromoteCmd(f),
		configRollbackCmd(f),
		configReconcileCmd(f),
		configPushCmd(f),
		configDeleteCmd(f),
	)
	return cmd
}

func configGetCmd(f *cliFlags) *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "get --key <key>",
		Short: "Read a config blob",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"config.get",
				"config",
				key,
				map[string]string{"key": key},
				func(backend cfgov.Backend, _ cfgovctx.Context) (configBlobReadResult, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return configBlobReadResult{}, keyErr
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					blob, getErr := backend.Get(cmd.Context(), coord)
					return configBlobReadResult{Blob: blob, Coordinate: coord, Key: normalizedKey}, getErr
				},
				func(configBlobReadResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			blob, coord, normalizedKey := readResult.Value.Blob, readResult.Value.Coordinate, readResult.Value.Key
			target := readResult.operationTarget()
			p := newPrinter(f)
			if f.Output == "plain" {
				if err := printOperationTarget(p, target, operationTargetRead); err != nil {
					return err
				}
				return p.Content(normalizedKey, string(blob.Content))
			}
			return targetJSONData(f, "ConfigItem", map[string]any{
				"namespace": coord.Namespace,
				"key":       normalizedKey,
				"revision":  blob.Revision,
				"sha256":    sha256Bytes(blob.Content),
				"content":   string(blob.Content),
			}, target, operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configListCmd(f *cliFlags) *cobra.Command {
	var group, query, prefix string
	var page, pageSize, limit int
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List config blobs",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"config.list",
				"config",
				firstNonEmpty(f.Namespace, "*"),
				map[string]any{"group": group, "query": query, "prefix": prefix, "page": page, "pageSize": pageSize, "limit": limit},
				func(backend cfgov.Backend, _ cfgovctx.Context) ([]cfgov.ListItem, error) {
					normalizedQuery := query
					if normalizedQuery != "" {
						var queryErr error
						normalizedQuery, queryErr = validateConfigKey(backend, normalizedQuery)
						if queryErr != nil {
							return nil, queryErr
						}
					}
					return backend.List(cmd.Context(), cfgov.ListOptions{
						Namespace: backend.Describe().Namespace,
						Group:     group,
						Query:     normalizedQuery,
						Prefix:    prefix,
						Page:      page,
						PageSize:  pageSize,
						Limit:     limit,
					})
				},
				func(items []cfgov.ListItem) int { return len(items) },
			)
			if err != nil {
				return err
			}
			items := readResult.Value
			target := readResult.operationTarget()
			p := newPrinter(f)
			if f.Output == "json" {
				return targetJSONList(f, "ConfigList", items, len(items), normalizedPage(page), normalizedPageSize(pageSize, len(items)), target)
			}
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.Coordinate.Namespace, item.Coordinate.Key, item.Revision, item.Type})
			}
			return p.Table([]string{"NAMESPACE", "KEY", "REVISION", "TYPE"}, rows)
		},
	}
	cmd.Flags().StringVarP(&group, "group", "g", "", "Nacos group filter")
	cmd.Flags().StringVarP(&query, "query", "q", "", "Exact key/dataId search")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Key prefix/search filter")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum items when paging is not used")
	return cmd
}

func configDiffCmd(f *cliFlags) *cobra.Command {
	var key, file, inlineContent, sourceContext, targetContext string
	cmd := &cobra.Command{
		Use:   "diff --key <key> (--file <path>|--content <string>)",
		Short: "Compare remote config with local content",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sourceContext != "" || targetContext != "" {
				return configContextDiff(cmd.Context(), f, key, sourceContext, targetContext)
			}
			local, err := readConfigInput(inlineContent, file)
			if err != nil {
				return err
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"config.diff",
				"config",
				key,
				map[string]any{
					"key":         key,
					"localSha256": sha256Bytes(local),
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (diffResult, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return diffResult{}, keyErr
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					remote, getErr := backend.Get(cmd.Context(), coord)
					if getErr != nil {
						return diffResult{}, getErr
					}
					result := diffSummary(remote.Content, local)
					if result.Same && isStrictNoChange(f) {
						return diffResult{}, apperrors.New(apperrors.CodeNoChangeRequired, "no changes detected", nil)
					}
					return result, nil
				},
				func(diffResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			summary := readResult.Value
			target := readResult.operationTarget()
			if f.Output == "plain" {
				p := newPrinter(f)
				if err := printOperationTarget(p, target, operationTargetRead); err != nil {
					return err
				}
				if err := p.Info(summary.Summary); err != nil {
					return err
				}
				for _, line := range summary.Lines {
					if err := p.Info(line); err != nil {
						return err
					}
				}
				return nil
			}
			return targetJSONData(f, "DiffResult", summary, target, operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Local file")
	cmd.Flags().StringVar(&inlineContent, "content", "", "Config content")
	cmd.Flags().StringVar(&sourceContext, "source-context", "", "Source context")
	cmd.Flags().StringVar(&targetContext, "target-context", "", "Target context")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configValidateCmd(f *cliFlags) *cobra.Command {
	var file, inlineContent, contentType string
	cmd := &cobra.Command{
		Use:   "validate (--file <path>|--content <string>)",
		Short: "Validate local config content",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			content, err := readConfigInput(inlineContent, file)
			if err != nil {
				return err
			}
			if contentType == "" {
				contentType = inferType(file)
			}
			err = validateContent(content, contentType)
			data := map[string]any{
				"file":   file,
				"source": configInputSource(inlineContent, file),
				"type":   contentType,
				"valid":  err == nil,
				"sha256": sha256Bytes(content),
				"bytes":  len(content),
			}
			if err != nil {
				data["error"] = err.Error()
				if f.Output == "json" {
					_ = newPrinter(f).JSONData("ValidationResult", data)
				}
				return err
			}
			return newPrinter(f).JSONData("ValidationResult", data)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "Local file")
	cmd.Flags().StringVar(&inlineContent, "content", "", "Config content")
	cmd.Flags().StringVar(&contentType, "type", "", "Config type: text, properties, json, yaml, xml")
	return cmd
}

func configPullCmd(f *cliFlags) *cobra.Command {
	var key, file string
	cmd := &cobra.Command{
		Use:   "pull --key <key> --file <path>",
		Short: "Pull a remote config into a local file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			readResult, err := runMandatoryBackendRead(
				f,
				"config.pull",
				"config",
				key,
				map[string]string{"key": key, "file": file},
				func(backend cfgov.Backend, _ cfgovctx.Context) (configBlobReadResult, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return configBlobReadResult{}, keyErr
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					blob, getErr := backend.Get(cmd.Context(), coord)
					return configBlobReadResult{Blob: blob, Coordinate: coord, Key: normalizedKey}, getErr
				},
				func(configBlobReadResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			ctxMeta := readResult.Context
			ctxName := readResult.ContextName
			blob, coord, normalizedKey := readResult.Value.Blob, readResult.Value.Coordinate, readResult.Value.Key
			target := readResult.operationTarget()
			if isPlanOnly(f) {
				markPreview(f)
				return targetJSONData(f, "ChangePlan", map[string]any{
					"resourceType": "file",
					"action":       "config pull",
					"file":         file,
					"key":          normalizedKey,
					"revision":     blob.Revision,
					"sha256":       sha256Bytes(blob.Content),
					"bytes":        len(blob.Content),
					"dryRun":       true,
				}, target, operationTargetRead)
			}
			mutation, err := beginMutationAudit(f, mutationAuditSpec{
				Action:      "config.pull",
				ContextName: ctxName,
				Context:     ctxMeta,
				Target:      audit.EventTarget{ResourceType: "file", Resource: file},
				Metadata: mutationAuditMetadata{
					PayloadFingerprint: mutationAuditFingerprint("payload:config.pull", blob.Content),
					PayloadBytes:       len(blob.Content),
					Revision:           blob.Revision,
					Items:              1,
					Creates:            1,
				},
			})
			if err != nil {
				return err
			}
			writeErr := writeLocalFile(file, blob.Content)
			if auditErr := finishMutationAudit(
				mutation,
				mutationAuditOutcome{Revision: blob.Revision},
				writeErr,
			); auditErr != nil {
				return auditErr
			}
			return targetJSONData(f, "ConfigItem", map[string]any{
				"namespace": coord.Namespace,
				"key":       normalizedKey,
				"file":      file,
				"revision":  blob.Revision,
				"sha256":    sha256Bytes(blob.Content),
			}, target, operationTargetRead)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Output file")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func configHistoryCmd(f *cliFlags) *cobra.Command {
	var key string
	var page, pageSize int
	cmd := &cobra.Command{
		Use:   "history --key <key>",
		Short: "Show config history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			options := cfgov.HistoryOptions{Page: page, PageSize: pageSize}
			readResult, err := runMandatoryBackendRead(
				f,
				"config.history",
				"config",
				key,
				map[string]any{"key": key, "options": options},
				func(backend cfgov.Backend, _ cfgovctx.Context) (configHistoryReadResult, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return configHistoryReadResult{}, keyErr
					}
					if !backend.Capabilities().SupportsHistory {
						return configHistoryReadResult{}, apperrors.New(apperrors.CodeNotImplemented, "backend does not support config history", nil)
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					items, total, historyErr := backend.History(cmd.Context(), coord, options)
					return configHistoryReadResult{Items: items, Total: total}, historyErr
				},
				func(result configHistoryReadResult) int { return len(result.Items) },
			)
			if err != nil {
				return err
			}
			items, total := readResult.Value.Items, readResult.Value.Total
			target := readResult.operationTarget()
			p := newPrinter(f)
			if f.Output == "json" {
				return targetJSONList(f, "HistoryList", items, total, normalizedPage(page), normalizedPageSize(pageSize, len(items)), target)
			}
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.ID, item.OpType, item.ModifiedTime, item.Operator, item.DataID, item.Group})
			}
			return p.Table([]string{"ID", "OP", "MODIFIED", "OPERATOR", "DATA ID", "GROUP"}, rows)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configListenCmd(f *cliFlags) *cobra.Command { //nolint:gocyclo // Cobra handler coordinates bounded listen state, output, and retry loop.
	var key string
	var maxEvents int
	var longPoll time.Duration
	cmd := &cobra.Command{
		Use:   "listen --key <key>",
		Short: "Watch one config with bounded long-polling",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if maxEvents <= 0 {
				return apperrors.New(apperrors.CodeUsageError, "--max-events must be greater than 0", nil)
			}
			if maxEvents > maxConfigListenEvents {
				return apperrors.New(
					apperrors.CodeUsageError,
					fmt.Sprintf("--max-events must not exceed %d", maxConfigListenEvents),
					nil,
				)
			}
			readResult, err := runMandatoryBackendRead(
				f,
				"config.listen",
				"config",
				key,
				map[string]any{
					"key":       key,
					"maxEvents": maxEvents,
					"longPoll":  longPoll.String(),
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) ([]cfgov.WatchEvent, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return nil, keyErr
					}
					if !backend.Capabilities().SupportsWatch {
						return nil, apperrors.New(apperrors.CodeNotImplemented, "backend does not support config listen", nil)
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					revision, revisionErr := backend.CurrentRevision(cmd.Context(), coord)
					if revisionErr != nil {
						return nil, revisionErr
					}
					events := make([]cfgov.WatchEvent, 0, maxEvents)
					const (
						listenBackoffStart = 2 * time.Second
						listenAbortAfter   = 20
					)
					backoff := listenBackoffStart
					consecutiveErrors := 0
					for len(events) < maxEvents {
						pollCtx, cancel := context.WithTimeout(cmd.Context(), longPoll+5*time.Second)
						event, watchErr := backend.Watch(pollCtx, coord, revision, cfgov.WatchOptions{LongPoll: longPoll})
						cancel()
						if watchErr != nil {
							nextBackoff, nextErrors, retryErr := handleListenPollError(
								cmd.Context(),
								f,
								watchErr,
								backoff,
								consecutiveErrors,
								listenAbortAfter,
							)
							backoff, consecutiveErrors = nextBackoff, nextErrors
							if retryErr != nil {
								return nil, retryErr
							}
							continue
						}
						consecutiveErrors = 0
						backoff = listenBackoffStart
						if !event.Changed {
							break
						}
						events = append(events, event)
						revision = event.Revision
					}
					return events, nil
				},
				func(events []cfgov.WatchEvent) int { return len(events) },
			)
			if err != nil {
				return err
			}
			events := readResult.Value
			target := readResult.operationTarget()
			if f.Output == "json" {
				return targetJSONList(f, "ConfigListenEvent", events, len(events), 1, len(events), target)
			}
			p := newPrinter(f)
			if err := printOperationTarget(p, target, operationTargetRead); err != nil {
				return err
			}
			for _, event := range events {
				if err := p.Info(fmt.Sprintf("changed %s revision=%s", event.Coordinate.Key, event.Revision)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().IntVar(&maxEvents, "max-events", 1, "Maximum change events before returning")
	cmd.Flags().DurationVar(&longPoll, "long-poll", 30*time.Second, "Long-poll duration")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func handleListenPollError(ctx context.Context, f *cliFlags, err error, backoff time.Duration, consecutiveErrors, abortAfter int) (time.Duration, int, error) {
	const (
		listenBackoffStart = 2 * time.Second
		listenBackoffMax   = 60 * time.Second
	)
	if ctx.Err() != nil {
		return backoff, consecutiveErrors, ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return listenBackoffStart, 0, nil
	}
	if apperrors.AsAppError(err).Code == apperrors.CodeAuthFailed {
		return backoff, consecutiveErrors, err
	}
	consecutiveErrors++
	_, _ = fmt.Fprintf(diagnosticWriter(f), "warning: listen poll failed (%d/%d), retrying in %s: %s\n", consecutiveErrors, abortAfter, backoff, redactedDiagnosticError(err))
	if consecutiveErrors >= abortAfter {
		return backoff, consecutiveErrors, apperrors.New(apperrors.CodeNetworkError, fmt.Sprintf("listen aborted after %d consecutive failures", consecutiveErrors), err)
	}
	timer := time.NewTimer(backoff)
	select {
	case <-ctx.Done():
		timer.Stop()
		return backoff, consecutiveErrors, ctx.Err()
	case <-timer.C:
	}
	if backoff < listenBackoffMax {
		backoff *= 2
		if backoff > listenBackoffMax {
			backoff = listenBackoffMax
		}
	}
	return backoff, consecutiveErrors, nil
}

func configPushCmd(f *cliFlags) *cobra.Command { //nolint:gocyclo // Cobra handler keeps config push safety, backup, dry-run, CAS, and strict-mode flow together.
	var key, file, inlineContent, contentType, expectedRevision string
	var noValidate, createOnly, updateOnly bool
	cmd := &cobra.Command{
		Use:   "push --key <key> (--file <path>|--content <string>)",
		Short: "Write a config blob",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if createOnly && updateOnly {
				return apperrors.New(apperrors.CodeUsageError, "--create-only and --update-only are mutually exclusive", nil)
			}
			content, err := readConfigInput(inlineContent, file)
			if err != nil {
				return err
			}
			if contentType == "" {
				contentType = inferType(firstNonEmpty(file, key))
			}
			contentType = normalizeType(contentType)
			if !noValidate {
				if err := validateContent(content, contentType); err != nil {
					return err
				}
			}
			class := cfgclass.Classify(cfgclass.OperationPush, content, contentType)
			backendRead, err := runMandatoryBackendRead(
				f,
				"config.push.preflight",
				"config",
				key,
				map[string]any{
					"key":              key,
					"contentSha256":    sha256Bytes(content),
					"contentBytes":     len(content),
					"contentType":      contentType,
					"expectedRevision": mutationAuditFingerprint("config.push.expected-revision", []byte(expectedRevision)),
					"createOnly":       createOnly,
					"updateOnly":       updateOnly,
				},
				func(backend cfgov.Backend, _ cfgovctx.Context) (configPushReadResult, error) {
					normalizedKey, keyErr := validateConfigKey(backend, key)
					if keyErr != nil {
						return configPushReadResult{}, keyErr
					}
					coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
					remote, exists, inspectErr := inspectConfigPushTarget(cmd.Context(), backend, coord)
					if inspectErr != nil {
						return configPushReadResult{}, inspectErr
					}
					plan := pushPlan(coord, content, class, remote.Revision)
					plan.CreateOnly = createOnly
					plan.UpdateOnly = updateOnly
					plan.TargetExists = &exists
					return configPushReadResult{
						Plan:       plan,
						Remote:     remote,
						Exists:     exists,
						Coordinate: coord,
						Key:        normalizedKey,
					}, nil
				},
				func(configPushReadResult) int { return 1 },
			)
			if err != nil {
				return err
			}
			backend, ctxMeta := backendRead.Backend, backendRead.Context
			ctxName := backendRead.ContextName
			plan, remote, exists := backendRead.Value.Plan, backendRead.Value.Remote, backendRead.Value.Exists
			coord, key := backendRead.Value.Coordinate, backendRead.Value.Key
			target := backendRead.operationTarget()
			if isPlanOnly(f) {
				markPreview(f)
				if err := validateConfigPushMode(createOnly, updateOnly, exists); err != nil {
					return err
				}
				appendAuditWarn(f, audit.EventType("config.write"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, audit.StatusSuccess, plan.Impact, nil)
				return targetJSONData(f, "ChangePlan", plan, target, operationTargetWrite)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			if err := validateConfigPushMode(createOnly, updateOnly, exists); err != nil {
				return err
			}
			req := cfgov.PutRequest{
				Coordinate:       coord,
				Content:          content,
				ContentType:      contentType,
				ExpectedRevision: expectedRevision,
				RequireAbsent:    createOnly,
			}
			if err := validateConfigPutPreconditions(backend.Capabilities(), req); err != nil {
				return err
			}
			if err := authorizeForContext(f, class.Risk, ctxMeta, "", ctxName); err != nil {
				return err
			}
			if done, err := finishIdempotentConfigPush(f, ctxMeta, coord, content, plan, remote, exists); done || err != nil {
				return err
			}
			metadata := mutationPayloadMetadata("config.write", content)
			metadata.Revision = expectedRevision
			metadata.Items = 1
			if exists {
				metadata.Updates = 1
			} else {
				metadata.Creates = 1
			}
			mutation, err := beginMutationAudit(f, mutationAuditSpec{
				Action:      "config.write",
				ContextName: ctxName,
				Context:     ctxMeta,
				Target:      audit.EventTarget{ResourceType: "config", Resource: key},
				Metadata:    metadata,
			})
			if err != nil {
				return err
			}
			backupResult, err := maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord)
			if err != nil {
				return finishMutationAudit(mutation, mutationAuditOutcome{}, err)
			}
			blob, err := backend.Put(cmd.Context(), req)
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.write"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, plan.Impact, err)
			if auditErr := finishMutationAudit(
				mutation,
				mutationAuditOutcome{Revision: blob.Revision},
				err,
			); auditErr != nil {
				return auditErr
			}
			return targetJSONData(f, "ChangeResult", map[string]any{
				"resourceType": "config",
				"namespace":    coord.Namespace,
				"key":          key,
				"revision":     blob.Revision,
				"risk":         class.Risk,
				"backup":       backupResult,
			}, target, operationTargetWrite)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVarP(&file, "file", "f", "", "Config file to push")
	cmd.Flags().StringVar(&inlineContent, "content", "", "Config content")
	cmd.Flags().StringVar(&contentType, "type", "", "Config type: text, properties, json, yaml, xml")
	cmd.Flags().StringVar(&expectedRevision, "expected-revision", "", "CAS revision precondition")
	cmd.Flags().BoolVar(&noValidate, "no-validate", false, "Skip local content format validation")
	cmd.Flags().BoolVar(&createOnly, "create-only", false, "Fail if the target config already exists")
	cmd.Flags().BoolVar(&updateOnly, "update-only", false, "Fail if the target config does not exist")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configDeleteCmd(f *cliFlags) *cobra.Command {
	var key, expectedRevision string
	cmd := &cobra.Command{
		Use:     "delete --key <key>",
		Aliases: []string{"del", "rm"},
		Short:   "Delete a config blob",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key = strings.TrimSpace(key)
			if key == "" {
				return apperrors.New(apperrors.CodeValidationFailed, "config key is required", nil)
			}
			ctxMeta, ctxName, err := resolvedContext(f)
			if err != nil {
				return err
			}
			target := operationTargetFromResolvedContext(f, ctxMeta, ctxName)
			class := cfgclass.Classify(cfgclass.OperationDelete, nil, "")
			if isPlanOnly(f) {
				markPreview(f)
				plan := map[string]any{"resourceType": "config", "key": key, "baseRisk": class.Risk, "impact": "delete one config blob"}
				return targetJSONData(f, "ChangePlan", plan, target, operationTargetWrite)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			var (
				coord        cfgov.Coordinate
				backupResult *backup.Result
			)
			execution, err := runAuthorizedBackendMutation(f, ctxMeta, ctxName, safety.R2, allowProductionConfigDelete, mutationAuditSpec{
				Action: "config.delete",
				Target: audit.EventTarget{ResourceType: "config", Resource: key},
				Metadata: mutationAuditMetadata{
					Revision: expectedRevision,
					Items:    1,
					Deletes:  1,
				},
			}, func(backend cfgov.Backend, _ cfgovctx.Context) error {
				normalizedKey, keyErr := validateConfigKey(backend, key)
				if keyErr != nil {
					return keyErr
				}
				key = normalizedKey
				coord = cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: normalizedKey}
				backupResult, keyErr = maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord)
				if keyErr != nil {
					return keyErr
				}
				operationErr := backend.Delete(cmd.Context(), cfgov.DeleteRequest{Coordinate: coord, ExpectedRevision: expectedRevision})
				appendAuditWarn(f, audit.EventType("config.delete"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, auditStatus(operationErr), "delete one config blob", operationErr)
				return operationErr
			})
			if err != nil {
				return err
			}
			return targetJSONData(
				f,
				"ChangeResult",
				map[string]any{"resourceType": "config", "namespace": coord.Namespace, "key": key, "deleted": true, "backup": backupResult},
				operationTargetFromDescription(execution.ContextName, execution.Backend.Describe()),
				operationTargetWrite,
			)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVar(&expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

type changePlan struct {
	ResourceType string           `json:"resourceType"`
	Coordinate   cfgov.Coordinate `json:"coordinate"`
	BaseRisk     safety.Risk      `json:"baseRisk"`
	Reason       string           `json:"reason"`
	Impact       string           `json:"impact"`
	SHA256       string           `json:"sha256"`
	Bytes        int              `json:"bytes"`
	CreateOnly   bool             `json:"createOnly,omitempty"`
	UpdateOnly   bool             `json:"updateOnly,omitempty"`
	TargetExists *bool            `json:"targetExists,omitempty"`
}

type configPushReadResult struct {
	Plan       changePlan
	Remote     cfgov.Blob
	Exists     bool
	Coordinate cfgov.Coordinate
	Key        string
}

type diffResult struct {
	Same         bool        `json:"same"`
	Summary      string      `json:"summary"`
	RemoteSHA256 string      `json:"remoteSha256"`
	LocalSHA256  string      `json:"localSha256"`
	RemoteBytes  int         `json:"remoteBytes"`
	LocalBytes   int         `json:"localBytes"`
	AddedLines   int         `json:"addedLines"`
	RemovedLines int         `json:"removedLines"`
	Lines        []string    `json:"lines"`
	Source       *diffTarget `json:"source,omitempty"`
	Target       *diffTarget `json:"target,omitempty"`
}

type diffTarget struct {
	Context   string `json:"context"`
	Backend   string `json:"backend"`
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
}

func pushPlan(coord cfgov.Coordinate, content []byte, class cfgclass.Result, before string) changePlan {
	hash := sha256Bytes(content)
	impact := fmt.Sprintf("write one config blob; bytes=%d; currentRevision=%s; targetSha256=%s", len(content), before, hash)
	if before == md5Like(content) {
		impact = "no content change detected by revision fingerprint"
	}
	return changePlan{
		ResourceType: "config",
		Coordinate:   coord,
		BaseRisk:     class.Risk,
		Reason:       class.Reason,
		Impact:       impact,
		SHA256:       hash,
		Bytes:        len(bytes.TrimRight(content, "\n")),
	}
}

func inspectConfigPushTarget(ctx context.Context, backend cfgov.Backend, coord cfgov.Coordinate) (cfgov.Blob, bool, error) {
	remote, err := backend.Get(ctx, coord)
	if err != nil {
		if apperrors.AsAppError(err).Code == apperrors.CodeResourceNotFound {
			return cfgov.Blob{}, false, nil
		}
		return cfgov.Blob{}, false, err
	}
	return remote, true, nil
}

func validateConfigPushMode(createOnly, updateOnly, exists bool) error {
	if createOnly && exists {
		return apperrors.New(apperrors.CodeResourceAlreadyExists, "config already exists", nil)
	}
	if updateOnly && !exists {
		return apperrors.New(apperrors.CodeResourceNotFound, "config does not exist", nil)
	}
	return nil
}

func validateConfigPutPreconditions(capabilities cfgov.Capabilities, req cfgov.PutRequest) error {
	if err := req.ValidatePreconditions(); err != nil {
		return err
	}
	if (req.RequireAbsent || req.ExpectedRevision != "") && !capabilities.SupportsCAS {
		return apperrors.New(apperrors.CodeNotImplemented, "backend does not support atomic config preconditions", nil)
	}
	return nil
}

func handleIdempotentConfigPush(f *cliFlags, meta cfgovctx.Context, coord cfgov.Coordinate, content []byte, plan changePlan, remote cfgov.Blob, exists bool) bool {
	if !exists {
		return false
	}
	if sha256Bytes(remote.Content) != sha256Bytes(content) {
		return false
	}
	appendAuditWarn(
		f,
		audit.EventType("config.write"),
		meta,
		audit.EventTarget{ResourceType: "config", Resource: coord.Key},
		auditStatusSkipped,
		plan.Impact,
		nil,
	)
	return true
}

func finishIdempotentConfigPush(f *cliFlags, meta cfgovctx.Context, coord cfgov.Coordinate, content []byte, plan changePlan, remote cfgov.Blob, exists bool) (bool, error) {
	skipped := handleIdempotentConfigPush(f, meta, coord, content, plan, remote, exists)
	if !skipped {
		return false, nil
	}
	if isStrictNoChange(f) {
		return true, apperrors.New(apperrors.CodeNoChangeRequired, "config already matches remote", nil)
	}
	return true, targetJSONData(f, "ChangeResult", map[string]any{
		"resourceType": "config",
		"namespace":    coord.Namespace,
		"key":          coord.Key,
		"skipped":      true,
		"reason":       "idempotent",
	}, operationTargetFromContext(f, meta), operationTargetWrite)
}

func validateBackupPolicy(f *cliFlags, meta cfgovctx.Context) error {
	if f.Backup && f.NoBackup {
		return apperrors.New(apperrors.CodeUsageError, "--backup and --no-backup are mutually exclusive", nil)
	}
	if meta.Protected && !f.Backup && !f.NoBackup {
		return apperrors.New(apperrors.CodeUsageError, "protected context writes require explicit --backup or --no-backup", nil)
	}
	return safety.ValidateBackupPolicy(f.NonInter, f.Backup, f.NoBackup, meta.Protected)
}

func maybeBackupConfig(ctx context.Context, f *cliFlags, backend cfgov.Backend, meta cfgovctx.Context, coord cfgov.Coordinate) (*backup.Result, error) {
	if !f.Backup || f.NoBackup {
		return nil, nil
	}
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
	group, dataID, err := backupIdentity(backend, coord.Key)
	if err != nil {
		return nil, err
	}
	result, err := backup.Write(root, backup.Request{
		Context:   f.contextName(),
		Namespace: namespaceOrPublic(coord.Namespace),
		Group:     group,
		DataID:    dataID,
		Content:   blob.Content,
		Operator:  currentOperator(f),
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to write backup", err)
	}
	appendAuditWarn(
		f,
		audit.EventType("backup.create"),
		meta,
		audit.EventTarget{ResourceType: "backup", Resource: result.BackupID},
		audit.StatusSuccess,
		"backup current config sha256="+result.SHA256,
		nil,
	)
	return &result, nil
}

func backupRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve home directory", err)
	}
	return filepath.Join(home, ".cfgov-cli", "backups"), nil
}

func validateContent(content []byte, contentType string) error {
	switch normalizeType(contentType) {
	case "text":
		if bytes.Contains(content, []byte{0}) {
			return apperrors.New(apperrors.CodeValidationFailed, "text config contains NUL bytes", nil)
		}
	case "properties":
		return validateProperties(content)
	case "json":
		if err := cfgclass.ValidateStructured(content, "json"); err != nil {
			return apperrors.New(apperrors.CodeValidationFailed, "invalid json config", err)
		}
	case "yaml":
		if err := cfgclass.ValidateStructured(content, "yaml"); err != nil {
			return apperrors.New(apperrors.CodeValidationFailed, "invalid yaml config", err)
		}
	case "xml":
		if err := cfgclass.ValidateStructured(content, "xml"); err != nil {
			return apperrors.New(apperrors.CodeValidationFailed, "invalid xml config", err)
		}
	default:
		return apperrors.New(apperrors.CodeValidationFailed, "unsupported config type", nil)
	}
	return nil
}

func validateProperties(content []byte) error {
	for i, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.ContainsAny(line, "=:") {
			continue
		}
		return apperrors.New(apperrors.CodeValidationFailed, fmt.Sprintf("invalid properties line %d", i+1), nil)
	}
	return nil
}

func inferType(file string) string {
	lower := strings.ToLower(file)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		return "yaml"
	case strings.HasSuffix(lower, ".properties"):
		return "properties"
	case strings.HasSuffix(lower, ".xml"):
		return "xml"
	default:
		return "text"
	}
}

func normalizeType(contentType string) string {
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "", "txt", "text":
		return "text"
	case "props", "properties":
		return "properties"
	case "json":
		return "json"
	case "yaml", "yml":
		return "yaml"
	case "xml":
		return "xml"
	default:
		return strings.ToLower(strings.TrimSpace(contentType))
	}
}

func readConfigInput(content, file string) ([]byte, error) {
	if content != "" && file != "" {
		return nil, apperrors.New(apperrors.CodeUsageError, "--content and --file are mutually exclusive", nil)
	}
	if content == "" && file == "" {
		return nil, apperrors.New(apperrors.CodeUsageError, "specify --content or --file", nil)
	}
	if file == "" {
		return []byte(content), nil
	}
	data, err := os.ReadFile(file) //nolint:gosec // Operator supplied path.
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read local file", err)
	}
	return data, nil
}

func configInputSource(content, file string) string {
	if file != "" {
		return "file"
	}
	if content != "" {
		return "content"
	}
	return ""
}

func validateConfigKey(backend cfgov.Backend, key string) (string, error) {
	key = strings.TrimSpace(key)
	if err := backend.ValidateKey(key); err != nil {
		return "", err
	}
	return key, nil
}

func backupIdentity(backend cfgov.Backend, key string) (string, string, error) {
	if backend.Describe().Backend == "nacos" {
		parsed, err := cfgov.ParseNacosKey(key)
		if err != nil {
			return "", "", err
		}
		return parsed.Group, parsed.DataID, nil
	}
	if err := backend.ValidateKey(key); err != nil {
		return "", "", err
	}
	return backend.Describe().Backend, key, nil
}

func diffSummary(remote, local []byte) diffResult {
	remoteHash := sha256Bytes(remote)
	localHash := sha256Bytes(local)
	added, removed := lineDelta(remote, local)
	same := remoteHash == localHash
	summary := fmt.Sprintf("remoteSha256=%s localSha256=%s addedLines=%d removedLines=%d", remoteHash, localHash, added, removed)
	if same {
		summary = "remote and local content are identical"
	}
	return diffResult{
		Same:         same,
		Summary:      summary,
		RemoteSHA256: remoteHash,
		LocalSHA256:  localHash,
		RemoteBytes:  len(remote),
		LocalBytes:   len(local),
		AddedLines:   added,
		RemovedLines: removed,
		Lines:        buildLineDiff(remote, local),
	}
}

func configContextDiff(ctx context.Context, f *cliFlags, key, sourceContext, targetContext string) error { //nolint:gocyclo // Validation, two reads, audit, and output errors are one command flow.
	if sourceContext == "" || targetContext == "" {
		return apperrors.New(apperrors.CodeUsageError, "--source-context and --target-context must both be specified", nil)
	}
	if key == "" {
		return apperrors.New(apperrors.CodeUsageError, "--key is required", nil)
	}
	sourceMeta, err := loadNamedContext(sourceContext)
	if err != nil {
		return err
	}
	targetMeta, err := loadNamedContext(targetContext)
	if err != nil {
		return err
	}
	spec := newReadAuditSpec(
		"config.diff",
		targetMeta,
		"config",
		sourceContext+"\x00"+targetContext+"\x00"+key,
		map[string]any{
			"sourceContext": sourceContext,
			"targetContext": targetContext,
			"key":           key,
		},
	)
	spec.ContextName = targetContext
	spec.Authorize = []readAuditAuthorization{
		{ContextName: sourceContext, Context: sourceMeta},
		{ContextName: targetContext, Context: targetMeta},
	}
	readResult, err := runMandatoryRead(
		f,
		spec,
		func() (configContextDiffReadResult, error) {
			source, sourceBuildErr := buildBackendFromNamedContext(ctx, f, sourceContext, sourceMeta)
			if sourceBuildErr != nil {
				return configContextDiffReadResult{}, sourceBuildErr
			}
			target, targetBuildErr := buildBackendFromNamedContext(ctx, f, targetContext, targetMeta)
			if targetBuildErr != nil {
				return configContextDiffReadResult{}, targetBuildErr
			}
			sourceKey, sourceKeyErr := validateConfigKey(source, key)
			if sourceKeyErr != nil {
				return configContextDiffReadResult{}, sourceKeyErr
			}
			targetKey, targetKeyErr := validateConfigKey(target, key)
			if targetKeyErr != nil {
				return configContextDiffReadResult{}, targetKeyErr
			}
			sourceCoord := cfgov.Coordinate{Namespace: source.Describe().Namespace, Key: sourceKey}
			targetCoord := cfgov.Coordinate{Namespace: target.Describe().Namespace, Key: targetKey}
			sourceBlob, sourceErr := source.Get(ctx, sourceCoord)
			if sourceErr != nil {
				return configContextDiffReadResult{}, sourceErr
			}
			targetBlob, targetErr := target.Get(ctx, targetCoord)
			if targetErr != nil {
				return configContextDiffReadResult{}, targetErr
			}
			result := diffSummary(targetBlob.Content, sourceBlob.Content)
			if result.Same && isStrictNoChange(f) {
				return configContextDiffReadResult{}, apperrors.New(apperrors.CodeNoChangeRequired, "no changes detected", nil)
			}
			result.Source = diffTargetFor(sourceContext, source.Describe(), sourceKey, sourceBlob.Content)
			result.Target = diffTargetFor(targetContext, target.Describe(), targetKey, targetBlob.Content)
			return configContextDiffReadResult{Diff: result, TargetDescription: target.Describe()}, nil
		},
		func(configContextDiffReadResult) int { return 2 },
	)
	if err != nil {
		return err
	}
	result := readResult.Diff
	operationTarget := operationTargetFromDescription(targetContext, readResult.TargetDescription)
	if f.Output == "plain" {
		p := newPrinter(f)
		if err := printOperationTarget(p, operationTarget, operationTargetRead); err != nil {
			return err
		}
		if err := p.Info(result.Summary); err != nil {
			return err
		}
		for _, line := range result.Lines {
			if err := p.Info(line); err != nil {
				return err
			}
		}
		return nil
	}
	return targetJSONData(f, "DiffResult", result, operationTarget, operationTargetRead)
}

func diffTargetFor(contextName string, desc cfgov.Description, key string, content []byte) *diffTarget {
	return &diffTarget{
		Context:   contextName,
		Backend:   desc.Backend,
		Namespace: desc.Namespace,
		Key:       key,
		SHA256:    sha256Bytes(content),
		Bytes:     len(content),
	}
}

func buildLineDiff(remote, local []byte) []string {
	remoteLines := strings.Split(strings.ReplaceAll(string(remote), "\r\n", "\n"), "\n")
	localLines := strings.Split(strings.ReplaceAll(string(local), "\r\n", "\n"), "\n")
	const maxDiffLines = 1000
	if len(remoteLines) > maxDiffLines || len(localLines) > maxDiffLines {
		return []string{fmt.Sprintf("diff too large to display (%d remote lines, %d local lines; limit %d)", len(remoteLines), len(localLines), maxDiffLines)}
	}
	lcs := make([][]int, len(remoteLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(localLines)+1)
	}
	for i := len(remoteLines) - 1; i >= 0; i-- {
		for j := len(localLines) - 1; j >= 0; j-- {
			if remoteLines[i] == localLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	lines := make([]string, 0)
	i, j := 0, 0
	for i < len(remoteLines) && j < len(localLines) {
		if remoteLines[i] == localLines[j] {
			lines = append(lines, "  "+remoteLines[i])
			i++
			j++
			continue
		}
		if lcs[i+1][j] >= lcs[i][j+1] {
			lines = append(lines, "- "+remoteLines[i])
			i++
		} else {
			lines = append(lines, "+ "+localLines[j])
			j++
		}
	}
	for ; i < len(remoteLines); i++ {
		lines = append(lines, "- "+remoteLines[i])
	}
	for ; j < len(localLines); j++ {
		lines = append(lines, "+ "+localLines[j])
	}
	return lines
}

func lineDelta(remote, local []byte) (int, int) {
	remoteLines := splitLines(remote)
	localLines := splitLines(local)
	counts := make(map[string]int, len(remoteLines))
	for _, line := range remoteLines {
		counts[line]++
	}
	added := 0
	for _, line := range localLines {
		if counts[line] > 0 {
			counts[line]--
			continue
		}
		added++
	}
	removed := 0
	for _, n := range counts {
		removed += n
	}
	return added, removed
}

func splitLines(content []byte) []string {
	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	normalized = strings.TrimSuffix(normalized, "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}

func writeLocalFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create output directory", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write output file", err)
	}
	return nil
}

func registerExportFileName(seen map[string]string, name string) error {
	clean := filepath.Clean(name)
	if name == "" ||
		filepath.IsAbs(clean) ||
		clean == "." ||
		clean == ".." ||
		filepath.Base(clean) != clean ||
		clean != name {
		return apperrors.New(apperrors.CodeValidationFailed, "export contains an unsafe file name", nil)
	}
	canonical := strings.ToLower(clean)
	if previous, exists := seen[canonical]; exists {
		return apperrors.New(
			apperrors.CodeConflict,
			fmt.Sprintf("export file name collision between %q and %q", previous, name),
			nil,
		)
	}
	seen[canonical] = name
	return nil
}

func preflightNewLocalFiles(dir string, names []string) error {
	seen := make(map[string]string, len(names))
	for _, name := range names {
		if err := registerExportFileName(seen, name); err != nil {
			return err
		}
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil {
			return apperrors.New(apperrors.CodeResourceAlreadyExists, "export target already exists: "+path, nil)
		} else if !os.IsNotExist(err) {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect export target", err)
		}
	}
	return nil
}

func writeNewLocalFile(path string, content []byte) (retErr error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create output directory", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // The operator-selected export target is preflighted and O_EXCL prevents overwrite races.
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return apperrors.New(apperrors.CodeResourceAlreadyExists, "export target already exists: "+path, nil)
		}
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create export target", err)
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	written, err := file.Write(content)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write export target", err)
	}
	if written != len(content) {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write export target", io.ErrShortWrite)
	}
	if err := file.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close export target", err)
	}
	removeOnError = false
	return nil
}

func normalizedPage(page int) int {
	if page <= 0 {
		return 1
	}
	return page
}

func normalizedPageSize(pageSize, fallback int) int {
	if pageSize > 0 {
		return pageSize
	}
	if fallback > 0 {
		return fallback
	}
	return 20
}

func namespaceOrPublic(namespace string) string {
	if namespace == "" {
		return "public"
	}
	return namespace
}

func sha256Bytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func md5Like(content []byte) string {
	sum := md5.Sum(content) // #nosec G401 -- Nacos revision compatibility fingerprint, not cryptography.
	return hex.EncodeToString(sum[:])
}
