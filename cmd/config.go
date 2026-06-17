package cmd

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Nacos revision fingerprints are MD5.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/backup"
	"github.com/JiangHe12/cfgov-cli/internal/cfgclass"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
	"github.com/JiangHe12/cfgov-cli/internal/cfgovctx"
)

func newConfigCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Govern config blobs"}
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
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			blob, err := backend.Get(cmd.Context(), coord)
			appendReadAudit(f, ctxMeta, key, err)
			if err != nil {
				return err
			}
			p := newPrinter(f)
			if f.Output == "plain" {
				p.Content(key, string(blob.Content))
				return nil
			}
			return p.JSONData("ConfigItem", map[string]any{
				"namespace": coord.Namespace,
				"key":       key,
				"revision":  blob.Revision,
				"sha256":    sha256Bytes(blob.Content),
				"content":   string(blob.Content),
			})
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
		Use:   "list",
		Short: "List config blobs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			if query != "" {
				query, err = validateConfigKey(backend, query)
				if err != nil {
					return err
				}
			}
			items, err := backend.List(cmd.Context(), cfgov.ListOptions{
				Namespace: backend.Describe().Namespace,
				Group:     group,
				Query:     query,
				Prefix:    prefix,
				Page:      page,
				PageSize:  pageSize,
				Limit:     limit,
			})
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.list"), ctxMeta, audit.EventTarget{ResourceType: "config"}, status, "", err)
			if err != nil {
				return err
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("ConfigList", items, len(items), normalizedPage(page), normalizedPageSize(pageSize, len(items)), false)
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.Coordinate.Namespace, item.Coordinate.Key, item.Revision, item.Type})
			}
			p.Table([]string{"NAMESPACE", "KEY", "REVISION", "TYPE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "Nacos group filter")
	cmd.Flags().StringVarP(&query, "query", "q", "", "Exact key/dataId search")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Key prefix/search filter")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum items when paging is not used")
	return cmd
}

func configDiffCmd(f *cliFlags) *cobra.Command {
	var key, file, inlineContent string
	cmd := &cobra.Command{
		Use:   "diff --key <key> (--file <path>|--content <string>)",
		Short: "Compare remote config with local content",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			local, err := readConfigInput(inlineContent, file)
			if err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			remote, err := backend.Get(cmd.Context(), coord)
			appendReadAudit(f, ctxMeta, key, err)
			if err != nil {
				return err
			}
			summary := diffSummary(remote.Content, local)
			if f.Output == "plain" {
				newPrinter(f).Info(summary.Summary)
				return nil
			}
			return newPrinter(f).JSONData("DiffResult", summary)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVar(&file, "file", "", "Local file")
	cmd.Flags().StringVar(&inlineContent, "content", "", "Config content")
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
	cmd.Flags().StringVar(&file, "file", "", "Local file")
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
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			blob, err := backend.Get(cmd.Context(), coord)
			appendReadAudit(f, ctxMeta, key, err)
			if err != nil {
				return err
			}
			if err := writeLocalFile(file, blob.Content); err != nil {
				return err
			}
			return newPrinter(f).JSONData("ConfigItem", map[string]any{
				"namespace": coord.Namespace,
				"key":       key,
				"file":      file,
				"revision":  blob.Revision,
				"sha256":    sha256Bytes(blob.Content),
			})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVar(&file, "file", "", "Output file")
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
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			if !backend.Capabilities().SupportsHistory {
				return apperrors.New(apperrors.CodeNotImplemented, "backend does not support config history", nil)
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			items, total, err := backend.History(cmd.Context(), coord, cfgov.HistoryOptions{Page: page, PageSize: pageSize})
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.history"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, "", err)
			if err != nil {
				return err
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("HistoryList", items, total, normalizedPage(page), normalizedPageSize(pageSize, len(items)), false)
			}
			rows := make([][]string, 0, len(items))
			for _, item := range items {
				rows = append(rows, []string{item.ID, item.OpType, item.ModifiedTime, item.Operator, item.DataID, item.Group})
			}
			p.Table([]string{"ID", "OP", "MODIFIED", "OPERATOR", "DATA ID", "GROUP"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configListenCmd(f *cliFlags) *cobra.Command {
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
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			if !backend.Capabilities().SupportsWatch {
				return apperrors.New(apperrors.CodeNotImplemented, "backend does not support config listen", nil)
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			revision, err := backend.CurrentRevision(cmd.Context(), coord)
			appendReadAudit(f, ctxMeta, key, err)
			if err != nil {
				return err
			}
			events := make([]cfgov.WatchEvent, 0, maxEvents)
			for len(events) < maxEvents {
				pollCtx, cancel := context.WithTimeout(cmd.Context(), longPoll+5*time.Second)
				event, err := backend.Watch(pollCtx, coord, revision, cfgov.WatchOptions{LongPoll: longPoll})
				cancel()
				if err != nil {
					return err
				}
				if !event.Changed {
					break
				}
				events = append(events, event)
				revision = event.Revision
			}
			if f.Output == "json" {
				return newPrinter(f).JSONList("ConfigListenEvent", events, len(events), 1, len(events), false)
			}
			for _, event := range events {
				newPrinter(f).Info(fmt.Sprintf("changed %s revision=%s", event.Coordinate.Key, event.Revision))
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

func configPushCmd(f *cliFlags) *cobra.Command {
	var key, file, inlineContent, contentType, expectedRevision string
	var noValidate bool
	cmd := &cobra.Command{
		Use:   "push --key <key> (--file <path>|--content <string>)",
		Short: "Write a config blob",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
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
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			plan := pushPlan(cmd.Context(), backend, coord, content, class)
			if f.DryRun {
				appendAuditWarn(f, audit.EventType("config.write"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, audit.StatusSuccess, plan.Impact, nil)
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			if err := authorize(f, class.Risk, ctxMeta, ""); err != nil {
				return err
			}
			backupResult, err := maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord)
			if err != nil {
				return err
			}
			req := cfgov.PutRequest{Coordinate: coord, Content: content, ContentType: contentType, ExpectedRevision: expectedRevision}
			blob, err := backend.Put(cmd.Context(), req)
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.write"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, plan.Impact, err)
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{
				"resourceType": "config",
				"namespace":    coord.Namespace,
				"key":          key,
				"revision":     blob.Revision,
				"risk":         class.Risk,
				"backup":       backupResult,
			})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVar(&file, "file", "", "Config file to push")
	cmd.Flags().StringVar(&inlineContent, "content", "", "Config content")
	cmd.Flags().StringVar(&contentType, "type", "", "Config type: text, properties, json, yaml, xml")
	cmd.Flags().StringVar(&expectedRevision, "expected-revision", "", "CAS revision precondition")
	cmd.Flags().BoolVar(&noValidate, "no-validate", false, "Skip local content format validation")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configDeleteCmd(f *cliFlags) *cobra.Command {
	var key, expectedRevision string
	cmd := &cobra.Command{
		Use:   "delete --key <key>",
		Short: "Delete a config blob",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			key, err = validateConfigKey(backend, key)
			if err != nil {
				return err
			}
			class := cfgclass.Classify(cfgclass.OperationDelete, nil, "")
			if f.DryRun {
				plan := map[string]any{"resourceType": "config", "key": key, "baseRisk": class.Risk, "impact": "delete one config blob"}
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := validateBackupPolicy(f, ctxMeta); err != nil {
				return err
			}
			if err := authorize(f, safety.R2, ctxMeta, allowProductionConfigDelete); err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			backupResult, err := maybeBackupConfig(cmd.Context(), f, backend, ctxMeta, coord)
			if err != nil {
				return err
			}
			err = backend.Delete(cmd.Context(), cfgov.DeleteRequest{Coordinate: coord, ExpectedRevision: expectedRevision})
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.delete"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, "delete one config blob", err)
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"resourceType": "config", "namespace": coord.Namespace, "key": key, "deleted": true, "backup": backupResult})
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
}

type diffResult struct {
	Same         bool   `json:"same"`
	Summary      string `json:"summary"`
	RemoteSHA256 string `json:"remoteSha256"`
	LocalSHA256  string `json:"localSha256"`
	RemoteBytes  int    `json:"remoteBytes"`
	LocalBytes   int    `json:"localBytes"`
	AddedLines   int    `json:"addedLines"`
	RemovedLines int    `json:"removedLines"`
}

func pushPlan(ctx context.Context, backend cfgov.Backend, coord cfgov.Coordinate, content []byte, class cfgclass.Result) changePlan {
	before, _ := backend.CurrentRevision(ctx, coord)
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

func appendReadAudit(f *cliFlags, ctxMeta cfgovctx.Context, key string, err error) {
	status := audit.StatusSuccess
	if err != nil {
		status = audit.StatusFailed
	}
	appendAuditWarn(f, audit.EventType("config.read"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, "", err)
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
		var v any
		if err := json.Unmarshal(content, &v); err != nil {
			return apperrors.New(apperrors.CodeValidationFailed, "invalid json config", err)
		}
	case "yaml":
		var v any
		if err := yaml.Unmarshal(content, &v); err != nil {
			return apperrors.New(apperrors.CodeValidationFailed, "invalid yaml config", err)
		}
	case "xml":
		if err := validateXML(content); err != nil {
			return err
		}
	default:
		return apperrors.New(apperrors.CodeValidationFailed, "unsupported config type", nil)
	}
	return nil
}

func validateXML(content []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	seenRoot := false
	depth := 0
	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return apperrors.New(apperrors.CodeValidationFailed, "invalid xml config", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if seenRoot {
					return apperrors.New(apperrors.CodeValidationFailed, "invalid xml config", nil)
				}
				seenRoot = true
			}
			depth++
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		}
	}
	if !seenRoot {
		return apperrors.New(apperrors.CodeValidationFailed, "invalid xml config", nil)
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
	}
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
