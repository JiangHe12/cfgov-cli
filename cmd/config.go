package cmd

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Nacos revision fingerprints are MD5.
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/cfgov-cli/internal/cfgclass"
	"github.com/JiangHe12/cfgov-cli/internal/cfgov"
)

func newConfigCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Govern config blobs"}
	cmd.AddCommand(configGetCmd(f), configPushCmd(f), configDeleteCmd(f))
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
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			blob, err := backend.Get(cmd.Context(), coord)
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.read"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, "", err)
			if err != nil {
				return err
			}
			data := map[string]any{
				"namespace": coord.Namespace,
				"key":       key,
				"revision":  blob.Revision,
				"content":   string(blob.Content),
			}
			p := newPrinter(f)
			if f.Output == "plain" {
				p.Content(key, string(blob.Content))
				return nil
			}
			return p.JSONData("ConfigItem", data)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func configPushCmd(f *cliFlags) *cobra.Command {
	var key, file, contentType, expectedRevision string
	cmd := &cobra.Command{
		Use:   "push --key <key> --file <path>",
		Short: "Write a config blob",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			content, err := os.ReadFile(file) //nolint:gosec // CLI reads the operator-specified config file.
			if err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to read config file", err)
			}
			class := cfgclass.Classify(cfgclass.OperationPush, content, contentType)
			backend, ctxMeta, err := buildBackend(f)
			if err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			plan := pushPlan(cmd.Context(), backend, coord, content, class)
			if f.DryRun {
				appendAuditWarn(f, audit.EventType("config.write"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, audit.StatusSuccess, plan.Impact, nil)
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := authorize(f, class.Risk, ctxMeta, ""); err != nil {
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
			})
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Config key: dataId or group/dataId")
	cmd.Flags().StringVar(&file, "file", "", "Config file to push")
	cmd.Flags().StringVar(&contentType, "type", "text", "Config type: text, properties, json, yaml")
	cmd.Flags().StringVar(&expectedRevision, "expected-revision", "", "CAS revision precondition")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("file")
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
			class := cfgclass.Classify(cfgclass.OperationDelete, nil, "")
			if f.DryRun {
				plan := map[string]any{"resourceType": "config", "key": key, "baseRisk": class.Risk, "impact": "delete one config blob"}
				return newPrinter(f).JSONData("ChangePlan", plan)
			}
			if err := authorize(f, safety.R2, ctxMeta, allowProductionConfigDelete); err != nil {
				return err
			}
			coord := cfgov.Coordinate{Namespace: backend.Describe().Namespace, Key: key}
			err = backend.Delete(cmd.Context(), cfgov.DeleteRequest{Coordinate: coord, ExpectedRevision: expectedRevision})
			status := audit.StatusSuccess
			if err != nil {
				status = audit.StatusFailed
			}
			appendAuditWarn(f, audit.EventType("config.delete"), ctxMeta, audit.EventTarget{ResourceType: "config", Resource: key}, status, "delete one config blob", err)
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("ChangeResult", map[string]any{"resourceType": "config", "namespace": coord.Namespace, "key": key, "deleted": true})
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
	Sha256       string           `json:"sha256"`
	Bytes        int              `json:"bytes"`
}

func pushPlan(ctx context.Context, backend cfgov.Backend, coord cfgov.Coordinate, content []byte, class cfgclass.Result) changePlan {
	before, _ := backend.CurrentRevision(ctx, coord)
	hash := sha256.Sum256(content)
	impact := fmt.Sprintf("write one config blob; bytes=%d; currentRevision=%s; targetSha256=%s", len(content), before, hex.EncodeToString(hash[:]))
	if before == md5Like(content) {
		impact = "no content change detected by revision fingerprint"
	}
	return changePlan{
		ResourceType: "config",
		Coordinate:   coord,
		BaseRisk:     class.Risk,
		Reason:       class.Reason,
		Impact:       impact,
		Sha256:       hex.EncodeToString(hash[:]),
		Bytes:        len(bytes.TrimRight(content, "\n")),
	}
}

func md5Like(content []byte) string {
	sum := md5.Sum(content) // #nosec G401 -- Nacos revision compatibility fingerprint, not cryptography.
	return hex.EncodeToString(sum[:])
}
