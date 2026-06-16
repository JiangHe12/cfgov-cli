package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
)

func newAuditCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect cfgov audit log"}
	cmd.AddCommand(auditQueryCmd(f), auditVerifyCmd(f))
	return cmd
}

func auditQueryCmd(f *cliFlags) *cobra.Command {
	var filter audit.Filter
	var since, until string
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query audit events",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			now := time.Now()
			if since != "" {
				t, err := audit.ParseTime(since, now)
				if err != nil {
					return apperrors.New(apperrors.CodeUsageError, "invalid --since", err)
				}
				filter.Since = &t
			}
			if until != "" {
				t, err := audit.ParseTime(until, now)
				if err != nil {
					return apperrors.New(apperrors.CodeUsageError, "invalid --until", err)
				}
				filter.Until = &t
			}
			path, err := audit.DefaultPath()
			if err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit path", err)
			}
			if filter.PrivateKey == "" {
				filter.PrivateKey = os.Getenv("CFGOV_CLI_AUDIT_PRIVATE_KEY")
			}
			result, err := audit.Query(path, filter)
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("AuditQueryResult", result)
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "Start time: 24h or RFC3339")
	cmd.Flags().StringVar(&until, "until", "", "End time: 24h or RFC3339")
	cmd.Flags().StringVar(&filter.EventType, "type", "", "Event type")
	cmd.Flags().StringVar(&filter.Operator, "operator", "", "Operator")
	cmd.Flags().StringVar(&filter.ContextName, "context", "", "Context name")
	cmd.Flags().StringVar(&filter.Status, "status", "", "Status")
	cmd.Flags().IntVar(&filter.Limit, "limit", 100, "Maximum events")
	cmd.Flags().BoolVar(&filter.Reverse, "reverse", true, "Newest first")
	return cmd
}

func auditVerifyCmd(f *cliFlags) *cobra.Command {
	var repair, yes bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit log integrity",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := audit.DefaultPath()
			if err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit path", err)
			}
			result, err := audit.Verify(path, audit.VerifyOptions{
				Decrypt:    os.Getenv("CFGOV_CLI_AUDIT_PRIVATE_KEY") != "",
				PrivateKey: os.Getenv("CFGOV_CLI_AUDIT_PRIVATE_KEY"),
				Repair:     repair,
				Confirm:    yes,
			})
			if err != nil {
				return err
			}
			return newPrinter(f).JSONData("AuditVerifyResult", result)
		},
	}
	cmd.Flags().BoolVar(&repair, "repair", false, "Quarantine malformed entries and rewrite audit log")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm audit repair")
	return cmd
}
