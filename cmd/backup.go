package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"

	"github.com/JiangHe12/cfgov-cli/internal/backup"
)

type backupCleanOptions struct {
	contextName string
	namespace   string
	dataID      string
	before      string
	keepLast    int
	confirm     bool
}

func newBackupCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "backup", Short: "Manage local cfgov backups"}
	cmd.AddCommand(backupListCmd(f), backupCleanCmd(f))
	return cmd
}

func backupListCmd(f *cliFlags) *cobra.Command {
	var contextName, namespace, dataID string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List local backups",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			root, err := backupRoot()
			if err != nil {
				return err
			}
			items, err := backup.List(root, backup.Filter{Context: contextName, Namespace: namespace, DataID: dataID})
			if err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to list backups", err)
			}
			return printBackupList(f, items)
		},
	}
	cmd.Flags().StringVar(&contextName, "context-filter", "", "Filter by context")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Filter by namespace")
	cmd.Flags().StringVar(&dataID, "data-id", "", "Filter by dataId")
	return cmd
}

func backupCleanCmd(f *cliFlags) *cobra.Command {
	opts := backupCleanOptions{keepLast: -1}
	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean local backups",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runBackupClean(f, opts)
		},
	}
	cmd.Flags().StringVar(&opts.contextName, "context-filter", "", "Filter by context")
	cmd.Flags().StringVarP(&opts.namespace, "namespace", "n", "", "Filter by namespace")
	cmd.Flags().StringVar(&opts.dataID, "data-id", "", "Filter by dataId")
	cmd.Flags().StringVar(&opts.before, "before", "", "Clean backups before this time (30d / RFC3339 / YYYY-MM-DD)")
	cmd.Flags().IntVar(&opts.keepLast, "keep-last", -1, "Keep the newest N matching backups (0 = delete all matching backups)")
	cmd.Flags().BoolVar(&opts.confirm, "confirm", false, "Actually delete matched backups")
	return cmd
}

func runBackupClean(f *cliFlags, opts backupCleanOptions) error {
	cleanOpts, err := backupCleanRequest(opts)
	if err != nil {
		return err
	}
	root, err := backupRoot()
	if err != nil {
		return err
	}
	cleanOpts.Apply = opts.confirm && !f.DryRun
	result, err := backup.Clean(root, cleanOpts)
	if err != nil {
		result.DryRun = !cleanOpts.Apply
	}
	status := audit.StatusSuccess
	if err != nil {
		status = audit.StatusFailed
	}
	appendBackupCleanAudit(f, result, status, err)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to clean backups", err)
	}
	return printBackupClean(f, result)
}

func backupCleanRequest(opts backupCleanOptions) (backup.CleanOptions, error) {
	if opts.before == "" && opts.keepLast < 0 {
		return backup.CleanOptions{}, apperrors.New(apperrors.CodeUsageError, "backup clean requires --before or --keep-last", nil)
	}
	if opts.before != "" && opts.keepLast >= 0 {
		return backup.CleanOptions{}, apperrors.New(apperrors.CodeUsageError, "backup clean accepts only one of --before or --keep-last", nil)
	}
	if opts.keepLast < -1 {
		return backup.CleanOptions{}, apperrors.New(apperrors.CodeUsageError, "--keep-last must be >= 0", nil)
	}
	out := backup.CleanOptions{Filter: backup.Filter{Context: opts.contextName, Namespace: opts.namespace, DataID: opts.dataID}}
	if opts.keepLast >= 0 {
		keepLast := opts.keepLast
		out.KeepLast = &keepLast
		return out, nil
	}
	before, err := parseBackupCleanBefore(opts.before, time.Now().UTC())
	if err != nil {
		return backup.CleanOptions{}, err
	}
	out.Before = &before
	return out, nil
}

func parseBackupCleanBefore(value string, now time.Time) (time.Time, error) {
	if t, err := audit.ParseTime(value, now); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, apperrors.New(apperrors.CodeUsageError, "invalid --before: expected relative (30d), RFC3339, or YYYY-MM-DD", nil)
	}
	return t, nil
}

func printBackupList(f *cliFlags, items []backup.Metadata) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("BackupList", items, len(items), 1, len(items), false)
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.BackupID, item.Context, item.Namespace, item.Group, item.DataID, item.SHA256, item.CreatedAt, item.Status, item.Path})
	}
	p.Table([]string{"BACKUP ID", "CONTEXT", "NAMESPACE", "GROUP", "DATA ID", "SHA256", "CREATED AT", "STATUS", "PATH"}, rows)
	return nil
}

func printBackupClean(f *cliFlags, result backup.CleanResult) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("BackupCleanResult", result)
	}
	files := backupCleanPaths(result)
	if len(files) == 0 {
		p.Info("(no backups matched)")
		return nil
	}
	if f.Output == "plain" {
		for _, file := range files {
			p.Info(file)
		}
		return nil
	}
	action := "would-delete"
	if !result.DryRun {
		action = "deleted"
	}
	rows := make([][]string, 0, len(files))
	for _, file := range files {
		rows = append(rows, []string{action, filepath.Base(file), file})
	}
	p.Table([]string{"ACTION", "FILE", "PATH"}, rows)
	if result.DryRun {
		p.Info(fmt.Sprintf("(dry-run: pass --confirm to delete %d backup file(s))", len(result.Deleted)))
	}
	return nil
}

func backupCleanPaths(result backup.CleanResult) []string {
	files := make([]string, 0, len(result.Deleted)+len(result.Removed))
	for _, item := range result.Deleted {
		files = append(files, item.Path)
	}
	for _, item := range result.Removed {
		files = append(files, item.Path)
	}
	sort.Strings(files)
	return files
}

func appendBackupCleanAudit(f *cliFlags, result backup.CleanResult, status string, err error) {
	deleted := backupCleanPaths(result)
	path, pathErr := audit.DefaultPath()
	if pathErr != nil {
		return
	}
	evt := audit.Event{
		EventType:   audit.EventBackupPrune,
		Operator:    currentOperator(f),
		Context:     audit.EventContext{Name: f.contextName()},
		Status:      status,
		Diff:        fmt.Sprintf("deleted=%d removed=%d dryRun=%t", len(result.Deleted), len(result.Removed), result.DryRun),
		BackupPrune: &audit.BackupPruneDetail{DeletedDirs: deleted, Count: len(deleted)},
	}
	if err != nil {
		appErr := apperrors.AsAppError(err)
		evt.Error = &audit.EventError{Code: string(appErr.Code), Message: appErr.Message}
	}
	_ = audit.AppendWithOptions(path, evt, auditOptions(f))
}
