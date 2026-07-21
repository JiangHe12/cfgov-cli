package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func newVersionCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			v, c, b := getVersionInfo()
			data := map[string]string{"version": v, "commit": c, "built": b}
			if f.Output == "json" {
				return newPrinter(f).JSONData("VersionInfo", data)
			}
			if f.Output == "plain" {
				if _, err := fmt.Fprintln(newPrinter(f).Out, v); err != nil {
					return apperrors.New(apperrors.CodeLocalIOError, "failed to write version output", err)
				}
				return nil
			}
			if _, err := fmt.Fprintf(newPrinter(f).Out, "cfgov-cli %s (commit: %s, built: %s)\n", v, c, b); err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to write version output", err)
			}
			return nil
		},
	}
}
