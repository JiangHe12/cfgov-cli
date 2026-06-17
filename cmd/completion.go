package cmd

import (
	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func newCompletionCmd(_ *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:       "completion {bash|zsh|fish|powershell}",
		Short:     "Generate shell completion script",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return root.GenPowerShellCompletion(cmd.OutOrStdout())
			default:
				return apperrors.New(apperrors.CodeUsageError, "shell must be bash, zsh, fish, or powershell", nil)
			}
		},
	}
}
