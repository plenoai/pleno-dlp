// Shell completion generation. Cobra ships the heavy lifting; this
// file only wraps it as a top-level subcommand so users can do
// `pleno-dlp completion bash > /etc/bash_completion.d/pleno-dlp`
// without remembering cobra's internal API.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// completionCmd is a single command that switches on the positional
// arg. Cobra's GenBashCompletion / GenZshCompletion / etc. already
// know about every flag and subcommand, so the generated output
// stays in sync with whatever flags scan.go declares without us
// maintaining a parallel list.
var completionCmd = &cobra.Command{
	Use:                   "completion <bash|zsh|fish|powershell>",
	Short:                 "Generate shell completion script",
	Long: `Generate a shell completion script for pleno-dlp.

Bash:
  source <(pleno-dlp completion bash)
  # or
  pleno-dlp completion bash > /etc/bash_completion.d/pleno-dlp

Zsh:
  pleno-dlp completion zsh > "${fpath[1]}/_pleno-dlp"

Fish:
  pleno-dlp completion fish | source

PowerShell:
  pleno-dlp completion powershell | Out-String | Invoke-Expression`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return Root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return Root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return Root.GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			return Root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
		default:
			// Unreachable thanks to OnlyValidArgs, but the explicit
			// branch makes the intent obvious to readers.
			return fmt.Errorf("unsupported shell %q", args[0])
		}
	},
}

func init() {
	Root.AddCommand(completionCmd)
}
