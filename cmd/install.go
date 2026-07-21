package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/audit"
)

var agentPaths = map[string]string{
	"claude":    ".claude/skills",
	"codex":     ".codex/skills",
	"opencode":  ".opencode/skills",
	"copilot":   ".copilot/skills",
	"cursor":    ".cursor/skills",
	"cc-switch": ".cc-switch/skills",
	"windsurf":  ".windsurf/skills",
	"aider":     ".aider/skills",
}

var skillFS fs.FS

// SetSkillFS injects the embedded skill file system from main.
func SetSkillFS(fsys fs.FS) {
	skillFS = fsys
}

func newInstallCmd(f *cliFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install <agent>",
		Short: "Install cfgov AI skill to an agent skills directory",
		Long: `Install cfgov-cli skill to the specified AI agent's skills directory.

Preset agents:
  claude      -> ~/.claude/skills/
  codex       -> ~/.codex/skills/
  opencode    -> ~/.opencode/skills/
  copilot     -> ~/.copilot/skills/
  cursor      -> ~/.cursor/skills/
  cc-switch   -> ~/.cc-switch/skills/
  windsurf    -> ~/.windsurf/skills/
  aider       -> ~/.aider/skills/

Custom path:
  cfgov install /my/path --skills  -> /my/path/cfgov-cli/`,
		Example: `  cfgov install claude --skills
  cfgov install codex --skills
  cfgov install /custom/path --skills`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return apperrors.New(apperrors.CodeUsageError, "install requires exactly one agent or path", nil)
			}
			if !cmd.Flags().Changed("skills") {
				return apperrors.New(apperrors.CodeUsageError, "please specify --skills flag", nil)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			skills, _ := cmd.Flags().GetBool("skills")
			if !skills {
				return apperrors.New(apperrors.CodeUsageError, "please specify --skills flag", nil)
			}
			return installSkills(f, args[0])
		},
	}
	cmd.Flags().Bool("skills", false, "Install skill files")
	_ = cmd.MarkFlagRequired("skills")
	return cmd
}

func installSkills(f *cliFlags, target string) error {
	installDir, err := resolveInstallDir(target)
	if err != nil {
		return err
	}

	dstDir := filepath.Join(installDir, "cfgov-cli")
	overwriting := skillInstallExists(dstDir)
	if isPlanOnly(f) {
		if skillFS == nil {
			return apperrors.New(apperrors.CodeLocalIOError, "embedded skill filesystem is not initialized", nil)
		}
		if _, err := fs.Stat(skillFS, "skills/cfgov-cli/SKILL.md"); err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to read embedded skill", err)
		}
		return printLocalChangePlan(f, "skill", "install", dstDir, map[string]any{"overwrite": overwriting})
	}
	snapshot, err := readEmbeddedSkillSnapshot(skillFS, "skills/cfgov-cli")
	if err != nil {
		return err
	}
	metadata := mutationValueMetadata("skill.install", snapshot)
	metadata.Items = len(snapshot) + 1
	if overwriting {
		metadata.Updates = metadata.Items
	} else {
		metadata.Creates = metadata.Items
	}
	mutation, err := beginMutationAudit(f, mutationAuditSpec{
		Action:   "skill.install",
		Target:   audit.EventTarget{ResourceType: "skill", Resource: dstDir},
		Metadata: metadata,
	})
	if err != nil {
		return err
	}
	succeeded, operationErr := writeEmbeddedSkillSnapshot(snapshot, dstDir)
	if operationErr == nil {
		operationErr = verifyInstalledSkill(dstDir)
	}
	if operationErr == nil {
		operationErr = writeInstallManifest(dstDir)
		if operationErr == nil {
			succeeded++
		}
	}
	if auditErr := finishBatchMutationAudit(mutation, len(snapshot)+1, succeeded, 0, operationErr); auditErr != nil {
		return auditErr
	}

	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("InstallResult", map[string]string{"path": dstDir})
	}
	if overwriting {
		return p.Info(fmt.Sprintf("overwriting existing skill at %s", dstDir))
	}
	return p.Success(fmt.Sprintf("skill installed to %s", dstDir))
}

func writeInstallManifest(dstDir string) error {
	version, commit, _ := getVersionInfo()
	manifest := fmt.Sprintf("installed-by: cfgov-cli %s (commit: %s)\ninstalled-at: %s\n",
		version, commit, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dstDir, ".installed-by"), []byte(manifest), 0o600); err != nil { //nolint:gosec // dstDir is user-selected install destination.
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write install manifest", err)
	}
	return nil
}

func skillInstallExists(dstDir string) bool {
	_, err := os.Stat(filepath.Join(dstDir, "SKILL.md"))
	return err == nil
}

func verifyInstalledSkill(dstDir string) error {
	path := filepath.Join(dstDir, "SKILL.md")
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("installation appears to have failed: SKILL.md not present at %s after copy", path), err)
	}
	return nil
}

func resolveInstallDir(target string) (string, error) {
	if skillsDir, ok := agentPaths[strings.ToLower(target)]; ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to get home directory", err)
		}
		return filepath.Join(home, skillsDir), nil
	}
	return target, nil
}

func readEmbeddedSkillSnapshot(fsys fs.FS, srcDir string) (map[string][]byte, error) {
	if fsys == nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "embedded skill filesystem is not initialized", nil)
	}
	snapshot := map[string][]byte{}
	err := fs.WalkDir(fsys, srcDir, func(sourcePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(fsys, sourcePath)
		if err != nil {
			return err
		}
		relative := strings.TrimPrefix(sourcePath, strings.TrimSuffix(srcDir, "/")+"/")
		snapshot[relative] = data
		return nil
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read embedded skill", err)
	}
	if len(snapshot) == 0 {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "embedded skill is empty", nil)
	}
	return snapshot, nil
}

func writeEmbeddedSkillSnapshot(snapshot map[string][]byte, dstDir string) (int, error) {
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	succeeded := 0
	for _, name := range names {
		dstPath := filepath.Join(dstDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o750); err != nil {
			return succeeded, apperrors.New(apperrors.CodeLocalIOError, "failed to create skill directory", err)
		}
		if err := os.WriteFile(dstPath, snapshot[name], 0o600); err != nil { //nolint:gosec // dstPath is the user-selected install destination.
			return succeeded, apperrors.New(apperrors.CodeLocalIOError, "failed to write skill file", err)
		}
		succeeded++
	}
	return succeeded, nil
}
