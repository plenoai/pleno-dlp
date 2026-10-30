"""Exercise action temporary-directory selection and cleanup without mount changes or downloads."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "select-executable-tempdir.sh"
ACTION = ROOT / "action.yml"


class ExecutableTempdirTest(unittest.TestCase):
    def run_selector(self, env, cwd, check=True):
        return subprocess.run(
            ["sh", str(SELECTOR)], cwd=cwd, env=env, text=True,
            capture_output=True, check=check,
        )

    def install_command_stubs(self, root, tmp_exec):
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        real_chmod = shutil.which("chmod")
        real_mktemp = shutil.which("mktemp")
        self.assertIsNotNone(real_chmod)
        self.assertIsNotNone(real_mktemp)

        fake_chmod = fake_bin / "chmod"
        fake_chmod.write_text(
            '#!/bin/sh\n'
            'if [ "${PLENO_DLP_DENY_ALL:-0}" = 1 ]; then exit 0; fi\n'
            'case "$2" in\n'
            '  "$PLENO_DLP_DENIED_ROOT_1"/*|"$PLENO_DLP_DENIED_ROOT_2"/*) exit 0 ;;\n'
            'esac\n'
            'exec "$PLENO_DLP_REAL_CHMOD" "$@"\n'
        )
        fake_chmod.chmod(0o755)

        fake_mktemp = fake_bin / "mktemp"
        fake_mktemp.write_text(
            '#!/bin/sh\n'
            'template=$2\n'
            'printf "%s\\n" "$template" >> "$PLENO_DLP_MKTEMP_LOG"\n'
            'case "$template" in\n'
            '  "$PLENO_DLP_TMP_SOURCE"/pleno-dlp-action.XXXXXX)\n'
            '    template="$PLENO_DLP_TMP_EXEC/${template##*/}" ;;\n'
            'esac\n'
            'exec "$PLENO_DLP_REAL_MKTEMP" -d "$template"\n'
        )
        fake_mktemp.chmod(0o755)

        return {
            "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "PLENO_DLP_REAL_CHMOD": real_chmod,
            "PLENO_DLP_REAL_MKTEMP": real_mktemp,
            "PLENO_DLP_TMP_SOURCE": str(Path("/tmp").resolve()),
            "PLENO_DLP_TMP_EXEC": str(tmp_exec),
            "PLENO_DLP_MKTEMP_LOG": str(root / "mktemp.log"),
            "PLENO_DLP_DENIED_ROOT_1": str(root / "never-denied-1"),
            "PLENO_DLP_DENIED_ROOT_2": str(root / "never-denied-2"),
        }

    def cleanup_script(self):
        lines = ACTION.read_text().splitlines()
        start = lines.index("    - name: Clean up downloaded action files")
        run = lines.index("      run: |", start)
        body = []
        for line in lines[run + 1:]:
            if line.startswith("        "):
                body.append(line[8:])
            elif not line.strip():
                body.append("")
            else:
                break
        return "\n".join(body)

    def run_cleanup(self, temp_dir):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        return subprocess.run(
            [bash, "-c", self.cleanup_script()],
            env=dict(os.environ, PLENO_DLP_TEMP_DIR=str(temp_dir)),
            text=True, capture_output=True,
        )

    def test_prefers_runner_temp_when_probe_executes(self):
        # Stub commands must live in the checkout, because /tmp may be noexec on hikae-flash.
        with tempfile.TemporaryDirectory(dir=os.environ.get("GITHUB_WORKSPACE", str(ROOT))) as root:
            runner_temp = Path(root) / "runner"
            workspace = Path(root) / "workspace"
            fallback = Path(root) / "fallback"
            runner_temp.mkdir()
            workspace.mkdir()
            fallback.mkdir()
            env = dict(os.environ, RUNNER_TEMP=str(runner_temp), TMPDIR=str(fallback),
                       GITHUB_WORKSPACE=str(workspace), PWD=str(workspace))

            result = self.run_selector(env, workspace)
            selected = Path(result.stdout.strip())

            self.assertEqual(selected.parent, runner_temp.resolve())
            self.assertTrue(selected.is_dir())
            self.assertFalse((selected / "exec-probe").exists())

    def test_falls_back_to_explicit_tmp_when_tmpdir_is_nonexec(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("GITHUB_WORKSPACE", str(ROOT))) as root_name:
            root = Path(root_name)
            noexec = root / "noexec"
            workspace = root / "workspace"
            tmp_exec = root / "mapped-tmp"
            noexec.mkdir()
            workspace.mkdir()
            tmp_exec.mkdir()
            env = dict(os.environ)
            env.update(self.install_command_stubs(root, tmp_exec))
            env.update({
                "RUNNER_TEMP": str(noexec),
                "TMPDIR": str(noexec),
                "GITHUB_WORKSPACE": str(workspace),
                "PWD": str(workspace),
                "PLENO_DLP_DENIED_ROOT_1": str(noexec.resolve()),
                "PLENO_DLP_DENIED_ROOT_2": str(root / "unused"),
            })

            result = self.run_selector(env, workspace)
            selected = Path(result.stdout.strip())
            attempts = Path(env["PLENO_DLP_MKTEMP_LOG"]).read_text().splitlines()

            self.assertEqual(selected.parent, tmp_exec.resolve())
            self.assertEqual(attempts, [
                f"{noexec.resolve()}/pleno-dlp-action.XXXXXX",
                f"{Path('/tmp').resolve()}/pleno-dlp-action.XXXXXX",
            ])
            self.assertEqual(list(noexec.iterdir()), [])
            self.assertFalse((selected / "exec-probe").exists())

    def test_fails_closed_and_removes_all_probe_directories(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("GITHUB_WORKSPACE", str(ROOT))) as root_name:
            root = Path(root_name)
            runner = root / "runner"
            tmpdir = root / "tmpdir"
            workspace = root / "workspace"
            working_directory = root / "working_directory"
            tmp_exec = root / "mapped-tmp"
            for directory in (runner, tmpdir, workspace, working_directory, tmp_exec):
                directory.mkdir()
            env = dict(os.environ)
            env.update(self.install_command_stubs(root, tmp_exec))
            env.update({
                "RUNNER_TEMP": str(runner),
                "TMPDIR": str(tmpdir),
                "GITHUB_WORKSPACE": str(workspace),
                "PWD": str(working_directory),
                "PLENO_DLP_DENY_ALL": "1",
            })

            result = self.run_selector(env, working_directory, check=False)
            attempts = Path(env["PLENO_DLP_MKTEMP_LOG"]).read_text().splitlines()

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("no executable temporary directory found", result.stderr)
            self.assertEqual(len(attempts), 5)
            for directory in (runner, tmpdir, workspace, working_directory, tmp_exec):
                self.assertEqual(list(directory.iterdir()), [])

    def test_skips_crlf_candidate_paths_before_output(self):
        for control in ("\n", "\r"):
            with self.subTest(control=repr(control)):
                with tempfile.TemporaryDirectory(dir=os.environ.get("GITHUB_WORKSPACE", str(ROOT))) as root_name:
                    root = Path(root_name)
                    bad = root / f"bad{control}"
                    workspace = root / "workspace"
                    tmp_exec = root / "mapped-tmp"
                    bad.mkdir()
                    workspace.mkdir()
                    tmp_exec.mkdir()
                    env = dict(os.environ)
                    env.update(self.install_command_stubs(root, tmp_exec))
                    env.update({
                        "RUNNER_TEMP": str(bad),
                        "TMPDIR": str(bad),
                        "GITHUB_WORKSPACE": str(workspace),
                        "PWD": str(workspace),
                    })

                    result = self.run_selector(env, workspace)
                    selected = Path(result.stdout.strip())
                    attempts = Path(env["PLENO_DLP_MKTEMP_LOG"]).read_text().splitlines()

                    self.assertEqual(selected.parent, tmp_exec.resolve())
                    self.assertNotIn("\n", str(selected))
                    self.assertNotIn("\r", str(selected))
                    self.assertEqual(len(result.stdout.splitlines()), 1)
                    self.assertEqual(attempts, [
                        f"{Path('/tmp').resolve()}/pleno-dlp-action.XXXXXX",
                    ])
                    self.assertEqual(list(bad.iterdir()), [])

    def test_cleanup_requires_our_canonical_mktemp_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("GITHUB_WORKSPACE", str(ROOT))) as root_name:
            root = Path(root_name)
            valid = root / "pleno-dlp-action.ABC123"
            valid.mkdir()
            result = self.run_cleanup(valid)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(valid.exists())

            malformed = root / "pleno-dlp-action.ABC12"
            malformed.mkdir()
            result = self.run_cleanup(malformed)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(malformed.is_dir())

            victim = root / "victim"
            victim.mkdir()
            symlink = root / "pleno-dlp-action.DEF456"
            symlink.symlink_to(victim, target_is_directory=True)
            result = self.run_cleanup(symlink)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(symlink.is_symlink())
            self.assertTrue(victim.is_dir())

            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            through_alias = root / "pleno-dlp-action.GHI789"
            through_alias.mkdir()
            result = self.run_cleanup(alias / through_alias.name)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(through_alias.is_dir())

            newline_path = str(root / "pleno-dlp-action.JKL012") + "\n"
            result = self.run_cleanup(newline_path)
            self.assertNotEqual(result.returncode, 0)

    def test_action_uses_selector_and_always_cleans_its_workdir(self):
        action = ACTION.read_text()
        self.assertIn('scripts/select-executable-tempdir.sh', action)
        self.assertIn('echo "temp-dir=$workdir" >> "$GITHUB_OUTPUT"', action)
        self.assertIn('if: always()', action)
        self.assertIn('steps.install.outputs.temp-dir', action)
        self.assertIn(r'^pleno-dlp-action\.[[:alnum:]]{6}$', action)
        self.assertIn('|| -L "$temp_dir"', action)
        self.assertIn('pwd -P', action)
        self.assertIn('rm -rf "$temp_dir"', action)


if __name__ == "__main__":
    unittest.main()
