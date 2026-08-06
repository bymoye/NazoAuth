from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "check_patch_coverage.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("check_patch_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CheckPatchCoverageTests(unittest.TestCase):
    def test_reads_only_ignore_list_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "codecov.yml"
            config.write_text(
                "coverage:\n  status: {}\nignore:\n  - \"tests/**\"\n  # comment\n  - src/glue.rs\nflags:\n  unit: {}\n",
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.codecov_ignores(config),
                ("tests/**", "src/glue.rs"),
            )

    def test_matches_repository_relative_ignore_patterns(self) -> None:
        patterns = ("tests/**", "/src/glue.rs")
        self.assertTrue(MODULE.is_ignored("tests/unit/example.rs", patterns))
        self.assertTrue(MODULE.is_ignored("src/glue.rs", patterns))
        self.assertFalse(MODULE.is_ignored("src/domain.rs", patterns))

    def test_reads_added_lines_from_the_complete_git_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "coverage-test@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Coverage Test"],
                cwd=repository,
                check=True,
            )
            source = repository / "src.rs"
            source.write_text("fn one() {}\nfn three() {}\n", encoding="utf-8")
            subprocess.run(["git", "add", "src.rs"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "base"],
                cwd=repository,
                check=True,
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            ).stdout.strip()
            source.write_text(
                "fn one() {}\nfn two() {}\nfn three_changed() {}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "src.rs"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "head"],
                cwd=repository,
                check=True,
            )

            self.assertEqual(
                MODULE.changed_lines(base, "HEAD", repository),
                {"src.rs": {2, 3}},
            )


if __name__ == "__main__":
    unittest.main()
