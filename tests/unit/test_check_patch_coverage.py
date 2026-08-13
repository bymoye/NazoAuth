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
    @staticmethod
    def _initialize_repository(repository: Path) -> None:
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

    @staticmethod
    def _commit(repository: Path, message: str) -> str:
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(
            ["git", "commit", "--quiet", "-m", message],
            cwd=repository,
            check=True,
        )
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        ).stdout.strip()

    @staticmethod
    def _run_gate(
        repository: Path,
        base: str,
        lcov: str,
    ) -> subprocess.CompletedProcess[str]:
        lcov_path = repository / "lcov.info"
        lcov_path.write_text(lcov, encoding="utf-8")
        config = repository / "codecov.yml"
        config.write_text("coverage:\n  status: {}\nignore:\n", encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--lcov",
                str(lcov_path),
                "--base",
                base,
                "--head",
                "HEAD",
                "--threshold",
                "90",
                "--repository",
                str(repository),
                "--codecov-config",
                str(config),
            ],
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )

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

    def test_missing_lcov_record_for_changed_rust_file_fails_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._initialize_repository(repository)
            source_directory = repository / "src"
            source_directory.mkdir()
            (source_directory / "base.rs").write_text(
                "pub fn existing() {}\n", encoding="utf-8"
            )
            base = self._commit(repository, "base")

            added = source_directory / "missing_record.rs"
            added.write_text(
                "pub fn added() { let value = 1; let _ = value; }\n",
                encoding="utf-8",
            )
            self._commit(repository, "add Rust file")

            result = self._run_gate(repository, base, "TN:\n")

            self.assertNotEqual(result.returncode, 0)

    def test_non_executable_change_in_instrumented_rust_file_is_not_misclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._initialize_repository(repository)
            source_directory = repository / "src"
            source_directory.mkdir()
            source = source_directory / "fixture.rs"
            source.write_text("pub fn existing() {}\n", encoding="utf-8")
            base = self._commit(repository, "base")

            source.write_text("/// Clarifies the API.\npub fn existing() {}\n", encoding="utf-8")
            self._commit(repository, "document Rust API")

            result = self._run_gate(
                repository,
                base,
                "SF:src/fixture.rs\nDA:2,1\nLF:1\nLH:1\nend_of_record\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_lcov_record_without_da_for_interface_file_does_not_fail_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            self._initialize_repository(repository)
            source_directory = repository / "src"
            source_directory.mkdir()
            (source_directory / "base.rs").write_text(
                "pub fn existing() {}\n", encoding="utf-8"
            )
            base = self._commit(repository, "base")

            (source_directory / "interface.rs").write_text(
                "pub trait Marker {}\n", encoding="utf-8"
            )
            self._commit(repository, "add interface")

            result = self._run_gate(
                repository,
                base,
                "SF:src/interface.rs\nFNF:0\nFNH:0\nLF:0\nLH:0\nend_of_record\n",
            )

            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
