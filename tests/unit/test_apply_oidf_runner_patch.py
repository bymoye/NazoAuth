import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "apply_oidf_runner_patch.py"
    spec = importlib.util.spec_from_file_location("apply_oidf_runner_patch", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


class ApplyOidfRunnerPatchTests(unittest.TestCase):
    def test_versioned_patch_matches_its_sha_bound_manifest(self):
        module = load_module()
        patch_text = module.PATCH_PATH.read_text(encoding="utf-8")

        self.assertEqual(module.OIDF_REF, "dee9a25160e789f0f80517674693ef7989ab9fa1")
        self.assertEqual(module.normalized_sha256(module.PATCH_PATH), module.PATCH_SHA256)
        self.assertEqual(set(module.TARGET_HASHES), {"scripts/run-test-plan.py"})
        self.assertIn("read_authoritative_terminal_info", patch_text)
        self.assertIn("conformance.get_module_info", patch_text)
        self.assertNotIn("from nazo_oidf_runner_consistency import", patch_text)

    def create_fixture(self, root: Path):
        module = load_module()
        suite = root / "suite"
        target = suite / "scripts" / "run-test-plan.py"
        target.parent.mkdir(parents=True)
        target.write_text("before\n", encoding="utf-8", newline="\n")
        run_git(suite, "init", "--quiet")
        run_git(suite, "config", "user.email", "oidf-patch-test@example.test")
        run_git(suite, "config", "user.name", "OIDF patch test")
        run_git(suite, "add", "scripts/run-test-plan.py")
        run_git(suite, "commit", "--quiet", "-m", "fixture")
        head = run_git(suite, "rev-parse", "HEAD")

        patch = root / "fixture.patch"
        patch.write_text(
            "diff --git a/scripts/run-test-plan.py b/scripts/run-test-plan.py\n"
            "--- a/scripts/run-test-plan.py\n"
            "+++ b/scripts/run-test-plan.py\n"
            "@@ -1 +1 @@\n"
            "-before\n"
            "+after\n",
            encoding="utf-8",
            newline="\n",
        )
        preimage = module.normalized_sha256(target)
        postimage = hashlib.sha256(b"after\n").hexdigest()
        patch_hash = module.normalized_sha256(patch)
        return module, suite, target, patch, head, preimage, postimage, patch_hash

    def test_exact_patch_is_applied_and_idempotently_reverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            options = {
                "expected_ref": head,
                "patch_path": patch,
                "patch_sha256": patch_hash,
                "target_hashes": {"scripts/run-test-plan.py": (preimage, postimage)},
            }

            self.assertTrue(module.ensure_oidf_runner_patch(suite, **options))
            self.assertEqual(target.read_text(encoding="utf-8"), "after\n")
            self.assertFalse(module.ensure_oidf_runner_patch(suite, **options))

    def test_repeat_verification_allows_generated_root_json_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            options = {
                "expected_ref": head,
                "patch_path": patch,
                "patch_sha256": patch_hash,
                "target_hashes": {"scripts/run-test-plan.py": (preimage, postimage)},
            }

            self.assertTrue(module.ensure_oidf_runner_patch(suite, **options))
            config = suite / "scripts" / "oidf-generated-plan-config.json"
            config.write_text('{"alias":"verified-and-overwritten-by-wrapper"}\n')
            self.assertEqual(module.unsafe_untracked_script_paths(suite), set())
            self.assertFalse(module.ensure_oidf_runner_patch(suite, **options))

    def test_wrong_head_is_rejected_before_patching(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, _head, preimage, postimage, patch_hash = fixture

            with self.assertRaisesRegex(module.OidfRunnerPatchError, "does not match"):
                module.ensure_oidf_runner_patch(
                    suite,
                    expected_ref="0" * 40,
                    patch_path=patch,
                    patch_sha256=patch_hash,
                    target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "before\n")

    def test_untracked_python_shadow_in_suite_scripts_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            shadow = suite / "scripts" / "conformance" / "__init__.py"
            shadow.parent.mkdir()
            shadow.write_text("raise RuntimeError('shadowed')\n", encoding="utf-8")

            with self.assertRaisesRegex(module.OidfRunnerPatchError, "untracked paths"):
                module.ensure_oidf_runner_patch(
                    suite,
                    expected_ref=head,
                    patch_path=patch,
                    patch_sha256=patch_hash,
                    target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "before\n")

    def test_ignored_untracked_pyc_in_suite_scripts_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            exclude = suite / ".git" / "info" / "exclude"
            exclude.write_text("scripts/__pycache__/\n", encoding="utf-8")
            pyc = suite / "scripts" / "__pycache__" / "conformance.cpython-314.pyc"
            pyc.parent.mkdir()
            pyc.write_bytes(b"untrusted bytecode")

            self.assertIn(
                "scripts/__pycache__/conformance.cpython-314.pyc",
                module.untracked_script_paths(suite),
            )
            with self.assertRaisesRegex(module.OidfRunnerPatchError, "untracked paths"):
                module.ensure_oidf_runner_patch(
                    suite,
                    expected_ref=head,
                    patch_path=patch,
                    patch_sha256=patch_hash,
                    target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "before\n")

    def test_untracked_directory_symlink_in_suite_scripts_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            attacker = Path(temporary) / "attacker-package"
            attacker.mkdir()
            (attacker / "__init__.py").write_text("raise RuntimeError\n", encoding="utf-8")
            shadow = suite / "scripts" / "conformance"
            try:
                shadow.symlink_to(attacker, target_is_directory=True)
            except OSError:
                detected = {"scripts/conformance"}
                context = mock.patch.object(
                    module,
                    "untracked_script_paths",
                    return_value=detected,
                )
            else:
                self.assertTrue(shadow.is_symlink())
                self.assertIn("scripts/conformance", module.untracked_script_paths(suite))
                context = mock.patch.object(
                    module,
                    "untracked_script_paths",
                    wraps=module.untracked_script_paths,
                )

            with context:
                with self.assertRaisesRegex(module.OidfRunnerPatchError, "untracked paths"):
                    module.ensure_oidf_runner_patch(
                        suite,
                        expected_ref=head,
                        patch_path=patch,
                        patch_sha256=patch_hash,
                        target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                    )
            self.assertEqual(target.read_text(encoding="utf-8"), "before\n")

    def test_json_symlink_and_json_named_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture
            options = {
                "expected_ref": head,
                "patch_path": patch,
                "patch_sha256": patch_hash,
                "target_hashes": {"scripts/run-test-plan.py": (preimage, postimage)},
            }
            outside = Path(temporary) / "attacker.json"
            outside.write_text("{}\n", encoding="utf-8")
            json_link = suite / "scripts" / "linked.json"
            try:
                json_link.symlink_to(outside)
            except OSError:
                json_link.write_text("{}\n", encoding="utf-8")
                original_is_symlink = Path.is_symlink

                def mocked_is_symlink(path):
                    return path == json_link or original_is_symlink(path)

                symlink_context = mock.patch.object(
                    Path,
                    "is_symlink",
                    mocked_is_symlink,
                )
            else:
                self.assertTrue(json_link.is_symlink())
                symlink_context = mock.patch.object(
                    module,
                    "untracked_script_paths",
                    wraps=module.untracked_script_paths,
                )

            with symlink_context:
                with self.assertRaisesRegex(module.OidfRunnerPatchError, "linked.json"):
                    module.ensure_oidf_runner_patch(suite, **options)

            json_link.unlink()
            json_directory = suite / "scripts" / "directory.json"
            json_directory.mkdir()
            (json_directory / "payload").write_text("not data\n", encoding="utf-8")
            with self.assertRaisesRegex(module.OidfRunnerPatchError, "directory.json/payload"):
                module.ensure_oidf_runner_patch(suite, **options)
            self.assertEqual(target.read_text(encoding="utf-8"), "before\n")

    def test_unknown_target_hash_and_patch_hash_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.create_fixture(Path(temporary))
            module, suite, target, patch, head, preimage, postimage, patch_hash = fixture

            with self.assertRaisesRegex(module.OidfRunnerPatchError, "patch checksum"):
                module.ensure_oidf_runner_patch(
                    suite,
                    expected_ref=head,
                    patch_path=patch,
                    patch_sha256="f" * 64,
                    target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                )

            target.write_text("unexpected\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(
                module.OidfRunnerPatchError, "neither preimage nor postimage"
            ):
                module.ensure_oidf_runner_patch(
                    suite,
                    expected_ref=head,
                    patch_path=patch,
                    patch_sha256=patch_hash,
                    target_hashes={"scripts/run-test-plan.py": (preimage, postimage)},
                )


if __name__ == "__main__":
    unittest.main()
