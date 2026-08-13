import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "oidf_evidence.py"
    spec = importlib.util.spec_from_file_location("oidf_evidence", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class OidfEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def write_archive(self, path: Path, *, plan_id: str, secret: str) -> None:
        payload = {
            "exportedAt": "Jul 19, 2026",
            "exportedFrom": "https://suite.example",
            "exportedBy": {"sub": "private-operator"},
            "testInfo": {
                "testId": "module-id",
                "testName": "oidcc-server",
                "planId": plan_id,
                "status": "FINISHED",
                "result": "PASSED",
                "variant": {"response_type": "code"},
                "owner": "private-owner",
                "config": {
                    "client_secret": secret,
                    "browser": [["text", "id", "password", secret]],
                },
            },
            "results": [
                {"result": "SUCCESS", "msg": f"access_token={secret}"},
                {"result": "INFO", "config": {"private_key": secret}},
                {
                    "result": "FAILURE",
                    "src": "ValidateCredentialTrust",
                    "msg": f"credential={secret}",
                    "args": {"credential": secret},
                },
                {
                    "result": "WARNING",
                    "src": f"unsafe source {secret}",
                    "msg": secret,
                },
            ],
        }
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("test-log-module-id.json", json.dumps(payload))
            archive.writestr("test-log-module-id.sig", "signature")

    def test_sanitizer_keeps_auditable_fields_and_removes_raw_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plan.zip"
            self.write_archive(archive, plan_id="plan-id", secret="top-secret")

            manifest_path = self.module.sanitize_evidence_tree(root)

            self.assertEqual(manifest_path, root / "evidence-manifest.json")
            self.assertFalse(archive.exists())
            content = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("top-secret", content)
            self.assertNotIn("private-operator", content)
            payload = json.loads(content)
            self.assertEqual(payload["summary"]["archive_count"], 1)
            self.assertEqual(payload["summary"]["plan_count"], 1)
            self.assertEqual(payload["summary"]["module_results"], {"PASSED": 1})
            self.assertEqual(
                payload["summary"]["condition_results"],
                {"FAILURE": 1, "INFO": 1, "SUCCESS": 1, "WARNING": 1},
            )
            module = payload["archives"][0]["modules"][0]
            self.assertTrue(module["signature_present"])
            self.assertEqual(
                module["problem_conditions"],
                [{"result": "FAILURE", "src": "ValidateCredentialTrust"}],
            )
            self.assertNotIn("config", module["test_info"])
            self.assertNotIn("owner", module["test_info"])

    def test_parent_manifest_combines_group_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in (1, 2):
                group = root / f"group-{index}"
                group.mkdir()
                self.write_archive(
                    group / f"plan-{index}.zip",
                    plan_id=f"plan-{index}",
                    secret=f"secret-{index}",
                )
                self.module.sanitize_evidence_tree(group)

            manifest_path = self.module.sanitize_evidence_tree(root)

            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["archive_count"], 2)
            self.assertEqual(payload["summary"]["plan_count"], 2)
            self.assertFalse(any((root / f"group-{index}" / "evidence-manifest.json").exists() for index in (1, 2)))
            self.assertEqual(
                [archive["file"] for archive in payload["archives"]],
                ["group-1/plan-1.zip", "group-2/plan-2.zip"],
            )

    def test_summarizer_rejects_too_many_zip_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plan.zip"
            self.write_archive(archive, plan_id="plan-id", secret="secret")

            with mock.patch.object(self.module, "MAX_ARCHIVE_MEMBERS", 1):
                with self.assertRaisesRegex(self.module.EvidenceError, "too many members"):
                    self.module.summarize_archive(archive, root)

    def test_summarizer_rejects_expanded_archive_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plan.zip"
            self.write_archive(archive, plan_id="plan-id", secret="secret")

            with mock.patch.object(self.module, "MAX_ARCHIVE_BYTES", 4):
                with self.assertRaisesRegex(self.module.EvidenceError, "bounded size"):
                    self.module.summarize_archive(archive, root)

    def test_summarizer_rejects_oversized_json_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "plan.zip"
            self.write_archive(archive, plan_id="plan-id", secret="secret")

            with mock.patch.object(self.module, "MAX_JSON_BYTES", 4):
                with self.assertRaisesRegex(self.module.EvidenceError, "bounded JSON size"):
                    self.module.summarize_archive(archive, root)


if __name__ == "__main__":
    unittest.main()
