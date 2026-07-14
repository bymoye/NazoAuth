import importlib.util
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script = ROOT / "scripts" / "check_spec_freshness.py"
    spec = importlib.util.spec_from_file_location("check_spec_freshness", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload, url="https://example.invalid/final"):
        self.payload = payload
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload

    def geturl(self):
        return self.url


class SpecFreshnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_repository_manifest_is_valid_and_complete(self):
        manifest = json.loads(
            (ROOT / "requirements" / "spec-freshness.json").read_text(encoding="utf-8")
        )

        self.module.validate_manifest(manifest, ROOT)
        identifiers = {entry["id"] for entry in manifest["sources"]}
        self.assertIn("oauth-browser-based-apps", identifiers)
        self.assertIn("oauth-grant-management-working", identifiers)
        self.assertIn("oauth-grant-management-id1", identifiers)
        self.assertIn("oidf-conformance-suite", identifiers)
        self.assertGreaterEqual(len(identifiers), 35)

    def test_manifest_rejects_duplicate_ids_and_unofficial_hosts(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": [],
            "sources": [
                {
                    "id": "same",
                    "title": "One",
                    "kind": "rfc",
                    "url": "https://example.com/rfc1",
                    "number": 1,
                    "markers": ["RFC 1"],
                },
                {
                    "id": "same",
                    "title": "Two",
                    "kind": "rfc",
                    "url": "https://www.rfc-editor.org/info/rfc2",
                    "number": 2,
                    "markers": ["RFC 2"],
                },
            ],
        }

        with self.assertRaisesRegex(ValueError, "official host|duplicate id"):
            self.module.validate_manifest(manifest, ROOT)

    def test_ietf_revision_mismatch_fails(self):
        entry = {
            "id": "browser",
            "title": "Browser",
            "kind": "ietf_draft",
            "url": "https://datatracker.ietf.org/doc/draft-example/",
            "document": "draft-example",
            "revision": "27",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps({"name": "draft-example", "rev": "26"}).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "expected revision 27, official source reports 26"):
            self.module.check_entry(entry, opener)

    def test_ietf_draft_rfc_transition_fails_even_when_revision_is_unchanged(self):
        entry = {
            "id": "browser",
            "title": "Browser",
            "kind": "ietf_draft",
            "url": "https://datatracker.ietf.org/doc/draft-example/",
            "document": "draft-example",
            "revision": "27",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps(
                {
                    "name": "draft-example",
                    "rev": "27",
                    "rfc": "/api/v1/doc/document/rfc9999/",
                }
            ).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "published or replaced by an RFC"):
            self.module.check_entry(entry, opener)

    def test_expired_ietf_draft_requires_status_review(self):
        entry = {
            "id": "draft",
            "title": "Draft",
            "kind": "ietf_draft",
            "url": "https://datatracker.ietf.org/doc/draft-example/",
            "document": "draft-example",
            "revision": "01",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps(
                {
                    "name": "draft-example",
                    "rev": "01",
                    "rfc": None,
                    "rfc_number": None,
                    "expires": "2000-01-01T00:00:00Z",
                }
            ).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "official draft is expired"):
            self.module.check_entry(entry, opener)

    def test_openid_marker_and_final_url_are_required(self):
        entry = {
            "id": "grant",
            "title": "Grant",
            "kind": "openid_document",
            "url": "https://openid.net/specs/oauth-v2-grant-management.html",
            "markers": ["oauth-v2-grant-management-03", "Second Implementer's Draft"],
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            b"oauth-v2-grant-management-03",
            "https://openid.net/specs/oauth-v2-grant-management.html",
        )

        with self.assertRaisesRegex(RuntimeError, "missing marker"):
            self.module.check_entry(entry, opener)

    def test_openid_redirect_to_unexpected_page_fails(self):
        entry = {
            "id": "grant",
            "title": "Grant",
            "kind": "openid_document",
            "url": "https://openid.net/specs/oauth-v2-grant-management.html",
            "markers": ["Grant Management"],
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            b"Grant Management",
            "https://example.com/copied-page.html",
        )

        with self.assertRaisesRegex(RuntimeError, "unexpected redirect target"):
            self.module.check_entry(entry, opener)

    def test_oidf_latest_release_tag_and_commit_are_required(self):
        entry = {
            "id": "suite",
            "title": "suite",
            "kind": "oidf_suite",
            "url": "https://gitlab.com/openid/conformance-suite/-/releases/release-v5.2.0",
            "api_url": "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest",
            "tag": "release-v5.2.0",
            "commit": "dee9a25160e789f0f80517674693ef7989ab9fa1",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps(
                {
                    "tag_name": "release-v5.1.44",
                    "commit": {"id": "f326"},
                }
            ).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "expected latest tag release-v5.2.0"):
            self.module.check_entry(entry, opener)

    def test_active_documents_reject_stale_draft_pins(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": ["active.md"],
            "sources": [
                {
                    "id": "browser",
                    "title": "Browser",
                    "kind": "ietf_draft",
                    "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/",
                    "document": "draft-ietf-oauth-browser-based-apps",
                    "revision": "27",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "active.md").write_text(
                "draft-ietf-oauth-browser-based-apps-26", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "stale draft pin"):
                self.module.validate_manifest(manifest, root)

    def test_active_documents_require_every_referenced_rfc_in_inventory(self):
        manifest = {
            "schema_version": 1,
            "active_document_globs": ["docs/*.md"],
            "active_document_paths": [],
            "sources": [
                {
                    "id": "rfc7009",
                    "title": "Revocation",
                    "kind": "rfc",
                    "url": "https://www.rfc-editor.org/info/rfc7009",
                    "number": 7009,
                    "markers": ["RFC 7009"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "current.md").write_text(
                "RFC 7009 and RFC 6750", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "untracked RFC 6750"):
                self.module.validate_manifest(manifest, root)

    def test_expected_file_markers_link_mutable_sources_to_active_claims(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": ["current.md"],
            "expected_file_markers": {"current.md": ["draft 27"]},
            "sources": [
                {
                    "id": "browser",
                    "title": "Browser",
                    "kind": "ietf_draft",
                    "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/",
                    "document": "draft-ietf-oauth-browser-based-apps",
                    "revision": "27",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "current.md").write_text("draft 26", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing expected active marker 'draft 27'"):
                self.module.validate_manifest(manifest, root)

    def test_manifest_rejects_active_path_escape(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": ["../outside.md"],
            "sources": [
                {
                    "id": "rfc7009",
                    "title": "Revocation",
                    "kind": "rfc",
                    "url": "https://www.rfc-editor.org/info/rfc7009",
                    "number": 7009,
                    "markers": ["RFC 7009"],
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "must stay within the repository"):
            self.module.validate_manifest(manifest, ROOT)

    def test_manifest_rejects_unofficial_suite_api(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": [],
            "sources": [
                {
                    "id": "suite",
                    "title": "suite",
                    "kind": "oidf_suite",
                    "url": "https://gitlab.com/openid/conformance-suite/-/releases/release-v5.2.0",
                    "api_url": "https://example.com/latest",
                    "tag": "release-v5.2.0",
                    "commit": "dee9a25160e789f0f80517674693ef7989ab9fa1",
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "official GitLab API"):
            self.module.validate_manifest(manifest, ROOT)

    def test_official_fetch_retries_transient_network_failures(self):
        attempts = []

        def opener(*_args, **_kwargs):
            attempts.append(1)
            if len(attempts) < 3:
                raise urllib.error.URLError("temporary timeout")
            return FakeResponse(b"ok", "https://www.rfc-editor.org/info/rfc9728/")

        request = urllib.request.Request("https://www.rfc-editor.org/info/rfc9728")
        payload, final_url = self.module._open_bytes(
            opener,
            request,
            attempts=3,
            sleeper=lambda _seconds: None,
        )

        self.assertEqual(payload, b"ok")
        self.assertEqual(final_url, "https://www.rfc-editor.org/info/rfc9728/")
        self.assertEqual(len(attempts), 3)


if __name__ == "__main__":
    unittest.main()
