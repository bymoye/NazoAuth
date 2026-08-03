from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_REVISION = "946451d1ce29965c9ab7aee05f5003552233160e"
OVERLAY_SHA256 = "1e17e43bfc019196f45b14f58bf07ffa3363f4746b9e8a51de6dfc7b334253ce"


class OidfSuiteOverlayTests(unittest.TestCase):
    def test_private_suite_overlay_is_pinned_and_hash_verified(self):
        patch_path = (
            ROOT
            / "deploy"
            / "oidf-suite"
            / "patches"
            / "0001-vp-mdoc-use-configured-issuer.patch"
        )
        patch = patch_path.read_bytes()
        self.assertEqual(hashlib.sha256(patch).hexdigest(), OVERLAY_SHA256)

        containerfile = (ROOT / "deploy" / "oidf-suite" / "Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertEqual(containerfile.count(UPSTREAM_REVISION), 2)
        self.assertEqual(containerfile.count(OVERLAY_SHA256), 2)
        self.assertIn('test "$(git rev-parse HEAD)" = "${OIDF_SUITE_UPSTREAM_REVISION}"', containerfile)
        self.assertIn('test -z "$(git status --porcelain)"', containerfile)
        self.assertIn("git apply --check /tmp/oidf-suite.patch", containerfile)
        self.assertIn("sha256sum -c -", containerfile)

    def test_overlay_only_replaces_the_stale_mdoc_fixture_key(self):
        patch = (
            ROOT
            / "deploy"
            / "oidf-suite"
            / "patches"
            / "0001-vp-mdoc-use-configured-issuer.patch"
        ).read_text(encoding="utf-8")
        changed_paths = {
            line[6:]
            for line in patch.splitlines()
            if line.startswith("+++ b/") or line.startswith("--- a/")
        }
        self.assertEqual(
            changed_paths,
            {
                "src/main/java/net/openid/conformance/condition/as/CreateMdocCredential.java",
                "src/main/kotlin/com/android/identity/testapp/TestAppUtils.kt",
            },
        )
        self.assertIn('env.getElementFromObject("config", "credential.signing_jwk")', patch)
        self.assertIn("JWK.parse(issuerSigningJwk).toECKey()", patch)
        self.assertNotIn("expected_failure", patch.lower())
        self.assertNotIn("disable", patch.lower())

    def test_overlay_is_not_referenced_by_public_github_workflows(self):
        workflow_dir = ROOT / ".github" / "workflows"
        for workflow_path in workflow_dir.glob("*.yml"):
            workflow = workflow_path.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow_path.name):
                self.assertNotIn("0001-vp-mdoc-use-configured-issuer.patch", workflow)
                self.assertNotIn("OIDF_SUITE_OVERLAY_SHA256", workflow)

    def test_host_suite_defaults_to_podman_and_has_no_fixed_target_hostname(self):
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('container_runtime=${OIDF_CONTAINER_RUNTIME:-podman}', bootstrap)
        self.assertIn('OIDF_TARGET_HOSTNAME: ${OIDF_TARGET_HOSTNAME:', compose)
        self.assertNotIn("567t0yglur-443.cnb.run", compose)


if __name__ == "__main__":
    unittest.main()
