from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_REVISION = "946451d1ce29965c9ab7aee05f5003552233160e"


class OidfSuiteDeploymentTests(unittest.TestCase):
    def test_private_suite_build_keeps_the_pinned_upstream_checkout_unmodified(self):
        containerfile = (ROOT / "deploy" / "oidf-suite" / "Containerfile").read_text(
            encoding="utf-8"
        )
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(containerfile.count(UPSTREAM_REVISION), 2)
        self.assertEqual(compose.count(UPSTREAM_REVISION), 1)
        self.assertIn('test "$(git rev-parse HEAD)" = "${OIDF_SUITE_UPSTREAM_REVISION}"', containerfile)
        self.assertIn('test -z "$(git status --porcelain)"', containerfile)
        self.assertNotIn("git apply", containerfile)
        self.assertNotIn("OIDF_SUITE_OVERLAY", containerfile)
        self.assertNotIn("OIDF_SUITE_OVERLAY", compose)

    def test_host_suite_defaults_to_podman_and_has_no_fixed_target_hostname(self):
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('container_runtime=${OIDF_CONTAINER_RUNTIME:-podman}', bootstrap)
        self.assertIn('OIDF_TARGET_HOSTNAME: ${OIDF_TARGET_HOSTNAME:', compose)


if __name__ == "__main__":
    unittest.main()
