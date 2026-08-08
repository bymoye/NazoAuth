from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_REVISION = "321bc5bc53601b9690b54c023c0cbfac0f0230f2"


class OidfSuiteDeploymentTests(unittest.TestCase):
    def test_private_suite_build_keeps_the_pinned_upstream_checkout_unmodified(self):
        containerfile = (ROOT / "deploy" / "oidf-suite" / "Containerfile").read_text(
            encoding="utf-8"
        )
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")

        self.assertEqual(containerfile.count(UPSTREAM_REVISION), 2)
        self.assertEqual(compose.count(UPSTREAM_REVISION), 0)
        self.assertIn(
            'test "$(git rev-parse HEAD)" = "${OIDF_SUITE_UPSTREAM_REVISION}"',
            containerfile,
        )
        self.assertIn('test -z "$(git status --porcelain)"', containerfile)
        self.assertNotIn("NAZOAUTH_SOURCE_REVISION", containerfile)
        self.assertIn(
            '--label "run.nazoauth.source.revision=$source_revision"', bootstrap
        )
        self.assertIn(
            "require_image_label \"$suite_image\" run.nazoauth.source.revision",
            bootstrap,
        )
        self.assertNotIn("git apply", containerfile)
        self.assertNotIn("OIDF_SUITE_OVERLAY", containerfile)
        self.assertNotIn("OIDF_SUITE_OVERLAY", compose)
        self.assertNotIn("build:", compose)

    def test_host_suite_defaults_to_podman_and_has_no_fixed_target_hostname(self):
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('container_runtime=${OIDF_CONTAINER_RUNTIME:-podman}', bootstrap)
        self.assertIn(': "${OIDF_TARGET_HOSTNAME:?set OIDF_TARGET_HOSTNAME}"', bootstrap)
        self.assertIn(
            '--env "OIDF_TARGET_HOSTNAME=$OIDF_TARGET_HOSTNAME"', bootstrap
        )
        self.assertIn('--build-context "oidf_suite=$OIDF_SUITE_SOURCE_DIR"', bootstrap)
        self.assertIn('git -C "$NAZOAUTH_SOURCE_DIR" status --porcelain', bootstrap)
        self.assertIn("run.nazoauth.source.revision", bootstrap)
        self.assertIn("compose up -d --no-build mongodb", bootstrap)
        self.assertIn("compose up -d --no-build\n", bootstrap)
        self.assertIn("Reusing exact OIDF Suite image", bootstrap)

    def test_suite_token_is_a_fresh_temporary_lease_with_protected_metadata(self):
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")
        revoke = (
            ROOT / "deploy" / "oidf-suite" / "revoke-api-token.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("OIDF_SUITE_TOKEN_METADATA_FILE", bootstrap)
        self.assertIn('data=b\'{"permanent":false}\'', bootstrap)
        self.assertIn('payload.get("_id")', bootstrap)
        self.assertIn('payload.get("expires")', bootstrap)
        self.assertIn("os.O_EXCL", bootstrap)
        self.assertIn("os.O_NOFOLLOW", bootstrap)
        self.assertIn("stat.S_IMODE(metadata.st_mode) != 0o600", bootstrap)
        self.assertIn('sh "$script_dir/revoke-api-token.sh"', bootstrap)
        self.assertNotIn("Reusing the existing protected suite token", bootstrap)
        self.assertIn('method="DELETE"', revoke)
        self.assertIn("status not in {200, 404}", revoke)
        self.assertIn("retaining protected token files", revoke)
        self.assertIn("legacy suite token file", revoke)
        self.assertIn("TOKEN_TTL_MS", revoke)

    def test_tls_ingress_and_pki_initialization_are_explicit_podman_steps(self):
        bootstrap = (
            ROOT / "deploy" / "oidf-suite" / "bootstrap-api-token.sh"
        ).read_text(encoding="utf-8")
        compose = (ROOT / "deploy" / "oidf-suite" / "compose.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "image: nazoauth-oidf-suite-nginx:${OIDF_SUITE_IMAGE_TAG:-321bc5bc}",
            compose,
        )
        self.assertIn('"0.0.0.0:8443:8443"', compose)
        self.assertNotIn('"0.0.0.0:8443:8080"', compose)
        self.assertNotIn("  pki-init:\n", compose)
        self.assertNotIn("  server-bootstrap:\n", compose)
        self.assertIn("name: nazoauth-oidf-suite-default", compose)
        self.assertIn('"$container_runtime" volume inspect nazoauth-oidf-proxy-pki', bootstrap)
        self.assertIn('"$container_runtime" volume create nazoauth-oidf-proxy-pki', bootstrap)
        self.assertIn("--volume nazoauth-oidf-proxy-pki:/pki", bootstrap)
        self.assertIn("external: true", compose)
        self.assertIn('"$container_runtime" run --rm', bootstrap)
        self.assertIn("--network nazoauth-oidf-suite-default", bootstrap)
        self.assertIn("--publish 127.0.0.1:18443:8080", bootstrap)
        self.assertIn('"$container_runtime" rm -f "$bootstrap_container"', bootstrap)
        self.assertIn('"$OIDF_SUITE_SOURCE_DIR/nginx/Dockerfile"', bootstrap)
        self.assertIn("Reusing exact OIDF Suite TLS ingress image", bootstrap)


if __name__ == "__main__":
    unittest.main()
