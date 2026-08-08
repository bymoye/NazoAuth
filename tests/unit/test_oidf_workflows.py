import json
import unittest
from pathlib import Path


def workflow_heredoc_json(workflow: str, name: str):
    marker = f"cat > {name} <<'JSON'"
    payload = workflow.split(marker, 1)[1].split("JSON", 1)[0]
    return json.loads(payload)

class OidfWorkflowTests(unittest.TestCase):
    def test_github_secrets_are_scoped_to_the_single_materializer_step_per_job(self):
        root = Path(__file__).resolve().parents[2]
        workflows = {
            "oidf-conformance.yml": {
                "jobs": 1,
                "secrets": (
                    "OIDF_PLAN_CONFIG_AGE_IDENTITY",
                    "OIDF_CIBA_AUTOMATED_DECISION_TOKEN",
                    "OIDF_CONFORMANCE_TOKEN",
                ),
            },
            "oidf-conformance-full.yml": {
                "jobs": 2,
                "secrets": (
                    "OIDF_PLAN_CONFIG_AGE_IDENTITY",
                    "OIDF_MTLS_MATERIAL_AGE_IDENTITY",
                    "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
                    "OIDF_CIBA_AUTOMATED_DECISION_TOKEN",
                    "OIDF_DELIVERED_CLIENT_MATERIAL_JSON",
                    "OIDF_CONFORMANCE_TOKEN",
                    "OIDF_USER_EMAIL",
                    "OIDF_USER_PASSWORD",
                ),
            },
            "openid4vc-conformance.yml": {
                "jobs": 1,
                "secrets": (
                    "OIDF_CONFORMANCE_TOKEN",
                    "OPENID4VC_OIDF_BASE_CONFIG_JSON",
                    "OPENID4VC_OIDF_MTLS_CONFIG_JSON",
                    "OPENID4VC_OIDF_DRIVER_CONFIG_JSON",
                    "OIDF_DELIVERED_CLIENT_MATERIAL_JSON",
                    "OIDF_USER_EMAIL",
                    "OIDF_USER_PASSWORD",
                    "OIDF_ADMIN_EMAIL",
                    "OIDF_ADMIN_PASSWORD",
                ),
            },
        }
        for name, contract in workflows.items():
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            jobs = contract["jobs"]
            self.assertEqual(
                workflow.count("materialize_github_oidf_secrets.py"),
                jobs,
                name,
            )
            self.assertEqual(
                workflow.count('rm -rf -- "$RUNNER_TEMP/oidf-secrets"'),
                jobs,
                name,
            )
            for secret in contract["secrets"]:
                self.assertEqual(
                    workflow.count(f"${{{{ secrets.{secret} }}}}"),
                    jobs,
                    f"{name}: {secret} must appear only on its materializer step",
                )

    def test_public_onboarding_workflow_derives_the_complete_ciba_matrix(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (
            root / ".github" / "workflows" / "oidf-public-onboarding-material.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("--derive-fapi-ciba-matrix-configs", workflow)
        self.assertIn(
            '--ciba-notification-base-url "$SUITE_BASE_URL"',
            workflow,
        )
        self.assertNotIn("suite_base_url:", workflow)
        self.assertIn(
            '--suite-base-url "$SUITE_BASE_URL"',
            workflow,
        )
        self.assertIn(
            "SUITE_BASE_URL: https://www.certification.openid.net",
            workflow,
        )
        self.assertNotIn("OIDF_CONFORMANCE_SERVER", workflow)
        self.assertIn("materialize_openid4vc_oidf_config.py", workflow)
        self.assertIn(
            "--config-json-file runtime/openid4vc/materialized/openid4vc-plan-configs.json",
            workflow,
        )
        self.assertIn("OPENID4VC_OIDF_BASE_CONFIG_JSON", workflow)
        self.assertIn("OPENID4VC_OIDF_DRIVER_CONFIG_JSON", workflow)
        self.assertIn("workflow_call:", workflow)
        self.assertEqual(workflow.count("credential_holder_email_sha256:"), 2)
        self.assertIn(
            '--credential-holder-email-sha256 "${{ inputs.credential_holder_email_sha256 }}"',
            workflow,
        )
        for secret in (
            "OIDF_PLAN_CONFIG_AGE_IDENTITY",
            "OIDF_MTLS_MATERIAL_AGE_IDENTITY",
            "OPENID4VC_OIDF_BASE_CONFIG_JSON",
            "OPENID4VC_OIDF_MTLS_CONFIG_JSON",
            "OPENID4VC_OIDF_DRIVER_CONFIG_JSON",
        ):
            self.assertIn(f"      {secret}:\n        required: true", workflow)
        self.assertNotIn("secrets.OIDF_CIBA_AUTOMATED_DECISION_TOKEN", workflow)
        self.assertNotIn(
            "secrets.OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN", workflow
        )
        self.assertIn("secrets.token_urlsafe(48)", workflow)
        self.assertIn(
            "--dynamic-registration-token-file dynamic-registration-initial-access-token",
            workflow,
        )

    def test_oidc_fapi_mtls_material_is_encrypted_and_applied_everywhere(self):
        root = Path(__file__).resolve().parents[2]
        encrypted = root / "docs" / "conformance" / "oidf-mtls-material.json.age"
        self.assertTrue(encrypted.is_file())
        self.assertNotIn("PRIVATE KEY", encrypted.read_bytes().decode("latin-1"))
        template = (
            root / "docs" / "conformance" / "oidf-plan-config-template.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn("-----BEGIN CERTIFICATE-----", template)
        for name in (
            "oidf-public-onboarding-material.yml",
            "oidf-conformance-full.yml",
        ):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            self.assertIn("OIDF_MTLS_MATERIAL_AGE_IDENTITY", workflow)
            self.assertIn("docs/conformance/oidf-mtls-material.json.age", workflow)
            self.assertIn("--mtls-material-file oidf-mtls-material.json", workflow)

    def test_full_matrix_can_bootstrap_official_onboarding_without_creating_plans(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (
            root / ".github" / "workflows" / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("onboarding_material_only:", workflow)
        self.assertIn(
            "uses: ./.github/workflows/oidf-public-onboarding-material.yml",
            workflow,
        )
        self.assertIn(
            "credential_holder_email_sha256: ${{ inputs.credential_holder_email_sha256 }}",
            workflow,
        )
        self.assertIn("release_tag: ${{ inputs.release_tag }}", workflow)
        self.assertIn("secrets: inherit", workflow)
        self.assertIn("if: ${{ !inputs.onboarding_material_only }}", workflow)
        self.assertIn(
            "if: ${{ !inputs.onboarding_material_only && inputs.runner_mode == 'parallel-isolated' }}",
            workflow,
        )
        self.assertEqual(
            workflow.count(
                '--dynamic-registration-token-file "$RUNNER_TEMP/oidf-secrets/dynamic-registration-token"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count("python scripts/materialize_github_oidf_secrets.py"),
            2,
        )
        self.assertEqual(
            workflow.count('rm -rf -- "$RUNNER_TEMP/oidf-secrets"'),
            2,
        )

    def test_official_runners_require_production_delivered_client_material(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("oidf-conformance-full.yml", "openid4vc-conformance.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            self.assertIn("OIDF_DELIVERED_CLIENT_MATERIAL_JSON", workflow)
            self.assertIn("apply_oidf_delivered_client_material.py", workflow)
            self.assertIn("--expected-target-issuer", workflow)
            self.assertIn("--expected-suite-base-url", workflow)

    def test_github_oidf_workflows_only_target_the_official_service(self):
        root = Path(__file__).resolve().parents[2]
        for name in (
            "oidf-conformance.yml",
            "oidf-conformance-full.yml",
            "oidf-public-onboarding-material.yml",
            "openid4vc-conformance.yml",
        ):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            with self.subTest(workflow=name):
                self.assertIn(
                    "https://www.certification.openid.net",
                    workflow,
                )
                self.assertNotIn("vars.OIDF_CONFORMANCE_SERVER", workflow)
                self.assertNotIn("oauth-test.nazo.run", workflow)

    def test_public_onboarding_artifacts_include_a_validated_mtls_ca_bundle(self):
        root = Path(__file__).resolve().parents[2]
        validation = (
            "python scripts/oidf_onboarding_bundle.py verify \\\n"
            "            --artifact-directory oidf-public-onboarding-material"
        )
        workflow = (
            root / ".github" / "workflows" / "oidf-public-onboarding-material.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(validation, workflow)
        self.assertIn('--source-commit "$SOURCE_COMMIT"', workflow)
        self.assertIn('--expected-source-commit "$SOURCE_COMMIT"', workflow)
        self.assertIn('git checkout --detach "$SOURCE_COMMIT"', workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"', workflow)
        self.assertIn("path: oidf-public-onboarding-material", workflow)

        conformance = (
            root / ".github" / "workflows" / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("Upload public OIDF onboarding material", conformance)

    def test_public_workflows_accept_only_exact_tag_bound_release_source(self):
        root = Path(__file__).resolve().parents[2]
        workflows = {
            "oidf-public-onboarding-material.yml": "SOURCE_COMMIT",
            "oidf-conformance-full.yml": "DEPLOYED_SHA",
        }
        for name, source_variable in workflows.items():
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            with self.subTest(workflow=name):
                self.assertIn("release_tag:", workflow)
                self.assertIn("required: true", workflow)
                self.assertIn("attestations: read", workflow)
                self.assertIn("RELEASE_TAG: ${{ inputs.release_tag }}", workflow)
                self.assertIn(
                    'git fetch --no-tags origin "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"',
                    workflow,
                )
                self.assertIn(
                    f'test "$(git rev-parse "refs/tags/$RELEASE_TAG^{{commit}}")" = "${source_variable}"',
                    workflow,
                )
                self.assertNotIn(
                    f'if ! git merge-base --is-ancestor "${source_variable}" "origin/${{{{ github.event.repository.default_branch }}}}"; then',
                    workflow,
                )
                self.assertIn(
                    'gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json tagName,isDraft',
                    workflow,
                )
                self.assertIn(
                    'test "$(jq -r \'.isDraft\' <<<"$release_json")" = false',
                    workflow,
                )
                self.assertIn(
            'bootstrap_subject="nazoauth-x86_64-unknown-linux-gnu"',
                    workflow,
                )
                self.assertIn(
            'bootstrap_subject="nazoauth-aarch64-unknown-linux-gnu"',
                    workflow,
                )
                self.assertIn('gh release download "$RELEASE_TAG"', workflow)
                self.assertIn('gh attestation verify "$subject"', workflow)
                self.assertIn(
                    '--cert-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release-security.yml@refs/tags/$RELEASE_TAG"',
                    workflow,
                )
                self.assertIn('--source-ref "refs/tags/$RELEASE_TAG"', workflow)
                self.assertIn(f'--source-digest "${source_variable}"', workflow)
                self.assertIn(
                    '--predicate-type "https://nazo.run/attestations/release-manifest/v1"',
                    workflow,
                )
                self.assertIn("--deny-self-hosted-runners", workflow)
                self.assertNotIn("github.head_ref", workflow)
                self.assertNotIn("refs/heads/$RELEASE_TAG", workflow)

                attestation = workflow.index('gh attestation verify "$subject"')
                checkout = workflow.index(f'git checkout --detach "${source_variable}"')
                self.assertLess(attestation, checkout)

        onboarding = (
            root / ".github" / "workflows" / "oidf-public-onboarding-material.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(onboarding.count("release_tag:"), 2)
        full = (root / ".github" / "workflows" / "oidf-conformance-full.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(full.count("needs: verify-release-source"), 2)
        self.assertEqual(full.count("ref: ${{ inputs.deployed_sha }}"), 2)
        self.assertEqual(full.count("git merge-base --is-ancestor"), 0)

    def test_public_runner_checks_out_the_exact_deployed_revision(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("oidf-conformance.yml", "openid4vc-conformance.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn('git checkout --detach "$DEPLOYED_SHA"', workflow)
                self.assertIn('test "$(git rev-parse HEAD)" = "$DEPLOYED_SHA"', workflow)
                self.assertIn(
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                    workflow,
                )

        oidf = (root / ".github" / "workflows" / "oidf-conformance.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(oidf.count('"$RUNNER_TEMP/oidf-secrets/plan-config.agekey"'), 2)
        self.assertNotIn("--identity oidf-plan-config.agekey", oidf)

    def test_oidf_workflows_default_to_latest_verified_release(self):
        root = Path(__file__).resolve().parents[2]
        expected = "dee9a25160e789f0f80517674693ef7989ab9fa1"
        for name in ("oidf-conformance.yml", "oidf-conformance-full.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn(f"OIDF_CONFORMANCE_SUITE_REF || '{expected}'", workflow)
            self.assertNotIn("33a724c7d809a6f9db05cbb513ff2a77cbac905e", workflow)

    def test_every_oidf_suite_checkout_preserves_official_tracked_sources(self):
        root = Path(__file__).resolve().parents[2]
        for name in (
            "oidf-conformance.yml",
            "oidf-conformance-full.yml",
            "openid4vc-conformance.yml",
        ):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("apply_oidf_runner_patch", workflow)
            self.assertEqual(
                workflow.count("status --porcelain --untracked-files=no"),
                2
                * workflow.count(
                    "git -C oidf-conformance-suite checkout --detach FETCH_HEAD"
                ),
            )

    def test_spec_freshness_workflow_separates_offline_and_online_checks(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "spec-freshness.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("python scripts/check_spec_freshness.py --offline", workflow)
        self.assertIn("python scripts/check_spec_freshness.py", workflow)
        self.assertIn("github.event_name != 'pull_request'", workflow)
        self.assertIn('      - "README.md"', workflow)
        self.assertIn("    needs: offline", workflow)
        self.assertIn("rhysd/actionlint:1.7.12", workflow)

    def test_full_matrix_workflow_keeps_serial_fallback(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("NO_PARALLEL: ${{ vars.OIDF_NO_PARALLEL || 'true' }}", workflow)
        self.assertIn('if [ "$NO_PARALLEL" = "true" ]; then', workflow)
        self.assertIn("args+=(--no-parallel)", workflow)

    def test_full_matrix_workflow_defaults_to_parallel_isolated_runner(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("default: parallel-isolated", workflow)
        self.assertIn(
            "RUNNER_MODE: ${{ inputs.runner_mode || vars.OIDF_RUNNER_MODE || 'parallel-isolated' }}",
            workflow,
        )

    def test_full_matrix_workflow_requires_explicit_target_issuer(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("target_issuer:", workflow)
        self.assertIn("required: true", workflow)
        self.assertIn(
            "OIDF_TARGET_ISSUER: ${{ inputs.target_issuer }}",
            workflow,
        )
        self.assertNotIn("OIDF_TARGET_ISSUER || 'https://auth.nazo.run'", workflow)
        self.assertIn("Supply workflow_dispatch input target_issuer", workflow)

    def test_full_matrix_workflow_has_parallel_isolated_mode(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github" / "workflows" / "oidf-conformance-full.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("runner_mode:", workflow)
        self.assertIn("parallel-isolated", workflow)
        self.assertIn("oidf-concurrent-plan-set.json", workflow)
        self.assertIn("oidf-ciba-plan-set.json", workflow)
        self.assertIn("01-oidc-core.json", workflow)
        self.assertIn("03a-fapi-ciba-private-key-jwt-poll.json", workflow)
        self.assertIn("03d-fapi-ciba-mtls-ping.json", workflow)
        self.assertIn("07-fapi-private-mtls.json", workflow)
        self.assertIn("oidf-rp-initiated-plan-set.json", workflow)
        self.assertIn("oidf-backchannel-plan-set.json", workflow)
        self.assertIn("oidf-frontchannel-plan-set.json", workflow)
        self.assertIn("oidf-session-management-plan-set.json", workflow)

        full_plan_set = workflow_heredoc_json(workflow, "oidf-full-plan-set.json")
        concurrent_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-concurrent-plan-set.json",
        )
        ciba_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-ciba-plan-set.json",
        )
        serial_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-rp-initiated-plan-set.json",
        ) + workflow_heredoc_json(
            workflow,
            "oidf-backchannel-plan-set.json",
        ) + workflow_heredoc_json(
            workflow,
            "oidf-frontchannel-plan-set.json",
        ) + workflow_heredoc_json(
            workflow,
            "oidf-session-management-plan-set.json",
        )

        self.assertEqual(len(full_plan_set), 27)
        self.assertEqual(len(concurrent_plan_set), 19)
        self.assertEqual(len(ciba_plan_set), 4)
        self.assertEqual(len(serial_plan_set), 4)
        self.assertEqual(len(set(full_plan_set)), 27)
        self.assertEqual(
            sum("fapi-ciba-id1-test-plan" in plan for plan in ciba_plan_set),
            4,
        )
        self.assertFalse(any("fapi-ciba-id1-test-plan" in plan for plan in concurrent_plan_set))
        self.assertFalse(set(concurrent_plan_set) & set(serial_plan_set))
        self.assertFalse(set(ciba_plan_set) & set(serial_plan_set))
        self.assertFalse(set(ciba_plan_set) & set(concurrent_plan_set))
        self.assertTrue(any("oidcc-basic-certification-test-plan" in plan for plan in concurrent_plan_set))
        self.assertFalse(
            any("oidcc-dynamic-certification-test-plan" in plan for plan in full_plan_set)
        )
        third_party_init = (
            "oidcc-3rdparty-init-login-certification-test-plan[response_type=code] "
            "oidf-oidcc-third-party-init-plan-config.json"
        )
        self.assertIn(third_party_init, concurrent_plan_set)
        setup_source = (root / "scripts" / "prepare_oidf_black_box.py").read_text(
            encoding="utf-8"
        )
        runner_source = (root / "scripts" / "run_oidf_conformance.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"oidcc-3rdparty-init-login-certification-test-plan[response_type=code] "',
            setup_source,
        )
        self.assertIn('"oidf-oidcc-third-party-init-plan-config.json"', setup_source)
        self.assertIn(
            'f"oidcc-3rdparty-init-login-certification-test-plan[response_type=code] '
            '{OIDCC_THIRD_PARTY_INIT_CONFIG_FILE}"',
            runner_source,
        )
        self.assertFalse(
            any("frontchannel-rp-initiated-logout" in plan for plan in concurrent_plan_set)
        )
        self.assertFalse(
            any("session-management-certification-test-plan" in plan for plan in concurrent_plan_set)
        )
        self.assertEqual(
            sorted(full_plan_set),
            sorted(concurrent_plan_set + ciba_plan_set + serial_plan_set),
        )

        expected_skips = workflow_heredoc_json(workflow, "oidf-expected-skips.json")
        self.assertEqual(len(expected_skips), 8)
        self.assertEqual(
            {item["configuration-filename"] for item in expected_skips},
            {
                "oidf-oidcc-basic-plan-config.json",
                "oidf-oidcc-dynamic-plan-config.json",
                "oidf-oidcc-formpost-plan-config.json",
            },
        )
        self.assertIn(
            "--expected-failures-file \"$expected_warnings_file\"",
            workflow,
        )
        self.assertIn("tests/contracts/oidf-official-expected-warnings.json", workflow)
        self.assertIn('local expected_skips_file="$RUNNER_TEMP/${plan_set_file%.json}-expected-skips.json"', workflow)

        expected_warnings = json.loads(
            (root / "tests" / "contracts" / "oidf-official-expected-warnings.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(len(expected_warnings), 26)
        self.assertEqual(
            {item["condition"] for item in expected_warnings},
            {"EnsureIncomingTls13"},
        )
        self.assertEqual(
            {item["expected-result"] for item in expected_warnings},
            {"warning"},
        )
        ciba_warnings = [
            item for item in expected_warnings if item["condition"] == "EnsureIncomingTls13"
        ]
        self.assertEqual(
            {item["variant"]["client_auth_type"] for item in ciba_warnings},
            {"private_key_jwt", "mtls"},
        )
        self.assertEqual({item["variant"]["ciba_mode"] for item in ciba_warnings}, {"ping"})
        self.assertEqual(
            {item["variant"]["fapi_ciba_profile"] for item in ciba_warnings},
            {"plain_fapi"},
        )
        self.assertEqual(
            {item["variant"]["client_registration"] for item in ciba_warnings},
            {"static_client"},
        )
        self.assertFalse(
            any("*" in json.dumps(item, sort_keys=True) for item in expected_warnings),
            "OIDF expected warnings must remain exact, not wildcard based",
        )

        self.assertIn('--export-dir "$RUNNER_TEMP/oidf-evidence/${plan_set_file%.json}"', workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn(
            "path: ${{ runner.temp }}/oidf-evidence/evidence-manifest.json",
            workflow,
        )
        self.assertNotIn("path: ${{ runner.temp }}/oidf-evidence\n", workflow)

    def test_parallel_isolated_mode_uses_separate_browser_sensitive_jobs(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        parallel_case = workflow.split("parallel-isolated)", 1)[1].split(";;", 1)[0]
        self.assertIn("run_oidf_plan_set 01-oidc-core.json", parallel_case)
        self.assertIn("run_oidf_plan_set 02-oidc-formpost-thirdparty-config.json", parallel_case)
        self.assertIn(
            "run_oidf_plan_set 03a-fapi-ciba-private-key-jwt-poll.json --no-parallel",
            parallel_case,
        )
        self.assertIn(
            "run_oidf_plan_set 03b-fapi-ciba-mtls-poll.json --no-parallel",
            parallel_case,
        )
        self.assertIn(
            "run_oidf_plan_set 03c-fapi-ciba-private-key-jwt-ping.json --no-parallel",
            parallel_case,
        )
        self.assertIn(
            "run_oidf_plan_set 03d-fapi-ciba-mtls-ping.json --no-parallel",
            parallel_case,
        )
        self.assertNotIn("run_oidf_plan_set 03-fapi-ciba.json", parallel_case)
        self.assertIn("run_oidf_plan_set 07-fapi-private-mtls.json", parallel_case)
        self.assertNotIn("oidf-browser-sensitive-plan-set.json", parallel_case)

        self.assertIn("oidf-conformance-browser-isolated:", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("plan_set_file: oidf-frontchannel-plan-set.json", workflow)
        self.assertIn("plan_set_file: oidf-session-management-plan-set.json", workflow)
        self.assertIn('--plan-set-json-file "${{ matrix.plan_set_file }}"', workflow)
        self.assertIn("--no-parallel", workflow)
        self.assertIn('--export-dir "$RUNNER_TEMP/oidf-evidence"', workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)


if __name__ == "__main__":
    unittest.main()
