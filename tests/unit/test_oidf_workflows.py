import json
import unittest
from pathlib import Path


def workflow_heredoc_json(workflow: str, name: str):
    marker = f"cat > {name} <<'JSON'"
    payload = workflow.split(marker, 1)[1].split("JSON", 1)[0]
    return json.loads(payload)

class OidfWorkflowTests(unittest.TestCase):
    def test_public_seed_artifacts_include_a_validated_mtls_ca_bundle(self):
        root = Path(__file__).resolve().parents[2]
        validation = (
            "python scripts/oidf_mtls_ca_bundle.py verify \\\n"
            "            --artifact-directory oidf-public-plan-configs"
        )
        for name in ("oidf-public-seed-configs.yml", "oidf-conformance-full.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            self.assertIn(validation, workflow)
            self.assertIn('--source-commit "$GITHUB_SHA"', workflow)
            self.assertIn('--expected-source-commit "$GITHUB_SHA"', workflow)
            self.assertIn("path: oidf-public-plan-configs", workflow)

    def test_oidf_workflows_default_to_latest_verified_release(self):
        root = Path(__file__).resolve().parents[2]
        expected = "dee9a25160e789f0f80517674693ef7989ab9fa1"
        for name in ("oidf-conformance.yml", "oidf-conformance-full.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn(f"OIDF_CONFORMANCE_SUITE_REF || '{expected}'", workflow)
            self.assertNotIn("33a724c7d809a6f9db05cbb513ff2a77cbac905e", workflow)

    def test_every_oidf_suite_checkout_applies_the_sha_bound_runner_patch(self):
        root = Path(__file__).resolve().parents[2]
        patch_command = (
            "python scripts/apply_oidf_runner_patch.py "
            "--suite-dir oidf-conformance-suite"
        )
        for name in ("oidf-conformance.yml", "oidf-conformance-full.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8"
            )
            self.assertEqual(
                workflow.count(patch_command),
                workflow.count("git -C oidf-conformance-suite checkout --detach FETCH_HEAD"),
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

    def test_full_matrix_workflow_defaults_to_no_parallel_runner(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("NO_PARALLEL: ${{ vars.OIDF_NO_PARALLEL || 'true' }}", workflow)
        self.assertIn('if [ "$NO_PARALLEL" = "true" ]; then', workflow)
        self.assertIn("args+=(--no-parallel)", workflow)

    def test_full_matrix_workflow_has_parallel_isolated_mode(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("runner_mode:", workflow)
        self.assertIn("parallel-isolated", workflow)
        self.assertIn("oidf-concurrent-plan-set.json", workflow)
        self.assertIn("oidf-frontchannel-plan-set.json", workflow)
        self.assertIn("oidf-session-management-plan-set.json", workflow)

        full_plan_set = workflow_heredoc_json(workflow, "oidf-full-plan-set.json")
        concurrent_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-concurrent-plan-set.json",
        )
        serial_plan_set = workflow_heredoc_json(
            workflow,
            "oidf-frontchannel-plan-set.json",
        ) + workflow_heredoc_json(
            workflow,
            "oidf-session-management-plan-set.json",
        )

        self.assertEqual(len(full_plan_set), 21)
        self.assertEqual(len(concurrent_plan_set), 19)
        self.assertEqual(len(serial_plan_set), 2)
        self.assertEqual(len(set(full_plan_set)), 21)
        self.assertFalse(set(concurrent_plan_set) & set(serial_plan_set))
        self.assertTrue(any("oidcc-basic-certification-test-plan" in plan for plan in concurrent_plan_set))
        self.assertTrue(
            any("oidcc-dynamic-certification-test-plan" in plan for plan in concurrent_plan_set)
        )
        self.assertIn(
            "oidcc-dynamic-certification-test-plan[response_type=code]:"
            "oidcc-userinfo-rs256 oidf-oidcc-dynamic-crypto-plan-config.json",
            concurrent_plan_set,
        )
        self.assertFalse(
            any("frontchannel-rp-initiated-logout" in plan for plan in concurrent_plan_set)
        )
        self.assertFalse(
            any("session-management-certification-test-plan" in plan for plan in concurrent_plan_set)
        )
        self.assertEqual(
            sorted(full_plan_set),
            sorted(concurrent_plan_set + serial_plan_set),
        )

        expected_skips = workflow_heredoc_json(workflow, "oidf-expected-skips.json")
        self.assertEqual(len(expected_skips), 2)
        self.assertNotIn(
            "oidf-oidcc-dynamic-crypto-plan-config.json",
            {item["configuration-filename"] for item in expected_skips},
        )

        self.assertIn('"$GITHUB_WORKSPACE/oidf-results/$export_subdir"', workflow)

    def test_parallel_isolated_mode_uses_separate_browser_sensitive_jobs(self):
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "oidf-conformance-full.yml"
        ).read_text(encoding="utf-8")

        parallel_case = workflow.split("parallel-isolated)", 1)[1].split(";;", 1)[0]
        self.assertIn("run_oidf_plan_set oidf-concurrent-plan-set.json concurrent", parallel_case)
        self.assertNotIn("oidf-browser-sensitive-plan-set.json", parallel_case)

        self.assertIn("oidf-conformance-browser-isolated:", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("plan_set_file: oidf-frontchannel-plan-set.json", workflow)
        self.assertIn("plan_set_file: oidf-session-management-plan-set.json", workflow)
        self.assertIn('--plan-set-json-file "${{ matrix.plan_set_file }}"', workflow)
        self.assertIn("--no-parallel", workflow)
        self.assertIn("oidf-conformance-results-frontchannel", workflow)
        self.assertIn("oidf-conformance-results-session-management", workflow)
        self.assertNotIn("oidf-conformance-results-oidcc-basic-static", workflow)


if __name__ == "__main__":
    unittest.main()
