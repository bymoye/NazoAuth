import json
import unittest
from pathlib import Path


def workflow_heredoc_json(workflow: str, name: str):
    marker = f"cat > {name} <<'JSON'"
    payload = workflow.split(marker, 1)[1].split("JSON", 1)[0]
    return json.loads(payload)

class OidfWorkflowTests(unittest.TestCase):
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

        self.assertEqual(len(full_plan_set), 20)
        self.assertEqual(len(concurrent_plan_set), 18)
        self.assertEqual(len(serial_plan_set), 2)
        self.assertEqual(len(set(full_plan_set)), 20)
        self.assertFalse(set(concurrent_plan_set) & set(serial_plan_set))
        self.assertTrue(any("oidcc-basic-certification-test-plan" in plan for plan in concurrent_plan_set))
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
