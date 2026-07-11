#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "perf" / "results"
DOCS = ROOT / "docs" / "performance" / "archive" / "dev"
DURATION = "30m"
INSTANCES = "1,2,4"
SCENARIO_RATES = {
    "token_only_client_credentials": "1000, 2500, 5000, 7500, 10000 flow/s",
    "oidc_cold_login_refresh": "16, 32, 64, 128, 256 flow/s",
    "oidc_logged_in_authorization_code": "16, 32, 64, 128, 256 flow/s",
    "oidc_refresh_only": "250, 500, 1000, 1500, 2000 flow/s",
    "fapi2_full_security": "16, 32, 64, 128, 256 flow/s",
}
SUFFIX_SCENARIO = {
    "token-only": "token_only_client_credentials",
    "oidc-cold-login": "oidc_cold_login_refresh",
    "oidc-logged-in": "oidc_logged_in_authorization_code",
    "oidc-refresh-only": "oidc_refresh_only",
    "fapi2-full-security": "fapi2_full_security",
}


def load_capacity_module():
    spec = importlib.util.spec_from_file_location("capacity_report", ROOT / "perf" / "capacity.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load perf/capacity.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command: list[str], timeout: int = 8) -> str:
    try:
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    output = completed.stdout.strip() or completed.stderr.strip()
    return output.replace("|", "-") if output else "unknown"


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def cpuset_for_suffix(suffix: str) -> str:
    text = read_text(RESULTS / f"docker-compose.cpuset-dev-{suffix}.yml")
    match = re.search(r"cpuset:\s*[\"']?([^\"'\n]+)", text)
    return match.group(1).strip() if match else "unrestricted"


def cpuset_count(value: str) -> str:
    if value == "unrestricted":
        return "unrestricted"
    count = 0
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = [int(item) for item in part.split("-", 1)]
            count += end - start + 1
        else:
            count += 1
    return str(count)


def markdown_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {field} | {value} |" for field, value in rows)
    return "\n".join(lines)


def evidence_block(*, suffix: str, scenario: str) -> str:
    cpuset = cpuset_for_suffix(suffix)
    rows = [
        ("Source commit", run(["git", "rev-parse", "HEAD"], 4)),
        ("Runner tag", "cnb:arch:amd64"),
        ("CPU set", cpuset),
        ("CPU set size", cpuset_count(cpuset)),
        ("Capacity scenario", scenario),
        ("Duration per point", DURATION),
        ("App instance stages", f"{INSTANCES} NazoAuth replica(s)"),
        ("Target rates", SCENARIO_RATES.get(scenario, "custom")),
        ("Results JSON", f"[perf/results/capacity-dev-{suffix}.json](../../../../perf/results/capacity-dev-{suffix}.json)"),
    ]
    return "## Evidence\n\n" + markdown_table(rows) + "\n\n"


def insert_evidence(source: str, evidence: str) -> str:
    source = re.sub(
        r"\n## Test Environment(?: and Topology)?\n\n\| Field \| Value \|\n\| --- \| --- \|\n(?:\| .* \| .* \|\n)+\n",
        "\n",
        source,
    )
    source = re.sub(r"\n## Notes\n\n(?:- .*\n)+", "\n", source)
    marker = "\n## Run Configuration\n"
    if marker in source:
        return source.replace(marker, "\n" + evidence + "## Run Configuration\n", 1)
    return source.rstrip() + "\n\n" + evidence


def finalize_report(*, capacity, suffix: str, scenario: str, require_complete: bool) -> None:
    results_path = RESULTS / f"capacity-dev-{suffix}.json"
    report_path = DOCS / f"performance-capacity-curve-dev-{suffix}.md"
    if not results_path.exists():
        print(f"skip {suffix}: missing {results_path}")
        return
    data = capacity.json.loads(results_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{suffix}: expected list results, got {type(data).__name__}")
    if require_complete and len(data) < 15:
        raise SystemExit(f"{suffix}: expected 15 capacity points before writeback, got {len(data)}")
    capacity.write_report(data, duration=DURATION, report_path=report_path, results_path=results_path)
    source = report_path.read_text(encoding="utf-8")
    source = insert_evidence(source, evidence_block(suffix=suffix, scenario=scenario))
    report_path.write_text(source, encoding="utf-8", newline="\n")
    print(f"finalized {report_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-partial", action="store_true", help="Rewrite reports even if fewer than 15 points are present.")
    args = parser.parse_args()

    capacity = load_capacity_module()
    for suffix, scenario in SUFFIX_SCENARIO.items():
        finalize_report(capacity=capacity, suffix=suffix, scenario=scenario, require_complete=not args.allow_partial)


if __name__ == "__main__":
    main()
