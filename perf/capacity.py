#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import time
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "perf" / "results"
DEFAULT_CAPACITY_RESULTS = RESULTS_DIR / "capacity-latest.json"
DEFAULT_CAPACITY_REPORT = ROOT / "docs" / "performance" / "performance-capacity-curve.md"
CHECKPOINT_LOCK = RESULTS_DIR / ".capacity-checkpoint.lock"

DEFAULT_RATES: dict[str, list[int]] = {
    "token_only_client_credentials": [1000, 2500, 5000, 7500, 10000],
    "oidc_cold_login_refresh": [16, 32, 64, 128, 256],
    "oidc_logged_in_authorization_code": [16, 32, 64, 128, 256],
    "oidc_refresh_only": [250, 500, 1000, 1500, 2000],
    "fapi2_full_security": [16, 32, 64, 128, 256],
    "fapi2_logged_in_high_security": [16, 32, 64, 128, 256],
    "mtls_client_credentials": [250, 500, 1000, 1500, 2000],
    "par_signed_request_object": [250, 500, 1000, 1500, 2000],
    "introspect_opaque_refresh_token": [16, 32, 64, 128, 256],
    "authorize_par_session": [16, 32, 64, 128, 256],
    "revoke_refresh_token": [16, 32, 64, 128, 256],
    "metadata_jwks": [250, 500, 1000, 1500, 2000],
    "ciba_private_key_jwt_dpop_poll": [16, 32, 64, 128, 256],
    "same_user_refresh_token_rotation": [8, 16, 32, 64, 128],
    "same_user_introspect_opaque_refresh_token": [8, 16, 32, 64, 128],
    "same_user_authorize_par_session": [8, 16, 32, 64, 128],
}


def parse_csv_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def run_command(command: list[str], env: dict[str, str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {' '.join(command)}")


def run_git(command: list[str], env: dict[str, str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if check and completed.returncode != 0:
        detail = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {' '.join(command)}\n{detail}")
    return completed


@contextlib.contextmanager
def checkpoint_lock():
    CHECKPOINT_LOCK.parent.mkdir(parents=True, exist_ok=True)
    acquired = False
    deadline = time.monotonic() + int(os.environ.get("CAPACITY_CHECKPOINT_LOCK_TIMEOUT_SECONDS", "900"))
    while time.monotonic() < deadline:
        try:
            CHECKPOINT_LOCK.mkdir()
            (CHECKPOINT_LOCK / "pid").write_text(str(os.getpid()), encoding="utf-8")
            acquired = True
            break
        except FileExistsError:
            time.sleep(2)
    if not acquired:
        raise RuntimeError(f"timed out waiting for capacity checkpoint lock: {CHECKPOINT_LOCK}")
    try:
        yield
    finally:
        try:
            for child in CHECKPOINT_LOCK.iterdir():
                child.unlink()
            CHECKPOINT_LOCK.rmdir()
        except FileNotFoundError:
            pass


def checkpoint_enabled() -> bool:
    return os.environ.get("CAPACITY_CHECKPOINT_COMMIT", "0") == "1"


def git_branch(env: dict[str, str]) -> str:
    configured = env.get("CAPACITY_CHECKPOINT_BRANCH") or env.get("CNB_BRANCH")
    if configured:
        return configured
    completed = run_git(["git", "branch", "--show-current"], env)
    branch = completed.stdout.strip()
    if not branch:
        raise RuntimeError("capacity checkpoint requires a checked-out branch")
    return branch


def checkpoint_commit(
    *,
    env: dict[str, str],
    report_path: Path,
    results_path: Path,
    instances: int,
    scenario: str,
    rate: int,
    status: str,
) -> None:
    if not checkpoint_enabled():
        return
    branch = git_branch(env)
    suffix = env.get("CAPACITY_REPORT_SUFFIX", scenario)
    run_git(["git", "config", "user.name", env.get("CNB_GIT_USER_NAME", "NazoAuth Capacity Bot")], env)
    run_git(
        ["git", "config", "user.email", env.get("CNB_GIT_USER_EMAIL", "nazoauth-capacity-bot@noreply.cnb.cool")],
        env,
    )
    paths = [display_path(report_path), display_path(results_path)]
    env_report = env.get("CAPACITY_ENV_REPORT_PATH")
    if env_report and root_path(env_report).exists():
        paths.append(display_path(root_path(env_report)))
    for attempt in range(1, 4):
        try:
            run_git(["git", "add", "-f", *paths], env)
            diff = run_git(["git", "diff", "--cached", "--quiet", "--", *paths], env, check=False)
            if diff.returncode == 0:
                print(f"capacity checkpoint has no changes for {suffix} {instances}x {scenario} {rate}/s")
                return
            message = f"Checkpoint capacity {suffix}: {instances}x {scenario} {rate}rps {status}"
            run_git(["git", "commit", "-m", message], env)
            run_git(["git", "pull", "--rebase", "--autostash", "origin", branch], env)
            run_git(["git", "push", "origin", f"HEAD:{branch}"], env)
            print(f"capacity checkpoint pushed: {suffix} {instances}x {scenario} {rate}/s status={status}")
            return
        except Exception as exc:
            print(f"capacity checkpoint attempt {attempt} failed: {exc}")
            if attempt == 3:
                if os.environ.get("CAPACITY_CHECKPOINT_STRICT", "1") == "1":
                    raise
                return
            time.sleep(attempt * 5)


def compose_project_name(env: dict[str, str]) -> str:
    value = env.get("COMPOSE_PROJECT_NAME", "nazoauth-perf").lower()
    value = re.sub(r"[^a-z0-9_-]+", "-", value).strip("-_")
    if not value or not value[0].isalnum():
        return "nazoauth-perf"
    return value[:63]


def compose_command(env: dict[str, str], *args: str) -> list[str]:
    compose_files = ["-f", "docker-compose.perf.yml"]
    if env.get("PERF_COMPOSE_OVERRIDE"):
        compose_files.extend(["-f", env["PERF_COMPOSE_OVERRIDE"]])
    return [
        "docker",
        "compose",
        "-p",
        compose_project_name(env),
        *compose_files,
        *args,
    ]


def copy_perf_results(env: dict[str, str], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run_command(compose_command(env, "cp", "perf:/results/.", str(destination)), env)


def root_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def service_metric(result: dict[str, Any], service: str, metric: str) -> float:
    return float(result.get("containers", {}).get("by_service", {}).get(service, {}).get(metric, 0))


def postgres_metric(result: dict[str, Any], metric: str) -> float:
    return float(result.get("postgres", {}).get(metric, 0))


def db_pool_metric(result: dict[str, Any], metric: str) -> float:
    return float(result.get("db_pool", {}).get(metric, 0))


def valkey_hit_rate(result: dict[str, Any]) -> float:
    valkey = result.get("valkey", {})
    hits = float(valkey.get("keyspace_hits", 0))
    misses = float(valkey.get("keyspace_misses", 0))
    total = hits + misses
    return hits / total if total > 0 else 0


def step_rps(result: dict[str, Any], *steps: str) -> float:
    wanted = set(steps)
    return sum(float(step["rps"]) for step in result.get("steps", []) if step["step"] in wanted)


def app_cpu_cores(result: dict[str, Any]) -> float:
    return service_metric(result, "nazoauth", "cpu_percent_avg") / 100


def per_core(value: float, result: dict[str, Any]) -> float:
    cores = app_cpu_cores(result)
    return value / cores if cores > 0 else 0


def target_ratio(result: dict[str, Any], target_rate: int) -> float:
    if target_rate <= 0:
        return 0
    return float(result.get("k6", {}).get("rps", 0)) / target_rate


def normalized_status(item: dict[str, Any]) -> str:
    result = item.get("result", {})
    if not isinstance(result, dict):
        return ""
    current = str(result.get("status", "passed"))
    if current in {"threshold_failed", "skipped_after_threshold_failure"}:
        return current
    target_rate = int(item.get("target_rate", 0) or 0)
    k6 = result.get("k6", {})
    dropped = int(k6.get("dropped_iterations", 0) or 0)
    if target_rate > 0 and (float(k6.get("rps", 0)) < target_rate * 0.99 or dropped > 0):
        return "target_miss"
    return current


def normalize_result_statuses(results: list[dict[str, Any]]) -> None:
    for item in results:
        result = item.get("result", {})
        if isinstance(result, dict):
            result["status"] = normalized_status(item)
            result.setdefault("k6", {}).setdefault("dropped_iterations", 0)
            result["k6"].setdefault("dropped_iterations_rate", 0)
            result["k6"]["target_rps_ratio"] = round(target_ratio(result, int(item.get("target_rate", 0) or 0)), 6)


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return lines


def write_report(results: list[dict[str, Any]], *, duration: str, report_path: Path, results_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    normalize_result_statuses(results)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows: list[list[Any]] = []
    step_rows: list[list[Any]] = []
    for item in results:
        result = item["result"]
        login_rps = step_rps(result, "login")
        token_rps = step_rps(
            result,
            "token_client_credentials",
            "mtls_client_credentials",
            "token_authorization_code",
            "token_refresh",
            "fapi_token_authorization_code",
            "fapi_token_refresh",
        )
        rows.append(
            [
                item["instances"],
                item["scenario"],
                item["target_rate"],
                result.get("status", "passed"),
                f"{result['k6']['rps']:.3f}",
                f"{result['k6'].get('target_rps_ratio', target_ratio(result, int(item['target_rate']))):.3f}",
                result["k6"].get("dropped_iterations", 0),
                f"{result['k6']['latency_ms']['p50']:.3f}",
                f"{result['k6']['latency_ms']['p95']:.3f}",
                f"{result['k6']['latency_ms']['p99']:.3f}",
                f"{result['k6']['error_rate']:.6f}",
                f"{app_cpu_cores(result):.3f}",
                f"{per_core(float(result['k6']['rps']), result):.3f}",
                f"{per_core(login_rps, result):.3f}",
                f"{per_core(token_rps, result):.3f}",
                f"{service_metric(result, 'postgres', 'cpu_percent_avg'):.3f}",
                f"{service_metric(result, 'valkey', 'cpu_percent_avg'):.3f}",
                f"{postgres_metric(result, 'mean_statement_ms'):.3f}",
                f"{postgres_metric(result, 'statements_per_http_request'):.3f}",
                f"{db_pool_metric(result, 'wait_ms_avg'):.3f}",
                f"{db_pool_metric(result, 'wait_ms_max_observed_process_lifetime'):.3f}",
                f"{valkey_hit_rate(result):.6f}",
                result.get("valkey", {}).get("keyspace_hits", 0),
                result.get("valkey", {}).get("keyspace_misses", 0),
            ]
        )
        for step in result.get("steps", []):
            step_rows.append(
                [
                    item["instances"],
                    item["scenario"],
                    item["target_rate"],
                    step["step"],
                    step["http_reqs"],
                    f"{step['rps']:.3f}",
                    f"{step['latency_ms']['p50']:.3f}",
                    f"{step['latency_ms']['p95']:.3f}",
                    f"{step['latency_ms']['p99']:.3f}",
                    f"{step['error_rate']:.6f}",
                ]
            )
    lines = [
        "# NazoAuth Capacity Curve Benchmarks",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "This report is generated by `perf/capacity.py`. It uses fixed arrival-rate k6 scenarios and can run the same traffic profile against 1, 2, and 4 NazoAuth replicas.",
        "",
        "## Run Configuration",
        "",
        *markdown_table(
            ["Setting", "Value"],
            [
                ["Duration per point", duration],
                ["Executor", "constant-arrival-rate"],
                ["Results JSON", display_path(results_path)],
            ],
        ),
        "",
        "## Capacity Curve",
        "",
        *markdown_table(
            [
                "Instances",
                "Scenario",
                "Target Rate",
                "Status",
                "Observed HTTP RPS",
                "Observed/Target",
                "Dropped Iterations",
                "p50 ms",
                "p95 ms",
                "p99 ms",
                "Error Rate",
                "App CPU Cores Avg",
                "HTTP RPS/App CPU Core",
                "Login RPS/App CPU Core",
                "Token RPS/App CPU Core",
                "Postgres CPU Avg %",
                "Valkey CPU Avg %",
                "Postgres Mean Statement ms",
                "DB Statements/HTTP Req",
                "DB Pool Wait Avg ms",
                "DB Pool Wait Max ms",
                "Valkey Hit Rate",
                "Valkey Hits",
                "Valkey Misses",
            ],
            rows,
        ),
        "",
        "## Step Breakdown",
        "",
        *markdown_table(
            ["Instances", "Scenario", "Target Rate", "Step", "Requests", "RPS", "p50 ms", "p95 ms", "p99 ms", "Error Rate"],
            step_rows,
        ),
        "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")


def write_results_and_report(
    results: list[dict[str, Any]],
    *,
    duration: str,
    report_path: Path,
    results_path: Path,
) -> None:
    normalize_result_statuses(results)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    write_report(results, duration=duration, report_path=report_path, results_path=results_path)


def run_point(*, scenario: str, rate: int, duration: str, instances: int, max_vus: int) -> dict[str, Any]:
    env = os.environ.copy()
    cnb_build = env.get("CNB_BUILD_ID", "")
    cnb_pipeline = env.get("CNB_PIPELINE_KEY", "")
    report_suffix = env.get("CAPACITY_REPORT_SUFFIX", scenario)
    if cnb_build and "COMPOSE_PROJECT_NAME" not in env:
        env["COMPOSE_PROJECT_NAME"] = f"nazoauth-{cnb_build}-{cnb_pipeline or report_suffix}"
    env.update(
        {
            "PERF_PROFILE": "capacity",
            "PERF_SCENARIO": scenario,
            "PERF_EXECUTOR": "constant-arrival-rate",
            "PERF_RATE": str(rate),
            "PERF_TIME_UNIT": "1s",
            "PERF_DURATION": duration,
            "PERF_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_FLOW_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_PRE_ALLOCATED_VUS": str(max(16, min(max_vus, rate * 2))),
            "PERF_MAX_VUS": str(max_vus),
            "PERF_USER_COUNT": str(max(max_vus, 64)),
            "PERF_VECTOR_COUNT": os.environ.get("PERF_VECTOR_COUNT", "1000"),
            "PERF_APP_REPLICAS": str(instances),
        }
    )
    point_results_dir = RESULTS_DIR / compose_project_name(env)
    point_results_dir.mkdir(parents=True, exist_ok=True)
    env["PERF_REPORT_PATH"] = "/results/performance/performance-benchmarks.md"
    down = compose_command(env, "down", "-v", "--remove-orphans")
    run_command(down, env)
    try:
        command = compose_command(
            env,
            "up",
            "--build",
            "--scale",
            f"nazoauth={instances}",
            "--abort-on-container-exit",
            "--exit-code-from",
            "perf",
        )
        run_command(command, env)
        copy_perf_results(env, point_results_dir)
        latest = json.loads((point_results_dir / "latest.json").read_text(encoding="utf-8"))
        if len(latest) != 1:
            raise RuntimeError(f"capacity point expected one result, got {len(latest)}")
        result = {
            "instances": instances,
            "scenario": scenario,
            "target_rate": rate,
            "duration": duration,
            "result": latest[0],
        }
        safe_name = f"capacity-{instances}x-{scenario}-{rate}rps"
        (RESULTS_DIR / f"{safe_name}.summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    finally:
        run_command(down, env)


def point_key(point: dict[str, Any]) -> tuple[int, str, int] | None:
    try:
        return (
            int(point["instances"]),
            str(point["scenario"]),
            int(point["target_rate"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def load_existing_results(results_path: Path) -> list[dict[str, Any]]:
    if not results_path.exists():
        return []
    data = json.loads(results_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError(f"capacity results must be a JSON array: {results_path}")
    results: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise RuntimeError(f"capacity result item must be an object: {results_path}")
        if point_key(item) is None:
            raise RuntimeError(f"capacity result item is missing point identity: {results_path}")
        results.append(item)
    return results


def point_status(point: dict[str, Any]) -> str:
    return normalized_status(point)


def has_lower_rate_threshold_failure(
    results: list[dict[str, Any]],
    *,
    instances: int,
    scenario: str,
    rate: int,
) -> bool:
    for item in results:
        key = point_key(item)
        if key is None:
            continue
        item_instances, item_scenario, item_rate = key
        if (
            item_instances == instances
            and item_scenario == scenario
            and item_rate < rate
            and point_status(item) == "threshold_failed"
        ):
            return True
    return False


def skipped_after_threshold_failure_point(*, scenario: str, rate: int, duration: str, instances: int) -> dict[str, Any]:
    return {
        "instances": instances,
        "scenario": scenario,
        "target_rate": rate,
        "duration": duration,
        "result": {
            "profile": "capacity",
            "scenario": scenario,
            "elapsed_seconds": 0,
            "status": "skipped_after_threshold_failure",
            "k6_exit_code": None,
            "k6": {
                "http_reqs": 0,
                "rps": 0,
                "error_rate": 0,
                "latency_ms": {
                    "p50": 0,
                    "p95": 0,
                    "p99": 0,
                },
            },
            "steps": [],
            "postgres": {
                "statement_calls": 0,
                "mean_statement_ms": 0,
                "statements_per_http_request": 0,
            },
            "db_pool": {
                "acquire_count": 0,
                "wait_ms_total": 0,
                "wait_ms_avg": 0,
                "wait_ms_max_observed_process_lifetime": 0,
            },
            "valkey": {
                "keyspace_hits": 0,
                "keyspace_misses": 0,
            },
            "containers": {
                "by_service": {},
            },
            "load_model": {
                "executor": "constant-arrival-rate",
                "target_rate": rate,
                "duration": duration,
                "app_replicas": instances,
                "observed_app_instances": instances,
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run NazoAuth fixed arrival-rate capacity curves.")
    parser.add_argument("--duration", default="30m")
    parser.add_argument("--instances", default="1,2,4", help="Comma-separated NazoAuth replica counts.")
    parser.add_argument("--scenarios", default=",".join(DEFAULT_RATES), help="Comma-separated capacity scenarios.")
    parser.add_argument("--rates", default="", help="Comma-separated rates applied to every selected scenario.")
    parser.add_argument("--report-path", default=str(DEFAULT_CAPACITY_REPORT))
    parser.add_argument("--results-path", default=str(DEFAULT_CAPACITY_RESULTS))
    parser.add_argument("--max-vus", type=int, default=512)
    parser.add_argument("--smoke", action="store_true", help="Use a short, low-rate matrix for toolchain validation.")
    args = parser.parse_args()

    if args.smoke:
        args.duration = "20s"
        instances = [1, 2]
        scenario_rates = {
            "token_only_client_credentials": [50],
            "oidc_refresh_only": [5],
        }
        args.max_vus = 64
    else:
        instances = parse_csv_ints(args.instances)
        selected = parse_csv(args.scenarios)
        explicit_rates = parse_csv_ints(args.rates) if args.rates else []
        scenario_rates = {
            scenario: explicit_rates or DEFAULT_RATES[scenario]
            for scenario in selected
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = root_path(args.report_path)
    results_path = root_path(args.results_path)
    results = load_existing_results(results_path)
    completed = {key for item in results if (key := point_key(item)) is not None}
    if results:
        print(f"resuming capacity matrix with {len(results)} completed point(s) from {results_path}")
        write_results_and_report(results, duration=args.duration, report_path=report_path, results_path=results_path)
    for instance_count in instances:
        for scenario, rates in scenario_rates.items():
            for rate in rates:
                key = (instance_count, scenario, rate)
                if key in completed:
                    print(
                        f"skip completed capacity point: instances={instance_count} "
                        f"scenario={scenario} rate={rate}/s"
                    )
                    continue
                if has_lower_rate_threshold_failure(
                    results,
                    instances=instance_count,
                    scenario=scenario,
                    rate=rate,
                ):
                    print(
                        f"skip capacity point after lower-rate threshold failure: "
                        f"instances={instance_count} scenario={scenario} rate={rate}/s"
                    )
                    point = skipped_after_threshold_failure_point(
                        scenario=scenario,
                        rate=rate,
                        duration=args.duration,
                        instances=instance_count,
                    )
                    results.append(point)
                    completed.add(key)
                    with checkpoint_lock():
                        write_results_and_report(
                            results,
                            duration=args.duration,
                            report_path=report_path,
                            results_path=results_path,
                        )
                        checkpoint_commit(
                            env=os.environ.copy(),
                            report_path=report_path,
                            results_path=results_path,
                            instances=instance_count,
                            scenario=scenario,
                            rate=rate,
                            status="skipped_after_threshold_failure",
                        )
                    continue
                print(
                    f"capacity point: instances={instance_count} "
                    f"scenario={scenario} rate={rate}/s duration={args.duration}"
                )
                point = run_point(
                    scenario=scenario,
                    rate=rate,
                    duration=args.duration,
                    instances=instance_count,
                    max_vus=args.max_vus,
                )
                results.append(point)
                completed.add(key)
                with checkpoint_lock():
                    write_results_and_report(
                        results,
                        duration=args.duration,
                        report_path=report_path,
                        results_path=results_path,
                    )
                    checkpoint_commit(
                        env=os.environ.copy(),
                        report_path=report_path,
                        results_path=results_path,
                        instances=instance_count,
                        scenario=scenario,
                        rate=rate,
                        status=point_status(point),
                    )


if __name__ == "__main__":
    main()
