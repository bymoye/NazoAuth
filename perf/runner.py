#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import psycopg
import redis

from seed import seed


BASE_URL = os.environ.get("BASE_URL", "http://nazoauth:8000").rstrip("/")
DATABASE_URL = os.environ["DATABASE_URL"]
VALKEY_URL = os.environ["VALKEY_URL"]
RESULTS_DIR = Path(os.environ.get("PERF_RESULTS_DIR", "/results"))
REPORT_PATH = Path(os.environ.get("PERF_REPORT_PATH", str(RESULTS_DIR / "benchmark-results.md")))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "nazoauth-perf")
APP_SERVICE = "nazoauth"
POSTGRES_SERVICE = "postgres"
VALKEY_SERVICE = "valkey"

PROFILES: dict[str, list[str]] = {
    "single-endpoint": [
        "token_client_credentials",
        "mtls_client_credentials",
        "par_signed_request_object",
    ],
    "oidc-mixed": [
        "refresh_token_rotation",
        "introspect_opaque_refresh_token",
        "authorize_par_session",
    ],
    "oidc-same-user-contention": [
        "same_user_refresh_token_rotation",
        "same_user_introspect_opaque_refresh_token",
        "same_user_authorize_par_session",
    ],
    "fapi2-high-security": [
        "fapi2_par_jar_private_key_jwt_dpop",
        "fapi2_logged_in_high_security",
    ],
    "extended-capacity": [
        "mtls_client_credentials",
        "par_signed_request_object",
        "introspect_opaque_refresh_token",
        "authorize_par_session",
        "revoke_refresh_token",
        "metadata_jwks",
        "ciba_private_key_jwt_dpop_poll",
        "same_user_refresh_token_rotation",
        "same_user_introspect_opaque_refresh_token",
        "same_user_authorize_par_session",
    ],
    "capacity": [
        "token_only_client_credentials",
        "oidc_cold_login_refresh",
        "oidc_logged_in_authorization_code",
        "oidc_refresh_only",
        "fapi2_full_security",
        "fapi2_logged_in_high_security",
    ],
}

VECTOR_STRIDE_MULTIPLIER = 12
VECTOR_STRIDE_FLOOR = 100
VECTOR_OFFSET_MULTIPLIERS = {
    "par_signed_request_object": 0,
    "refresh_token_rotation": 1,
    "introspect_opaque_refresh_token": 2,
    "authorize_par_session": 3,
    "fapi2_par_jar_private_key_jwt_dpop": 4,
    "same_user_refresh_token_rotation": 5,
    "same_user_introspect_opaque_refresh_token": 6,
    "same_user_authorize_par_session": 7,
    "oidc_cold_login_refresh": 8,
    "oidc_logged_in_authorization_code": 9,
    "oidc_refresh_only": 10,
    "fapi2_full_security": 11,
    "fapi2_logged_in_high_security": 12,
    "revoke_refresh_token": 13,
}
VECTORIZED_SCENARIOS = set(VECTOR_OFFSET_MULTIPLIERS)


def wait_for_service() -> None:
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            with urlopen(f"{BASE_URL}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError("NazoAuth perf service did not become healthy")


def get_json_url(url: str) -> dict[str, Any]:
    request = Request(url, headers={"accept": "application/json"})
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(path: str) -> dict[str, Any]:
    return get_json_url(f"{BASE_URL}{path}")


def duration_seconds(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smh]?)\s*", value)
    if not match:
        raise RuntimeError(f"unsupported duration format: {value}")
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    if unit == "h":
        return amount * 3600
    if unit == "m":
        return amount * 60
    return amount


def reset_pg_stats() -> None:
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("SELECT pg_stat_statements_reset()")
        conn.commit()


def pg_stats() -> dict[str, Any]:
    with psycopg.connect(DATABASE_URL) as conn:
        row = conn.execute(
            """
            SELECT
                COALESCE(SUM(calls), 0)::bigint AS calls,
                COALESCE(SUM(total_plan_time + total_exec_time), 0)::double precision AS total_ms,
                COALESCE(SUM(rows), 0)::bigint AS rows
            FROM pg_stat_statements
            WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND query NOT ILIKE '%pg_stat_statements%'
            """
        ).fetchone()
        size = conn.execute("SELECT pg_database_size(current_database())").fetchone()[0]
    calls = int(row[0] or 0)
    total_ms = float(row[1] or 0)
    return {
        "statement_calls": calls,
        "total_statement_ms": round(total_ms, 3),
        "mean_statement_ms": round(total_ms / calls, 3) if calls else 0,
        "rows": int(row[2] or 0),
        "database_bytes": int(size),
    }


def valkey_stats() -> dict[str, int]:
    client = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
    info = client.info("stats")
    keyspace = client.info("keyspace")
    return {
        "keyspace_hits": int(info.get("keyspace_hits", 0)),
        "keyspace_misses": int(info.get("keyspace_misses", 0)),
        "commands_processed": int(info.get("total_commands_processed", 0)),
        "expired_keys": int(info.get("expired_keys", 0)),
        "db0_keys": int(keyspace.get("db0", {}).get("keys", 0)) if isinstance(keyspace.get("db0"), dict) else 0,
    }


def delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {key: int(after.get(key, 0)) - int(before.get(key, 0)) for key in after}


def parse_percent(value: str) -> float:
    return float(value.strip().rstrip("%") or 0)


def parse_memory_bytes(value: str) -> int:
    first = value.split("/")[0].strip()
    match = re.match(r"^([0-9.]+)([A-Za-z]+)$", first)
    if not match:
        return 0
    amount = float(match.group(1))
    unit = match.group(2).lower()
    factors = {
        "b": 1,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
    }
    return int(amount * factors.get(unit, 1))


def compose_containers() -> list[dict[str, str]]:
    command = [
        "docker",
        "ps",
        "--filter",
        f"label=com.docker.compose.project={COMPOSE_PROJECT}",
        "--format",
        "{{json .}}",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    containers: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        name = raw.get("Names") or raw.get("Names".lower()) or raw.get("Name") or raw.get("ID")
        if not name:
            continue
        inspect = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{ index .Config.Labels \"com.docker.compose.service\" }}",
                name,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        service = inspect.stdout.strip()
        if service in {APP_SERVICE, POSTGRES_SERVICE, VALKEY_SERVICE}:
            containers.append({"name": name, "service": service})
    return containers


def app_metric_urls() -> list[str]:
    urls: list[str] = []
    for container in compose_containers():
        if container["service"] != APP_SERVICE:
            continue
        completed = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container["name"],
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        ip_address = completed.stdout.strip()
        if ip_address:
            urls.append(f"http://{ip_address}:8000/__perf/metrics")
    return urls or [f"{BASE_URL}/__perf/metrics"]


def get_app_metrics() -> dict[str, Any]:
    metrics = [get_json_url(url) for url in app_metric_urls()]
    db_pools = [metric["db_pool"] for metric in metrics]
    return {
        "instances": len(metrics),
        "db_pool": {
            "acquire_count": sum(pool["acquire_count"] for pool in db_pools),
            "wait_nanos_total": sum(pool["wait_nanos_total"] for pool in db_pools),
            "wait_nanos_max": max((pool["wait_nanos_max"] for pool in db_pools), default=0),
        },
    }


def docker_stats_once() -> list[dict[str, Any]]:
    containers = compose_containers()
    names = [container["name"] for container in containers]
    service_by_name = {container["name"]: container["service"] for container in containers}
    if not names:
        return []
    command = ["docker", "stats", "--no-stream", "--format", "{{json .}}", *names]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    samples = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        name = raw.get("Name") or raw.get("Container")
        samples.append(
            {
                "name": name,
                "service": service_by_name.get(name, "unknown"),
                "cpu_percent": parse_percent(raw.get("CPUPerc", "0%")),
                "memory_bytes": parse_memory_bytes(raw.get("MemUsage", "0B / 0B")),
            }
        )
    return samples


class StatsSampler:
    def __init__(self) -> None:
        self.samples: dict[str, list[dict[str, float]]] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "StatsSampler":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            for sample in docker_stats_once():
                name = sample["name"]
                self.samples.setdefault(name, []).append(sample)
            self._stop.wait(1)

    def summary(self) -> dict[str, Any]:
        by_container: dict[str, Any] = {}
        for name, samples in self.samples.items():
            cpu = [sample["cpu_percent"] for sample in samples]
            mem = [sample["memory_bytes"] for sample in samples]
            by_container[name] = {
                "service": samples[0].get("service", "unknown") if samples else "unknown",
                "samples": len(samples),
                "cpu_percent_avg": round(statistics.fmean(cpu), 3) if cpu else 0,
                "cpu_percent_max": round(max(cpu), 3) if cpu else 0,
                "memory_bytes_avg": round(statistics.fmean(mem)) if mem else 0,
                "memory_bytes_max": max(mem) if mem else 0,
            }
        by_service: dict[str, Any] = {}
        for service in {item["service"] for item in by_container.values()}:
            service_items = [item for item in by_container.values() if item["service"] == service]
            by_service[service] = {
                "containers": len(service_items),
                "cpu_percent_avg": round(sum(item["cpu_percent_avg"] for item in service_items), 3),
                "cpu_percent_max": round(sum(item["cpu_percent_max"] for item in service_items), 3),
                "memory_bytes_avg": round(sum(item["memory_bytes_avg"] for item in service_items)),
                "memory_bytes_max": sum(item["memory_bytes_max"] for item in service_items),
            }
        return {
            "by_container": by_container,
            "by_service": by_service,
        }


def k6_http_reqs(summary: dict[str, Any]) -> int:
    metric = summary.get("metrics", {}).get("http_reqs", {})
    values = metric.get("values", metric)
    return int(values.get("count", 0))


def k6_metric_values(summary: dict[str, Any], metric_name: str) -> dict[str, Any]:
    metric = summary.get("metrics", {}).get(metric_name, {})
    return metric.get("values", metric)


def k6_metric_ratio(summary: dict[str, Any], metric_name: str, default: float) -> float:
    values = k6_metric_values(summary, metric_name)
    return metric_ratio(values, default)


def metric_ratio(values: dict[str, Any], default: float) -> float:
    if "rate" in values:
        return float(values["rate"])
    if "value" in values:
        return float(values["value"])
    return default


def k6_check_rate(summary: dict[str, Any]) -> float:
    return k6_metric_ratio(summary, "checks", 0)


def k6_error_rate(summary: dict[str, Any]) -> float:
    return k6_metric_ratio(summary, "http_req_failed", 0)


def k6_protocol_failed(summary: dict[str, Any]) -> bool:
    return k6_error_rate(summary) >= 0.01 or k6_check_rate(summary) < 0.99


def k6_brief(summary: dict[str, Any]) -> dict[str, Any]:
    metrics = summary.get("metrics", {})
    duration_metric = metrics.get("http_req_duration", {})
    failed_metric = metrics.get("http_req_failed", {})
    reqs_metric = metrics.get("http_reqs", {})
    dropped_metric = metrics.get("dropped_iterations", {})
    duration = duration_metric.get("values", duration_metric)
    failed = failed_metric.get("values", failed_metric)
    reqs = reqs_metric.get("values", reqs_metric)
    dropped = dropped_metric.get("values", dropped_metric)
    return {
        "http_reqs": int(reqs.get("count", 0)),
        "rps": round(float(reqs.get("rate", 0)), 3),
        "error_rate": round(k6_error_rate(summary), 6),
        "dropped_iterations": int(dropped.get("count", 0)),
        "dropped_iterations_rate": round(float(dropped.get("rate", 0)), 3),
        "latency_ms": {
            "p50": round(float(duration.get("med", 0)), 3),
            "p95": round(float(duration.get("p(95)", 0)), 3),
            "p99": round(float(duration.get("p(99)", 0)), 3),
        },
    }


def parse_metric_tags(metric_name: str, prefix: str) -> dict[str, str] | None:
    if not metric_name.startswith(f"{prefix}{{") or not metric_name.endswith("}"):
        return None
    raw_tags = metric_name[len(prefix) + 1 : -1]
    tags: dict[str, str] = {}
    for item in raw_tags.split(","):
        key, separator, value = item.partition(":")
        if separator:
            tags[key] = value
    return tags


def metric_values(summary: dict[str, Any], metric_name: str) -> dict[str, Any]:
    metric = summary.get("metrics", {}).get(metric_name, {})
    return metric.get("values", metric)


def metric_by_step(summary: dict[str, Any], metric_name: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for key, metric in summary.get("metrics", {}).items():
        tags = parse_metric_tags(key, metric_name)
        if not tags or "step" not in tags:
            continue
        result[tags["step"]] = metric.get("values", metric)
    return result


def k6_step_brief(summary: dict[str, Any]) -> list[dict[str, Any]]:
    durations = metric_by_step(summary, "http_req_duration")
    reqs = metric_by_step(summary, "http_reqs")
    failures = metric_by_step(summary, "http_req_failed")
    steps = []
    for step in sorted(durations):
        duration = durations[step]
        request = reqs.get(step, {})
        failed = failures.get(step, {})
        request_count = int(request.get("count", 0))
        if request_count == 0:
            continue
        steps.append(
            {
                "step": step,
                "http_reqs": request_count,
                "rps": round(float(request.get("rate", 0)), 3),
                "error_rate": round(metric_ratio(failed, 0), 6),
                "latency_ms": {
                    "p50": round(float(duration.get("med", 0)), 3),
                    "p95": round(float(duration.get("p(95)", 0)), 3),
                    "p99": round(float(duration.get("p(99)", 0)), 3),
                },
            }
        )
    return steps


def run_scenario(profile: str, scenario: str) -> dict[str, Any]:
    safe_name = f"{profile}-{scenario}".replace("_", "-")
    k6_summary_path = RESULTS_DIR / f"{safe_name}.k6.json"
    combined_path = RESULTS_DIR / f"{safe_name}.summary.json"
    reset_pg_stats()
    valkey_before = valkey_stats()
    app_before = get_app_metrics()
    env = os.environ.copy()
    env["PERF_PROFILE"] = profile
    env["PERF_SCENARIO"] = scenario
    command = [
        "k6",
        "run",
        *(
            ["--log-output", "file=/dev/null"]
            if os.environ.get("PERF_EXECUTOR") == "constant-arrival-rate"
            else []
        ),
        "--summary-export",
        str(k6_summary_path),
        "/perf/k6/oauth.js",
    ]
    started = time.perf_counter()
    with StatsSampler() as sampler:
        completed = subprocess.run(command, env=env, text=True)
    elapsed = time.perf_counter() - started
    if not k6_summary_path.exists():
        raise RuntimeError(f"k6 scenario failed before writing summary: {profile}/{scenario}")
    k6_summary = json.loads(k6_summary_path.read_text(encoding="utf-8"))
    app_after = get_app_metrics()
    pg = pg_stats()
    valkey = delta(valkey_stats(), valkey_before)
    http_reqs = k6_http_reqs(k6_summary)
    if http_reqs == 0:
        raise RuntimeError(f"k6 scenario produced zero HTTP requests: {profile}/{scenario}")
    db_pool_before = app_before["db_pool"]
    db_pool_after = app_after["db_pool"]
    acquire_delta = db_pool_after["acquire_count"] - db_pool_before["acquire_count"]
    wait_delta = db_pool_after["wait_nanos_total"] - db_pool_before["wait_nanos_total"]
    k6 = k6_brief(k6_summary)
    target_rate = int(os.environ.get("PERF_RATE", "0") or 0)
    target_miss = (
        os.environ.get("PERF_EXECUTOR") == "constant-arrival-rate"
        and target_rate > 0
        and (k6["rps"] < target_rate * 0.99 or k6["dropped_iterations"] > 0)
    )
    status = "passed"
    if completed.returncode != 0:
        status = "threshold_failed"
    elif target_miss:
        status = "target_miss"
    combined = {
        "profile": profile,
        "scenario": scenario,
        "elapsed_seconds": round(elapsed, 3),
        "status": status,
        "k6_exit_code": completed.returncode,
        "k6": k6,
        "steps": k6_step_brief(k6_summary),
        "postgres": {
            **pg,
            "statements_per_http_request": round(pg["statement_calls"] / http_reqs, 3) if http_reqs else 0,
        },
        "db_pool": {
            "acquire_count": acquire_delta,
            "wait_ms_total": round(wait_delta / 1_000_000, 3),
            "wait_ms_avg": round(wait_delta / acquire_delta / 1_000_000, 3) if acquire_delta else 0,
            "wait_ms_max_observed_process_lifetime": round(db_pool_after["wait_nanos_max"] / 1_000_000, 3),
        },
        "valkey": valkey,
        "containers": sampler.summary(),
        "load_model": {
            "executor": os.environ.get("PERF_EXECUTOR", "") or "default",
            "target_rate": target_rate,
            "duration": os.environ.get("PERF_DURATION", "20s"),
            "app_replicas": int(os.environ.get("PERF_APP_REPLICAS", str(app_after.get("instances", 1))) or 1),
            "observed_app_instances": app_after.get("instances", 1),
        },
    }
    combined_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    is_capacity_run = os.environ.get("PERF_EXECUTOR") == "constant-arrival-rate"
    if completed.returncode != 0 and k6_protocol_failed(k6_summary) and not is_capacity_run:
        raise RuntimeError(f"k6 scenario failed protocol checks: {profile}/{scenario}")
    print(
        f"{profile}/{scenario}: "
        f"status={combined['status']} "
        f"rps={combined['k6']['rps']} "
        f"p95={combined['k6']['latency_ms']['p95']}ms "
        f"errors={combined['k6']['error_rate']} "
        f"db_calls={combined['postgres']['statement_calls']}"
    )
    return combined


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return lines


def format_mb(value: int | float) -> str:
    return f"{value / 1024 / 1024:.1f}"


def service_metric(result: dict[str, Any], service: str, metric: str) -> float:
    return float(result.get("containers", {}).get("by_service", {}).get(service, {}).get(metric, 0))


def step_rps(result: dict[str, Any], *steps: str) -> float:
    wanted = set(steps)
    return sum(float(step["rps"]) for step in result.get("steps", []) if step["step"] in wanted)


def app_cpu_cores(result: dict[str, Any]) -> float:
    return service_metric(result, APP_SERVICE, "cpu_percent_avg") / 100


def per_app_cpu_core(value: float, result: dict[str, Any]) -> str:
    cores = app_cpu_cores(result)
    if cores <= 0:
        return "0.000"
    return f"{value / cores:.3f}"


def write_markdown_report(results: list[dict[str, Any]]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# NazoAuth Performance Benchmarks",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "This report is generated by `perf/runner.py` from k6, PostgreSQL, Valkey, and Docker container metrics. The JSON source for the latest run is `perf/results/latest.json`.",
        "",
        "## Run Configuration",
        "",
        *markdown_table(
            ["Setting", "Value"],
            [
                ["PERF_PROFILE", os.environ.get("PERF_PROFILE", "all")],
                ["PERF_SCENARIO", os.environ.get("PERF_SCENARIO", "") or "(all selected scenarios)"],
                ["PERF_DURATION", os.environ.get("PERF_DURATION", "20s")],
                ["PERF_VUS", os.environ.get("PERF_VUS", "8")],
                ["PERF_FLOW_VUS", os.environ.get("PERF_FLOW_VUS", "") or os.environ.get("PERF_VUS", "8")],
                ["PERF_ITERATIONS", os.environ.get("PERF_ITERATIONS", "50")],
                ["PERF_USER_COUNT", os.environ.get("PERF_USER_COUNT", "64")],
                ["PERF_VECTOR_COUNT", os.environ.get("PERF_VECTOR_COUNT", "1000")],
                ["PERF_EXECUTOR", os.environ.get("PERF_EXECUTOR", "") or "(scenario default)"],
                ["PERF_RATE", os.environ.get("PERF_RATE", "") or "(not fixed-rate)"],
                ["PERF_APP_REPLICAS", os.environ.get("PERF_APP_REPLICAS", "1")],
            ],
        ),
        "",
        "## Scenario Summary",
        "",
        *markdown_table(
            ["Profile", "Scenario", "HTTP RPS", "p50 ms", "p95 ms", "p99 ms", "Error Rate", "DB Statements/Req", "Valkey Hits", "Valkey Misses"],
            [
                [
                    result["profile"],
                    result["scenario"],
                    f"{result['k6']['rps']:.3f}",
                    f"{result['k6']['latency_ms']['p50']:.3f}",
                    f"{result['k6']['latency_ms']['p95']:.3f}",
                    f"{result['k6']['latency_ms']['p99']:.3f}",
                    f"{result['k6']['error_rate']:.6f}",
                    f"{result['postgres']['statements_per_http_request']:.3f}",
                    result["valkey"]["keyspace_hits"],
                    result["valkey"]["keyspace_misses"],
                ]
                for result in results
            ],
        ),
        "",
        "## Normalized Throughput",
        "",
        *markdown_table(
            ["Profile", "Scenario", "App Instances", "App CPU Cores Avg", "HTTP RPS/App CPU Core", "Login RPS/App CPU Core", "Token RPS/App CPU Core"],
            [
                [
                    result["profile"],
                    result["scenario"],
                    result.get("load_model", {}).get("observed_app_instances", 1),
                    f"{app_cpu_cores(result):.3f}",
                    per_app_cpu_core(float(result["k6"]["rps"]), result),
                    per_app_cpu_core(step_rps(result, "login"), result),
                    per_app_cpu_core(
                        step_rps(
                            result,
                            "token_client_credentials",
                            "mtls_client_credentials",
                            "token_authorization_code",
                            "token_refresh",
                            "fapi_token_authorization_code",
                            "fapi_token_refresh",
                        ),
                        result,
                    ),
                ]
                for result in results
            ],
        ),
        "",
        "## Step Latency Breakdown",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"### {result['profile']} / {result['scenario']}",
                "",
                *markdown_table(
                    ["Step", "Requests", "RPS", "p50 ms", "p95 ms", "p99 ms", "Error Rate"],
                    [
                        [
                            step["step"],
                            step["http_reqs"],
                            f"{step['rps']:.3f}",
                            f"{step['latency_ms']['p50']:.3f}",
                            f"{step['latency_ms']['p95']:.3f}",
                            f"{step['latency_ms']['p99']:.3f}",
                            f"{step['error_rate']:.6f}",
                        ]
                        for step in result["steps"]
                    ],
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## Resource Summary",
            "",
            *markdown_table(
                ["Profile", "Scenario", "Server CPU Avg %", "Server CPU Max %", "Server Mem Max MiB", "Postgres CPU Avg %", "Postgres Mem Max MiB", "Valkey CPU Avg %", "Valkey Mem Max MiB"],
                [
                    [
                        result["profile"],
                        result["scenario"],
                        f"{service_metric(result, APP_SERVICE, 'cpu_percent_avg'):.3f}",
                        f"{service_metric(result, APP_SERVICE, 'cpu_percent_max'):.3f}",
                        format_mb(service_metric(result, APP_SERVICE, "memory_bytes_max")),
                        f"{service_metric(result, POSTGRES_SERVICE, 'cpu_percent_avg'):.3f}",
                        format_mb(service_metric(result, POSTGRES_SERVICE, "memory_bytes_max")),
                        f"{service_metric(result, VALKEY_SERVICE, 'cpu_percent_avg'):.3f}",
                        format_mb(service_metric(result, VALKEY_SERVICE, "memory_bytes_max")),
                    ]
                    for result in results
                ],
            ),
            "",
            "## Notes",
            "",
            "- OIDC mixed scenarios are full serial user flows, not single-endpoint throughput tests.",
            "- Login steps intentionally include Argon2 user-password verification; that cost must not be replaced with a fast digest.",
            "- `client_credentials` client-secret verification uses the high-entropy machine-secret digest path and should be interpreted separately from user-password login.",
            "- `perf/results/latest.json` remains the machine-readable source of truth for this report.",
            "",
        ]
    )
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def selected_profiles() -> dict[str, list[str]]:
    profile = os.environ.get("PERF_PROFILE", "all")
    scenario = os.environ.get("PERF_SCENARIO", "").strip()
    if scenario:
        return {profile if profile != "all" else "custom": [scenario]}
    if profile == "all":
        return PROFILES
    if profile not in PROFILES:
        raise RuntimeError(f"unknown PERF_PROFILE={profile}")
    return {profile: PROFILES[profile]}


def ensure_vector_capacity() -> None:
    iterations = int(os.environ.get("PERF_ITERATIONS", "50"))
    requested = int(os.environ.get("PERF_VECTOR_COUNT", "1000"))
    duration = duration_seconds(os.environ.get("PERF_DURATION", "20s"))
    rate = int(os.environ.get("PERF_RATE", "0") or 0)
    scenario = os.environ.get("PERF_SCENARIO", "").strip()
    vector_stride = max(iterations, VECTOR_STRIDE_FLOOR)
    if os.environ.get("PERF_EXECUTOR") == "constant-arrival-rate" and scenario:
        offset = VECTOR_OFFSET_MULTIPLIERS.get(scenario, 0) * vector_stride
        if scenario not in VECTORIZED_SCENARIOS:
            minimum = VECTOR_STRIDE_FLOOR
        elif scenario == "oidc_refresh_only":
            max_vus = int(os.environ.get("PERF_MAX_VUS") or os.environ.get("PERF_PRE_ALLOCATED_VUS") or 64)
            minimum = offset + max(max_vus + 1, VECTOR_STRIDE_FLOOR)
        else:
            scheduled_iterations = rate * duration
            boundary_cushion = max(rate, 1)
            minimum = offset + max(scheduled_iterations + boundary_cushion, VECTOR_STRIDE_FLOOR)
    else:
        minimum = max(iterations, VECTOR_STRIDE_FLOOR) * VECTOR_STRIDE_MULTIPLIER
    if requested < minimum:
        os.environ["PERF_VECTOR_COUNT"] = str(minimum)
        print(
            f"PERF_VECTOR_COUNT={requested} is below the replay-safe minimum; "
            f"using {minimum} flow vectors"
        )


def ensure_user_capacity() -> None:
    vus = int(os.environ.get("PERF_VUS", "8"))
    flow_vus = int(os.environ.get("PERF_FLOW_VUS") or vus)
    max_vus = int(os.environ.get("PERF_MAX_VUS") or flow_vus)
    preallocated_vus = int(os.environ.get("PERF_PRE_ALLOCATED_VUS") or flow_vus)
    requested = int(os.environ.get("PERF_USER_COUNT", "64"))
    minimum = max(vus, flow_vus, max_vus, preallocated_vus, 1)
    if requested < minimum:
        os.environ["PERF_USER_COUNT"] = str(minimum)
        print(
            f"PERF_USER_COUNT={requested} is below the multi-user concurrency minimum; "
            f"using {minimum} seeded users"
        )


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    wait_for_service()
    ensure_vector_capacity()
    ensure_user_capacity()
    seed()
    results = []
    for profile, scenarios in selected_profiles().items():
        for scenario in scenarios:
            results.append(run_scenario(profile, scenario))
    (RESULTS_DIR / "latest.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    write_markdown_report(results)


if __name__ == "__main__":
    main()
