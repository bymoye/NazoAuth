#!/usr/bin/env python3
"""Run the public OIDC/FAPI/FAPI-CIBA matrix as one reversible operation."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import os
import queue
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidf_evidence import sanitize_evidence_tree  # noqa: E402
from conformance_lease_control import (  # noqa: E402
    ConformanceLeaseControlError,
    create as create_lease,
    revoke_and_cleanup,
)
from oidf_secret_input import (  # noqa: E402
    SecretInputError,
    add_secret_source_arguments,
    read_secret_document,
    sanitized_environment,
)
from run_oidf_conformance import (  # noqa: E402
    allowed_review_contexts_by_alias,
    expected_problem_contexts_by_alias,
    expected_skip_contexts_by_alias,
    inspect_oidf_state,
)


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SECRET_FIELDS = (
    "OIDF_APPLICANT_EMAIL",
    "OIDF_APPLICANT_PASSWORD",
    "OIDF_ADMIN_EMAIL",
    "OIDF_ADMIN_PASSWORD",
    "OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN",
    "OIDF_CIBA_AUTOMATED_DECISION_TOKEN",
    "OIDF_CONFORMANCE_TOKEN",
)
SECRET_INPUT_FIELDS = tuple(name.lower() for name in REQUIRED_SECRET_FIELDS)
OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS = frozenset({"EnsureIncomingTls13"})
MAX_SAFE_GROUP_WORKERS = 4
MAX_BROWSER_GROUP_WORKERS = 2


class PublicRunError(RuntimeError):
    pass


def origin(value: str, option: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
        raise PublicRunError(f"{option} must be an HTTPS origin without a path")
    return parsed._replace(path="", query="", fragment="").geturl()


def command(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
) -> None:
    subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        input=stdin,
        pass_fds=pass_fds,
        check=True,
    )


def output(args: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def verify_source(source_dir: Path, expected_sha: str, label: str) -> None:
    head = output(["git", "rev-parse", "HEAD"], cwd=source_dir)
    if head != expected_sha:
        raise PublicRunError(
            f"{label} source commit {head} does not match expected {expected_sha}"
        )
    if output(["git", "status", "--porcelain"], cwd=source_dir):
        raise PublicRunError(f"{label} source tree must be clean")


def verify_suite(suite_dir: Path, suite_revision: str) -> None:
    if output(["git", "rev-parse", "HEAD"], cwd=suite_dir) != suite_revision:
        raise PublicRunError(f"suite must be checked out at {suite_revision}")
    if output(["git", "status", "--porcelain"], cwd=suite_dir):
        raise PublicRunError("official conformance-suite source tree must be clean")


def cleanup_suite_runner_configs(suite_dir: Path, work_dir: Path) -> None:
    plan_configs = work_dir / "oidf-plan-configs.json"
    if not plan_configs.is_file():
        return
    document = json.loads(plan_configs.read_text(encoding="utf-8"))
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict):
        raise PublicRunError("OIDF plan config bundle must contain a configs object")
    tracked = set(output(["git", "ls-files", "--", "scripts"], cwd=suite_dir).splitlines())
    for name in configs:
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.startswith("oidf-")
            or not name.endswith("-plan-config.json")
        ):
            raise PublicRunError(f"unsafe OIDF runner config filename: {name!r}")
        relative = f"scripts/{name}"
        if relative in tracked:
            continue
        target = suite_dir / relative
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise PublicRunError(f"unsafe OIDF runner config cleanup target: {target}")
        target.unlink(missing_ok=True)


def normalized_secrets(value: dict[str, str]) -> dict[str, str]:
    return {
        name: value[name.lower()]
        for name in REQUIRED_SECRET_FIELDS
    }


@contextlib.contextmanager
def secret_pipe(value: str):
    reader, writer = os.pipe()
    write_errors: list[OSError] = []

    def write_secret() -> None:
        payload = value.encode("utf-8")
        try:
            written = 0
            while written < len(payload):
                written += os.write(writer, payload[written:])
        except OSError as error:
            write_errors.append(error)
        finally:
            os.close(writer)

    delivery = threading.Thread(
        target=write_secret,
        name="oidf-secret-fd-writer",
        daemon=True,
    )
    delivery.start()
    try:
        yield reader
    finally:
        delivery.join(timeout=5)
        if delivery.is_alive():
            os.close(reader)
            delivery.join()
            raise PublicRunError("suite token descriptor was not consumed within its bound")
        os.close(reader)
        if write_errors and sys.exc_info()[0] is None:
            raise PublicRunError("suite token descriptor delivery failed") from write_errors[0]


def suite_request(server: str, token: str | None) -> int:
    url = f"{server}/api/plan?start=0&length=1"
    headers = {"Accept": "application/json", "User-Agent": "nazo-public-oidf-runner/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read(1024 * 1024 + 1)
            return response.status
    except urllib.error.HTTPError as error:
        with error:
            error.read(1024 * 1024 + 1)
            return error.code


def verify_suite_boundary(server: str, token: str) -> None:
    if suite_request(server, None) != 401:
        raise PublicRunError("unauthenticated conformance-suite API request must return 401")
    if suite_request(server, token) != 200:
        raise PublicRunError("authenticated conformance-suite API request must return 200")


def protect_directory(path: Path) -> None:
    if not path.exists():
        return
    path.chmod(0o700)
    for item in path.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)


def validate_output_paths(work_dir: Path, export_dir: Path, suite_dir: Path) -> None:
    for path, name in ((work_dir, "--work-dir"), (export_dir, "--export-dir")):
        if path == ROOT or path.is_relative_to(ROOT):
            raise PublicRunError(f"{name} must be outside the product source tree")
        if path == suite_dir or path.is_relative_to(suite_dir):
            raise PublicRunError(f"{name} must be outside the conformance-suite source tree")
    paths_overlap = (
        work_dir == export_dir
        or work_dir.is_relative_to(export_dir)
        or export_dir.is_relative_to(work_dir)
    )
    if paths_overlap:
        raise PublicRunError("--work-dir and --export-dir must not contain one another")


class ProxyTrust:
    def __init__(self, target: Path, executable: Path, work_dir: Path) -> None:
        self.target = target.resolve()
        self.executable = executable.resolve()
        self.backup = work_dir / "proxy-trust-bundle.before.pem"
        self.installed = False

    def _validate_and_reload(self) -> None:
        command([str(self.executable), "-t"])
        command([str(self.executable), "-s", "reload"])

    def install(self, approved_bundle: Path) -> None:
        if not self.target.is_file() or not self.executable.is_file():
            raise PublicRunError("proxy trust target and executable must already exist")
        shutil.copyfile(self.target, self.backup)
        self.backup.chmod(0o600)
        trust_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trust_context.load_verify_locations(cafile=str(approved_bundle))
        self.target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.target.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with approved_bundle.open("rb") as source:
                shutil.copyfileobj(source, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(0o644)
        os.replace(temporary_path, self.target)
        try:
            self._validate_and_reload()
        except BaseException:
            os.replace(self.backup, self.target)
            self._validate_and_reload()
            raise
        self.installed = True

    def restore(self) -> None:
        if not self.installed:
            return
        os.replace(self.backup, self.target)
        self._validate_and_reload()
        self.installed = False


def onboarding_args(
    action: str,
    work_dir: Path,
    issuer: str,
    lease_id: str | None = None,
) -> list[str]:
    arguments = [
        sys.executable,
        str(ROOT / "scripts" / "apply_public_conformance_onboarding.py"),
        action,
        "--target-issuer",
        issuer,
        "--credentials-stdin",
        "--manifest",
        str(work_dir / "oidf-onboarding-manifest.json"),
        "--plan-configs",
        str(work_dir / "oidf-plan-configs.json"),
        "--plan-set",
        str(work_dir / "oidf-plan-set.json"),
        "--plan-manifest",
        str(work_dir / "oidf-plan-set-manifest.json"),
        "--runner-env",
        str(work_dir / "oidf-runner.env"),
        "--delivered-client-material",
        str(work_dir / "oidf-delivered-client-material.json"),
        "--state-file",
        str(work_dir / "oidf-onboarding-state.json"),
        "--trust-bundle",
        str(work_dir / "approved-mtls-trust-anchors.pem"),
    ]
    if lease_id is not None:
        arguments.extend(["--lease-id", lease_id])
    return arguments


def onboarding_credentials(secrets: dict[str, str]) -> bytes:
    document = {
        "applicant_email": secrets["OIDF_APPLICANT_EMAIL"],
        "applicant_password": secrets["OIDF_APPLICANT_PASSWORD"],
        "admin_email": secrets["OIDF_ADMIN_EMAIL"],
        "admin_password": secrets["OIDF_ADMIN_PASSWORD"],
    }
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def provisioning_args(issuer: str) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "scripts" / "provision_public_oidf_applicant.py"),
        "--target-issuer",
        issuer,
        "--secrets-stdin",
    ]


@contextlib.contextmanager
def private_secret_file(directory: Path, document: dict[str, str]):
    descriptor, name = tempfile.mkstemp(
        dir=directory,
        prefix=".oidf-secrets-",
        suffix=".json",
    )
    path = Path(name)
    try:
        payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        path.chmod(0o600)
        yield path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)


def filter_problem_records(
    source: Path,
    plan_set: Path,
    destination: Path,
    *,
    excluded_conditions: frozenset[str] = frozenset(),
) -> None:
    plans = json.loads(plan_set.read_text(encoding="utf-8"))
    if not isinstance(plans, list) or not all(isinstance(item, str) for item in plans):
        raise PublicRunError(f"{plan_set} must contain a JSON array of plan expressions")
    configs = {expression.rsplit(" ", 1)[-1] for expression in plans}
    records = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
        raise PublicRunError(f"{source} must contain a JSON array of problem records")
    selected = [
        record
        for record in records
        if record.get("configuration-filename") in configs
        and record.get("condition") not in excluded_conditions
    ]
    destination.write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")


def split_plan_groups(work_dir: Path) -> tuple[tuple[str, Path, bool], ...]:
    source_files = (
        "oidf-plan-set-concurrent.json",
        "oidf-plan-set-ciba.json",
        "oidf-plan-set-rp-initiated.json",
        "oidf-plan-set-backchannel.json",
        "oidf-plan-set-frontchannel.json",
        "oidf-plan-set-session.json",
    )
    source_plans: dict[str, list[str]] = {}
    for filename in source_files:
        path = work_dir / filename
        plans = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(plans, list) or not all(isinstance(item, str) for item in plans):
            raise PublicRunError(f"{path} must contain a JSON array of plan expressions")
        source_plans[filename] = plans

    concurrent = source_plans["oidf-plan-set-concurrent.json"]

    def matches(*needles: str) -> list[str]:
        return [plan for plan in concurrent if all(needle in plan for needle in needles)]

    grouped: list[tuple[str, list[str], bool]] = [
        ("01-oidc-core", matches("oidcc-basic-certification-test-plan"), False),
        (
            "02-oidc-formpost-thirdparty-config",
            [
                *matches("oidcc-formpost-basic-certification-test-plan"),
                *matches("oidcc-3rdparty-init-login-certification-test-plan"),
                *matches("oidcc-config-certification-test-plan"),
            ],
            False,
        ),
    ]

    ciba = source_plans["oidf-plan-set-ciba.json"]
    for name, client_auth_type, mode in (
        ("03a-fapi-ciba-private-key-jwt-poll", "private_key_jwt", "poll"),
        ("03b-fapi-ciba-mtls-poll", "mtls", "poll"),
        ("03c-fapi-ciba-private-key-jwt-ping", "private_key_jwt", "ping"),
        ("03d-fapi-ciba-mtls-ping", "mtls", "ping"),
    ):
        grouped.append(
            (
                name,
                [
                    plan
                    for plan in ciba
                    if f"client_auth_type={client_auth_type}" in plan
                    and f"ciba_mode={mode}" in plan
                ],
                True,
            )
        )

    grouped.extend(
        (
            (
                "04-fapi-message-and-mtls-dpop",
                [
                    *matches("fapi2-message-signing-final-test-plan"),
                    *matches(
                        "fapi2-security-profile-final-test-plan",
                        "client_auth_type=mtls",
                        "sender_constrain=dpop",
                    ),
                ],
                False,
            ),
            (
                "05-fapi-mtls-mtls",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=mtls",
                    "sender_constrain=mtls",
                ),
                False,
            ),
            (
                "06-fapi-private-dpop",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=private_key_jwt",
                    "sender_constrain=dpop",
                ),
                False,
            ),
            (
                "07-fapi-private-mtls",
                matches(
                    "fapi2-security-profile-final-test-plan",
                    "client_auth_type=private_key_jwt",
                    "sender_constrain=mtls",
                ),
                False,
            ),
            (
                "08-rp-initiated",
                source_plans["oidf-plan-set-rp-initiated.json"],
                True,
            ),
            (
                "09-backchannel",
                source_plans["oidf-plan-set-backchannel.json"],
                True,
            ),
            (
                "10-frontchannel",
                source_plans["oidf-plan-set-frontchannel.json"],
                True,
            ),
            ("11-session", source_plans["oidf-plan-set-session.json"], True),
        )
    )

    assigned = [plan for _, plans, _ in grouped for plan in plans]
    expected = [plan for plans in source_plans.values() for plan in plans]
    if any(not plans for _, plans, _ in grouped) or sorted(assigned) != sorted(expected):
        raise PublicRunError("bounded OIDF plan groups must exactly cover every source plan")

    result = []
    for name, plans, isolated in grouped:
        destination = work_dir / f"oidf-plan-set-{name}.json"
        destination.write_text(json.dumps(plans, indent=2) + "\n", encoding="utf-8")
        result.append((name, destination, isolated))
    return tuple(result)


def prepare_group_invocations(
    args: argparse.Namespace,
    work_dir: Path,
) -> tuple[tuple[str, list[str]], ...]:
    invocations = []
    for name, plan_set_file, isolated in split_plan_groups(work_dir):
        expected_skips_file = work_dir / f"oidf-expected-skips-{name}.json"
        expected_warnings_file = work_dir / f"oidf-expected-warnings-{name}.json"
        filter_problem_records(
            work_dir / "oidf-expected-skips.json",
            plan_set_file,
            expected_skips_file,
        )
        filter_problem_records(
            ROOT / "tests" / "contracts" / "oidf-official-expected-warnings.json",
            plan_set_file,
            expected_warnings_file,
            excluded_conditions=OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS,
        )
        invocation = [
            sys.executable,
            str(ROOT / "scripts" / "run_oidf_conformance.py"),
            "--suite-dir",
            "{suite_dir}",
            "--suite-revision",
            args.suite_revision,
            "--conformance-server",
            args.conformance_server,
            "--plan-set-json-file",
            str(plan_set_file),
            "--config-json-file",
            str(work_dir / "oidf-plan-configs.json"),
            "--target-issuer",
            args.target_issuer,
            "--export-dir",
            str(args.export_dir / name),
            "--expected-skips-file",
            str(expected_skips_file),
            "--expected-failures-file",
            str(expected_warnings_file),
            "--timeout-seconds",
            str(args.timeout_seconds),
            "--monitor-interval-seconds",
            str(args.monitor_interval_seconds),
            "--verbose",
        ]
        if isolated:
            invocation.append("--no-parallel")
        invocations.append((name, invocation))
    return tuple(invocations)


def group_lane(name: str) -> str:
    if name.startswith("03"):
        return "ciba"
    if name.startswith(("08", "09", "10", "11")):
        return "browser"
    return "safe"


def add_suite_worktree(suite_dir: Path, destination: Path, revision: str) -> None:
    command(
        [
            "git",
            "-C",
            str(suite_dir),
            "worktree",
            "add",
            "--detach",
            str(destination),
            revision,
        ]
    )
    try:
        verify_suite(destination, revision)
    except BaseException as error:
        try:
            remove_suite_worktree(suite_dir, destination)
        except BaseException as cleanup_error:
            raise ExceptionGroup(
                "OIDF suite worktree verification and cleanup failed",
                [error, cleanup_error],
            ) from error
        raise


def remove_suite_worktree(suite_dir: Path, destination: Path) -> None:
    command(
        [
            "git",
            "-C",
            str(suite_dir),
            "worktree",
            "remove",
            "--force",
            str(destination),
        ]
    )


def run_group_phase(
    phase: str,
    invocations: tuple[tuple[str, list[str]], ...],
    suite_dirs: tuple[Path, ...],
    workers: int,
    env: dict[str, str],
    suite_token: str,
) -> None:
    if not invocations:
        return
    available: queue.SimpleQueue[Path] = queue.SimpleQueue()
    for suite_dir in suite_dirs[:workers]:
        available.put(suite_dir)

    def run_one(name: str, invocation: list[str]) -> None:
        suite_dir = available.get()
        try:
            resolved = [
                str(suite_dir) if value == "{suite_dir}" else value
                for value in invocation
            ]
            print(f"OIDF {phase} group start: {name}", flush=True)
            with secret_pipe(suite_token) as descriptor:
                resolved.extend(["--token-fd", str(descriptor)])
                command(resolved, env=env, pass_fds=(descriptor,))
            print(f"OIDF {phase} group complete: {name}", flush=True)
        finally:
            available.put(suite_dir)

    failures: list[BaseException] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix=f"oidf-{phase}",
    ) as executor:
        futures = {
            executor.submit(run_one, name, invocation): name
            for name, invocation in invocations
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except BaseException as error:
                error.add_note(f"OIDF {phase} group failed: {futures[future]}")
                failures.append(error)
    if failures:
        raise ExceptionGroup(f"OIDF {phase} group execution failed", failures)


def run_plan_groups(
    args: argparse.Namespace,
    work_dir: Path,
    env: dict[str, str],
    suite_token: str,
) -> None:
    safe_workers = getattr(args, "safe_group_workers", 1)
    browser_workers = getattr(args, "browser_group_workers", 1)
    invocations = prepare_group_invocations(args, work_dir)
    phases = {
        lane: tuple(item for item in invocations if group_lane(item[0]) == lane)
        for lane in ("safe", "ciba", "browser")
    }
    worker_count = max(safe_workers, browser_workers)
    if worker_count == 1:
        suite_dirs = (args.suite_dir,)
        worktrees: tuple[Path, ...] = ()
    else:
        worktree_root = work_dir / "suite-workers"
        worktree_root.mkdir()
        worktrees = tuple(
            worktree_root / f"worker-{index:02d}"
            for index in range(1, worker_count + 1)
        )
        created = []
        try:
            for destination in worktrees:
                add_suite_worktree(args.suite_dir, destination, args.suite_revision)
                created.append(destination)
        except BaseException:
            for destination in reversed(created):
                remove_suite_worktree(args.suite_dir, destination)
            raise
        suite_dirs = worktrees

    failure: BaseException | None = None
    try:
        run_group_phase("safe", phases["safe"], suite_dirs, safe_workers, env, suite_token)
        run_group_phase("ciba", phases["ciba"], suite_dirs, 1, env, suite_token)
        run_group_phase(
            "browser",
            phases["browser"],
            suite_dirs,
            browser_workers,
            env,
            suite_token,
        )
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors = []
        for destination in reversed(worktrees):
            try:
                remove_suite_worktree(args.suite_dir, destination)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            raise ExceptionGroup("OIDF suite worktree cleanup failed", cleanup_errors) from failure
    if failure is not None:
        raise failure


def aliases_from_config_bundle(work_dir: Path) -> dict[str, str]:
    path = work_dir / "oidf-plan-configs.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    configs = document.get("configs") if isinstance(document, dict) else None
    if not isinstance(configs, dict):
        raise PublicRunError(f"{path} must contain a configs object")
    aliases: dict[str, str] = {}
    for name, config in configs.items():
        alias = config.get("alias") if isinstance(config, dict) else None
        if not isinstance(name, str) or not isinstance(alias, str) or not alias.strip():
            raise PublicRunError(f"{path} contains a config without an alias")
        aliases[name] = alias
    return aliases


def inspect_complete_matrix(
    args: argparse.Namespace,
    work_dir: Path,
    token: str,
) -> None:
    aliases_by_config = aliases_from_config_bundle(work_dir)
    expected_warnings = work_dir / "oidf-expected-warnings-final.json"
    filter_problem_records(
        ROOT / "tests" / "contracts" / "oidf-official-expected-warnings.json",
        work_dir / "oidf-plan-set.json",
        expected_warnings,
        excluded_conditions=OFFICIAL_INGRESS_ONLY_WARNING_CONDITIONS,
    )
    inspection = {
        "allowed_reviews_by_alias": allowed_review_contexts_by_alias(aliases_by_config),
        "allowed_expected_problems_by_alias": expected_problem_contexts_by_alias(
            expected_warnings, aliases_by_config
        ),
        "allowed_expected_skips_by_alias": expected_skip_contexts_by_alias(
            work_dir / "oidf-expected-skips.json", aliases_by_config
        ),
    }

    def inspect(stage: str) -> None:
        failure = inspect_oidf_state(
            args.conformance_server,
            token,
            set(aliases_by_config.values()),
            final=True,
            **inspection,
        )
        if failure:
            raise PublicRunError(f"OIDF complete-matrix {stage} check failed: {failure}")

    inspect("immediate")
    if args.final_stabilization_seconds > 0:
        print(
            "OIDF complete-matrix stabilization window: "
            f"{args.final_stabilization_seconds} seconds",
            flush=True,
        )
        time.sleep(args.final_stabilization_seconds)
    inspect("stabilized")


def run(args: argparse.Namespace) -> None:
    if args.final_stabilization_seconds < 0:
        raise PublicRunError("--final-stabilization-seconds must be zero or greater")
    if not 60 <= args.lease_ttl_seconds <= 86_400:
        raise PublicRunError("--lease-ttl-seconds must be between 60 and 86400")
    args.safe_group_workers = getattr(
        args, "safe_group_workers", MAX_SAFE_GROUP_WORKERS
    )
    args.browser_group_workers = getattr(
        args, "browser_group_workers", MAX_BROWSER_GROUP_WORKERS
    )
    if not 1 <= args.safe_group_workers <= MAX_SAFE_GROUP_WORKERS:
        raise PublicRunError(
            f"--safe-group-workers must be between 1 and {MAX_SAFE_GROUP_WORKERS}"
        )
    if not 1 <= args.browser_group_workers <= MAX_BROWSER_GROUP_WORKERS:
        raise PublicRunError(
            f"--browser-group-workers must be between 1 and {MAX_BROWSER_GROUP_WORKERS}"
        )
    args.target_issuer = origin(args.target_issuer, "--target-issuer")
    args.conformance_server = origin(args.conformance_server, "--conformance-server")
    args.work_dir = args.work_dir.resolve()
    args.export_dir = args.export_dir.resolve()
    args.suite_dir = args.suite_dir.resolve()
    args.nazoauthctl = args.nazoauthctl.resolve()
    if not args.nazoauthctl.is_file():
        raise PublicRunError("--nazoauthctl must resolve to a regular file")
    if args.nazoauthctl_config is not None:
        if not args.nazoauthctl_config.is_absolute():
            raise PublicRunError("--nazoauthctl-config must be absolute")
        args.nazoauthctl_config = args.nazoauthctl_config.resolve()
    args.runner_sha = getattr(args, "runner_sha", None) or args.deployed_sha
    args.deployed_source_dir = getattr(args, "deployed_source_dir", None) or ROOT
    args.deployed_source_dir = args.deployed_source_dir.resolve()
    if args.work_dir.exists() or args.export_dir.exists():
        raise PublicRunError("--work-dir and --export-dir must not already exist")
    validate_output_paths(args.work_dir, args.export_dir, args.suite_dir)
    verify_source(ROOT, args.runner_sha, "runner")
    if args.deployed_source_dir != ROOT or args.deployed_sha != args.runner_sha:
        verify_source(args.deployed_source_dir, args.deployed_sha, "deployed")
    verify_suite(args.suite_dir, args.suite_revision)
    secret_document = read_secret_document(args, required_fields=SECRET_INPUT_FIELDS)
    secrets = normalized_secrets(secret_document)
    env = sanitized_environment(
        {
            "OIDF_TARGET_ISSUER": args.target_issuer,
            "OIDF_MTLS_TARGET_ISSUER": args.target_issuer,
            "OIDF_SUITE_BASE_URL": args.conformance_server,
            "OIDF_RUN_NAMESPACE": args.run_namespace,
            "OIDF_RUNTIME_DIR": str(args.work_dir),
        }
    )
    credentials = onboarding_credentials(secrets)
    args.work_dir.parent.mkdir(parents=True, exist_ok=True)
    args.export_dir.parent.mkdir(parents=True, exist_ok=True)
    proxy = ProxyTrust(args.proxy_trust_bundle, args.proxy_executable, args.work_dir)
    state_file = args.work_dir / "oidf-onboarding-state.json"
    active_lease_id: str | None = None
    failure: BaseException | None = None
    try:
        command(provisioning_args(args.target_issuer), env=env, stdin=credentials)
        preparation_secrets = {
            field: secret_document[field]
            for field in (
                "oidf_applicant_email",
                "oidf_applicant_password",
                "oidf_dynamic_registration_initial_access_token",
                "oidf_ciba_automated_decision_token",
            )
        }
        with private_secret_file(args.work_dir.parent, preparation_secrets) as secret_file:
            command(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "prepare_oidf_black_box.py"),
                    "--secret-file",
                    str(secret_file),
                ],
                env=env,
            )
        protect_directory(args.work_dir)
        active_lease_id = create_lease(
            args.nazoauthctl,
            args.nazoauthctl_config,
            profile="oidc-fapi-ciba",
            material=args.work_dir / "oidf-onboarding-manifest.json",
            ttl_seconds=args.lease_ttl_seconds,
        )
        command(
            onboarding_args(
                "apply",
                args.work_dir,
                args.target_issuer,
                active_lease_id,
            ),
            env=env,
            stdin=credentials,
        )
        proxy.install(args.work_dir / "approved-mtls-trust-anchors.pem")
        verify_suite_boundary(args.conformance_server, secrets["OIDF_CONFORMANCE_TOKEN"])
        run_plan_groups(
            args,
            args.work_dir,
            env,
            secrets["OIDF_CONFORMANCE_TOKEN"],
        )
        inspect_complete_matrix(
            args,
            args.work_dir,
            secrets["OIDF_CONFORMANCE_TOKEN"],
        )
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors: list[BaseException] = []
        try:
            cleanup_suite_runner_configs(args.suite_dir, args.work_dir)
            verify_suite(args.suite_dir, args.suite_revision)
        except BaseException as error:
            cleanup_errors.append(error)
        if state_file.exists():
            try:
                command(
                    onboarding_args("cleanup", args.work_dir, args.target_issuer),
                    env=env,
                    stdin=credentials,
                )
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            proxy.restore()
        except BaseException as error:
            cleanup_errors.append(error)
        if active_lease_id is not None:
            try:
                revoke_and_cleanup(
                    args.nazoauthctl,
                    args.nazoauthctl_config,
                    active_lease_id,
                )
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            sanitize_evidence_tree(args.export_dir)
        except BaseException as error:
            cleanup_errors.append(error)
        protect_directory(args.work_dir)
        protect_directory(args.export_dir)
        if cleanup_errors:
            raise ExceptionGroup("public OIDF cleanup failed", cleanup_errors) from failure
    if failure is not None:
        raise failure


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument(
        "--deployed-source-dir",
        type=Path,
        help="clean checkout matching --deployed-sha when the runner is newer",
    )
    parser.add_argument(
        "--runner-sha",
        help="exact runner checkout commit; defaults to --deployed-sha",
    )
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--conformance-server", required=True)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--run-namespace", required=True)
    parser.add_argument("--proxy-trust-bundle", type=Path, required=True)
    parser.add_argument("--proxy-executable", type=Path, required=True)
    parser.add_argument("--nazoauthctl", type=Path, required=True)
    parser.add_argument("--nazoauthctl-config", type=Path)
    parser.add_argument("--lease-ttl-seconds", type=int, default=28_800)
    add_secret_source_arguments(parser)
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    parser.add_argument("--monitor-interval-seconds", type=int, default=30)
    parser.add_argument(
        "--safe-group-workers",
        type=int,
        default=MAX_SAFE_GROUP_WORKERS,
        help="parallel workers for independent OIDC/FAPI plan groups (1-4)",
    )
    parser.add_argument(
        "--browser-group-workers",
        type=int,
        default=MAX_BROWSER_GROUP_WORKERS,
        help="parallel workers for isolated logout/session plan groups (1-2)",
    )
    parser.add_argument(
        "--final-stabilization-seconds",
        type=int,
        default=45,
        help="quiet window before the second complete-matrix state inspection",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args(argv))
    except (
        ConformanceLeaseControlError,
        PublicRunError,
        SecretInputError,
        subprocess.CalledProcessError,
    ) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
