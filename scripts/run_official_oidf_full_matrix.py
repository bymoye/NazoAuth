#!/usr/bin/env python3
"""Run the official OIDF 27 + 17 matrix from a local operator host.

This entry point is deliberately a thin coordinator.  The existing public
OIDC/FAPI/CIBA runner owns its 27-plan lifecycle and the existing OpenID4VC
runner owns its 17-plan lifecycle.  Secrets are read once from a closed JSON
document and are forwarded to each child over standard input; GitHub, argv,
and environment variables are not secret providers.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from conformance_lease_control import (  # noqa: E402
    ConformanceLeaseControlError,
    add_candidate_target_arguments,
    candidate_target_from_args,
)
from oidf_evidence import sanitize_evidence_tree  # noqa: E402
from oidf_secret_input import (  # noqa: E402
    SecretInputError,
    add_secret_source_arguments,
    read_secret_document,
    sanitized_environment,
)


OFFICIAL_CONFORMANCE_SERVER = "https://www.certification.openid.net"
SECRET_FIELDS = (
    "applicant_email",
    "applicant_password",
    "admin_email",
    "admin_password",
    "admin_mfa_totp_secret",
    "oidf_conformance_token",
    "issuer_management_token",
    "verifier_management_token",
)
EXPECTED_PLAN_COUNT = 44
RUN_NAMESPACE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")


class OfficialFullMatrixError(RuntimeError):
    pass


def append_option(arguments: list[str], name: str, value: object | None) -> None:
    if value is not None:
        arguments.extend((name, str(value)))


def child_run_namespaces(base: str) -> tuple[str, str]:
    namespaces = (f"{base}-protocol", f"{base}-openid4vc")
    if any(RUN_NAMESPACE_PATTERN.fullmatch(value) is None for value in namespaces):
        raise OfficialFullMatrixError(
            "--run-namespace must produce 1-32 character lowercase child namespaces "
            "containing only letters, digits, or internal hyphens"
        )
    return namespaces


def common_arguments(
    args: argparse.Namespace,
    *,
    suite_dir: Path | None = None,
) -> list[str]:
    arguments = [
        "--deployed-sha",
        args.deployed_sha,
        "--runner-sha",
        args.runner_sha or args.deployed_sha,
        "--target-issuer",
        args.target_issuer,
        "--conformance-server",
        OFFICIAL_CONFORMANCE_SERVER,
        "--suite-dir",
        str(suite_dir or args.suite_dir),
        "--suite-revision",
        args.suite_revision,
        "--nazoauthctl",
        str(args.nazoauthctl),
        "--lease-ttl-seconds",
        str(args.lease_ttl_seconds),
    ]
    append_option(arguments, "--deployed-source-dir", args.deployed_source_dir)
    append_option(arguments, "--nazoauthctl-config", args.nazoauthctl_config)
    candidate = candidate_target_from_args(args)
    if candidate is not None:
        arguments.extend(
            (
                "--candidate-release",
                candidate.release,
                "--candidate-revision",
                candidate.revision,
                "--candidate-build-id",
                candidate.build_id,
                "--candidate-oci-digest",
                candidate.oci_digest,
            )
        )
    return arguments


def command(arguments: list[str], *, cwd: Path = ROOT) -> None:
    subprocess.run(
        arguments,
        cwd=cwd,
        env=sanitized_environment(),
        check=True,
    )


def create_suite_worktree(source: Path, destination: Path, revision: str) -> None:
    command(
        ["git", "-C", str(source), "worktree", "add", "--detach", str(destination), revision]
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=destination,
        env=sanitized_environment(),
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=destination,
        env=sanitized_environment(),
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if head != revision or status:
        raise OfficialFullMatrixError("isolated OpenID4VC suite worktree is not exact and clean")


def remove_suite_worktree(source: Path, destination: Path) -> None:
    command(
        ["git", "-C", str(source), "worktree", "remove", "--force", str(destination)]
    )


def public_secret_document(secrets: dict[str, str]) -> dict[str, str]:
    return {
        "oidf_applicant_email": secrets["applicant_email"],
        "oidf_applicant_password": secrets["applicant_password"],
        "oidf_admin_email": secrets["admin_email"],
        "oidf_admin_password": secrets["admin_password"],
        "oidf_admin_totp_secret": secrets["admin_mfa_totp_secret"],
        "oidf_conformance_token": secrets["oidf_conformance_token"],
    }


def openid4vc_secret_document(secrets: dict[str, str]) -> dict[str, str]:
    return {
        "applicant_email": secrets["applicant_email"],
        "applicant_password": secrets["applicant_password"],
        "admin_email": secrets["admin_email"],
        "admin_password": secrets["admin_password"],
        "admin_mfa_totp_secret": secrets["admin_mfa_totp_secret"],
        "suite_token": secrets["oidf_conformance_token"],
        "issuer_management_token": secrets["issuer_management_token"],
        "verifier_management_token": secrets["verifier_management_token"],
    }


def run_child(script: str, arguments: list[str], secrets: dict[str, str]) -> None:
    payload = (json.dumps(secrets, separators=(",", ":")) + "\n").encode("utf-8")
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *arguments, "--secrets-stdin"],
        cwd=ROOT,
        env=sanitized_environment(),
        input=payload,
        check=False,
    )
    if completed.returncode != 0:
        raise OfficialFullMatrixError(
            f"{script} exited with status {completed.returncode}"
        )


def load_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OfficialFullMatrixError("official evidence manifest is unreadable") from error
    if not isinstance(payload, dict) or payload.get("format_version") != 1:
        raise OfficialFullMatrixError("official evidence manifest has an unsupported format")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise OfficialFullMatrixError("official evidence manifest has no summary")
    return payload


def write_receipt(
    args: argparse.Namespace,
    manifest_path: Path | None,
    *,
    outcome: str,
) -> None:
    summary: dict[str, object] | None = None
    manifest_sha256: str | None = None
    if manifest_path is not None:
        manifest = load_manifest(manifest_path)
        summary = manifest["summary"]  # type: ignore[assignment]
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if outcome == "PASSED" and (
        summary is None or summary.get("plan_count") != EXPECTED_PLAN_COUNT
    ):
        raise OfficialFullMatrixError(
            f"successful official full matrix must bind {EXPECTED_PLAN_COUNT} plan IDs"
        )
    receipt = {
        "format_version": 1,
        "runner": "local-official-oidf-full-matrix",
        "outcome": outcome,
        "deployed_sha": args.deployed_sha,
        "runner_sha": args.runner_sha or args.deployed_sha,
        "suite_revision": args.suite_revision,
        "target_issuer": args.target_issuer,
        "conformance_server": OFFICIAL_CONFORMANCE_SERVER,
        "plan_registry": {"oidc_fapi_ciba_logout_session": 27, "openid4vc": 17},
        "evidence": None
        if summary is None
        else {
            "manifest": manifest_path.name,
            "manifest_sha256": manifest_sha256,
            "summary": summary,
        },
    }
    path = args.export_dir / "official-full-matrix-receipt.json"
    temporary = args.export_dir / ".official-full-matrix-receipt.json.tmp"
    temporary.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    os.replace(temporary, path)


def run(args: argparse.Namespace) -> None:
    if not 60 <= args.lease_ttl_seconds <= 86_400:
        raise OfficialFullMatrixError(
            "--lease-ttl-seconds must be between 60 and 86400"
        )
    protocol_namespace, openid4vc_namespace = child_run_namespaces(
        args.run_namespace
    )
    args.work_dir = args.work_dir.resolve()
    args.export_dir = args.export_dir.resolve()
    args.suite_dir = args.suite_dir.resolve()
    configured_prior_manifest = getattr(args, "prior_evidence_manifest", None)
    prior_manifest = (
        configured_prior_manifest.resolve()
        if configured_prior_manifest is not None
        else None
    )
    if prior_manifest is not None:
        load_manifest(prior_manifest)
    if args.work_dir.exists() or args.export_dir.exists():
        raise OfficialFullMatrixError("--work-dir and --export-dir must not already exist")
    if args.work_dir == args.export_dir:
        raise OfficialFullMatrixError("--work-dir and --export-dir must be distinct")
    secrets = read_secret_document(args, required_fields=SECRET_FIELDS)
    args.work_dir.mkdir(parents=True, mode=0o700)
    args.export_dir.mkdir(parents=True, mode=0o700)
    args.work_dir.chmod(0o700)
    args.export_dir.chmod(0o700)
    if prior_manifest is not None:
        prior_dir = args.export_dir / "prior"
        prior_dir.mkdir(mode=0o700)
        copied = prior_dir / "evidence-manifest.json"
        shutil.copyfile(prior_manifest, copied)
        copied.chmod(0o600)
    openid4vc_suite_dir = args.work_dir / "openid4vc-suite"
    worktree_created = False
    failure: BaseException | None = None
    manifest_path: Path | None = None
    try:
        create_suite_worktree(args.suite_dir, openid4vc_suite_dir, args.suite_revision)
        worktree_created = True
        protocol_common = common_arguments(args)
        openid4vc_common = common_arguments(args, suite_dir=openid4vc_suite_dir)
        protocol_arguments = [
            *protocol_common,
            "--work-dir",
            str(args.work_dir / "oidc-fapi-ciba"),
            "--export-dir",
            str(args.export_dir / "oidc-fapi-ciba"),
            "--run-namespace",
            protocol_namespace,
            "--proxy-trust-bundle",
            str(args.proxy_trust_bundle),
            "--proxy-executable",
            str(args.proxy_executable),
            "--safe-group-workers",
            str(getattr(args, "protocol_safe_group_workers", 2)),
            "--browser-group-workers",
            str(getattr(args, "protocol_browser_group_workers", 2)),
            "--timeout-seconds",
            str(args.protocol_timeout_seconds),
            "--monitor-interval-seconds",
            str(args.protocol_monitor_interval_seconds),
            "--final-stabilization-seconds",
            str(args.final_stabilization_seconds),
            "--parallel-ready-file",
            str(args.work_dir / "protocol-parallel-ready"),
        ]
        for group in getattr(args, "protocol_groups", None) or ():
            protocol_arguments.extend(("--group", group))
        openid4vc_arguments = [
            *openid4vc_common,
            "--work-dir",
            str(args.work_dir / "openid4vc"),
            "--export-dir",
            str(args.export_dir / "openid4vc"),
            "--run-namespace",
            openid4vc_namespace,
            "--prepared-install-dir",
            str(args.prepared_install_dir),
            "--request-object-trust-anchor-pem",
            str(args.request_object_trust_anchor_pem),
            "--plan-group-size",
            str(args.openid4vc_plan_group_size),
            "--timeout-seconds",
            str(args.openid4vc_timeout_seconds),
            "--monitor-interval-seconds",
            str(args.openid4vc_monitor_interval_seconds),
        ]
        ready_file = args.work_dir / "protocol-parallel-ready"
        errors: list[BaseException] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            protocol_future = executor.submit(
                run_child,
                "run_public_oidf_conformance.py",
                protocol_arguments,
                public_secret_document(secrets),
            )
            deadline = time.monotonic() + 300
            while not ready_file.is_file():
                if protocol_future.done():
                    protocol_future.result()
                    raise OfficialFullMatrixError(
                        "protocol runner exited before its parallel readiness signal"
                    )
                if time.monotonic() >= deadline:
                    raise OfficialFullMatrixError(
                        "protocol runner did not reach parallel readiness within 300 seconds"
                    )
                time.sleep(0.1)
            ready_file.unlink()
            openid4vc_future = executor.submit(
                run_child,
                "run_host_local_openid4vc_conformance.py",
                openid4vc_arguments,
                openid4vc_secret_document(secrets),
            )
            futures = {
                protocol_future: "protocol",
                openid4vc_future: "openid4vc",
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except BaseException as error:
                    error.add_note(f"official {futures[future]} matrix failed")
                    errors.append(error)
        if errors:
            raise ExceptionGroup("official parallel matrix execution failed", errors)
    except BaseException as error:
        failure = error
    finally:
        if worktree_created:
            try:
                remove_suite_worktree(args.suite_dir, openid4vc_suite_dir)
            except BaseException as cleanup_error:
                if failure is not None:
                    failure = ExceptionGroup(
                        "official execution and suite worktree cleanup failed",
                        [failure, cleanup_error],
                    )
                else:
                    failure = cleanup_error
        try:
            manifest_path = sanitize_evidence_tree(args.export_dir)
            write_receipt(
                args,
                manifest_path,
                outcome="PASSED" if failure is None else "FAILED",
            )
        except BaseException as cleanup_error:
            if failure is not None:
                raise ExceptionGroup(
                    "official full-matrix execution and evidence reduction failed",
                    [failure, cleanup_error],
                )
            raise
    if failure is not None:
        raise failure


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument("--deployed-source-dir", type=Path)
    parser.add_argument("--runner-sha")
    parser.add_argument("--target-issuer", required=True)
    parser.add_argument("--suite-dir", type=Path, required=True)
    parser.add_argument("--suite-revision", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--run-namespace", required=True)
    parser.add_argument("--proxy-trust-bundle", type=Path, required=True)
    parser.add_argument("--proxy-executable", type=Path, required=True)
    parser.add_argument("--prepared-install-dir", type=Path, required=True)
    parser.add_argument("--request-object-trust-anchor-pem", type=Path, required=True)
    parser.add_argument("--nazoauthctl", type=Path, required=True)
    parser.add_argument("--nazoauthctl-config", type=Path)
    add_candidate_target_arguments(parser)
    parser.add_argument("--lease-ttl-seconds", type=int, default=28_800)
    add_secret_source_arguments(parser)
    parser.add_argument("--protocol-timeout-seconds", type=int, default=14_400)
    parser.add_argument("--protocol-monitor-interval-seconds", type=int, default=30)
    parser.add_argument("--protocol-safe-group-workers", type=int, default=2)
    parser.add_argument("--protocol-browser-group-workers", type=int, default=2)
    parser.add_argument(
        "--protocol-group",
        dest="protocol_groups",
        action="append",
        help="run only this bounded protocol group; repeat when resuming",
    )
    parser.add_argument(
        "--prior-evidence-manifest",
        type=Path,
        help="sanitized manifest from already completed plans to merge into this receipt",
    )
    parser.add_argument("--final-stabilization-seconds", type=int, default=45)
    parser.add_argument("--openid4vc-plan-group-size", type=int, default=17)
    parser.add_argument("--openid4vc-timeout-seconds", type=int, default=4_800)
    parser.add_argument("--openid4vc-monitor-interval-seconds", type=int, default=10)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args(argv))
    except (
        ConformanceLeaseControlError,
        OfficialFullMatrixError,
        SecretInputError,
        subprocess.SubprocessError,
    ) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
