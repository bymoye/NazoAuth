#!/usr/bin/env python3
"""Create and retire short-lived NazoAuth conformance leases through nazoauthctl."""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from pathlib import Path

from oidf_secret_input import sanitized_environment


class ConformanceLeaseControlError(RuntimeError):
    pass


class CandidateTarget:
    __slots__ = ("release", "revision", "build_id", "oci_digest")

    def __init__(self, release: str, revision: str, build_id: str, oci_digest: str) -> None:
        if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", release):
            raise ConformanceLeaseControlError("candidate release must be a canonical version tag")
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
            raise ConformanceLeaseControlError("candidate revision must be a Git object ID")
        if not re.fullmatch(r"[0-9A-Za-z.:_@/+\-]{1,256}", build_id):
            raise ConformanceLeaseControlError("candidate build ID is unsafe")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", oci_digest):
            raise ConformanceLeaseControlError("candidate OCI digest must be lowercase sha256")
        self.release = release
        self.revision = revision
        self.build_id = build_id
        self.oci_digest = oci_digest

    def arguments(self) -> list[str]:
        return [
            "--candidate-release",
            self.release,
            "--candidate-revision",
            self.revision,
            "--candidate-build-id",
            self.build_id,
            "--candidate-oci-digest",
            self.oci_digest,
        ]


def add_candidate_target_arguments(parser) -> None:
    parser.add_argument("--candidate-release")
    parser.add_argument("--candidate-revision")
    parser.add_argument("--candidate-build-id")
    parser.add_argument("--candidate-oci-digest")


def candidate_target_from_args(args) -> CandidateTarget | None:
    values = (
        getattr(args, "candidate_release", None),
        getattr(args, "candidate_revision", None),
        getattr(args, "candidate_build_id", None),
        getattr(args, "candidate_oci_digest", None),
    )
    if not any(value is not None for value in values):
        return None
    if not all(value is not None for value in values):
        raise ConformanceLeaseControlError(
            "candidate target requires release, revision, build ID, and OCI digest"
        )
    return CandidateTarget(*values)


def _command_line(
    nazoauthctl: Path,
    config: Path | None,
    candidate: CandidateTarget | None,
    arguments: list[str],
) -> list[str]:
    command = [str(nazoauthctl)]
    if config is not None:
        command.extend(["--config", str(config)])
    command.append("conformance")
    if candidate is not None:
        command.extend(candidate.arguments())
    command.extend(arguments)
    return command


def receipt(
    nazoauthctl: Path,
    config: Path | None,
    candidate: CandidateTarget | None,
    arguments: list[str],
) -> dict[str, object]:
    completed = subprocess.run(
        _command_line(nazoauthctl, config, candidate, arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=sanitized_environment(),
        check=False,
    )
    if completed.returncode != 0:
        operation = " ".join(arguments[:2])
        raise ConformanceLeaseControlError(f"nazoauthctl conformance {operation} failed")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ConformanceLeaseControlError(
            "nazoauthctl returned a non-JSON conformance lease receipt"
        ) from error
    if not isinstance(document, dict):
        raise ConformanceLeaseControlError(
            "nazoauthctl conformance lease receipt must be a JSON object"
        )
    return document


def _find_lease_id(value: object) -> str | None:
    if isinstance(value, dict):
        candidate = value.get("lease_id")
        if isinstance(candidate, str):
            try:
                return str(uuid.UUID(candidate))
            except ValueError:
                pass
        for child in value.values():
            if found := _find_lease_id(child):
                return found
    elif isinstance(value, list):
        for child in value:
            if found := _find_lease_id(child):
                return found
    return None


def create(
    nazoauthctl: Path,
    config: Path | None,
    *,
    profile: str,
    material: Path,
    dynamic_registration_token_file: Path | None = None,
    ciba_automated_decision_token_file: Path | None = None,
    ttl_seconds: int,
    candidate: CandidateTarget | None = None,
) -> str:
    arguments = [
        "lease",
        "create",
        "--profile",
        profile,
        "--material",
        str(material),
    ]
    if dynamic_registration_token_file is not None:
        arguments.extend(
            [
                "--dynamic-registration-token-file",
                str(dynamic_registration_token_file),
            ]
        )
    if ciba_automated_decision_token_file is not None:
        arguments.extend(
            [
                "--ciba-automated-decision-token-file",
                str(ciba_automated_decision_token_file),
            ]
        )
    arguments.extend(["--ttl-seconds", str(ttl_seconds), "--yes"])
    document = receipt(
        nazoauthctl,
        config,
        candidate,
        arguments,
    )
    lease_id = _find_lease_id(document)
    if lease_id is None:
        raise ConformanceLeaseControlError(
            "nazoauthctl create receipt contains no valid lease_id"
        )
    return lease_id


def revoke_and_cleanup(
    nazoauthctl: Path,
    config: Path | None,
    lease_id: str,
    *,
    candidate: CandidateTarget | None = None,
) -> None:
    lease_uuid = str(uuid.UUID(lease_id))
    errors: list[BaseException] = []
    try:
        receipt(
            nazoauthctl,
            config,
            candidate,
            [
                "lease",
                "revoke",
                "--lease-id",
                lease_uuid,
                "--yes",
            ],
        )
    except BaseException as error:
        errors.append(error)
    try:
        receipt(
            nazoauthctl,
            config,
            candidate,
            ["lease", "cleanup", "--yes"],
        )
    except BaseException as error:
        errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise ExceptionGroup("conformance lease revoke and cleanup failed", errors)
