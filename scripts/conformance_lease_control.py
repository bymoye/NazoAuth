#!/usr/bin/env python3
"""Create and retire short-lived NazoAuth conformance leases through nazoauthctl."""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

from oidf_secret_input import sanitized_environment


class ConformanceLeaseControlError(RuntimeError):
    pass


def _command_line(
    nazoauthctl: Path,
    config: Path | None,
    arguments: list[str],
) -> list[str]:
    command = [str(nazoauthctl)]
    if config is not None:
        command.extend(["--config", str(config)])
    command.extend(arguments)
    return command


def receipt(
    nazoauthctl: Path,
    config: Path | None,
    arguments: list[str],
) -> dict[str, object]:
    completed = subprocess.run(
        _command_line(nazoauthctl, config, arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=sanitized_environment(),
        check=False,
    )
    if completed.returncode != 0:
        operation = " ".join(arguments[:3])
        raise ConformanceLeaseControlError(f"nazoauthctl {operation} failed")
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
    ttl_seconds: int,
) -> str:
    document = receipt(
        nazoauthctl,
        config,
        [
            "conformance",
            "lease",
            "create",
            "--profile",
            profile,
            "--material",
            str(material),
            "--ttl-seconds",
            str(ttl_seconds),
            "--yes",
        ],
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
) -> None:
    receipt(
        nazoauthctl,
        config,
        [
            "conformance",
            "lease",
            "revoke",
            "--lease-id",
            str(uuid.UUID(lease_id)),
            "--yes",
        ],
    )
    receipt(
        nazoauthctl,
        config,
        ["conformance", "lease", "cleanup", "--yes"],
    )
