#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "nazozero/NazoAuth"
OCI_REPOSITORY = "ghcr.io/nazozero/nazoauth"
PROTOCOL_VERSION = 1
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*"
    r"))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}


def load_closed_json(path: Path, keys: set[str], name: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{name} must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{name} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict) or set(value) != keys:
        raise SystemExit(f"{name} has an unexpected closed schema")
    return value


def require_string(value: Any, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SystemExit(f"{name} must be a non-empty bounded string")
    return value


def validate_artifact_descriptor(
    value: Any, name: str, *, repository: str | None = None
) -> dict[str, Any]:
    keys = {"repository", "name", "sha256", "size"}
    if not isinstance(value, dict) or set(value) != keys:
        raise SystemExit(f"{name} has an unexpected closed schema")
    artifact_repository = require_string(value["repository"], f"{name}.repository")
    if repository is not None and artifact_repository != repository:
        raise SystemExit(f"{name}.repository is not the expected repository")
    artifact_name = require_string(value["name"], f"{name}.name", 255)
    if Path(artifact_name).name != artifact_name or "/" in artifact_name or "\\" in artifact_name:
        raise SystemExit(f"{name}.name must be a plain file name")
    digest = require_string(value["sha256"], f"{name}.sha256", 64)
    if not HEX_SHA256.fullmatch(digest):
        raise SystemExit(f"{name}.sha256 must be lowercase SHA-256")
    if not isinstance(value["size"], int) or isinstance(value["size"], bool) or value["size"] <= 0:
        raise SystemExit(f"{name}.size must be a positive integer")
    return {
        "repository": artifact_repository,
        "name": artifact_name,
        "sha256": digest,
        "size": value["size"],
    }


def local_artifact(path: Path, expected_name: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.name != expected_name:
        raise SystemExit(f"release artifact must be the expected regular file: {expected_name}")
    size = path.stat().st_size
    if size <= 0:
        raise SystemExit(f"release artifact must not be empty: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "repository": REPOSITORY,
        "name": expected_name,
        "sha256": digest.hexdigest(),
        "size": size,
    }


def validate_frontend(path: Path) -> dict[str, Any]:
    value = load_closed_json(
        path,
        {"schema", "repository", "version", "commit", "release_identity", "artifact"},
        "frontend descriptor",
    )
    if value["schema"] != 1:
        raise SystemExit("frontend descriptor has an unsupported schema")
    repository = require_string(value["repository"], "frontend.repository")
    if repository != "nazozero/NazoAuthWeb":
        raise SystemExit("frontend.repository must be nazozero/NazoAuthWeb")
    version = require_string(value["version"], "frontend.version")
    if not VERSION.fullmatch(version):
        raise SystemExit("frontend.version must be an immutable vSemVer tag")
    commit = require_string(value["commit"], "frontend.commit", 40)
    if not GIT_COMMIT.fullmatch(commit):
        raise SystemExit("frontend.commit must be a full lowercase Git commit")
    identity = require_string(value["release_identity"], "frontend.release_identity")
    expected_identity = (
        f"https://github.com/{repository}/.github/workflows/"
        f"release.yml@refs/tags/{version}"
    )
    if identity != expected_identity:
        raise SystemExit("frontend.release_identity does not bind its repository and tag")
    artifact = validate_artifact_descriptor(
        value["artifact"], "frontend.artifact", repository=repository
    )
    if artifact["name"] != "nazoauth-web.tar.gz":
        raise SystemExit("frontend.artifact.name must be nazoauth-web.tar.gz")
    return {
        "repository": repository,
        "version": version,
        "commit": commit,
        "release_identity": identity,
        "artifact": artifact,
    }


def validate_oci(path: Path) -> dict[str, Any]:
    value = load_closed_json(
        path,
        {"repository", "index_digest", "platform_manifests"},
        "OCI descriptor",
    )
    if value["repository"] != OCI_REPOSITORY:
        raise SystemExit(f"OCI repository must be {OCI_REPOSITORY}")
    if not isinstance(value["index_digest"], str) or not SHA256.fullmatch(value["index_digest"]):
        raise SystemExit("OCI index digest must be a lowercase sha256 digest")
    manifests = value["platform_manifests"]
    expected_platforms = {"linux/amd64", "linux/arm64"}
    if not isinstance(manifests, dict) or set(manifests) != expected_platforms:
        raise SystemExit("OCI platform manifests must contain exactly linux/amd64 and linux/arm64")
    if any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in manifests.values()):
        raise SystemExit("OCI platform manifest digest must be lowercase sha256")
    return {
        "repository": OCI_REPOSITORY,
        "index_digest": value["index_digest"],
        "platform_manifests": {platform: manifests[platform] for platform in sorted(manifests)},
    }


def validate_policy(path: Path) -> dict[str, Any]:
    policy = load_closed_json(
        path,
        {
            "schema",
            "artifact_rollback",
            "schema_compatible",
            "database_restore",
            "irreversible_migration",
            "minimum_supported_version",
            "migration_floor",
            "rationale",
        },
        "release update policy",
    )
    if policy["schema"] != 2:
        raise SystemExit("release update policy has an unsupported schema")
    for field in ("artifact_rollback", "schema_compatible", "irreversible_migration"):
        if not isinstance(policy[field], bool):
            raise SystemExit(f"{field} must be boolean")
    if policy["database_restore"] not in {"backup", "pitr", "none"}:
        raise SystemExit("database_restore must be backup, pitr, or none")
    if policy["irreversible_migration"] and policy["schema_compatible"]:
        raise SystemExit("an irreversible migration cannot be schema compatible")
    minimum = require_string(policy["minimum_supported_version"], "minimum_supported_version")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", minimum):
        raise SystemExit("minimum_supported_version must be SemVer without a v prefix")
    floor = require_string(policy["migration_floor"], "migration_floor", 14)
    if not re.fullmatch(r"[0-9]{14}", floor):
        raise SystemExit("migration_floor must be a 14-digit migration version")
    migration_versions = sorted(
        candidate.name.split("_", 1)[0]
        for candidate in (ROOT / "migrations").iterdir()
        if candidate.is_dir() and re.match(r"^[0-9]{14}_", candidate.name)
    )
    if not migration_versions or floor != migration_versions[-1]:
        raise SystemExit("migration_floor must equal the newest migration")
    rationale = require_string(policy["rationale"], "rationale").strip()
    return {
        "artifact": policy["artifact_rollback"],
        "schema_compatible": policy["schema_compatible"],
        "database_restore": policy["database_restore"],
        "irreversible_migration": policy["irreversible_migration"],
        "minimum_supported_version": minimum,
        "migration_floor": floor,
        "rationale": rationale,
    }


def validate_operator_compatibility(path: Path) -> dict[str, Any]:
    value = load_closed_json(
        path,
        {"schema", "version", "minimum_ctl_version", "maximum_ctl_version_exclusive"},
        "operator protocol compatibility",
    )
    if value["schema"] != 1 or value["version"] != PROTOCOL_VERSION:
        raise SystemExit("operator protocol compatibility version is unsupported")
    minimum = require_string(value["minimum_ctl_version"], "minimum_ctl_version", 32)
    maximum = require_string(
        value["maximum_ctl_version_exclusive"],
        "maximum_ctl_version_exclusive",
        32,
    )
    semver = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
    minimum_match = semver.fullmatch(minimum)
    maximum_match = semver.fullmatch(maximum)
    if minimum_match is None or maximum_match is None:
        raise SystemExit("controller compatibility bounds must be stable SemVer")
    minimum_tuple = tuple(int(part) for part in minimum_match.groups())
    maximum_tuple = tuple(int(part) for part in maximum_match.groups())
    if minimum_tuple >= maximum_tuple:
        raise SystemExit("controller compatibility range must be non-empty")
    return {
        "version": PROTOCOL_VERSION,
        "minimum_ctl_version": minimum,
        "maximum_ctl_version_exclusive": maximum,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--backend-commit", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--operator-compatibility", type=Path, required=True)
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--oci", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        raise SystemExit("version must be an immutable vSemVer tag")
    if args.target not in TARGETS:
        raise SystemExit("target is not in the closed supported Release target set")
    backend_commit = args.backend_commit.strip().lower()
    if not GIT_COMMIT.fullmatch(backend_commit):
        raise SystemExit("backend commit must be a full lowercase Git commit")
    if not re.fullmatch(r"[0-9A-Za-z.:_@/+\-]{1,256}", args.build_id):
        raise SystemExit("build id is invalid")
    extension = ".exe" if "windows" in args.target else ""
    binary_name = f"nazoauth-{args.target}{extension}"
    manifest = {
        "schema": 5,
        "version": args.version,
        "target": args.target,
        "backend_commit": backend_commit,
        "release_identity": (
            "https://github.com/nazozero/NazoAuth/"
            f".github/workflows/release-security.yml@refs/tags/{args.version}"
        ),
        "embedded": {
            "release": args.version,
            "revision": backend_commit,
            "protocol": PROTOCOL_VERSION,
            "build_id": args.build_id,
        },
        "operator_protocol": validate_operator_compatibility(args.operator_compatibility),
        "artifacts": {
            "binary": local_artifact(args.binary, binary_name),
        },
        "frontend": validate_frontend(args.frontend),
        "oci": validate_oci(args.oci),
        "rollback": validate_policy(args.policy),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
