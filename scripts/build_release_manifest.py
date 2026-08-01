#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
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


def artifact(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"release artifact must be a regular file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise SystemExit(f"release artifact must not be empty: {path}")
    return {
        "name": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": size,
    }


def commit(value: str, name: str) -> str:
    value = value.strip().lower()
    if not GIT_COMMIT.fullmatch(value):
        raise SystemExit(f"{name} must be a full lowercase Git commit")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--backend-commit", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--frontend-commit", required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ui", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--updater", type=Path, required=True)
    parser.add_argument("--updater-sbom", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        raise SystemExit("version must be an immutable vMAJOR.MINOR.PATCH tag")
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    expected_policy_keys = {
        "schema",
        "artifact_rollback",
        "schema_compatible",
        "database_restore",
        "irreversible_migration",
        "minimum_supported_version",
        "migration_floor",
        "rationale",
    }
    if set(policy) != expected_policy_keys or policy["schema"] != 2:
        raise SystemExit("release update policy has an unexpected schema")
    for field in ["artifact_rollback", "schema_compatible", "irreversible_migration"]:
        if not isinstance(policy[field], bool):
            raise SystemExit(f"{field} must be boolean")
    if policy["database_restore"] not in {"backup", "pitr", "none"}:
        raise SystemExit("database_restore must be backup, pitr, or none")
    if policy["irreversible_migration"] and policy["schema_compatible"]:
        raise SystemExit("an irreversible migration cannot be schema compatible")
    if not re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
        policy["minimum_supported_version"],
    ):
        raise SystemExit("minimum_supported_version must be MAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[0-9]{14}", policy["migration_floor"]):
        raise SystemExit("migration_floor must be a 14-digit migration version")
    if not isinstance(policy["rationale"], str) or not policy["rationale"].strip():
        raise SystemExit("release update policy requires a rationale")
    migration_versions = sorted(
        path.name.split("_", 1)[0]
        for path in (ROOT / "migrations").iterdir()
        if path.is_dir() and re.match(r"^[0-9]{14}_", path.name)
    )
    if not migration_versions or policy["migration_floor"] != migration_versions[-1]:
        raise SystemExit(
            "migration_floor must equal the newest migration; review rollback "
            "compatibility for every migration-bearing release"
        )

    backend_commit = commit(args.backend_commit, "backend commit")
    frontend_commit = commit(args.frontend_commit, "frontend commit")
    image_digest = args.image_digest.strip().lower()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise SystemExit("image digest must be a lowercase sha256 OCI image ID")
    if not re.fullmatch(r"[0-9A-Za-z.:_@/+\-]{1,256}", args.build_id):
        raise SystemExit("build id is invalid")
    manifest = {
        "schema": 3,
        "version": args.version,
        "backend_commit": backend_commit,
        "frontend_commit": frontend_commit,
        "image_ref": f"localhost/nazo-oauth-server:{args.version}",
        "release_identity": (
            "https://github.com/nazozero/NazoAuth/"
            f".github/workflows/release-security.yml@refs/tags/{args.version}"
        ),
        "image_oci_digest": image_digest,
        "embedded": {
            "release": args.version,
            "revision": backend_commit,
            "protocol": 1,
            "build_id": args.build_id,
        },
        "artifacts": {
            "image": artifact(args.image),
            "ui": artifact(args.ui),
            "binary": artifact(args.binary),
            "bootstrap": artifact(args.bootstrap),
            "updater": artifact(args.updater),
            "updater_sbom": artifact(args.updater_sbom),
            "sbom": artifact(args.sbom),
        },
        "rollback": {
            "artifact": policy["artifact_rollback"],
            "schema_compatible": policy["schema_compatible"],
            "database_restore": policy["database_restore"],
            "irreversible_migration": policy["irreversible_migration"],
            "minimum_supported_version": policy["minimum_supported_version"],
            "migration_floor": policy["migration_floor"],
            "rationale": policy["rationale"].strip(),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
