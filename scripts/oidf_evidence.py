#!/usr/bin/env python3
"""Reduce OIDF result archives to a credential-free evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from collections import Counter
from pathlib import Path


FORMAT_VERSION = 1
MANIFEST_NAME = "evidence-manifest.json"
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
SAFE_TEST_INFO_FIELDS = (
    "testId",
    "testName",
    "variant",
    "started",
    "description",
    "alias",
    "planId",
    "status",
    "version",
    "summary",
    "publish",
    "result",
)
PROBLEM_RESULTS = frozenset({"FAILURE", "WARNING", "REVIEW"})
SAFE_CONDITION_SOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:$-]{0,127}$")


class EvidenceError(RuntimeError):
    """Raised when an exported archive cannot be reduced safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def result_counts(results: object) -> dict[str, int]:
    if not isinstance(results, list):
        raise EvidenceError("OIDF export results must be an array")
    counts: Counter[str] = Counter()
    for entry in results:
        if not isinstance(entry, dict):
            raise EvidenceError("OIDF export result entry must be an object")
        value = entry.get("result")
        counts[value if isinstance(value, str) and value else "UNSPECIFIED"] += 1
    return dict(sorted(counts.items()))


def problem_conditions(results: object) -> list[dict[str, str]]:
    """Retain diagnostic condition identities without messages or arguments."""
    if not isinstance(results, list):
        raise EvidenceError("OIDF export results must be an array")
    observed: set[tuple[str, str]] = set()
    problems: list[dict[str, str]] = []
    for entry in results:
        if not isinstance(entry, dict):
            raise EvidenceError("OIDF export result entry must be an object")
        result = entry.get("result")
        source = entry.get("src")
        if (
            result not in PROBLEM_RESULTS
            or not isinstance(source, str)
            or SAFE_CONDITION_SOURCE.fullmatch(source) is None
        ):
            continue
        identity = (result, source)
        if identity in observed:
            continue
        observed.add(identity)
        problems.append({"result": result, "src": source})
    return problems


def summarize_archive(path: Path, root: Path) -> dict[str, object]:
    modules: list[dict[str, object]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError(f"OIDF archive contains too many members: {path}")
            total_size = 0
            for member in members:
                if member.file_size < 0:
                    raise EvidenceError(
                        f"OIDF archive member has a negative size: {path}:{member.filename}"
                    )
                total_size += member.file_size
                if total_size > MAX_ARCHIVE_BYTES:
                    raise EvidenceError(f"OIDF archive expands beyond the bounded size: {path}")

            json_members = sorted(
                (member for member in members if member.filename.endswith(".json")),
                key=lambda member: member.filename,
            )
            json_names = [member.filename for member in json_members]
            if not json_names:
                raise EvidenceError(f"OIDF archive contains no JSON modules: {path}")
            names = {member.filename for member in members}
            for member in json_members:
                name = member.filename
                if member.file_size > MAX_JSON_BYTES:
                    raise EvidenceError(
                        f"OIDF JSON module exceeds the bounded JSON size: {path}:{name}"
                    )
                with archive.open(member, "r") as source:
                    encoded = source.read(MAX_JSON_BYTES + 1)
                if len(encoded) > MAX_JSON_BYTES:
                    raise EvidenceError(
                        f"OIDF JSON module exceeds the bounded JSON size: {path}:{name}"
                    )
                payload = json.loads(encoded)
                if not isinstance(payload, dict):
                    raise EvidenceError(f"OIDF module export must be an object: {path}:{name}")
                test_info = payload.get("testInfo")
                if not isinstance(test_info, dict):
                    raise EvidenceError(f"OIDF module export lacks testInfo: {path}:{name}")
                safe_info = {
                    field: test_info[field]
                    for field in SAFE_TEST_INFO_FIELDS
                    if field in test_info
                }
                results = payload.get("results")
                modules.append(
                    {
                        "file": name,
                        "signature_present": name.removesuffix(".json") + ".sig" in names,
                        "test_info": safe_info,
                        "condition_results": result_counts(results),
                        "problem_conditions": problem_conditions(results),
                    }
                )
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid OIDF evidence archive {path}: {error}") from error

    return {
        "file": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "modules": modules,
    }


def aggregate_archives(archives: list[dict[str, object]]) -> dict[str, object]:
    module_results: Counter[str] = Counter()
    condition_results: Counter[str] = Counter()
    module_count = 0
    plan_ids: set[str] = set()
    for archive in archives:
        modules = archive.get("modules")
        if not isinstance(modules, list):
            raise EvidenceError("evidence manifest archive modules must be an array")
        for module in modules:
            if not isinstance(module, dict):
                raise EvidenceError("evidence manifest module must be an object")
            module_count += 1
            test_info = module.get("test_info")
            if not isinstance(test_info, dict):
                raise EvidenceError("evidence manifest module lacks test_info")
            result = test_info.get("result")
            module_results[result if isinstance(result, str) and result else "UNSPECIFIED"] += 1
            plan_id = test_info.get("planId")
            if isinstance(plan_id, str) and plan_id:
                plan_ids.add(plan_id)
            counts = module.get("condition_results")
            if not isinstance(counts, dict):
                raise EvidenceError("evidence manifest module lacks condition_results")
            for name, count in counts.items():
                if not isinstance(name, str) or not isinstance(count, int) or count < 0:
                    raise EvidenceError("invalid evidence condition result count")
                condition_results[name] += count
    return {
        "archive_count": len(archives),
        "plan_count": len(plan_ids),
        "module_count": module_count,
        "module_results": dict(sorted(module_results.items())),
        "condition_results": dict(sorted(condition_results.items())),
    }


def load_child_manifest(path: Path, root: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid child evidence manifest {path}: {error}") from error
    if not isinstance(payload, dict) or payload.get("format_version") != FORMAT_VERSION:
        raise EvidenceError(f"unsupported child evidence manifest: {path}")
    archives = payload.get("archives")
    if not isinstance(archives, list):
        raise EvidenceError(f"child evidence manifest lacks archives: {path}")
    prefix = path.parent.relative_to(root)
    result: list[dict[str, object]] = []
    for archive in archives:
        if not isinstance(archive, dict) or not isinstance(archive.get("file"), str):
            raise EvidenceError(f"invalid archive in child evidence manifest: {path}")
        copied = dict(archive)
        copied["file"] = (prefix / archive["file"]).as_posix()
        result.append(copied)
    return result


def sanitize_evidence_tree(root: Path) -> Path | None:
    root = root.resolve()
    if not root.exists():
        return None
    if not root.is_dir():
        raise EvidenceError(f"evidence export path is not a directory: {root}")

    manifest_path = root / MANIFEST_NAME
    archives = [summarize_archive(path, root) for path in sorted(root.rglob("*.zip"))]
    child_manifests = [
        path
        for path in sorted(root.rglob(MANIFEST_NAME))
        if path != manifest_path
    ]
    for child in child_manifests:
        archives.extend(load_child_manifest(child, root))

    if not archives:
        return manifest_path if manifest_path.is_file() else None
    archives.sort(key=lambda archive: str(archive["file"]))
    payload = {
        "format_version": FORMAT_VERSION,
        "summary": aggregate_archives(archives),
        "archives": archives,
    }
    temporary = root / f".{MANIFEST_NAME}.tmp"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.replace(temporary, manifest_path)

    for path in sorted(root.rglob("*.zip")):
        path.unlink()
    for child in child_manifests:
        child.unlink()
    return manifest_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export_dir", type=Path)
    return parser.parse_args()


def main() -> int:
    manifest = sanitize_evidence_tree(parse_args().export_dir)
    if manifest is None:
        raise SystemExit("no OIDF evidence archives found")
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
