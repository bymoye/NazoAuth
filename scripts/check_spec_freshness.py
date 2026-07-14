#!/usr/bin/env python3
"""Validate NazoAuth's protocol-source inventory, optionally against official sites."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "requirements" / "spec-freshness.json"
ALLOWED_HOSTS = {
    "ietf_draft": {"datatracker.ietf.org"},
    "rfc": {"www.rfc-editor.org"},
    "openid_document": {"openid.net", "openid.bitbucket.io"},
    "oidf_suite": {"gitlab.com"},
}
DRAFT_PIN = re.compile(r"\b(draft-[a-z0-9-]+)-(\d{2})\b")
RFC_REFERENCE = re.compile(r"\bRFC\s*(\d{4})\b", re.IGNORECASE)


def _required_text(value: object, field: str, entry_id: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{entry_id}: {field} must be a non-empty string")
    return value


def validate_manifest(manifest: dict, root: Path = ROOT) -> None:
    if manifest.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty list")

    ids: set[str] = set()
    urls: set[str] = set()
    current_drafts: dict[str, str] = {}
    for entry in sources:
        if not isinstance(entry, dict):
            raise ValueError("every source must be an object")
        entry_id = _required_text(entry.get("id"), "id", "source")
        kind = _required_text(entry.get("kind"), "kind", entry_id)
        url = _required_text(entry.get("url"), "url", entry_id)
        _required_text(entry.get("title"), "title", entry_id)
        if entry_id in ids:
            raise ValueError(f"duplicate id: {entry_id}")
        if url in urls:
            raise ValueError(f"duplicate URL: {url}")
        ids.add(entry_id)
        urls.add(url)
        if kind not in ALLOWED_HOSTS:
            raise ValueError(f"{entry_id}: unsupported kind {kind}")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS[kind]:
            raise ValueError(f"{entry_id}: URL must use an official host for {kind}")

        if kind == "ietf_draft":
            document = _required_text(entry.get("document"), "document", entry_id)
            revision = _required_text(entry.get("revision"), "revision", entry_id)
            if not re.fullmatch(r"\d{2}", revision):
                raise ValueError(f"{entry_id}: revision must contain two digits")
            current_drafts[document] = revision
        elif kind in {"rfc", "openid_document"}:
            markers = entry.get("markers")
            if not isinstance(markers, list) or not markers or not all(
                isinstance(marker, str) and marker for marker in markers
            ):
                raise ValueError(f"{entry_id}: markers must be non-empty strings")
        elif kind == "oidf_suite":
            api_url = _required_text(entry.get("api_url"), "api_url", entry_id)
            api = urlparse(api_url)
            if (
                api.scheme != "https"
                or api.hostname != "gitlab.com"
                or not api.path.startswith(
                    "/api/v4/projects/openid%2Fconformance-suite/releases/"
                )
            ):
                raise ValueError(f"{entry_id}: api_url must use the official GitLab API")
            _required_text(entry.get("tag"), "tag", entry_id)
            commit = _required_text(entry.get("commit"), "commit", entry_id)
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError(f"{entry_id}: commit must be a full lowercase SHA-1")

    paths = manifest.get("active_document_paths", [])
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise ValueError("active_document_paths must be a list of strings")
    globs = manifest.get("active_document_globs", [])
    if not isinstance(globs, list) or not all(isinstance(pattern, str) for pattern in globs):
        raise ValueError("active_document_globs must be a list of strings")
    forbidden = manifest.get("forbidden_active_markers", {})
    if not isinstance(forbidden, dict):
        raise ValueError("forbidden_active_markers must be an object")

    resolved_root = root.resolve()
    managed: dict[str, Path] = {}
    for relative in paths:
        path = (resolved_root / relative).resolve()
        if not path.is_relative_to(resolved_root):
            raise ValueError(
                f"active document path must stay within the repository: {relative}"
            )
        if not path.is_file():
            raise ValueError(f"active document does not exist: {relative}")
        managed[path.relative_to(resolved_root).as_posix()] = path
    for pattern in globs:
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError(f"active document glob must stay within the repository: {pattern}")
        matches = [path.resolve() for path in resolved_root.glob(pattern) if path.is_file()]
        if not matches:
            raise ValueError(f"active document glob matched no files: {pattern}")
        for path in matches:
            if not path.is_relative_to(resolved_root):
                raise ValueError(
                    f"active document glob must stay within the repository: {pattern}"
                )
            managed[path.relative_to(resolved_root).as_posix()] = path

    referenced_rfcs: set[int] = set()
    for relative, path in sorted(managed.items()):
        text = path.read_text(encoding="utf-8")
        referenced_rfcs.update(int(number) for number in RFC_REFERENCE.findall(text))
        for document, revision in DRAFT_PIN.findall(text):
            expected = current_drafts.get(document)
            if expected is not None and revision != expected:
                raise ValueError(
                    f"{relative}: stale draft pin {document}-{revision}; expected {expected}"
                )
        for marker, replacement in forbidden.items():
            if marker in text:
                raise ValueError(
                    f"{relative}: stale active marker {marker!r}; use {replacement!r}"
                )

    inventoried_rfcs = {
        entry["number"] for entry in sources if entry["kind"] == "rfc"
    }
    for number in sorted(referenced_rfcs - inventoried_rfcs):
        raise ValueError(f"active documents reference untracked RFC {number}")

    expected_markers = manifest.get("expected_file_markers", {})
    if not isinstance(expected_markers, dict):
        raise ValueError("expected_file_markers must be an object")
    for relative, markers in expected_markers.items():
        path = (resolved_root / relative).resolve()
        if not path.is_relative_to(resolved_root):
            raise ValueError(f"expected marker path must stay within the repository: {relative}")
        if not path.is_file():
            raise ValueError(f"expected marker file does not exist: {relative}")
        if not isinstance(markers, list) or not all(
            isinstance(marker, str) and marker for marker in markers
        ):
            raise ValueError(f"expected markers for {relative} must be non-empty strings")
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                raise ValueError(
                    f"{relative}: missing expected active marker {marker!r}"
                )


def _open_bytes(
    opener,
    request: urllib.request.Request,
    *,
    attempts: int = 3,
    sleeper=time.sleep,
) -> tuple[bytes, str]:
    last_error: BaseException | None = None
    for attempt in range(attempts):
        try:
            with opener(request, timeout=30) as response:
                return response.read(), response.geturl()
        except urllib.error.HTTPError as error:
            if error.code != 429 and error.code < 500:
                raise RuntimeError(
                    f"official source rejected {request.full_url}: HTTP {error.code}"
                ) from error
            last_error = error
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        if attempt + 1 < attempts:
            sleeper(2**attempt)
    raise RuntimeError(f"network failure for {request.full_url}: {last_error}") from last_error


def _normalized_url(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return parsed.scheme.lower(), parsed.netloc.lower(), path


def _validate_final_url(entry: dict, final_url: str) -> None:
    allowed = entry.get("allowed_final_urls", [entry["url"]])
    if _normalized_url(final_url) not in {_normalized_url(url) for url in allowed}:
        raise RuntimeError(
            f"{entry['id']}: official source returned unexpected redirect target {final_url}"
        )


def check_entry(entry: dict, opener=urllib.request.urlopen) -> str:
    kind = entry["kind"]
    if kind == "ietf_draft":
        document = entry["document"]
        api_url = (
            "https://datatracker.ietf.org/api/v1/doc/document/"
            f"{quote(document, safe='')}/?format=json"
        )
        request = urllib.request.Request(api_url, headers={"User-Agent": "NazoAuth-spec-freshness/1"})
        payload, _ = _open_bytes(opener, request)
        data = json.loads(payload)
        reported = data.get("rev")
        expected = entry["revision"]
        if reported != expected:
            raise RuntimeError(
                f"{entry['id']}: expected revision {expected}, official source reports {reported}"
            )
        if data.get("name") != document:
            raise RuntimeError(f"{entry['id']}: official document name mismatch")
        if data.get("rfc") is not None or data.get("rfc_number") is not None:
            raise RuntimeError(
                f"{entry['id']}: draft was published or replaced by an RFC; review the final document"
            )
        expires = data.get("expires")
        if isinstance(expires, str):
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if expires_at <= datetime.now(timezone.utc):
                raise RuntimeError(
                    f"{entry['id']}: official draft is expired; review its current status"
                )
        return f"{entry['id']}: {document}-{expected}"

    if kind in {"rfc", "openid_document"}:
        request = urllib.request.Request(
            entry["url"], headers={"User-Agent": "NazoAuth-spec-freshness/1"}
        )
        payload, final_url = _open_bytes(opener, request)
        _validate_final_url(entry, final_url)
        text = payload.decode("utf-8", errors="replace")
        searchable = re.sub(r"\s+", " ", text)
        for marker in entry["markers"]:
            normalized_marker = re.sub(r"\s+", " ", marker)
            if normalized_marker not in searchable:
                raise RuntimeError(
                    f"{entry['id']}: official page {final_url} is missing marker {marker!r}"
                )
        return f"{entry['id']}: official markers present"

    if kind == "oidf_suite":
        request = urllib.request.Request(
            entry["api_url"], headers={"User-Agent": "NazoAuth-spec-freshness/1"}
        )
        payload, _ = _open_bytes(opener, request)
        data = json.loads(payload)
        reported_tag = data.get("tag_name")
        if reported_tag != entry["tag"]:
            raise RuntimeError(
                f"{entry['id']}: expected latest tag {entry['tag']}, official source reports {reported_tag}"
            )
        reported_commit = (data.get("commit") or {}).get("id")
        if reported_commit != entry["commit"]:
            raise RuntimeError(
                f"{entry['id']}: expected commit {entry['commit']}, official source reports {reported_commit}"
            )
        return f"{entry['id']}: {reported_tag} @ {reported_commit}"

    raise RuntimeError(f"{entry['id']}: unsupported kind {kind}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--offline", action="store_true", help="validate inventory and active pins only"
    )
    args = parser.parse_args(argv)

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest, ROOT)
    print(f"offline validation passed: {len(manifest['sources'])} official sources")
    if args.offline:
        return 0

    failures: list[str] = []
    for entry in manifest["sources"]:
        try:
            print(check_entry(entry))
        except (RuntimeError, ValueError, json.JSONDecodeError) as error:
            failures.append(str(error))
            print(f"ERROR: {error}", file=sys.stderr)
    if failures:
        print(f"online validation failed: {len(failures)} source(s)", file=sys.stderr)
        return 1
    print(f"online validation passed: {len(manifest['sources'])} official sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
