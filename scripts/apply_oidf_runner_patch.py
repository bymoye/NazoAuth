#!/usr/bin/env python3
"""Apply the SHA-bound, fail-closed patch for the pinned OIDF runner."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from pathlib import PurePosixPath
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
OIDF_REF = "dee9a25160e789f0f80517674693ef7989ab9fa1"
PATCH_PATH = ROOT / "scripts" / "patches" / "oidf-v5.2.0-terminal-info.patch"
PATCH_SHA256 = "77ab55c2c871219271a8dc623545eba4d38c4b3c5706f670eff1c5235259dfaa"
TARGET_HASHES = {
    "scripts/run-test-plan.py": (
        "a3ddb43b2c295f85a6f853a36697881abb4b1c8dddb6d6944ecb787e05fb40f9",
        "7cc72dced2165aee8725531499a1720218778c0c13b09defa881502f9d4db555",
    ),
}
class OidfRunnerPatchError(RuntimeError):
    """The checked-out suite cannot safely receive the pinned patch."""


def normalized_sha256(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def git(suite_dir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(suite_dir), *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def changed_tracked_paths(suite_dir: Path, *, staged: bool = False) -> set[str]:
    args = ["diff", "--name-only"]
    if staged:
        args.append("--cached")
    result = git(suite_dir, *args)
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def untracked_script_paths(suite_dir: Path) -> set[str]:
    result = git(
        suite_dir,
        "ls-files",
        "--others",
        "-z",
    )
    return {
        path
        for raw_path in result.stdout.split("\0")
        if (path := raw_path.strip().replace("\\", "/"))
        and (path == "scripts" or path.startswith("scripts/"))
    }


def unsafe_untracked_script_paths(suite_dir: Path) -> set[str]:
    scripts_dir = suite_dir / "scripts"
    unsafe = set()
    for path in untracked_script_paths(suite_dir):
        parsed = PurePosixPath(path)
        target = suite_dir.joinpath(*parsed.parts)
        safe_generated_json = (
            len(parsed.parts) == 2
            and parsed.parts[0] == "scripts"
            and parsed.suffix.lower() == ".json"
            and not scripts_dir.is_symlink()
            and target.is_file()
            and not target.is_symlink()
        )
        if not safe_generated_json:
            unsafe.add(path)
    return unsafe


def ensure_oidf_runner_patch(
    suite_dir: Path,
    *,
    expected_ref: str = OIDF_REF,
    patch_path: Path = PATCH_PATH,
    patch_sha256: str = PATCH_SHA256,
    target_hashes: Mapping[str, tuple[str, str]] = TARGET_HASHES,
) -> bool:
    """Apply and verify the patch; return ``True`` only when it was newly applied."""

    suite_dir = suite_dir.resolve(strict=True)
    patch_path = patch_path.resolve(strict=True)
    if normalized_sha256(patch_path) != patch_sha256:
        raise OidfRunnerPatchError("OIDF runner patch checksum does not match its manifest")

    head = git(suite_dir, "rev-parse", "HEAD").stdout.strip()
    if head != expected_ref:
        raise OidfRunnerPatchError(
            f"OIDF suite HEAD {head!r} does not match required revision {expected_ref!r}"
        )
    if changed_tracked_paths(suite_dir, staged=True):
        raise OidfRunnerPatchError("OIDF suite has staged tracked changes")
    untracked_scripts = unsafe_untracked_script_paths(suite_dir)
    if untracked_scripts:
        raise OidfRunnerPatchError(
            "OIDF suite scripts contain untracked paths: "
            + ", ".join(sorted(untracked_scripts))
        )

    target_paths = set(target_hashes)
    actual_hashes: dict[str, str] = {}
    for relative_path in target_hashes:
        target = suite_dir / relative_path
        if target.is_symlink() or not target.is_file():
            raise OidfRunnerPatchError(f"OIDF patch target is not a regular file: {relative_path}")
        actual_hashes[relative_path] = normalized_sha256(target)

    preimage = all(
        actual_hashes[path] == expected_hashes[0]
        for path, expected_hashes in target_hashes.items()
    )
    postimage = all(
        actual_hashes[path] == expected_hashes[1]
        for path, expected_hashes in target_hashes.items()
    )
    changed = changed_tracked_paths(suite_dir)

    if preimage:
        if changed:
            raise OidfRunnerPatchError(
                "OIDF suite has tracked changes before patching: " + ", ".join(sorted(changed))
            )
        git(suite_dir, "apply", "--check", str(patch_path))
        git(suite_dir, "apply", str(patch_path))
        applied = True
    elif postimage:
        if changed != target_paths:
            raise OidfRunnerPatchError(
                "OIDF suite patched state has unexpected tracked changes: "
                + ", ".join(sorted(changed))
            )
        git(suite_dir, "apply", "--reverse", "--check", str(patch_path))
        applied = False
    else:
        details = ", ".join(f"{path}={digest}" for path, digest in sorted(actual_hashes.items()))
        raise OidfRunnerPatchError(
            f"OIDF patch target hash is neither preimage nor postimage: {details}"
        )

    for relative_path, (_, expected_postimage) in target_hashes.items():
        actual = normalized_sha256(suite_dir / relative_path)
        if actual != expected_postimage:
            raise OidfRunnerPatchError(
                f"OIDF patched target checksum mismatch for {relative_path}: {actual}"
            )
    git(suite_dir, "diff", "--check", "--", *sorted(target_paths))
    if changed_tracked_paths(suite_dir) != target_paths:
        raise OidfRunnerPatchError("OIDF patch changed files outside its declared target set")
    return applied


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    applied = ensure_oidf_runner_patch(args.suite_dir)
    action = "applied" if applied else "already verified"
    print(f"OIDF runner consistency patch {action} for {OIDF_REF}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
