#!/usr/bin/env python3
"""Fail when concrete database, KV or object-storage adapters leak into business graphs."""

from __future__ import annotations

import re
import subprocess
import sys


GRAPHS = {
    "nazo-oauth-server": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "nazo-oauth-server-object-store",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-key-management": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-identity": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-oauth-server-valkey": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
    ),
    "nazo-oauth-server-postgres": (
        "fred",
        "nazo-valkey",
        "nazo-oauth-server-valkey",
    ),
}


def package_names(package: str) -> set[str]:
    command = [
        "cargo",
        "tree",
        "--locked",
        "--package",
        package,
        "--edges",
        "normal,build",
        "--prefix",
        "none",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no cargo diagnostic"
        raise RuntimeError(f"cargo tree failed for {package}: {detail}")
    names: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)\s+v\d", line.strip())
        if match:
            names.add(match.group(1))
    return names


def main() -> int:
    violations: list[str] = []
    for package, forbidden in GRAPHS.items():
        try:
            names = package_names(package)
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 2
        leaked = sorted(set(forbidden) & names)
        if leaked:
            violations.append(f"{package}: {', '.join(leaked)}")
    if violations:
        print("persistence dependency isolation failed:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("database, transient-state and object-storage dependency isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
