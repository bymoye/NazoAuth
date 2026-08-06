#!/usr/bin/env python3
"""Check executable lines changed since a Git base against an LCOV report."""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from merge_lcov import parse_lcov


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def codecov_ignores(config: Path) -> tuple[str, ...]:
    patterns: list[str] = []
    in_ignore = False
    for raw_line in config.read_text(encoding="utf-8").splitlines():
        if raw_line == "ignore:":
            in_ignore = True
            continue
        if in_ignore and raw_line and not raw_line[0].isspace():
            break
        if not in_ignore:
            continue
        stripped = raw_line.strip()
        if stripped.startswith("- "):
            patterns.append(stripped[2:].strip().strip('"\''))
    return tuple(patterns)


def is_ignored(path: str, patterns: tuple[str, ...]) -> bool:
    normalized = path.removeprefix("./")
    return any(
        fnmatch.fnmatchcase(normalized, pattern.removeprefix("/"))
        for pattern in patterns
    )


def changed_lines(base: str, head: str | None, repository: Path) -> dict[str, set[int]]:
    revision = base if head is None else f"{base}...{head}"
    result = subprocess.run(
        [
            "git",
            "diff",
            "--unified=0",
            "--no-color",
            "--find-renames",
            revision,
            "--",
        ],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    changed: dict[str, set[int]] = defaultdict(set)
    path: str | None = None
    new_line: int | None = None
    for line in result.stdout.splitlines():
        if line.startswith("+++ "):
            value = line[4:]
            path = None if value == "/dev/null" else value.removeprefix("b/")
            new_line = None
            continue
        match = HUNK.match(line)
        if match:
            new_line = int(match.group(1))
            continue
        if path is None or new_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed[path].add(new_line)
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        elif not line.startswith("\\"):
            new_line += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument(
        "--include-worktree",
        action="store_true",
        help="compare the base directly with the index and working tree",
    )
    parser.add_argument("--threshold", type=float, default=90.0)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--codecov-config", type=Path, default=Path("codecov.yml"))
    args = parser.parse_args()

    repository = args.repository.resolve()
    config = args.codecov_config
    if not config.is_absolute():
        config = repository / config
    ignores = codecov_ignores(config)
    records = parse_lcov(args.lcov.read_text(encoding="utf-8"))
    diff = changed_lines(
        args.base,
        None if args.include_worktree else args.head,
        repository,
    )

    rows: list[tuple[str, int, int]] = []
    for path, lines in diff.items():
        if is_ignored(path, ignores):
            continue
        record = records.get(path)
        if record is None:
            continue
        executable = lines.intersection(record.lines)
        if not executable:
            continue
        hit = sum(record.lines[line][0] > 0 for line in executable)
        rows.append((path, hit, len(executable)))

    total_hit = sum(hit for _path, hit, _total in rows)
    total = sum(count for _path, _hit, count in rows)
    percentage = 100.0 if total == 0 else total_hit * 100.0 / total
    for path, hit, count in sorted(rows, key=lambda row: (row[1] - row[2], row[0])):
        if hit != count:
            print(f"{hit:5d}/{count:<5d} {hit * 100.0 / count:6.2f}%  {path}")
    print(f"patch coverage: {total_hit}/{total} ({percentage:.5f}%)")
    if percentage + sys.float_info.epsilon < args.threshold:
        print(
            f"patch coverage is below the required {args.threshold:.2f}%",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
