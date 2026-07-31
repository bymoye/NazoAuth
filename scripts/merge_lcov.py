#!/usr/bin/env python3
"""Merge LCOV reports by source file without losing overlapping coverage."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path


class LcovError(ValueError):
    pass


@dataclass
class SourceRecord:
    functions: set[str] = field(default_factory=set)
    function_hits: dict[str, int] = field(default_factory=dict)
    lines: dict[int, tuple[int, str | None]] = field(default_factory=dict)
    branches: dict[tuple[int, str, str], int | None] = field(default_factory=dict)

    def merge(self, other: SourceRecord) -> None:
        self.functions.update(other.functions)
        for name, hits in other.function_hits.items():
            self.function_hits[name] = self.function_hits.get(name, 0) + hits
        for number, (hits, checksum) in other.lines.items():
            previous_hits, previous_checksum = self.lines.get(number, (0, checksum))
            if (
                previous_checksum is not None
                and checksum is not None
                and previous_checksum != checksum
            ):
                raise LcovError(f"conflicting checksum for line {number}")
            self.lines[number] = (previous_hits + hits, previous_checksum or checksum)
        for key, taken in other.branches.items():
            previous = self.branches.get(key)
            if previous is None:
                self.branches[key] = taken
            elif taken is not None:
                self.branches[key] = previous + taken


def _nonnegative(value: str, field_name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise LcovError(f"invalid {field_name}: {value!r}") from error
    if parsed < 0:
        raise LcovError(f"negative {field_name}: {value!r}")
    return parsed


def parse_lcov(text: str) -> dict[str, SourceRecord]:
    records: dict[str, SourceRecord] = {}
    source: str | None = None
    current: SourceRecord | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("TN:"):
            continue
        if line.startswith("SF:"):
            if current is not None:
                raise LcovError(f"line {line_number}: nested SF record")
            source = line[3:]
            if not source:
                raise LcovError(f"line {line_number}: empty source path")
            current = SourceRecord()
            continue
        if line == "end_of_record":
            if source is None or current is None:
                raise LcovError(f"line {line_number}: end without SF record")
            records.setdefault(source, SourceRecord()).merge(current)
            source = None
            current = None
            continue
        if current is None:
            raise LcovError(f"line {line_number}: data outside SF record")

        if line.startswith("FN:"):
            definition = line[3:]
            if "," not in definition:
                raise LcovError(f"line {line_number}: malformed FN record")
            current.functions.add(definition)
        elif line.startswith("FNDA:"):
            value = line[5:].split(",", 1)
            if len(value) != 2 or not value[1]:
                raise LcovError(f"line {line_number}: malformed FNDA record")
            current.function_hits[value[1]] = current.function_hits.get(value[1], 0) + _nonnegative(
                value[0], "function hit count"
            )
        elif line.startswith("DA:"):
            value = line[3:].split(",", 2)
            if len(value) < 2:
                raise LcovError(f"line {line_number}: malformed DA record")
            number = _nonnegative(value[0], "source line")
            hits = _nonnegative(value[1], "line hit count")
            checksum = value[2] if len(value) == 3 and value[2] else None
            previous_hits, previous_checksum = current.lines.get(number, (0, checksum))
            if (
                previous_checksum is not None
                and checksum is not None
                and previous_checksum != checksum
            ):
                raise LcovError(f"line {line_number}: conflicting checksum")
            current.lines[number] = (previous_hits + hits, previous_checksum or checksum)
        elif line.startswith("BRDA:"):
            value = line[5:].split(",", 3)
            if len(value) != 4:
                raise LcovError(f"line {line_number}: malformed BRDA record")
            key = (_nonnegative(value[0], "branch line"), value[1], value[2])
            taken = None if value[3] == "-" else _nonnegative(value[3], "branch hit count")
            previous = current.branches.get(key)
            if previous is None:
                current.branches[key] = taken
            elif taken is not None:
                current.branches[key] = previous + taken
        elif line.startswith(("FNF:", "FNH:", "LF:", "LH:", "BRF:", "BRH:")):
            _nonnegative(line.split(":", 1)[1], "summary count")
        else:
            raise LcovError(f"line {line_number}: unsupported LCOV record {line!r}")

    if current is not None:
        raise LcovError("unterminated SF record")
    return records


def render_lcov(records: dict[str, SourceRecord]) -> str:
    output: list[str] = []
    for source in sorted(records):
        record = records[source]
        output.append(f"SF:{source}")
        output.extend(f"FN:{definition}" for definition in sorted(record.functions))
        for name in sorted(record.function_hits):
            output.append(f"FNDA:{record.function_hits[name]},{name}")
        output.append(f"FNF:{len(record.functions)}")
        output.append(
            f"FNH:{sum(record.function_hits.get(definition.split(',', 1)[1], 0) > 0 for definition in record.functions)}"
        )
        for number in sorted(record.lines):
            hits, checksum = record.lines[number]
            suffix = f",{checksum}" if checksum is not None else ""
            output.append(f"DA:{number},{hits}{suffix}")
        output.append(f"LF:{len(record.lines)}")
        output.append(f"LH:{sum(hits > 0 for hits, _ in record.lines.values())}")
        for (number, block, branch), taken in sorted(record.branches.items()):
            output.append(
                f"BRDA:{number},{block},{branch},{'-' if taken is None else taken}"
            )
        output.append(f"BRF:{len(record.branches)}")
        output.append(f"BRH:{sum(taken is not None and taken > 0 for taken in record.branches.values())}")
        output.append("end_of_record")
    return "\n".join(output) + ("\n" if output else "")


def merge_reports(paths: list[Path]) -> dict[str, SourceRecord]:
    merged: dict[str, SourceRecord] = {}
    for path in paths:
        for source, record in parse_lcov(path.read_text(encoding="utf-8")).items():
            merged.setdefault(source, SourceRecord()).merge(record)
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    args.output.write_text(render_lcov(merge_reports(args.inputs)), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
