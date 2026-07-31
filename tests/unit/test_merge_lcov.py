import importlib.util
import random
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "merge_lcov.py"
SPEC = importlib.util.spec_from_file_location("merge_lcov", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
merge_lcov = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = merge_lcov
SPEC.loader.exec_module(merge_lcov)


FIRST = """\
TN:
SF:src/example.rs
FN:10,alpha
FNDA:0,alpha
FNF:1
FNH:0
DA:10,0
DA:11,3
LF:2
LH:1
end_of_record
"""

SECOND = """\
SF:src/example.rs
FN:10,alpha
FN:20,beta
FNDA:2,alpha
FNDA:1,beta
FNF:2
FNH:2
DA:10,2
DA:12,1
LF:2
LH:2
end_of_record
"""

GOLDEN = """\
SF:src/example.rs
FN:10,alpha
FN:20,beta
FNDA:2,alpha
FNDA:1,beta
FNF:2
FNH:2
DA:10,2
DA:11,3
DA:12,1
LF:3
LH:3
BRF:0
BRH:0
end_of_record
"""


class MergeLcovTests(unittest.TestCase):
    def test_golden_union_preserves_any_observed_hit(self) -> None:
        merged = merge_lcov.parse_lcov(FIRST)
        for source, record in merge_lcov.parse_lcov(SECOND).items():
            merged.setdefault(source, merge_lcov.SourceRecord()).merge(record)
        self.assertEqual(merge_lcov.render_lcov(merged), GOLDEN)

    def test_merge_is_order_independent_for_line_coverage(self) -> None:
        rng = random.Random(0x4E415A4F)
        for _ in range(100):
            left = rng.randrange(0, 50)
            right = rng.randrange(0, 50)
            reports = [
                f"SF:x.rs\nDA:7,{left}\nLF:1\nLH:{int(left > 0)}\nend_of_record\n",
                f"SF:x.rs\nDA:7,{right}\nLF:1\nLH:{int(right > 0)}\nend_of_record\n",
            ]
            forward = merge_lcov.parse_lcov(reports[0])
            forward["x.rs"].merge(merge_lcov.parse_lcov(reports[1])["x.rs"])
            reverse = merge_lcov.parse_lcov(reports[1])
            reverse["x.rs"].merge(merge_lcov.parse_lcov(reports[0])["x.rs"])
            self.assertEqual(forward["x.rs"].lines, reverse["x.rs"].lines)
            self.assertEqual(forward["x.rs"].lines[7][0], left + right)

    def test_parser_fails_closed_on_truncated_or_unknown_records(self) -> None:
        with self.assertRaises(merge_lcov.LcovError):
            merge_lcov.parse_lcov("SF:x.rs\nDA:1,1\n")
        with self.assertRaises(merge_lcov.LcovError):
            merge_lcov.parse_lcov("SF:x.rs\nXX:1\nend_of_record\n")

    def test_source_root_collapses_absolute_and_relative_build_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "crates" / "service" / "src" / "lib.rs"
            absolute = merge_lcov.parse_lcov(
                f"SF:{source}\nDA:7,2\nLF:1\nLH:1\nend_of_record\n"
            )
            relative = merge_lcov.parse_lcov(
                "SF:crates/service/src/lib.rs\nDA:7,3\nLF:1\nLH:1\nend_of_record\n"
            )
            merged: dict[str, merge_lcov.SourceRecord] = {}
            for records in (absolute, relative):
                for path, record in records.items():
                    normalized = merge_lcov.normalize_source(path, root)
                    merged.setdefault(normalized, merge_lcov.SourceRecord()).merge(record)

            self.assertEqual(list(merged), ["crates/service/src/lib.rs"])
            self.assertEqual(merged["crates/service/src/lib.rs"].lines[7][0], 5)


if __name__ == "__main__":
    unittest.main()
