#!/usr/bin/env python3
"""Unit tests for the CI bench-gate scripts (check_bench_floor.py, check_bench_regression.py).

Run: python3 -m unittest .github/scripts/test_bench_scripts.py
"""

import datetime
import json
import os
import sys
import tempfile
import unittest

# Add the scripts directory to the path so we can import the modules.
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

from bench_parse import parse_all_throughput, parse_throughput
from check_bench_floor import mib_to_mb

# ── Mock criterion output ────────────────────────────────────────────

MOCK_CRITERION_OUTPUT = """\
Benchmarking throughput/push/clean-json
Benchmarking throughput/push/clean-json: Warming up for 3.0000 s
Benchmarking throughput/push/clean-json: Collecting 100 samples in estimated 5.0000 s (1000 iterations)
Benchmarking throughput/push/clean-json: Analyzing
throughput/push/clean-json
                        time:   [2.0000 ms 2.1000 ms 2.2000 ms]
                        thrpt:  [454.55 MiB/s 476.19 MiB/s 500.00 MiB/s]
Benchmarking throughput/push/clean-text
Benchmarking throughput/push/clean-text: Warming up for 3.0000 s
Benchmarking throughput/push/clean-text: Collecting 100 samples in estimated 5.0000 s (800 iterations)
Benchmarking throughput/push/clean-text: Analyzing
throughput/push/clean-text
                        time:   [3.0000 ms 3.2000 ms 3.4000 ms]
                        thrpt:  [294.12 MiB/s 312.50 MiB/s 333.33 MiB/s]
Benchmarking throughput/push/dirty-mixed
Benchmarking throughput/push/dirty-mixed: Warming up for 3.0000 s
Benchmarking throughput/push/dirty-mixed: Collecting 100 samples in estimated 5.0000 s (900 iterations)
Benchmarking throughput/push/dirty-mixed: Analyzing
throughput/push/dirty-mixed
                        time:   [1.5000 ms 1.6000 ms 1.7000 ms]
                        thrpt:  [588.24 MiB/s 625.00 MiB/s 666.67 MiB/s]
"""

# Criterion scales the throughput unit with magnitude — a fast corpus can
# print GiB/s (or KiB/s when slow). The parser must normalize.
UNIT_SCALING_OUTPUT = """\
Benchmarking throughput/push/clean-json: Analyzing
throughput/push/clean-json
                        time:   [900.00 us 950.00 us 1.0000 ms]
                        thrpt:  [1.0000 GiB/s 1.0500 GiB/s 1.1000 GiB/s]
Benchmarking throughput/push/clean-text: Analyzing
throughput/push/clean-text
                        time:   [2.0000 s 2.1000 s 2.2000 s]
                        thrpt:  [480.00 KiB/s 500.00 KiB/s 520.00 KiB/s]
"""


class TestParseFloor(unittest.TestCase):
    """Tests for check_bench_floor.py parsing."""

    def test_parse_throughput_valid(self):
        result = parse_throughput(MOCK_CRITERION_OUTPUT, "throughput/push/clean-json")
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result, 476.19, places=1)

    def test_parse_throughput_clean_text(self):
        result = parse_throughput(MOCK_CRITERION_OUTPUT, "throughput/push/clean-text")
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result, 312.50, places=1)

    def test_parse_throughput_missing(self):
        result = parse_throughput(MOCK_CRITERION_OUTPUT, "throughput/push/nonexistent")
        self.assertIsNone(result)

    def test_parse_throughput_empty_input(self):
        result = parse_throughput("", "throughput/push/clean-json")
        self.assertIsNone(result)

    def test_mib_to_mb_conversion(self):
        # 477.83 MiB/s should be approximately 500.98 MB/s.
        result = mib_to_mb(477.83)
        self.assertAlmostEqual(result, 500.98, places=0)

    def test_mib_to_mb_zero(self):
        self.assertAlmostEqual(mib_to_mb(0), 0.0)

    def test_mib_to_mb_known_value(self):
        # 1 MiB = 1,048,576 bytes = 1.048576 MB.
        self.assertAlmostEqual(mib_to_mb(1.0), 1.048576, places=4)


class TestParseRegression(unittest.TestCase):
    """Tests for check_bench_regression.py parsing."""

    def test_parse_all_throughput(self):
        results = parse_all_throughput(MOCK_CRITERION_OUTPUT)
        self.assertIn("throughput/push/clean-json", results)
        self.assertIn("throughput/push/clean-text", results)
        self.assertIn("throughput/push/dirty-mixed", results)
        self.assertEqual(len(results), 3)

    def test_parse_all_throughput_empty(self):
        results = parse_all_throughput("")
        self.assertEqual(len(results), 0)

    def test_parse_all_throughput_values(self):
        results = parse_all_throughput(MOCK_CRITERION_OUTPUT)
        self.assertAlmostEqual(results["throughput/push/clean-json"], 476.19, places=1)
        self.assertAlmostEqual(results["throughput/push/clean-text"], 312.50, places=1)
        self.assertAlmostEqual(results["throughput/push/dirty-mixed"], 625.00, places=1)


class TestUnitNormalization(unittest.TestCase):
    """criterion scales the thrpt unit (KiB/s…GiB/s) — the parser must normalize."""

    def test_parse_gib(self):
        result = parse_throughput(UNIT_SCALING_OUTPUT, "throughput/push/clean-json")
        self.assertAlmostEqual(result, 1.05 * 1024, places=1)

    def test_parse_kib(self):
        result = parse_throughput(UNIT_SCALING_OUTPUT, "throughput/push/clean-text")
        self.assertAlmostEqual(result, 500.0 / 1024, places=4)

    def test_parse_all_normalized(self):
        results = parse_all_throughput(UNIT_SCALING_OUTPUT)
        self.assertAlmostEqual(results["throughput/push/clean-json"], 1.05 * 1024, places=1)
        self.assertAlmostEqual(results["throughput/push/clean-text"], 500.0 / 1024, places=4)


class TestMakeBaseline(unittest.TestCase):
    """Tests for make_baseline.py."""

    def test_make_baseline_structure(self):
        from make_baseline import make_baseline

        baseline = make_baseline(MOCK_CRITERION_OUTPUT, "x86_64-unknown-linux-gnu")
        self.assertEqual(baseline["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(baseline["generated"], datetime.date.today().isoformat())
        benchmarks = baseline["benchmarks"]
        self.assertEqual(len(benchmarks), 3)
        self.assertAlmostEqual(
            benchmarks["throughput/push/clean-json"]["median_mibs"], 476.19, places=1
        )
        self.assertAlmostEqual(
            benchmarks["throughput/push/dirty-mixed"]["median_mibs"], 625.00, places=1
        )

    def test_make_baseline_empty_output_raises(self):
        from make_baseline import make_baseline

        with self.assertRaises(ValueError):
            make_baseline("", "x86_64")


class TestFloorIntegration(unittest.TestCase):
    """Integration tests for the floor check (end-to-end with temp files)."""

    def _run_floor_check(self, output_text: str, floor: float) -> int:
        """Write output to a temp file and run check_bench_floor.main()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(output_text)
            f.flush()
            tmp_path = f.name
        try:
            old_argv = sys.argv
            sys.argv = ["check_bench_floor.py", tmp_path, str(floor)]
            try:
                from check_bench_floor import main
                main()
                return 0
            except SystemExit as e:
                return e.code if e.code is not None else 0
            finally:
                sys.argv = old_argv
        finally:
            os.unlink(tmp_path)

    def test_floor_pass(self):
        # clean-text = 312.5 MiB/s = ~327.7 MB/s, floor = 300 → pass.
        rc = self._run_floor_check(MOCK_CRITERION_OUTPUT, 300)
        self.assertEqual(rc, 0)

    def test_floor_fail(self):
        # clean-text = 312.5 MiB/s = ~327.7 MB/s, floor = 500 → fail.
        rc = self._run_floor_check(MOCK_CRITERION_OUTPUT, 500)
        self.assertEqual(rc, 1)


class TestRegressionIntegration(unittest.TestCase):
    """Integration tests for the regression check."""

    def _run_regression_check(self, output_text: str, baseline, threshold: float) -> int:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(output_text)
            f.flush()
            output_path = f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # `baseline` is a dict to dump, or raw text for malformed-JSON cases.
            if isinstance(baseline, str):
                f.write(baseline)
            else:
                json.dump(baseline, f)
            f.flush()
            baseline_path = f.name
        try:
            old_argv = sys.argv
            sys.argv = ["check_bench_regression.py", output_path, baseline_path, str(threshold)]
            try:
                from check_bench_regression import main
                main()
                return 0
            except SystemExit as e:
                return e.code if e.code is not None else 0
            finally:
                sys.argv = old_argv
        finally:
            os.unlink(output_path)
            os.unlink(baseline_path)

    def test_regression_pass(self):
        baseline = {
            "benchmarks": {
                "throughput/push/clean-json": {"median_mibs": 470.0},
                "throughput/push/clean-text": {"median_mibs": 300.0},
            }
        }
        rc = self._run_regression_check(MOCK_CRITERION_OUTPUT, baseline, 10)
        self.assertEqual(rc, 0)

    def test_regression_fail(self):
        baseline = {
            "benchmarks": {
                "throughput/push/clean-text": {"median_mibs": 500.0},
                # Current = 312.5 MiB/s, baseline = 500 → regression of 37.5%.
            }
        }
        rc = self._run_regression_check(MOCK_CRITERION_OUTPUT, baseline, 10)
        self.assertEqual(rc, 1)

    def test_missing_baseline_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(MOCK_CRITERION_OUTPUT)
            f.flush()
            output_path = f.name
        try:
            old_argv = sys.argv
            sys.argv = ["check_bench_regression.py", output_path, "/nonexistent/baseline.json", "10"]
            try:
                from check_bench_regression import main
                main()
                return_code = 0
            except SystemExit as e:
                return_code = e.code if e.code is not None else 0
            finally:
                sys.argv = old_argv
            self.assertEqual(return_code, 0)  # Missing baseline → warning, exit 0
        finally:
            os.unlink(output_path)

    def test_invalid_json_baseline_fails(self):
        # A malformed baseline must fail loudly, not crash with a traceback.
        rc = self._run_regression_check(MOCK_CRITERION_OUTPUT, "not json {", 10)
        self.assertEqual(rc, 1)

    def test_baseline_entry_missing_median_mibs_fails(self):
        baseline = {
            "benchmarks": {
                "throughput/push/clean-text": {"wrong_key": 300.0},
            }
        }
        rc = self._run_regression_check(MOCK_CRITERION_OUTPUT, baseline, 10)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
