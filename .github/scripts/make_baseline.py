#!/usr/bin/env python3
"""Generate a regression-gate baseline JSON from criterion bench output.

Usage: python3 make_baseline.py <bench-output.txt> <out.json> [target]

Parses the throughput/push/* benchmarks and writes the baseline format
consumed by check_bench_regression.py. The nightly bench-floor job runs
this and uploads the result as an artifact; to enable the regression gate,
download the artifact from a green run and commit it to
docs/benchmarks/baselines/<ARCH>.json.
"""

import datetime
import json
import subprocess
import sys

from bench_parse import parse_all_throughput


def rustc_version() -> str:
    """Best-effort rustc version for the baseline metadata."""
    try:
        return subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def make_baseline(output: str, target: str = "") -> dict:
    """Build the baseline dict from criterion bench output."""
    current = parse_all_throughput(output)
    if not current:
        raise ValueError("no throughput benchmarks found in output")
    return {
        "generated": datetime.date.today().isoformat(),
        "rustc": rustc_version(),
        "target": target,
        "benchmarks": {name: {"median_mibs": mibs} for name, mibs in sorted(current.items())},
    }


def main() -> None:
    if len(sys.argv) not in (3, 4):
        print(f"Usage: {sys.argv[0]} <bench-output.txt> <out.json> [target]", file=sys.stderr)
        sys.exit(2)

    output_file = sys.argv[1]
    out_file = sys.argv[2]
    target = sys.argv[3] if len(sys.argv) == 4 else ""

    with open(output_file) as f:
        output = f.read()

    try:
        baseline = make_baseline(output, target)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    with open(out_file, "w") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")

    print(f"wrote {out_file}:")
    for name, entry in baseline["benchmarks"].items():
        print(f"  {name}: {entry['median_mibs']:.1f} MiB/s")


if __name__ == "__main__":
    main()
