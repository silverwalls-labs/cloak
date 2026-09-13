#!/usr/bin/env python3
"""Check that no throughput benchmark regressed >N% against a stored baseline.

Usage: python3 check_bench_regression.py <bench-output.txt> <baseline.json> <threshold_pct>

Parses criterion's default output for throughput/push/* benchmarks, compares
median MiB/s against stored values in the baseline JSON, and fails if any
benchmark regressed beyond the threshold.
"""

import json
import re
import sys


def parse_all_throughput(output: str) -> dict[str, float]:
    """Extract median throughput (MiB/s) for all throughput/push/* benchmarks."""
    # Match blocks like:
    # throughput/push/clean-json
    #                         time:   [...]
    #                         thrpt:  [lower MiB/s median MiB/s upper MiB/s]
    pattern = re.compile(
        r"^(throughput/push/\S+)\s*$"
        r".*?"
        r"thrpt:\s*\[\s*([\d.]+)\s+MiB/s\s+([\d.]+)\s+MiB/s\s+([\d.]+)\s+MiB/s\s*\]",
        re.MULTILINE | re.DOTALL,
    )
    results = {}
    for match in pattern.finditer(output):
        name = match.group(1)
        median = float(match.group(3))  # middle value
        results[name] = median
    return results


def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <bench-output.txt> <baseline.json> <threshold_pct>",
            file=sys.stderr,
        )
        sys.exit(2)

    output_file = sys.argv[1]
    baseline_file = sys.argv[2]
    threshold_pct = float(sys.argv[3])

    with open(output_file) as f:
        output = f.read()

    try:
        with open(baseline_file) as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print(f"WARNING: baseline file {baseline_file} not found — skipping regression check")
        print("Run benchmarks and commit the baseline to enable regression gating.")
        sys.exit(0)

    current = parse_all_throughput(output)
    stored = baseline.get("benchmarks", {})

    if not current:
        print("ERROR: no throughput benchmarks found in output", file=sys.stderr)
        sys.exit(1)

    regressions = []
    for name, current_mibs in sorted(current.items()):
        if name not in stored:
            print(f"  {name}: {current_mibs:.1f} MiB/s (no baseline — skipped)")
            continue
        baseline_mibs = stored[name]["median_mibs"]
        change_pct = ((current_mibs - baseline_mibs) / baseline_mibs) * 100
        status = "OK" if change_pct > -threshold_pct else "REGRESSED"
        print(f"  {name}: {current_mibs:.1f} MiB/s (baseline: {baseline_mibs:.1f}, {change_pct:+.1f}%) [{status}]")
        if change_pct < -threshold_pct:
            regressions.append((name, baseline_mibs, current_mibs, change_pct))

    if regressions:
        print(f"\nFAIL: {len(regressions)} benchmark(s) regressed beyond {threshold_pct}%:", file=sys.stderr)
        for name, base, curr, pct in regressions:
            print(f"  {name}: {base:.1f} → {curr:.1f} MiB/s ({pct:+.1f}%)", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\nPASS: no regressions beyond {threshold_pct}%")


if __name__ == "__main__":
    main()
