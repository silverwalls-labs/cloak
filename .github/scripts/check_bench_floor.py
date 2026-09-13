#!/usr/bin/env python3
"""Check that the clean-path throughput meets the ≥500 MB/s floor.

Usage: python3 check_bench_floor.py <bench-output.txt> <floor_mbs>

Parses criterion's default output for the throughput/push/clean-json and
throughput/push/clean-text benchmarks, extracts the median MiB/s from the
[lower median upper] line, converts to MB/s, and asserts the WORSE of the
two meets the floor.
"""

import re
import sys


def parse_throughput(output: str, bench_id: str) -> float | None:
    """Extract median throughput (MiB/s) for a given benchmark ID.

    Criterion output looks like:
        throughput/push/clean-json
                                time:   [1.2345 ms 1.2500 ms 1.2600 ms]
                                thrpt:  [345.00 MiB/s 350.00 MiB/s 355.00 MiB/s]

    The median is the middle value in the thrpt line.
    """
    # Find the block for this benchmark.
    pattern = re.compile(
        rf"^{re.escape(bench_id)}\s*$"
        r".*?"
        r"thrpt:\s*\[\s*([\d.]+)\s+MiB/s\s+([\d.]+)\s+MiB/s\s+([\d.]+)\s+MiB/s\s*\]",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(output)
    if not match:
        return None
    return float(match.group(2))  # median (middle value)


def mib_to_mb(mib: float) -> float:
    """Convert MiB/s to MB/s."""
    return mib * 1_048_576 / 1_000_000


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <bench-output.txt> <floor_mbs>", file=sys.stderr)
        sys.exit(2)

    output_file = sys.argv[1]
    floor_mbs = float(sys.argv[2])

    with open(output_file) as f:
        output = f.read()

    json_mib = parse_throughput(output, "throughput/push/clean-json")
    text_mib = parse_throughput(output, "throughput/push/clean-text")

    if json_mib is None:
        print("ERROR: could not find throughput/push/clean-json in bench output", file=sys.stderr)
        sys.exit(1)
    if text_mib is None:
        print("ERROR: could not find throughput/push/clean-text in bench output", file=sys.stderr)
        sys.exit(1)

    json_mbs = mib_to_mb(json_mib)
    text_mbs = mib_to_mb(text_mib)
    worse = min(json_mbs, text_mbs)

    print(f"clean-json: {json_mib:.1f} MiB/s ({json_mbs:.1f} MB/s)")
    print(f"clean-text: {text_mib:.1f} MiB/s ({text_mbs:.1f} MB/s)")
    print(f"floor reference (worse): {worse:.1f} MB/s (gate: ≥{floor_mbs} MB/s)")

    if worse < floor_mbs:
        print(f"FAIL: {worse:.1f} MB/s < {floor_mbs} MB/s floor", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"PASS: {worse:.1f} MB/s ≥ {floor_mbs} MB/s floor")


if __name__ == "__main__":
    main()
