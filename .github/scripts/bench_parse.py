#!/usr/bin/env python3
"""Shared criterion-output parsing for the bench gate scripts."""

import re

# criterion scales the throughput unit to the measured value (KiB/s, MiB/s,
# GiB/s, TiB/s) — normalize everything to MiB/s.
UNIT_TO_MIB = {
    "KiB/s": 1 / 1024,
    "MiB/s": 1.0,
    "GiB/s": 1024.0,
    "TiB/s": 1024.0 * 1024.0,
}

_THRPT = (
    r"thrpt:\s*\[\s*([\d.]+)\s+([KMGT]iB)/s\s+"
    r"([\d.]+)\s+[KMGT]iB/s\s+([\d.]+)\s+[KMGT]iB/s\s*\]"
)


def parse_throughput(output: str, bench_id: str) -> float | None:
    """Extract the median throughput (MiB/s, unit-normalized) for one benchmark.

    Criterion output looks like:
        throughput/push/clean-json
                                time:   [1.2345 ms 1.2500 ms 1.2600 ms]
                                thrpt:  [345.00 MiB/s 350.00 MiB/s 355.00 MiB/s]

    The median is the middle value of the thrpt line. The unit is captured
    because criterion scales it with the magnitude (KiB/s … TiB/s).
    """
    pattern = re.compile(
        rf"^{re.escape(bench_id)}\s*$"
        r".*?"
        rf"{_THRPT}",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(output)
    if not match:
        return None
    median = float(match.group(3))
    return median * UNIT_TO_MIB[match.group(2) + "/s"]


def parse_all_throughput(output: str) -> dict[str, float]:
    """Median throughput (MiB/s, unit-normalized) for every throughput/push/* benchmark."""
    pattern = re.compile(
        r"^(throughput/push/\S+)\s*$"
        r".*?"
        rf"{_THRPT}",
        re.MULTILINE | re.DOTALL,
    )
    results = {}
    for match in pattern.finditer(output):
        name = match.group(1)
        median = float(match.group(4))
        results[name] = median * UNIT_TO_MIB[match.group(3) + "/s"]
    return results
