#!/usr/bin/env python3
"""
multi_file_diff.py — find constant vs varying bytes across sample files.

Given several files believed to share a format, this tool reports:

  * File-header diff: for the first N bytes of every file, which byte
    positions are identical across all files (strong magic/header
    candidates) vs. which differ (fields that legitimately vary per file,
    like timestamps in a header, sequence numbers, or file IDs).

  * Per-record diff (when --record-size is given): across every record in
    every file, which byte COLUMNS within the record are always the same
    (constants, flags with one value in the sample, padding) vs. which
    vary. This is particularly useful for spotting type-tag bytes, version
    bytes, and always-zero reserved regions.

Two different things get conflated in the naive approach, so we separate
them:
  - "Constant across all files" (file-level)
  - "Constant across all records within each file, but potentially
    different between files" (per-file header/footer signals)

Usage:
    python multi_file_diff.py file1 file2 file3 ...
    python multi_file_diff.py *.gpl --record-size 28
    python multi_file_diff.py *.gpl --record-size 28 --header-bytes 32
"""

import argparse
import sys
from collections import Counter
from pathlib import Path


def load_files(paths):
    out = []
    for p in paths:
        data = Path(p).read_bytes()
        out.append((str(p), data))
    return out


def file_header_diff(files, header_bytes):
    """
    Compare the first `header_bytes` of every file. At each offset, report
    whether the byte is constant across files, and if so what its value is.
    """
    lengths = [len(d) for _, d in files]
    eff = min(header_bytes, min(lengths))
    if eff <= 0:
        return []

    results = []
    for off in range(eff):
        vals = [d[off] for _, d in files]
        uniq = set(vals)
        results.append({
            "offset": off,
            "constant": len(uniq) == 1,
            "value": vals[0] if len(uniq) == 1 else None,
            "distinct": len(uniq),
            "sample": vals[:4],
        })
    return results


def per_record_diff(files, record_size):
    """
    For every file, treat it as a sequence of records of `record_size` bytes
    and, for each column, collect the set of values seen across all records
    in all files. Column entropy = count of distinct values.
    """
    columns = [Counter() for _ in range(record_size)]
    total_records = 0
    per_file_records = []

    for name, data in files:
        n = len(data) // record_size
        per_file_records.append((name, n))
        total_records += n
        for row in range(n):
            base = row * record_size
            for col in range(record_size):
                columns[col][data[base + col]] += 1

    report = []
    for col in range(record_size):
        c = columns[col]
        distinct = len(c)
        most_common_val, most_common_count = c.most_common(1)[0]
        pct = 100.0 * most_common_count / total_records if total_records else 0
        report.append({
            "column": col,
            "distinct_values": distinct,
            "dominant_value": most_common_val,
            "dominant_pct": pct,
        })
    return report, per_file_records, total_records


# ---------- pretty printing --------------------------------------------------

def print_header_diff(header):
    if not header:
        print("  (no header bytes to compare)")
        return

    # Group runs of same-status (constant/variable) for readability.
    print(f"  {'offset':>6}  {'status':<12}  {'value':<8}  {'distinct':>8}")
    print("  " + "-" * 40)
    run_start = None
    run_state = None
    run_value = None

    def flush(run_end):
        nonlocal run_start, run_state, run_value
        if run_start is None:
            return
        span = (f"0x{run_start:04x}" if run_start == run_end
                else f"0x{run_start:04x}-0x{run_end:04x}")
        if run_state == "const":
            print(f"  {span:>6}  {'CONSTANT':<12}  "
                  f"0x{run_value:02x}     {'1':>8}")
        else:
            print(f"  {span:>6}  {'varies':<12}  {'-':<8}  "
                  f"(see below)")
        run_start = None

    for h in header:
        state = "const" if h["constant"] else "vary"
        value = h["value"] if h["constant"] else None
        if run_state == state and run_value == value:
            continue
        flush(h["offset"] - 1)
        run_start = h["offset"]
        run_state = state
        run_value = value
    flush(header[-1]["offset"])


def print_record_diff(report, record_size):
    # Classify each column
    constants = [r for r in report if r["distinct_values"] == 1]
    low_var = [r for r in report if 2 <= r["distinct_values"] <= 8]
    mid_var = [r for r in report if 9 <= r["distinct_values"] <= 64]
    high_var = [r for r in report if r["distinct_values"] > 64]

    print(f"\n  Summary over {record_size} columns:")
    print(f"    {len(constants):>3} constant columns "
          f"(always same byte — padding/reserved/flags)")
    print(f"    {len(low_var):>3} low-variance columns (2-8 distinct values — "
          f"enums, small counters)")
    print(f"    {len(mid_var):>3} mid-variance columns (9-64 distinct — "
          f"low-order bytes of small numbers)")
    print(f"    {len(high_var):>3} high-variance columns (>64 distinct — "
          f"high-order bytes of wide-range numeric fields)")

    print(f"\n  Detail:")
    print(f"    {'col':>3}  {'#distinct':>9}  {'dominant':<14}  {'notes'}")
    print("    " + "-" * 52)
    for r in report:
        col = r["column"]
        d = r["distinct_values"]
        dv = r["dominant_value"]
        pct = r["dominant_pct"]
        # Pct dominance is a stronger signal than distinct-count when a fill
        # pattern (0x00 padding, 0xFF erased flash, pre-allocated fill
        # records, etc.) swamps the real data.
        if d == 1:
            note = f"always 0x{dv:02x}"
        elif pct > 80:
            note = (f"{pct:.0f}% 0x{dv:02x} — likely fill/padding; "
                    f"real data in the minority")
        elif pct > 50:
            note = f"{pct:.0f}% 0x{dv:02x} — dominant value + variation"
        elif d <= 8:
            note = "small set of values — probable enum/flag"
        elif d > 200:
            note = "looks random — high-entropy data byte"
        else:
            note = ""
        print(f"    {col:>3}  {d:>9}  0x{dv:02x} ({pct:>5.1f}%)   {note}")


# ---------- CLI --------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("files", nargs="+", help="sample files (same format)")
    ap.add_argument("--header-bytes", type=int, default=32,
                    help="how many leading bytes to diff across files")
    ap.add_argument("--record-size", type=int, default=0,
                    help="if known, run a per-record column diff at this size")
    args = ap.parse_args()

    if len(args.files) < 2:
        print("error: supply at least 2 files", file=sys.stderr)
        sys.exit(1)

    files = load_files(args.files)

    print(f"=== multi_file_diff ({len(files)} files) ===")
    for name, data in files:
        print(f"  {name}: {len(data)} bytes")

    print(f"\n-- File-header diff (first {args.header_bytes} bytes) --")
    header = file_header_diff(files, args.header_bytes)
    print_header_diff(header)
    print()
    print("  CONSTANT runs at file offset 0 are prime magic-byte candidates.")
    print("  If *all* header offsets are CONSTANT, the file has no per-file")
    print("  header and is likely a bare stream of records.")
    print("  If early bytes vary but in a structured way (e.g. timestamps),")
    print("  those are per-file header fields — worth a closer look.")

    if args.record_size > 0:
        report, per_file, total = per_record_diff(files, args.record_size)
        print(f"\n-- Per-record column diff "
              f"(record_size={args.record_size}, {total} records total) --")
        for name, n in per_file:
            print(f"    {name}: {n} records")
        print_record_diff(report, args.record_size)


if __name__ == "__main__":
    main()
