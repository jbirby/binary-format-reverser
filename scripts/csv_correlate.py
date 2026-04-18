#!/usr/bin/env python3
"""
csv_correlate.py — reference-driven field finder.

This is the single biggest accelerator for reverse-engineering a fixed-record
binary format when you have a "known-good" CSV/JSON/GPX export of the same
data. You tell the tool:

    - the binary file
    - the record size (from structure_probe.py)
    - a CSV of expected per-record values

...and for each column in the CSV it brute-force searches every offset,
every numeric type, both endiannesses, and a ladder of scale factors
(1, 10, 100, 1000, 1e4, 1e5, 1e6, 1e7 — covering every common
"integer-as-fixed-point" encoding used in GPS/sensor formats) to find byte
groups in the record that decode to the expected values.

Output is a ranked list of (offset, type, endian, scale) hypotheses per CSV
column, with the match score (fraction of records where decoded value
agrees with the expected value, within tolerance).

This is the workflow that found the DG-388 fields in hours rather than days:
you don't guess, the tool tells you "bytes 8-11 as int32 LE divided by 1e7
match the Latitude column at 100%".

Usage:
    python csv_correlate.py file.bin --record-size 28 --csv expected.csv
    python csv_correlate.py file.bin --record-size 28 --csv expected.csv \\
        --column Latitude --tolerance 1e-6
    python csv_correlate.py file.bin --record-size 28 --csv expected.csv \\
        --skip-records 10 --max-records 500

Options:
    --record-size N     size of each binary record (required)
    --csv PATH          CSV with header row and one row per record
    --column NAME       only search for this CSV column (else all numeric)
    --tolerance FLOAT   relative tolerance for numeric match (default 1e-4)
    --skip-records N    skip the first N binary records (for files that
                        have a header; also the first N CSV rows)
    --max-records N     limit analysis to first N records (for speed)
    --min-score FLOAT   only report hypotheses above this match fraction
                        (default 0.9)
    --record-offset N   start of first record within the file (default 0)
"""

import argparse
import csv
import struct
import sys
from pathlib import Path


# All the fixed-width numeric struct formats we'll try. Each tuple is
# (label, struct_format, size_in_bytes).
NUMERIC_TYPES = [
    ("u8",  "B", 1),
    ("i8",  "b", 1),
    ("u16", "H", 2),
    ("i16", "h", 2),
    ("u32", "I", 4),
    ("i32", "i", 4),
    ("u64", "Q", 8),
    ("i64", "q", 8),
    ("f32", "f", 4),
    ("f64", "d", 8),
]

# Scale factors. The binary stores expected_value * scale as an integer,
# so to decode we divide by `scale`. 1 means no scaling. The big ones
# (1e6, 1e7) cover coordinate encodings; the small ones cover things like
# "km/h * 100" or "degrees * 100". Negative log tries bit-shift scales.
SCALES = [1, 10, 100, 1000, 10_000, 100_000, 1_000_000, 10_000_000]


# Non-linear transforms applied AFTER scale division. Any transform that
# can't sensibly be expressed as value/scale goes here. The identity
# transform is always tried first (and implicitly); other transforms only
# surface as a hit when the linear interpretation fails.
def _ddmm2deg(x):
    """NMEA DDMM.MMMM -> decimal degrees. 2504.1214 -> 25.068690.

    GPS devices often store coordinates in NMEA form even inside binary
    logs (Qstarz BL-1000, various NMEA-over-serial loggers). It can't be
    expressed as a single scale factor, so it lives in TRANSFORMS.
    """
    if x is None:
        return None
    # Avoid breaking on the occasional 0.0 sentinel / skipped row
    sign = -1.0 if x < 0 else 1.0
    x = abs(x)
    deg = int(x / 100)
    minutes = x - deg * 100
    if minutes >= 60:
        # Out of NMEA range; signal "not DDMM" by returning a big value
        return sign * x
    return sign * (deg + minutes / 60.0)


TRANSFORMS = [
    ("identity", lambda x: x),
    ("ddmm",     _ddmm2deg),
]


def is_numericish(s):
    """Is this CSV cell a float/int?"""
    if s is None:
        return False
    s = s.strip()
    if not s:
        return False
    try:
        float(s)
        return True
    except ValueError:
        return False


def to_float(s):
    return float(s.strip())


def load_csv(path, skip_records, max_records):
    """Load CSV into {column_name: [float, float, ...]}. Non-numeric columns
    are dropped with a note."""
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    if skip_records:
        rows = rows[skip_records:]
    if max_records is not None:
        rows = rows[:max_records]

    cols = {}
    for i, name in enumerate(header):
        cells = [r[i] if i < len(r) else "" for r in rows]
        if all(is_numericish(c) for c in cells):
            cols[name] = [to_float(c) for c in cells]
        else:
            cols[name] = None  # non-numeric, skipped
    return header, cols, len(rows)


def unpack_column(data, record_size, record_offset, n_records,
                  byte_offset, fmt, type_size, endian):
    """
    Extract one candidate field from every record: given record layout,
    pull `type_size` bytes at `byte_offset` within each record and decode
    with struct format `fmt` and endian prefix.

    Returns None if any record would read past end of data.
    Returns a list of floats otherwise.
    """
    full_fmt = endian + fmt
    out = []
    for rec in range(n_records):
        off = record_offset + rec * record_size + byte_offset
        if off + type_size > len(data):
            return None
        try:
            (v,) = struct.unpack_from(full_fmt, data, off)
        except struct.error:
            return None
        out.append(float(v))
    return out


def _close(a, b, tolerance):
    scale = max(abs(a), abs(b), 1.0)
    return abs(a - b) <= tolerance * scale


def score_match(decoded, expected, tolerance):
    """
    Fraction of rows where decoded ≈ expected, using either relative
    tolerance (for non-tiny values) or absolute (for values near zero).
    """
    if len(decoded) != len(expected):
        return 0.0
    good = sum(1 for d, e in zip(decoded, expected) if _close(d, e, tolerance))
    return good / len(decoded)


def score_match_unordered(decoded, expected, tolerance):
    """
    Same as score_match, but both sequences are sorted first. This catches
    cases where the reference CSV has the same values as the binary but in
    a different order — e.g., GPSBabel reordering trackpoints after
    waypoints when the binary interleaves them. Weaker evidence than an
    ordered match: any permutation counts, so surface these hits only
    when the ordered match fails.
    """
    if len(decoded) != len(expected):
        return 0.0
    d_sorted = sorted(decoded)
    e_sorted = sorted(expected)
    good = sum(1 for d, e in zip(d_sorted, e_sorted)
               if _close(d, e, tolerance))
    return good / len(decoded)


def search_column(data, record_size, record_offset, n_records,
                  expected, tolerance, min_score, try_unordered=True):
    """
    Brute-force search for byte groups that decode to `expected`.
    Yields hypothesis dicts, ranked by score.

    For each (offset, type, endian, scale, transform) tuple:
      - score ordered match (CSV row i == binary record i)
      - if ordered < min_score and --unordered allowed, score sorted-match
        as a fallback; flag those hits as "unordered"
    """
    hits = []

    # We'll only search offsets that fit; the biggest type (f64/u64) needs 8
    # bytes, but smaller types can start anywhere up to record_size-1.
    for byte_offset in range(record_size):
        for label, fmt, type_size in NUMERIC_TYPES:
            if byte_offset + type_size > record_size:
                continue
            for endian, endian_label in (("<", "LE"), (">", "BE")):
                decoded = unpack_column(
                    data, record_size, record_offset, n_records,
                    byte_offset, fmt, type_size, endian)
                if decoded is None:
                    continue
                for scale in SCALES:
                    scaled = [d / scale for d in decoded]
                    for tname, tfn in TRANSFORMS:
                        try:
                            transformed = [tfn(v) for v in scaled]
                        except (ValueError, OverflowError, ZeroDivisionError):
                            continue
                        s = score_match(transformed, expected, tolerance)
                        matched_unordered = False
                        if s < min_score and try_unordered:
                            s_un = score_match_unordered(
                                transformed, expected, tolerance)
                            if s_un >= min_score:
                                s = s_un
                                matched_unordered = True
                        if s >= min_score:
                            hits.append({
                                "offset": byte_offset,
                                "size": type_size,
                                "type": label,
                                "endian": endian_label,
                                "scale": scale,
                                "transform": tname,
                                "score": s,
                                "unordered": matched_unordered,
                                "sample_decoded": transformed[:3],
                                "sample_expected": expected[:3],
                            })
    # Prefer ordered hits over unordered at the same score, prefer linear
    # (identity) over DDMM at the same score, prefer lower offset.
    hits.sort(key=lambda h: (
        -h["score"],
        h["unordered"],
        0 if h["transform"] == "identity" else 1,
        h["offset"],
        h["size"],
    ))
    return hits


# ---------- CLI --------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("file", help="binary file")
    ap.add_argument("--record-size", type=int, required=True)
    ap.add_argument("--csv", required=True, help="reference CSV")
    ap.add_argument("--column", help="only search this CSV column")
    ap.add_argument("--tolerance", type=float, default=1e-4)
    ap.add_argument("--skip-records", type=int, default=0,
                    help="skip N records at start of binary AND CSV")
    ap.add_argument("--max-records", type=int, default=500,
                    help="limit brute-force to first N records (speed)")
    ap.add_argument("--min-score", type=float, default=0.9)
    ap.add_argument("--record-offset", type=int, default=0,
                    help="byte offset of first record (skip file header)")
    ap.add_argument("--ordered-only", action="store_true",
                    help="disable sorted-match fallback (default: enabled). "
                         "Sorted-match helps when the reference tool "
                         "reorders records (waypoints before trackpoints, "
                         "etc.), but is weaker evidence per hit.")
    args = ap.parse_args()

    data = Path(args.file).read_bytes()

    header, cols, n_csv_rows = load_csv(args.csv, args.skip_records,
                                        args.max_records)
    n_records = n_csv_rows
    usable = (len(data) - args.record_offset) // args.record_size \
             - args.skip_records
    n_records = min(n_records, usable)
    if n_records < 5:
        print(f"error: only {n_records} records to correlate (need >=5). "
              f"Check --record-size / --skip-records / --record-offset.",
              file=sys.stderr)
        sys.exit(1)

    # Start offset for binary records after any skip
    record_offset = args.record_offset + args.skip_records * args.record_size

    print(f"=== csv_correlate: {args.file} ===")
    print(f"Record size: {args.record_size}  records analyzed: {n_records}")
    print(f"CSV: {args.csv}  columns: {header}")
    print(f"Tolerance: {args.tolerance}  min_score: {args.min_score}")

    target_cols = [args.column] if args.column else header
    for name in target_cols:
        if name not in cols:
            print(f"\n[{name}] not in CSV header — skipping")
            continue
        if cols[name] is None:
            print(f"\n[{name}] non-numeric column — skipping")
            continue
        expected = cols[name][:n_records]
        print(f"\n--- {name} ---")
        print(f"  expected sample: {expected[:3]}")
        hits = search_column(
            data, args.record_size, record_offset, n_records,
            expected, args.tolerance, args.min_score,
            try_unordered=not args.ordered_only)
        if not hits:
            print(f"  no match >= {args.min_score*100:.0f}%. Try --tolerance "
                  f"larger, or --min-score smaller, or check endian/offset.")
            continue
        # Collapse duplicates: u32/i32 LE at offset X with scale 1 often
        # matches the same bytes as f32 sometimes; show distinct (offset,
        # size) groups. Keep the top hit per (offset, size).
        seen = set()
        shown = 0
        for h in hits:
            key = (h["offset"], h["size"])
            if key in seen:
                continue
            seen.add(key)
            extras = []
            if h["transform"] != "identity":
                extras.append(f"transform={h['transform']}")
            if h["unordered"]:
                extras.append("unordered (values match but row order differs)")
            extra_str = ("  " + "  ".join(extras)) if extras else ""
            print(f"  {h['score']*100:6.1f}%  "
                  f"offset=0x{h['offset']:02x} ({h['offset']})  "
                  f"{h['type']} {h['endian']}  "
                  f"scale=1/{h['scale']}{extra_str}")
            shown += 1
            if shown >= 5:
                break
        if len(hits) > shown:
            print(f"  ({len(hits) - shown} more hypotheses suppressed)")


if __name__ == "__main__":
    main()
