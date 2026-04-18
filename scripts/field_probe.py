#!/usr/bin/env python3
"""
field_probe.py — black-box field hypothesis tester.

When you don't have a reference CSV (no csv_correlate) you have to guess
what each field is. This tool speeds that up in two modes:

  * Targeted:  "at offset 8, assume i32 LE — show me the distribution"
    (min/max/mean/stddev across every record, plus sample values and a
    sanity check for common encodings — are the values plausible as a
    timestamp? as 1e-7 degrees? as a date?).

  * Scan:      "try every reasonable type at every offset — flag any that
    look like a sensible encoding"
    A value is "sensible" if it:
      - is monotonic (ascending/descending, strong signal for timestamps
        or sequence numbers)
      - falls in a plausible lat/lon range when divided by 1e5..1e7
      - looks like YYYYMMDD or HHMMSS when treated as int
      - has a tight variance (suggests a real measurement rather than
        random bytes)
      - is a small enum (<=8 distinct values — probable flag)

This doesn't confirm a field, it surfaces candidates for you to verify.
Pair with csv_correlate when reference data is available.

Usage:
    python field_probe.py file.bin --record-size 28 --offset 8 --type i32 \\
        --endian LE
    python field_probe.py file.bin --record-size 28 --scan
    python field_probe.py file.bin --record-size 28 --scan --skip-zero-records
"""

import argparse
import math
import statistics
import struct
import sys
from collections import Counter
from pathlib import Path


TYPES = {
    "u8":  ("B", 1), "i8":  ("b", 1),
    "u16": ("H", 2), "i16": ("h", 2),
    "u32": ("I", 4), "i32": ("i", 4),
    "u64": ("Q", 8), "i64": ("q", 8),
    "f32": ("f", 4), "f64": ("d", 8),
}

ENDIAN = {"LE": "<", "BE": ">"}


def read_records(data, record_size, skip_zero_records, record_offset=0):
    """Iterate records (as bytes), skipping blank ones if requested."""
    for base in range(record_offset, len(data) - record_size + 1, record_size):
        rec = data[base:base + record_size]
        if skip_zero_records and all(b == 0 for b in rec):
            continue
        yield base, rec


def decode_all(records, byte_offset, fmt, size, endian):
    """Return list of decoded values from each record."""
    prefix = ENDIAN[endian] if endian in ENDIAN else endian
    full = prefix + fmt
    out = []
    for base, rec in records:
        if byte_offset + size > len(rec):
            return None
        (v,) = struct.unpack_from(full, rec, byte_offset)
        out.append(v)
    return out


# -------- "does this look like <something>?" heuristics ---------------------

def looks_like_yyyymmdd(values):
    """Values plausibly in range 19900101..20991231?"""
    hits = 0
    for v in values:
        v = int(v)
        if 19900101 <= v <= 20991231:
            y, md = divmod(v, 10000)
            m, d = divmod(md, 100)
            if 1 <= m <= 12 and 1 <= d <= 31:
                hits += 1
    return hits / max(1, len(values))


def looks_like_hhmmss(values):
    """Values plausibly HHMMSS?"""
    hits = 0
    for v in values:
        v = int(v)
        if 0 <= v <= 235959:
            h, ms = divmod(v, 10000)
            m, s = divmod(ms, 100)
            if 0 <= h <= 23 and 0 <= m <= 59 and 0 <= s <= 59:
                hits += 1
    return hits / max(1, len(values))


def looks_like_unix_timestamp(values):
    """Roughly between year 2000 and year 2050 as Unix epoch seconds?"""
    lo, hi = 946684800, 2524608000  # 2000-01-01 .. 2050-01-01
    hits = sum(1 for v in values if lo <= int(v) <= hi)
    return hits / max(1, len(values))


def looks_like_coord(values, scale):
    """After dividing by `scale`, does it fall in [-180, 180] with some variance?"""
    scaled = [v / scale for v in values]
    in_range = sum(1 for s in scaled if -180 <= s <= 180)
    if in_range / len(scaled) < 0.95:
        return 0.0
    # require some spread — all-zero columns "fall in range" but aren't coords
    if len(scaled) >= 4:
        try:
            var = statistics.pvariance(scaled)
        except statistics.StatisticsError:
            var = 0
        if var < 1e-12:
            return 0.0
    return in_range / len(scaled)


# -------- float-specific heuristics -----------------------------------------
# These apply to f32/f64 values directly (no scale division); wrong-
# interpretation floats produce NaN, Inf, or wildly huge exponents so
# we gate everything on "all values are finite and in a plausible range".

def _finite_and_spread(values):
    """Reject all-zero, all-NaN, all-Inf, and no-variance columns."""
    if not values:
        return False
    if not all(math.isfinite(v) for v in values):
        return False
    if all(v == 0.0 for v in values):
        return False
    # Reject absurdly-huge floats up front; wrong-interpretation bytes
    # frequently decode to ~1e38 f32 values that overflow pvariance.
    if any(abs(v) > 1e30 for v in values):
        return False
    if len(values) >= 4:
        try:
            if statistics.pvariance(values) < 1e-20:
                return False
        except (statistics.StatisticsError, OverflowError):
            return False
    return True


def looks_like_coord_f(values):
    """Float already decimal degrees (±180), with non-trivial variance."""
    if not _finite_and_spread(values):
        return 0.0
    in_range = sum(1 for v in values if -180.0 <= v <= 180.0)
    return in_range / len(values) if in_range == len(values) else 0.0


def looks_like_ddmm_f(values):
    """Float in NMEA DDMM.MMMM form (0..18060 range, decimals look like minutes)."""
    if not _finite_and_spread(values):
        return 0.0
    # NMEA range: lat up to 9060 (90°00.00'), lon up to 18060 (180°00.00')
    if not all(0.0 <= abs(v) <= 18100.0 for v in values):
        return 0.0
    # The fractional part's hundreds place should look like minutes (<60).
    # For every value, compute minutes = abs(v) - int(abs(v)/100)*100
    for v in values:
        a = abs(v)
        minutes = a - int(a / 100) * 100
        if minutes >= 60.0:
            return 0.0
    return 1.0


def looks_like_altitude_f(values):
    """Float in plausible altitude range (-500 to 20000 m)."""
    if not _finite_and_spread(values):
        return 0.0
    if all(-500.0 <= v <= 20000.0 for v in values):
        return 1.0
    return 0.0


def looks_like_speed_f(values):
    """Float non-negative, <=2000 km/h (well above every plausible vehicle)."""
    if not _finite_and_spread(values):
        return 0.0
    if all(0.0 <= v <= 2000.0 for v in values):
        return 1.0
    return 0.0


def looks_like_heading_f(values):
    """Float in 0-360 range."""
    if not _finite_and_spread(values):
        return 0.0
    if all(0.0 <= v <= 360.0 for v in values):
        return 1.0
    return 0.0


def looks_like_small_unit_f(values):
    """Catch-all for plausibly-scaled floats (e.g. dop, g-force) — non-huge,
    non-tiny, finite. Tagged weakly."""
    if not _finite_and_spread(values):
        return 0.0
    if all(abs(v) < 1e6 for v in values):
        # require at least *some* magnitude spread to avoid a constant column
        if max(values) - min(values) > 1e-6:
            return 1.0
    return 0.0


def is_monotonic(values, direction="up"):
    """
    Is the sequence meaningfully monotonic? Requires both:
      (a) near-monotonic adjacency, AND
      (b) enough distinct values — otherwise a column of constants trivially
          scores 100% monotonic, which is not informative.
    """
    if len(values) < 3:
        return 0.0
    if len(set(values)) < max(3, len(values) // 20):
        return 0.0
    good = 0
    total = 0
    prev = values[0]
    for v in values[1:]:
        total += 1
        if direction == "up" and v >= prev:
            good += 1
        elif direction == "down" and v <= prev:
            good += 1
        prev = v
    return good / total


# -------- reports ------------------------------------------------------------

def describe(values, label):
    n = len(values)
    if n == 0:
        print(f"  [{label}] no values"); return
    vmin = min(values); vmax = max(values)
    uniq = len(set(values))
    try:
        mean = statistics.fmean(values)
        stdev = statistics.pstdev(values) if n > 1 else 0.0
    except (statistics.StatisticsError, TypeError):
        mean = stdev = 0.0
    print(f"  [{label}] n={n}  min={vmin}  max={vmax}  "
          f"unique={uniq}  mean={mean:.3f}  stdev={stdev:.3f}")
    print(f"     sample: {values[:8]}")

    # Heuristic tags
    tags = []
    mono_up = is_monotonic(values, "up")
    mono_dn = is_monotonic(values, "down")
    if mono_up > 0.95:
        tags.append(f"monotonic ↑ ({mono_up*100:.0f}%) — likely counter/timestamp")
    elif mono_dn > 0.95:
        tags.append(f"monotonic ↓ ({mono_dn*100:.0f}%) — likely countdown")

    if all(isinstance(v, int) for v in values):
        d = looks_like_yyyymmdd(values)
        if d > 0.9:
            tags.append(f"YYYYMMDD date pattern ({d*100:.0f}%)")
        t = looks_like_hhmmss(values)
        if t > 0.9:
            tags.append(f"HHMMSS time pattern ({t*100:.0f}%)")
        u = looks_like_unix_timestamp(values)
        if u > 0.9:
            tags.append(f"Unix epoch range ({u*100:.0f}%)")
        for scale in (1e5, 1e6, 1e7):
            c = looks_like_coord(values, scale)
            if c > 0.95:
                tags.append(f"looks like degrees / {scale:g} "
                            f"(lat/lon ~{values[0]/scale:.4f}°)")

    if uniq <= 8 and n > 20:
        dist = Counter(values).most_common()
        tags.append(f"low cardinality ({uniq} values) — enum/flag: {dist}")

    if tags:
        for t in tags:
            print(f"     → {t}")


def probe_one(data, record_size, record_offset, offset, type_name, endian,
              skip_zero):
    if type_name not in TYPES:
        print(f"error: unknown type {type_name}. Choose from "
              f"{list(TYPES)}", file=sys.stderr)
        sys.exit(1)
    fmt, size = TYPES[type_name]
    records = list(read_records(data, record_size, skip_zero, record_offset))
    values = decode_all(records, offset, fmt, size, endian)
    if values is None:
        print(f"error: offset+size exceeds record_size", file=sys.stderr)
        sys.exit(1)
    print(f"=== field at offset {offset}, type {type_name} {endian} ===")
    describe(values, f"{type_name}{endian}@{offset}")


def scan_all(data, record_size, record_offset, skip_zero, max_hits_per_offset=4):
    """Try every type×endian at every offset; report anything with a heuristic tag.

    Wider types (u32/i32/f32/u64/f64) are reported first because they're the
    more likely "real" interpretation when both narrow and wide types flag
    the same offset.
    """
    records = list(read_records(data, record_size, skip_zero, record_offset))
    n = len(records)
    print(f"=== scan over {record_size}-byte records ({n} records) ===")
    # Iteration order: widest first
    ordered_types = sorted(TYPES.items(), key=lambda kv: -kv[1][1])

    for offset in range(record_size):
        hits = []
        for type_name, (fmt, size) in ordered_types:
            if offset + size > record_size:
                continue
            for endian in ("LE", "BE"):
                if size == 1 and endian == "BE":
                    continue  # single-byte types have no endianness
                vals = decode_all(records, offset, fmt, size, endian)
                if vals is None:
                    continue
                tags = []
                is_int_type = type_name not in ("f32", "f64")
                if is_int_type:
                    mono_up = is_monotonic(vals, "up")
                    if mono_up > 0.98:
                        tags.append(f"monotonic↑ {mono_up*100:.0f}%")
                    if looks_like_yyyymmdd(vals) > 0.95:
                        tags.append("YYYYMMDD")
                    if looks_like_hhmmss(vals) > 0.95:
                        tags.append("HHMMSS")
                    if looks_like_unix_timestamp(vals) > 0.95:
                        tags.append("unix_ts")
                    for scale in (1e5, 1e6, 1e7):
                        if looks_like_coord(vals, scale) > 0.98:
                            tags.append(f"coord/{scale:g}")
                else:
                    # Float-specific tags. Only emit strong tags — weak
                    # "small_unit" tag lives in its own if-branch below so
                    # it doesn't drown out integer tags at the same offset.
                    if looks_like_coord_f(vals) > 0:
                        tags.append("coord_deg (float)")
                    if looks_like_ddmm_f(vals) > 0:
                        tags.append("coord_ddmm (float NMEA)")
                    if looks_like_altitude_f(vals) > 0 \
                            and not looks_like_coord_f(vals):
                        tags.append("altitude_m (float)")
                    if looks_like_speed_f(vals) > 0 \
                            and not looks_like_coord_f(vals) \
                            and not looks_like_altitude_f(vals):
                        tags.append("speed_kmh (float)")
                    if looks_like_heading_f(vals) > 0 \
                            and not looks_like_coord_f(vals):
                        tags.append("heading_deg (float)")
                uniq = len(set(vals))
                if is_int_type and 2 <= uniq <= 4 and n > 20:
                    tags.append(f"enum({uniq}): "
                                f"{sorted(set(vals))[:4]}")
                if tags:
                    hits.append((type_name, endian, tags, vals[:3], size))

        if hits:
            # Per offset, show one hit per distinct "meaningful-tag" using
            # the widest type that produced that tag. Prevents truncation
            # at u64 when u64 and i32 both match the same offset with
            # different tags (u64=monotonic, i32=YYYYMMDD).
            picked = {}  # tag -> (type_name, endian, [all tags], sample, size)
            for tup in hits:  # hits are already widest-first ordered
                type_name, endian, tags, sample, size = tup
                for t in tags:
                    if t not in picked:
                        picked[t] = tup

            # Collapse into unique hit tuples (preserving order of appearance)
            seen_tups = []
            for tup in picked.values():
                if tup not in seen_tups:
                    seen_tups.append(tup)

            print(f"\noffset 0x{offset:02x} ({offset}):")
            for type_name, endian, tags, sample, _ in \
                    seen_tups[:max_hits_per_offset]:
                print(f"  {type_name} {endian}  [{', '.join(tags)}]  "
                      f"sample={sample}")


# -------- CLI ---------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--record-size", type=int, required=True)
    ap.add_argument("--record-offset", type=int, default=0,
                    help="start of first record (skip file header)")
    ap.add_argument("--offset", type=int, default=None,
                    help="byte offset within record (targeted mode)")
    ap.add_argument("--type", default=None,
                    help=f"numeric type ({'/'.join(TYPES)})")
    ap.add_argument("--endian", choices=["LE", "BE"], default="LE")
    ap.add_argument("--scan", action="store_true",
                    help="try every type at every offset; tag interesting ones")
    ap.add_argument("--skip-zero-records", action="store_true",
                    help="ignore records that are all zeros (pre-allocated blanks)")
    args = ap.parse_args()

    data = Path(args.file).read_bytes()

    if args.scan:
        scan_all(data, args.record_size, args.record_offset,
                 args.skip_zero_records)
        return

    if args.offset is None or args.type is None:
        print("error: need --offset and --type (or --scan)", file=sys.stderr)
        sys.exit(1)

    probe_one(data, args.record_size, args.record_offset,
              args.offset, args.type, args.endian, args.skip_zero_records)


if __name__ == "__main__":
    main()
