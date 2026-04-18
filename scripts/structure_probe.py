#!/usr/bin/env python3
"""
structure_probe.py — first-pass reconnaissance on an unknown binary file.

Runs four quick analyses and prints a report:

  1. File-size factorization         -> candidate record sizes
  2. Column-entropy record-size hunt -> ranks candidate sizes by how
                                        "record-like" the file looks at
                                        that stride (low per-column entropy
                                        at small offsets is a strong signal)
  3. Printable-string extraction     -> ASCII and UTF-16-LE strings, with
                                        offsets (magic bytes, version
                                        strings, field names often hide here)
  4. Global byte-frequency + entropy -> total file entropy and the
                                        byte-value histogram (0x00 spikes
                                        suggest padding, 0xFF spikes suggest
                                        erased flash, flat = compressed/
                                        encrypted)

Usage:
    python structure_probe.py <file> [--min-record 4] [--max-record 256]
                                     [--top 8] [--min-string 4]

No dependencies outside the Python 3 standard library.
"""

import argparse
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

# Allow `python scripts/structure_probe.py ...` to find container_probe.py
# as a sibling module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from container_probe import check_magic as _check_container_magic
except ImportError:  # pragma: no cover
    _check_container_magic = None


# ---------- helpers ----------------------------------------------------------

def shannon_entropy(values):
    """Shannon entropy in bits, over whatever iterable of hashables you pass."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def factors_up_to(n, lo, hi):
    """All divisors of n in [lo, hi] (inclusive)."""
    out = []
    i = lo
    while i <= hi and i <= n:
        if n % i == 0:
            out.append(i)
        i += 1
    return out


# ---------- analyses ---------------------------------------------------------

def record_size_score(data, record_size):
    """
    Score how "record-like" `data` looks when chopped into fixed-size rows of
    `record_size` bytes. The score is the mean of per-column Shannon entropy:
    low entropy means bytes at that column take few distinct values across
    records, which is the signature of a fixed field (a flag byte, a tag, an
    always-zero padding byte, etc.). A real record format will usually have
    several low-entropy columns mixed in with high-entropy data columns, so
    the *mean* lands well below log2(256)=8.

    Returns (mean_entropy, min_entropy, n_rows).
    """
    n_rows = len(data) // record_size
    if n_rows < 4:
        return (8.0, 8.0, n_rows)  # not enough rows to judge

    columns = [[] for _ in range(record_size)]
    for row in range(n_rows):
        base = row * record_size
        for col in range(record_size):
            columns[col].append(data[base + col])

    ents = [shannon_entropy(c) for c in columns]
    return (sum(ents) / len(ents), min(ents), n_rows)


def hunt_record_size(data, lo, hi, top_k=8):
    """
    Look at every size in [lo, hi] that divides the file length evenly, plus
    a handful of common non-divisors (for files that might have trailing
    padding), and rank by record_size_score.
    """
    file_len = len(data)
    candidates = set(factors_up_to(file_len, lo, hi))
    # Also include every size whose remainder is small (<=0.5% of file)
    for s in range(lo, hi + 1):
        if file_len % s <= max(1, file_len // 200):
            candidates.add(s)

    results = []
    for s in sorted(candidates):
        mean_h, min_h, nrows = record_size_score(data, s)
        # A small "bonus" for exact divisors — real formats rarely have a
        # trailing partial record.
        exact = (file_len % s == 0)
        results.append({
            "size": s,
            "mean_col_entropy": mean_h,
            "min_col_entropy": min_h,
            "n_rows": nrows,
            "exact_divisor": exact,
        })

    # Rank: prefer exact-divisor sizes, then lowest mean_col_entropy.
    results.sort(key=lambda r: (not r["exact_divisor"], r["mean_col_entropy"]))
    return results[:top_k]


def extract_strings(data, min_len=4):
    """Find printable ASCII and UTF-16-LE strings with their offsets."""
    ascii_hits = []
    # Printable ASCII (0x20..0x7E) + tab/newline/cr
    for m in re.finditer(rb"[\x09\x0a\x0d\x20-\x7e]{%d,}" % min_len, data):
        ascii_hits.append((m.start(), m.group().decode("ascii", errors="replace")))

    utf16_hits = []
    # UTF-16-LE: printable ASCII char followed by 0x00, repeated.
    pattern = (rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in re.finditer(pattern, data):
        s = m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
        utf16_hits.append((m.start(), s))

    return ascii_hits, utf16_hits


def byte_histogram(data):
    counts = Counter(data)
    h = shannon_entropy(data)
    return counts, h


# ---------- variable-length record detection --------------------------------

import struct as _struct


LENGTH_FRAMING_VARIANTS = [
    # (label, struct_fmt, byte_size, length_field_offset)
    ("u8 @0",          "<B", 1, 0),
    ("u16 LE @0",      "<H", 2, 0),
    ("u16 BE @0",      ">H", 2, 0),
    ("u32 LE @0",      "<I", 4, 0),
    ("u32 BE @0",      ">I", 4, 0),
    ("u16 LE @2",      "<H", 2, 2),
    ("u16 BE @2",      ">H", 2, 2),
    ("u16 LE @4",      "<H", 2, 4),
    ("u32 LE @4",      "<I", 4, 4),
]


def try_length_prefixed_walk(data, fmt, size, field_off,
                             includes_header, min_rec, max_rec):
    """
    Walk the file assuming each record starts with a length field. Returns
    (n_records, ok) where ok=True means the walk consumed exactly the whole
    file with every length in the [min_rec, max_rec] range.
    """
    pos = 0
    n = 0
    while pos < len(data):
        if len(data) - pos < field_off + size:
            return (n, False)
        raw = _struct.unpack_from(fmt, data, pos + field_off)[0]
        rec_size = raw if includes_header else raw + field_off + size
        if rec_size < min_rec or rec_size > max_rec:
            return (n, False)
        if pos + rec_size > len(data):
            return (n, False)
        pos += rec_size
        n += 1
        # Guard: absurdly many short records likely means wrong framing.
        if n > len(data):
            return (n, False)
    return (n, pos == len(data))


def hunt_length_prefix(data, min_rec=4, max_rec=65536):
    """Try every framing variant; return successful walks sorted by record count."""
    results = []
    for label, fmt, size, off in LENGTH_FRAMING_VARIANTS:
        for includes_header in (True, False):
            n, ok = try_length_prefixed_walk(
                data, fmt, size, off, includes_header, min_rec, max_rec)
            if ok and n >= 2:
                results.append({
                    "label": label,
                    "length_field_struct": fmt,
                    "length_field_size": size,
                    "length_field_offset": off,
                    "length_includes_header": includes_header,
                    "n_records": n,
                })
    # Prefer fewer variants with the same record count: smaller size first,
    # then includes_header=True (more common convention).
    results.sort(key=lambda r: (-r["n_records"], r["length_field_size"],
                                not r["length_includes_header"]))
    return results


def hunt_delimiters(data, top_k=5):
    """
    Find candidate delimiter bytes: those that appear with unusually regular
    spacing. Scores by 1 / coefficient_of_variation of gaps — a true
    delimiter has low variance in the space between occurrences.
    """
    candidates = []
    counts = Counter(data)
    for byte_val, count in counts.items():
        if count < 4:
            continue
        # Skip bytes that are overwhelmingly common (likely 0x00 padding) or
        # rare enough to be noise.
        if count > len(data) * 0.5 or count < 3:
            continue
        positions = [i for i, b in enumerate(data) if b == byte_val]
        gaps = [positions[i + 1] - positions[i]
                for i in range(len(positions) - 1)]
        if not gaps:
            continue
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap < 2:
            continue
        variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        std = variance ** 0.5
        cv = std / mean_gap if mean_gap else 99
        candidates.append({
            "byte": byte_val,
            "count": count,
            "mean_gap": mean_gap,
            "cv": cv,
        })
    # Low CV = regular spacing = delimiter-like
    candidates.sort(key=lambda c: c["cv"])
    return candidates[:top_k]


# ---------- report -----------------------------------------------------------

def report(path, args):
    data = Path(path).read_bytes()
    file_len = len(data)
    print(f"=== structure_probe: {path} ===")
    print(f"File size: {file_len} bytes ({file_len:,})")
    if file_len == 0:
        print("Empty file — nothing to analyze.")
        return

    # --- Container-format sanity check
    if _check_container_magic is not None:
        hits = _check_container_magic(data)
        if hits:
            print("\n-- Container format detected --")
            for name, hint, offset in hits:
                off_s = f"at offset {offset}" if offset else "at offset 0"
                print(f"  {name} ({off_s})")
            print()
            print("  This file is a recognized container format, not a")
            print("  fixed-record stream. The binary-format-reverser toolkit")
            print("  does not model chunked containers — run")
            print(f"  `python container_probe.py {path}` for suggested")
            print("  libraries and a chunk-walk inventory. The record-size")
            print("  scan below will run anyway but its results are unlikely")
            print("  to be meaningful for this kind of file.")

    # --- Global stats
    counts, h_total = byte_histogram(data)
    print(f"\n-- Global byte stats --")
    print(f"Shannon entropy: {h_total:.3f} bits/byte (max 8.0)")
    top5 = counts.most_common(5)
    pct = lambda c: 100.0 * c / file_len
    print("Top 5 byte values: " + ", ".join(
        f"0x{b:02x}={c} ({pct(c):.1f}%)" for b, c in top5))
    if h_total > 7.5:
        print("  Entropy is high — data may be compressed/encrypted, or this")
        print("  is a dense packed format with few constant bytes.")
    if counts.get(0x00, 0) > file_len * 0.3:
        print("  Many 0x00 bytes — likely padding or uninitialized regions.")
    if counts.get(0xFF, 0) > file_len * 0.3:
        print("  Many 0xFF bytes — likely erased flash pages or padding.")

    # --- Record-size hunt
    print(f"\n-- Candidate record sizes ({args.min_record}..{args.max_record}) --")
    print(f"{'size':>6}  {'rows':>8}  {'exact':>5}  "
          f"{'mean_col_H':>11}  {'min_col_H':>10}")
    print("-" * 50)
    candidates = hunt_record_size(data, args.min_record, args.max_record,
                                  top_k=args.top)
    for r in candidates:
        print(f"{r['size']:>6}  {r['n_rows']:>8}  "
              f"{'YES' if r['exact_divisor'] else 'no':>5}  "
              f"{r['mean_col_entropy']:>11.3f}  {r['min_col_entropy']:>10.3f}")

    # Post-process: among exact-divisor candidates with strong scores, the
    # smallest one is usually the true record size (larger sizes are just
    # multiples that look equally good). Take everything within 0.25 bits of
    # the best mean_col_entropy and pick the smallest.
    exact = [r for r in candidates if r["exact_divisor"]]
    if exact:
        best_h = min(r["mean_col_entropy"] for r in exact)
        strong = [r for r in exact if r["mean_col_entropy"] <= best_h + 0.25]
        best = min(strong, key=lambda r: r["size"])
        print()
        print(f"Best guess: record_size = {best['size']} bytes "
              f"({best['n_rows']} records).")
        if len(strong) > 1:
            multiples = [r["size"] for r in strong if r["size"] != best["size"]]
            if all(m % best["size"] == 0 for m in multiples):
                print(f"  ({', '.join(str(m) for m in multiples)} are "
                      f"multiples of {best['size']}, so they score similarly.)")
    print()
    print("Lower mean_col_H + exact divisor = stronger record-size candidate.")
    print("min_col_H near 0.0 means at least one column is a near-constant")
    print("(flag byte, type tag, always-zero padding) — a classic fixed-record")
    print("signature. Next step: run field_probe.py with the best candidate.")

    # --- Variable-length record detection
    print(f"\n-- Variable-length record detection --")
    print("Trying length-prefixed framings (each record starts with its "
          "own size field):")
    lp_hits = hunt_length_prefix(data,
                                 min_rec=args.min_record,
                                 max_rec=args.max_record)
    if not lp_hits:
        print("  No length-prefixed framing matched the entire file.")
    else:
        print(f"  {'variant':<14}  {'incl_hdr':>8}  {'records':>8}")
        for h in lp_hits[:5]:
            print(f"  {h['label']:<14}  "
                  f"{'yes' if h['length_includes_header'] else 'no':>8}  "
                  f"{h['n_records']:>8}")
        print("  If any of these consumed the entire file with a plausible")
        print("  record count, the format is probably length-prefixed, not")
        print("  fixed-record. Set record_framing='length_prefixed' in the")
        print("  fieldmap with the matching length_field_type/offset.")

    print("\nDelimiter candidates (bytes with unusually regular spacing):")
    delims = hunt_delimiters(data, top_k=5)
    if not delims:
        print("  No strong delimiter candidates.")
    else:
        print(f"  {'byte':>4}  {'count':>6}  {'mean_gap':>8}  {'cv':>6}")
        for d in delims:
            print(f"  0x{d['byte']:02x}  {d['count']:>6}  "
                  f"{d['mean_gap']:>8.1f}  {d['cv']:>6.3f}")
        print("  cv = coefficient of variation of gaps. cv < 0.1 suggests")
        print("  a true record delimiter; higher values are probably just")
        print("  common data bytes.")

    # --- Strings
    print(f"\n-- Embedded strings (min_len={args.min_string}) --")
    ascii_hits, utf16_hits = extract_strings(data, min_len=args.min_string)
    if not ascii_hits and not utf16_hits:
        print("  No printable strings of that length. Format is likely pure")
        print("  binary (typical for tight fixed-record telemetry formats).")
    if ascii_hits:
        print(f"  ASCII strings ({len(ascii_hits)} found):")
        for off, s in ascii_hits[:20]:
            # Clip very long strings
            if len(s) > 80:
                s = s[:77] + "..."
            print(f"    0x{off:08x}  {s!r}")
        if len(ascii_hits) > 20:
            print(f"    ... ({len(ascii_hits) - 20} more)")
    if utf16_hits:
        print(f"  UTF-16-LE strings ({len(utf16_hits)} found):")
        for off, s in utf16_hits[:20]:
            if len(s) > 80:
                s = s[:77] + "..."
            print(f"    0x{off:08x}  {s!r}")
        if len(utf16_hits) > 20:
            print(f"    ... ({len(utf16_hits) - 20} more)")

    # --- Quick tail/head hex
    print(f"\n-- First 64 bytes (look for magic/header) --")
    dump_hex(data[:64])
    print(f"\n-- Last 32 bytes (look for trailer/checksum) --")
    dump_hex(data[-32:], base_offset=file_len - min(32, file_len))


def dump_hex(blob, base_offset=0, width=16):
    for i in range(0, len(blob), width):
        chunk = blob[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {base_offset + i:08x}  {hx:<{width*3}}  |{asc}|")


# ---------- CLI --------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("file", help="binary file to analyze")
    ap.add_argument("--min-record", type=int, default=4)
    ap.add_argument("--max-record", type=int, default=256)
    ap.add_argument("--top", type=int, default=8,
                    help="how many record-size candidates to show")
    ap.add_argument("--min-string", type=int, default=4)
    args = ap.parse_args()

    if not Path(args.file).exists():
        print(f"error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    report(args.file, args)


if __name__ == "__main__":
    main()
