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
import re
import sys
from collections import Counter
from pathlib import Path


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


# ---------- report -----------------------------------------------------------

def report(path, args):
    data = Path(path).read_bytes()
    file_len = len(data)
    print(f"=== structure_probe: {path} ===")
    print(f"File size: {file_len} bytes ({file_len:,})")
    if file_len == 0:
        print("Empty file — nothing to analyze.")
        return

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
