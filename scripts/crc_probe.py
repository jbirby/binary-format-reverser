#!/usr/bin/env python3
"""
crc_probe.py — identify the checksum or CRC algorithm protecting each
record of a fixed-record binary file (or a whole file with a known
trailer checksum).

The probe takes the file, picks a candidate "checksum window" inside each
record (last 1, 2, or 4 bytes by default — override with --checksum-offset
and --checksum-size), computes every bundled checksum algorithm over the
*other* bytes of the record, and reports any algorithm that agrees with
the candidate value on at least 90% of records.

Algorithms bundled (stdlib only, no external libraries):

    SUM-8, SUM-16-LE, SUM-16-BE, SUM-32-LE, SUM-32-BE
    XOR-8
    TWOS-COMP-8 (NMEA-style, (-sum) & 0xFF)
    CRC-8, CRC-8/MAXIM (Dallas 1-wire), CRC-8/ROHC
    CRC-16/ARC, CRC-16/MODBUS, CRC-16/CCITT-FALSE, CRC-16/XMODEM,
      CRC-16/KERMIT, CRC-16/USB
    CRC-32 (Ethernet/ZIP), CRC-32/BZIP2, CRC-32C (Castagnoli)

Unknown checksum algorithms not in this list won't be detected. When the
probe finds no match it prints the counts of distinct checksum values in
the candidate window — a near-uniform distribution means the field
really does behave like a checksum (even if we can't name the algorithm);
a highly skewed distribution means the field probably isn't a checksum
at all.

Usage:
    # Fixed-record file, checksum is the last byte of each record:
    python crc_probe.py file.bin --record-size 16

    # Checksum is u16 BE at offset 2 in each record, covering bytes 4-15:
    python crc_probe.py file.bin --record-size 16 \\
        --checksum-offset 2 --checksum-size 2 --checksum-endian BE \\
        --data-range 4:16

    # File-level trailer: last 4 bytes are a checksum over the file
    # minus those 4 bytes:
    python crc_probe.py file.bin --file-trailer 4
"""

import argparse
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# Generic CRC kernel. Parameterized by (width, poly, init, refin, refout,
# xorout) — the "Rocksoft Model CRC" specification used by almost every
# published CRC catalog.
# ---------------------------------------------------------------------------

def _reflect(val, width):
    r = 0
    for i in range(width):
        if val & (1 << i):
            r |= 1 << (width - 1 - i)
    return r


def _crc(data, width, poly, init, refin, refout, xorout):
    crc = init
    top_bit = 1 << (width - 1)
    mask = (1 << width) - 1
    for byte in data:
        b = _reflect(byte, 8) if refin else byte
        crc ^= b << (width - 8)
        for _ in range(8):
            if crc & top_bit:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= mask
    if refout:
        crc = _reflect(crc, width)
    return crc ^ xorout


# Simple checksums (not CRCs)
def sum8(data):        return sum(data) & 0xff
def sum16(data):       return sum(data) & 0xffff
def sum32(data):       return sum(data) & 0xffffffff
def xor8(data):
    x = 0
    for b in data:
        x ^= b
    return x
def twos_comp_8(data): return (-sum(data)) & 0xff


# ---------------------------------------------------------------------------
# Algorithm registry. Each entry is:
#   (name, width_bits, callable(data) -> int)
# ---------------------------------------------------------------------------

ALGORITHMS = [
    ("SUM-8",             8,  sum8),
    ("XOR-8",             8,  xor8),
    ("TWOS-COMP-8",       8,  twos_comp_8),
    ("CRC-8",             8,  lambda d: _crc(d, 8,  0x07, 0x00, False, False, 0x00)),
    ("CRC-8/MAXIM",       8,  lambda d: _crc(d, 8,  0x31, 0x00, True,  True,  0x00)),
    ("CRC-8/ROHC",        8,  lambda d: _crc(d, 8,  0x07, 0xff, True,  True,  0x00)),
    ("CRC-8/ITU",         8,  lambda d: _crc(d, 8,  0x07, 0x00, False, False, 0x55)),

    ("SUM-16",            16, sum16),
    ("CRC-16/ARC",        16, lambda d: _crc(d, 16, 0x8005, 0x0000, True,  True,  0x0000)),
    ("CRC-16/MODBUS",     16, lambda d: _crc(d, 16, 0x8005, 0xffff, True,  True,  0x0000)),
    ("CRC-16/CCITT-FALSE",16, lambda d: _crc(d, 16, 0x1021, 0xffff, False, False, 0x0000)),
    ("CRC-16/XMODEM",     16, lambda d: _crc(d, 16, 0x1021, 0x0000, False, False, 0x0000)),
    ("CRC-16/KERMIT",     16, lambda d: _crc(d, 16, 0x1021, 0x0000, True,  True,  0x0000)),
    ("CRC-16/USB",        16, lambda d: _crc(d, 16, 0x8005, 0xffff, True,  True,  0xffff)),
    ("CRC-16/GENIBUS",    16, lambda d: _crc(d, 16, 0x1021, 0xffff, False, False, 0xffff)),

    ("SUM-32",            32, sum32),
    # zlib.crc32 is the standard Ethernet/ZIP CRC-32 and is much faster
    # than our Python-implemented generic kernel.
    ("CRC-32",            32, lambda d: zlib.crc32(bytes(d)) & 0xffffffff),
    ("CRC-32/BZIP2",      32, lambda d: _crc(d, 32, 0x04c11db7, 0xffffffff, False, False, 0xffffffff)),
    ("CRC-32C",           32, lambda d: _crc(d, 32, 0x1edc6f41, 0xffffffff, True,  True,  0xffffffff)),
    ("CRC-32/MPEG-2",     32, lambda d: _crc(d, 32, 0x04c11db7, 0xffffffff, False, False, 0x00000000)),
]


# ---------------------------------------------------------------------------
# Probe driver.
# ---------------------------------------------------------------------------

def _unpack_candidate(rec, off, size, endian):
    """Extract an unsigned integer of `size` bytes at `off`, given endian."""
    fmt_char = {1: "B", 2: "H", 4: "I"}[size]
    prefix = "<" if endian == "LE" else ">"
    return struct.unpack_from(prefix + fmt_char, rec, off)[0]


def _diverse(values):
    """True if the candidate column takes >=3 distinct values — a checksum
    over varying data has lots of unique values, while a constant
    (always 0x00 or 0xFF) column is usually padding, not a checksum."""
    return len(set(values)) >= 3


def try_location(records, ckof, cksize, endian, data_ranges):
    """
    Try every algorithm whose width matches `cksize * 8` at the given
    checksum location. `data_ranges` is a list of (lo, hi) byte slices
    to feed the algorithm; the default of one slice covering everything
    except the checksum window is provided by the caller.
    """
    candidates = [_unpack_candidate(r, ckof, cksize, endian) for r in records]
    if not _diverse(candidates):
        return [], candidates

    hits = []
    target_width = cksize * 8
    for name, width, fn in ALGORITHMS:
        if width != target_width:
            continue
        # Assemble the data blob from all non-checksum slices.
        match = 0
        for rec, cand in zip(records, candidates):
            data = b"".join(rec[lo:hi] for (lo, hi) in data_ranges)
            computed = fn(data)
            if computed == cand:
                match += 1
        pct = match / len(records)
        if pct >= 0.90:
            hits.append({
                "algorithm": name,
                "width_bits": width,
                "match_rate": pct,
                "matches": match,
                "total": len(records),
            })
    hits.sort(key=lambda h: -h["match_rate"])
    return hits, candidates


def report_record_level(path, record_size, ckof=None, cksize=None,
                        endian="LE", data_ranges=None, top_n=5):
    data = Path(path).read_bytes()
    n_rec = len(data) // record_size
    if n_rec < 3:
        print("Need at least 3 records to probe for a checksum.")
        return
    records = [data[i * record_size:(i + 1) * record_size] for i in range(n_rec)]

    print(f"=== crc_probe: {path} ===")
    print(f"{n_rec} records of {record_size} bytes each.")

    # Build the list of (ckof, cksize, endian, data_ranges) configurations
    # to try. If the user specified exact parameters, try only those. Else
    # sweep the common trailing windows.
    configs = []
    if ckof is not None and cksize is not None:
        drng = data_ranges or [(0, ckof),
                               (ckof + cksize, record_size)]
        # Drop empty ranges
        drng = [(a, b) for (a, b) in drng if b > a]
        # If cksize is 1 there's no endianness; try only the given one.
        endians = [endian] if cksize == 1 else [endian]
        for e in endians:
            configs.append((ckof, cksize, e, drng))
    else:
        for s in (1, 2, 4):
            if s > record_size:
                continue
            ck_off = record_size - s
            drng = [(0, ck_off)]
            if s == 1:
                configs.append((ck_off, 1, "LE", drng))
            else:
                configs.append((ck_off, s, "LE", drng))
                configs.append((ck_off, s, "BE", drng))

    any_hit = False
    for (co, cs, end, drng) in configs:
        label = f"checksum @ offset {co}, {cs} byte{'s' if cs > 1 else ''} {end}"
        hits, cands = try_location(records, co, cs, end, drng)
        if not _diverse(cands):
            continue
        print(f"\n-- Probing {label} --")
        if hits:
            any_hit = True
            for h in hits[:top_n]:
                print(f"  MATCH  {h['algorithm']:<22} "
                      f"{h['matches']}/{h['total']} records "
                      f"({h['match_rate']*100:.1f}%)")
        else:
            # Report the distribution so the user can see whether the
            # field looks checksum-like.
            uniq = len(set(cands))
            cnt = Counter(cands)
            top = cnt.most_common(3)
            most_common_pct = top[0][1] / len(cands)
            print(f"  no bundled algorithm matched. {uniq} distinct "
                  f"values; most common value 0x{top[0][0]:x} appears "
                  f"{most_common_pct*100:.1f}% of the time.")
            if uniq > len(records) * 0.5:
                print(f"    (high-cardinality field — it behaves like a")
                print(f"    checksum even if this probe can't name it.")
                print(f"    Suspect a non-bundled polynomial or an offset")
                print(f"    on the data range. Try --data-range to adjust.)")

    if not any_hit:
        print()
        print("No bundled algorithm matched any standard trailing window.")
        print("Possible next steps:")
        print("  • Try --checksum-offset/--checksum-size at a non-trailing")
        print("    location (some formats put the CRC near the start).")
        print("  • Try --data-range to shrink the data window (the CRC may")
        print("    cover only part of the record — e.g. the payload but")
        print("    not the header).")
        print("  • The algorithm might be custom or a rare CRC variant")
        print("    not in this probe's catalog.")


def report_file_trailer(path, trailer_size, endian="LE"):
    """Check whether the last N bytes of the file are a checksum over
    the preceding bytes."""
    data = Path(path).read_bytes()
    if len(data) <= trailer_size:
        print("file too short for the requested trailer size.")
        return
    payload = data[:-trailer_size]
    trailer = data[-trailer_size:]
    expected = int.from_bytes(trailer,
                              "big" if endian == "BE" else "little")

    print(f"=== crc_probe: {path} (file trailer) ===")
    print(f"file size: {len(data)} bytes; last {trailer_size} bytes "
          f"({endian}) = 0x{expected:0{trailer_size*2}x}")
    target_width = trailer_size * 8
    any_hit = False
    for name, width, fn in ALGORITHMS:
        if width != target_width:
            continue
        if fn(payload) == expected:
            any_hit = True
            print(f"  MATCH  {name}")
    if not any_hit:
        print("  no bundled algorithm matched.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_data_range(arg):
    """Parse 'LO:HI[,LO:HI,...]' into a list of (lo, hi) tuples."""
    ranges = []
    for piece in arg.split(","):
        a, b = piece.split(":")
        ranges.append((int(a), int(b)))
    return ranges


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--record-size", type=int,
                    help="fixed record size in bytes (omit if using "
                         "--file-trailer)")
    ap.add_argument("--checksum-offset", type=int, default=None,
                    help="byte offset of the checksum within each record")
    ap.add_argument("--checksum-size", type=int, default=None,
                    choices=(1, 2, 4),
                    help="checksum size in bytes (1, 2, or 4)")
    ap.add_argument("--checksum-endian", choices=("LE", "BE"), default="LE")
    ap.add_argument("--data-range", type=_parse_data_range, default=None,
                    help="byte ranges (within a record) that the checksum "
                         "covers, as 'LO:HI,LO:HI,...' . Default is "
                         "everything except the checksum window.")
    ap.add_argument("--file-trailer", type=int, default=None,
                    choices=(1, 2, 4),
                    help="treat the last N bytes of the whole file as the "
                         "checksum; probe algorithms over the rest")
    ap.add_argument("--file-trailer-endian", choices=("LE", "BE"),
                    default="LE")
    args = ap.parse_args()

    if not Path(args.file).exists():
        print(f"error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    if args.file_trailer is not None:
        report_file_trailer(args.file, args.file_trailer,
                            args.file_trailer_endian)
        return

    if args.record_size is None:
        print("error: --record-size is required unless --file-trailer is "
              "given", file=sys.stderr)
        sys.exit(2)

    report_record_level(
        args.file,
        record_size=args.record_size,
        ckof=args.checksum_offset,
        cksize=args.checksum_size,
        endian=args.checksum_endian,
        data_ranges=args.data_range,
    )


if __name__ == "__main__":
    main()
