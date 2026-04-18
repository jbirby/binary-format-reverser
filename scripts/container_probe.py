#!/usr/bin/env python3
"""
container_probe.py — detect whether a file is a container/chunk format
rather than a fixed-record or variable-length stream of records.

Two-stage analysis:

  1. Magic-byte lookup against a dictionary of ~30 common container,
     archive, image, audio, video, and executable formats. Prints the
     identified format and hints about the right tool for the job.

  2. Generic chunk-walk probe. Tries a handful of TYPE/LEN header
     layouts (e.g. TYPE4+LEN4LE, LEN4BE+TYPE4, TYPE1+LEN1) and reports
     any walk from offset 0 that consumes >=90% of the file with
     plausible chunk sizes and printable-ASCII type codes. Useful for
     undocumented formats that use chunk structure but aren't in the
     magic-byte table.

Neither stage decodes the chunks — this tool is a signpost, not a
parser. If the magic-byte stage fires, stop using binary-format-reverser
and reach for the right library. If only the chunk-walk stage fires,
you're on your own but at least you know the shape.

Usage:
    python container_probe.py <file>
"""

import argparse
import string
import struct
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Magic-byte dictionary.
#
# Each entry is (offset, magic_bytes, format_name, hint). offset=0 for most;
# a few formats (tar, iso) embed their magic deeper in the file.
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = [
    # --- Compressed/archive
    (0, b"\x1f\x8b",                       "gzip",
     "Use Python's gzip module or `gunzip`. The inner file may itself be "
     "a fixed-record format; decompress first, then re-run structure_probe."),
    (0, b"BZh",                            "bzip2",
     "Use Python's bz2 module or `bunzip2`."),
    (0, b"\xfd7zXZ\x00",                   "xz/lzma",
     "Use Python's lzma module or `unxz`."),
    (0, b"7z\xbc\xaf\x27\x1c",             "7z archive",
     "Use the py7zr library or the `7z` CLI."),
    (0, b"Rar!\x1a\x07\x00",               "RAR archive (v1.5)",
     "Use `unrar` or rarfile."),
    (0, b"Rar!\x1a\x07\x01\x00",           "RAR archive (v5)",
     "Use `unrar` or rarfile."),
    (0, b"PK\x03\x04",                     "ZIP archive / JAR / XLSX / DOCX / ODF / EPUB",
     "Use Python's zipfile module. ZIP-based Office and OpenDocument "
     "files also match this."),
    (0, b"PK\x05\x06",                     "empty ZIP archive",
     "Use Python's zipfile module."),
    (0, b"\x75\x73\x74\x61\x72",           "tar archive fragment",
     "This ustar signature normally appears at offset 257; if it's at 0 "
     "the file may be a partial extract."),

    # --- Images
    (0, b"\x89PNG\r\n\x1a\n",              "PNG image",
     "Use Pillow (PIL). Chunk format: LEN(4BE)+TYPE(4)+DATA+CRC(4) after "
     "the 8-byte signature."),
    (0, b"\xff\xd8\xff",                   "JPEG image",
     "Use Pillow. JPEG has a marker-based segment structure (0xFF + type + "
     "length), not a clean chunk walk."),
    (0, b"GIF87a",                         "GIF image (87a)",
     "Use Pillow."),
    (0, b"GIF89a",                         "GIF image (89a)",
     "Use Pillow."),
    (0, b"BM",                             "BMP image (or possibly other 'BM' prefix)",
     "Use Pillow. Watch out for false positives: BMP's signature is "
     "short, so verify the next few bytes look like a BMP DIB header."),
    (0, b"II*\x00",                        "TIFF image (little-endian)",
     "Use Pillow. TIFF uses an IFD (directory) structure, not chunks."),
    (0, b"MM\x00*",                        "TIFF image (big-endian)",
     "Use Pillow."),
    (4, b"ftyp",                           "MP4 / QuickTime / HEIC container",
     "Use pymediainfo, pymp4, or ffprobe. ISOBMFF uses LEN(4BE)+TYPE(4) "
     "box structure."),
    (0, b"\x00\x00\x01\x00",               "Windows ICO icon",
     "Use Pillow."),

    # --- Audio
    (0, b"RIFF",                           "RIFF container (WAV / AVI / WebP / ...)",
     "Check bytes 8-11 for the form type. RIFF uses TYPE(4)+LEN(4LE)+DATA "
     "chunks aligned to even boundaries."),
    (0, b"FORM",                           "IFF / AIFF container",
     "IFF uses TYPE(4)+LEN(4BE)+DATA chunks."),
    (0, b"OggS",                           "Ogg container (Vorbis/Opus/FLAC-Ogg)",
     "Use pyogg or ffmpeg."),
    (0, b"fLaC",                           "FLAC audio",
     "Use mutagen or soundfile."),
    (0, b"ID3",                            "MP3 with ID3 tags",
     "Use mutagen or pydub."),
    (0, b"ADIF",                           "AAC (ADIF)",
     "Use ffmpeg."),
    (0, b"MThd",                           "MIDI file",
     "Use mido."),

    # --- Video
    (0, b"\x1a\x45\xdf\xa3",               "Matroska / WebM (EBML)",
     "Use pymatroska or ffmpeg. EBML uses variable-length integers — "
     "not a simple chunk walk."),
    (0, b"FLV\x01",                        "Flash Video (FLV)",
     "Use pyflv or ffmpeg."),

    # --- Documents
    (0, b"%PDF-",                          "PDF document",
     "Use the `pdf` skill or the pypdf library."),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Compound File Binary (OLE / legacy Office .doc/.xls/.ppt)",
     "Use olefile; for legacy Word specifically, antiword or LibreOffice."),
    (0, b"{\\rtf",                         "RTF document",
     "Plain-ish text — open in any editor."),

    # --- Executables / code
    (0, b"\x7fELF",                        "ELF executable / shared object",
     "Use pyelftools, `readelf`, or `objdump`."),
    (0, b"MZ",                             "DOS/PE executable (.exe, .dll)",
     "Use pefile for Windows PE analysis."),
    (0, b"\xfe\xed\xfa\xce",               "Mach-O 32-bit big-endian",
     "Use macholib or `otool`."),
    (0, b"\xfe\xed\xfa\xcf",               "Mach-O 64-bit big-endian",
     "Use macholib or `otool`."),
    (0, b"\xce\xfa\xed\xfe",               "Mach-O 32-bit little-endian",
     "Use macholib or `otool`."),
    (0, b"\xcf\xfa\xed\xfe",               "Mach-O 64-bit little-endian",
     "Use macholib or `otool`."),
    (0, b"\xca\xfe\xba\xbe",               "Java class file OR Mach-O Universal binary",
     "Disambiguate by file extension and context."),
    (0, b"\xde\xd0\xd0\x0d\xfe\xca\xfe\xca", "Dalvik/Android .dex (varies)",
     "Use androguard."),
    (0, b"dex\n",                          "Dalvik executable (.dex)",
     "Use androguard."),

    # --- Filesystems / disk images
    (0, b"SQLite format 3\x00",            "SQLite database",
     "Use sqlite3 directly — it's already a structured DB."),
    (0, b"ustar",                          "tar archive (POSIX ustar)",
     "Use Python's tarfile module. Normally found at offset 257."),
    (0x8001, b"CD001",                     "ISO 9660 CD/DVD image",
     "Use pycdlib or mount the image."),

    # --- Capture / packet formats
    (0, b"\xd4\xc3\xb2\xa1",               "pcap capture (little-endian)",
     "Use scapy or dpkt."),
    (0, b"\xa1\xb2\xc3\xd4",               "pcap capture (big-endian)",
     "Use scapy or dpkt."),
    (0, b"\n\r\r\n",                       "pcapng capture",
     "Use pyshark or scapy."),

    # --- Misc
    (0, b"Cr24",                           "Chrome extension (CRX)",
     "CRX is a ZIP with a header — strip the header and unzip."),
    (0, b"\x3c\x3f\x78\x6d\x6c",           "XML (<?xml)",
     "Plain text — use any XML parser."),
    (0, b"{",                              "possibly JSON",
     "Might be plain JSON; try parsing with the json module."),
    (0, b"[",                              "possibly JSON array",
     "Might be plain JSON; try parsing with the json module."),
]


def check_magic(data):
    """Return a list of matching (name, hint, offset) for every signature hit."""
    hits = []
    for offset, magic, name, hint in MAGIC_SIGNATURES:
        if offset + len(magic) > len(data):
            continue
        if data[offset:offset + len(magic)] == magic:
            hits.append((name, hint, offset))
    return hits


# ---------------------------------------------------------------------------
# Generic chunk-walk probe.
#
# A chunk header is TYPE + LEN (or LEN + TYPE). We try all combinations of:
#   - TYPE width: 1, 2, 4 bytes
#   - LEN width:  1, 2, 4 bytes
#   - Order:      TYPE-first or LEN-first
#   - Endianness (for multi-byte LEN): LE or BE
#   - LEN includes the header, or covers only the payload
#
# A walk succeeds if every chunk fits, the walk consumes >= WALK_COVERAGE of
# the file, and at least HINT_MIN_CHUNKS chunks were parsed.
# ---------------------------------------------------------------------------

WALK_COVERAGE = 0.90
HINT_MIN_CHUNKS = 4
MAX_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MiB sanity cap

_LEN_FMTS = {
    (1, "LE"): "<B", (1, "BE"): ">B",
    (2, "LE"): "<H", (2, "BE"): ">H",
    (4, "LE"): "<I", (4, "BE"): ">I",
}


def _looks_printable(bytestr):
    """Return True if every byte is printable ASCII."""
    return all(b in b" !\"#$%&'()*+,-./0123456789:;<=>?@"
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    b"[\\]^_`abcdefghijklmnopqrstuvwxyz"
                    b"{|}~\t" for b in bytestr)


def _try_walk(data, start, type_width, len_width, type_first,
              len_endian, len_includes_header):
    """
    Walk the file as a chunk stream. Returns a dict describing the walk
    result: always includes n_chunks and bytes_covered; sets 'ok' if the
    walk completed within WALK_COVERAGE of the file.
    """
    header_size = type_width + len_width
    pos = start
    n = 0
    types = []
    len_fmt = _LEN_FMTS[(len_width, len_endian)]

    while pos < len(data):
        if len(data) - pos < header_size:
            break
        if type_first:
            type_bytes = data[pos:pos + type_width]
            raw_len = struct.unpack_from(len_fmt, data, pos + type_width)[0]
        else:
            raw_len = struct.unpack_from(len_fmt, data, pos)[0]
            type_bytes = data[pos + len_width:pos + len_width + type_width]

        chunk_size = raw_len if len_includes_header else raw_len + header_size
        # Even-alignment for RIFF-like formats: don't special-case, just use
        # the size as-is. If it's too wrong the walk will fail.

        if chunk_size < header_size or chunk_size > MAX_CHUNK_SIZE:
            break
        if pos + chunk_size > len(data):
            break

        types.append(bytes(type_bytes))
        pos += chunk_size
        n += 1

        # Sanity: avoid runaway walks on pathological input.
        if n > len(data):
            break

    coverage = (pos - start) / max(1, len(data) - start)
    type_counts = {}
    for t in types:
        type_counts[t] = type_counts.get(t, 0) + 1

    # Score: how many type codes are printable ASCII? Printable type codes
    # are a strong signal for real chunk formats (RIFF, PNG, IFF).
    printable_types = sum(1 for t in type_counts if _looks_printable(t))
    type_diversity = len(type_counts)

    return {
        "n_chunks": n,
        "bytes_covered": pos - start,
        "coverage": coverage,
        # Require >=1 printable type code: real chunk formats reliably
        # use ASCII tags (PNG IHDR/IDAT/IEND, RIFF fmt /data, IFF FORM),
        # and this filter kills most of the false positives on
        # random-looking fixed-record or padded data.
        "ok": (coverage >= WALK_COVERAGE
               and n >= HINT_MIN_CHUNKS
               and printable_types >= 1),
        "types": sorted(type_counts.items(), key=lambda kv: -kv[1]),
        "type_diversity": type_diversity,
        "printable_types": printable_types,
    }


def hunt_chunks(data, start=0):
    """
    Try every reasonable chunk-header layout and return the walks that
    consumed at least WALK_COVERAGE of the file.
    """
    variants = []
    for type_width in (1, 2, 4):
        for len_width in (1, 2, 4):
            for type_first in (True, False):
                for len_endian in ("LE", "BE"):
                    if len_width == 1 and len_endian == "BE":
                        continue  # endianness meaningless for u8
                    for incl in (True, False):
                        label = (
                            f"{'TYPE' + str(type_width) if type_first else ''}"
                            f"{'+' if type_first else ''}"
                            f"LEN{len_width}{len_endian}"
                            f"{'+TYPE' + str(type_width) if not type_first else ''}"
                            f" {'incl' if incl else 'excl'}"
                        )
                        result = _try_walk(data, start, type_width, len_width,
                                           type_first, len_endian, incl)
                        if result["ok"]:
                            result["label"] = label
                            result["type_width"] = type_width
                            result["len_width"] = len_width
                            result["type_first"] = type_first
                            result["len_endian"] = len_endian
                            result["len_includes_header"] = incl
                            variants.append(result)

    # Rank: prefer higher coverage, then more printable type codes, then
    # more chunks. A walk with 12 chunks and 4 printable types beats one
    # with 200 chunks and 0 printable types — the latter is probably a
    # false positive from data that happens to pass the length checks.
    variants.sort(key=lambda v: (-v["coverage"],
                                 -v["printable_types"],
                                 -v["type_diversity"],
                                 -v["n_chunks"]))
    return variants


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def report(path):
    data = Path(path).read_bytes()
    print(f"=== container_probe: {path} ===")
    print(f"File size: {len(data):,} bytes")

    # --- Magic-byte stage
    print("\n-- Magic-byte signature lookup --")
    hits = check_magic(data)
    if hits:
        for name, hint, offset in hits:
            off_s = f"at offset {offset}" if offset else "at offset 0"
            print(f"  MATCH {off_s}: {name}")
            print(f"         {hint}")
        print()
        print("A magic-byte match means the file is almost certainly a "
              "container")
        print("format, not a fixed-record stream. The binary-format-reverser "
              "toolkit")
        print("is the wrong tool — use the suggested library instead.")
    else:
        print("  No known container magic detected in the first few bytes.")

    # --- Chunk-walk stage
    print("\n-- Generic chunk-walk probe --")
    print(f"Searching for TLV layouts that cover >={WALK_COVERAGE*100:.0f}% "
          f"of the file with >={HINT_MIN_CHUNKS} chunks.")

    # Try walking from offset 0 and from several plausible post-magic offsets.
    starts = [0]
    # If there's a RIFF header, try starting chunks at offset 12.
    if data[:4] == b"RIFF":
        starts.append(12)
    # If there's a PNG magic, try starting chunks at offset 8.
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        starts.append(8)

    any_walk = False
    for start in starts:
        walks = hunt_chunks(data, start=start)
        if not walks:
            continue
        any_walk = True
        print(f"\n  Walks from offset {start} (top 5):")
        print(f"  {'layout':<40}  {'chunks':>6}  {'coverage':>9}  "
              f"{'printable':>9}")
        for v in walks[:5]:
            cov_s = f"{v['coverage']*100:.1f}%"
            print(f"  {v['label']:<40}  {v['n_chunks']:>6}  "
                  f"{cov_s:>9}  {v['printable_types']:>9}")
        # Show type-code samples for the top walk only.
        top = walks[0]
        print(f"  Top walk's chunk types (most-frequent first, up to 10):")
        for t, count in top["types"][:10]:
            if _looks_printable(t):
                printable = t.decode("ascii", errors="replace")
                print(f"    {count:>5}x  {t.hex()}  ({printable!r})")
            else:
                print(f"    {count:>5}x  {t.hex()}")

    if not any_walk:
        print("  No TLV layout covered the file. Either the format is not")
        print("  chunk-based, or it uses a scheme this probe doesn't model")
        print("  (variable-length integers, compressed chunk table, etc.).")
    else:
        print()
        print("A clean chunk walk with printable type codes is a strong")
        print("signal that the file has chunk structure. You probably want")
        print("to parse it chunk-by-chunk rather than as a fixed-record")
        print("stream. This tool does not generate chunk parsers — the walk")
        print("above is reconnaissance only.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("file")
    args = ap.parse_args()

    if not Path(args.file).exists():
        print(f"error: {args.file} not found", file=sys.stderr)
        sys.exit(1)
    report(args.file)


if __name__ == "__main__":
    main()
