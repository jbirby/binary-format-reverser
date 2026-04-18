#!/usr/bin/env python3
"""
gen_docs.py — turn a confirmed fieldmap JSON into a README-style spec.

Produces the same style of format documentation as the DG-388 writeup:
field table with Offset/Size/Type/Encoding columns, followed by notes,
validation summary, and a "how the format was decoded" section if those
metadata fields are populated.

Usage:
    python gen_docs.py fieldmap.json > FORMAT.md
    python gen_docs.py fieldmap.json -o FORMAT.md
"""

import argparse
import json
import sys
from pathlib import Path


TYPE_LABELS = {
    "u8":  "uint8",  "i8":  "int8",
    "u16": "uint16", "i16": "int16",
    "u32": "uint32", "i32": "int32",
    "u64": "uint64", "i64": "int64",
    "f32": "float32","f64": "float64",
    "bytes": "bytes", "utf8": "utf8", "pad": "(padding)",
}


def render_field_table(fields):
    any_bits = any("bit_width" in f for f in fields)
    lines = []
    if any_bits:
        lines.append("| Offset | Size | Bits | Type | Field | Encoding |")
        lines.append("|--------|------|------|------|-------|----------|")
    else:
        lines.append("| Offset | Size | Type | Field | Encoding |")
        lines.append("|--------|------|------|-------|----------|")
    # Sort by byte offset, then by bit_offset for bit-packed fields
    sorted_fields = sorted(
        fields,
        key=lambda x: (x["offset"], x.get("bit_offset", 0)))
    for f in sorted_fields:
        if f.get("type") == "pad":
            continue
        off = f["offset"]
        size = f["size"]
        span = f"{off}" if size == 1 else f"{off}-{off + size - 1}"
        type_label = TYPE_LABELS.get(f["type"], f["type"])
        name = f["name"]
        encoding = f.get("encoding", "")
        scale = f.get("scale")
        unit = f.get("unit", "")
        enc_parts = []
        if encoding:
            enc_parts.append(encoding)
        if scale and scale != 1:
            enc_parts.append(f"value / {scale}")
        if unit:
            enc_parts.append(unit)
        if f.get("bit_signed"):
            enc_parts.append("signed")
        enc_str = "; ".join(enc_parts) if enc_parts else "—"
        if any_bits:
            if "bit_width" in f:
                bo = int(f.get("bit_offset", 0))
                bw = int(f["bit_width"])
                bit_span = f"{bo}" if bw == 1 else f"{bo}-{bo + bw - 1}"
            else:
                bit_span = "all"
            lines.append(f"| {span} | {size} | {bit_span} | {type_label} | "
                         f"{name} | {enc_str} |")
        else:
            lines.append(f"| {span} | {size} | {type_label} | {name} | "
                         f"{enc_str} |")
    return "\n".join(lines)


def render_doc(fm):
    out = []
    out.append(f"# {fm.get('format_name', 'Binary format')}\n")
    if fm.get("description"):
        out.append(fm["description"].strip() + "\n")

    out.append("## Record layout\n")
    endian = "little-endian" if fm.get("endianness", "little") == "little" \
        else "big-endian"
    hdr = fm.get("file_header_size", 0)
    record_size = fm["record_size"]
    framing = fm.get("record_framing", "fixed")

    if framing == "fixed":
        if hdr:
            out.append(f"Each file begins with a {hdr}-byte header, followed "
                       f"by a stream of fixed **{record_size}-byte records**.")
        else:
            out.append(f"Each file is a sequence of fixed "
                       f"**{record_size}-byte records** with no file header.")
    elif framing == "length_prefixed":
        lf_type = fm.get("length_field_type", "u16")
        lf_off = fm.get("length_field_offset", 0)
        lf_endian = fm.get("length_field_endian", fm.get("endianness", "little"))
        incl = fm.get("length_includes_header", True)
        incl_str = ("includes the length field itself" if incl
                    else "excludes the length field itself")
        hdr_prefix = (f"Each file begins with a {hdr}-byte header, followed by "
                      if hdr else "Each file is ")
        out.append(f"{hdr_prefix}a stream of **length-prefixed records** of "
                   f"varying size. Each record starts with a {lf_type} "
                   f"{lf_endian}-endian length field at offset {lf_off} "
                   f"that {incl_str}. The field layout below is positioned "
                   f"relative to the start of each record.")
    elif framing == "delimited":
        delim = fm.get("delimiter", "")
        pos = fm.get("delimiter_position", "trailing")
        hdr_prefix = (f"Each file begins with a {hdr}-byte header, followed by "
                      if hdr else "Each file is ")
        out.append(f"{hdr_prefix}a stream of **delimiter-framed records** of "
                   f"varying size, separated by the {pos} byte sequence "
                   f"`{delim}`.")
    out.append(f"All multi-byte integer fields are **{endian}**.\n")

    out.append(render_field_table(fm["fields"]))
    out.append("")

    if fm.get("key_details"):
        out.append("### Key details\n")
        for note in fm["key_details"]:
            out.append(f"- {note}")
        out.append("")

    if fm.get("validation"):
        v = fm["validation"]
        out.append("## Validation\n")
        if v.get("sample_file"):
            out.append(f"Verified against `{v['sample_file']}`.")
        if v.get("records"):
            out.append(f"- {v['records']} records analyzed")
        if v.get("verified_fields"):
            out.append(f"- Fields confirmed by reference-data correlation: "
                       f"{', '.join(v['verified_fields'])}")
        if v.get("notes"):
            out.append("- " + v["notes"])
        out.append("")

    if fm.get("provenance"):
        out.append("## How the format was decoded\n")
        out.append(fm["provenance"].strip() + "\n")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("fieldmap")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    fm = json.loads(Path(args.fieldmap).read_text())
    doc = render_doc(fm)

    if args.output:
        Path(args.output).write_text(doc)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(doc)


if __name__ == "__main__":
    main()
