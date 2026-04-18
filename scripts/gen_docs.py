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
    lines = []
    lines.append("| Offset | Size | Type | Field | Encoding |")
    lines.append("|--------|------|------|-------|----------|")
    for f in sorted(fields, key=lambda x: x["offset"]):
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
        enc_str = "; ".join(enc_parts) if enc_parts else "—"
        lines.append(f"| {span} | {size} | {type_label} | {name} | {enc_str} |")
    return "\n".join(lines)


def render_doc(fm):
    out = []
    out.append(f"# {fm.get('format_name', 'Binary format')}\n")
    if fm.get("description"):
        out.append(fm["description"].strip() + "\n")

    out.append("## Record layout\n")
    structure = fm.get("structure", "fixed_record")
    endian = "little-endian" if fm.get("endianness", "little") == "little" \
        else "big-endian"
    hdr = fm.get("file_header_size", 0)
    record_size = fm["record_size"]
    if hdr:
        out.append(f"Each file begins with a {hdr}-byte header, followed "
                   f"by a stream of fixed **{record_size}-byte records**.")
    else:
        out.append(f"Each file is a sequence of fixed **{record_size}-byte "
                   f"records** with no file header.")
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
