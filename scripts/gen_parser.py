#!/usr/bin/env python3
"""
gen_parser.py — turn a confirmed fieldmap JSON into a runnable Python parser.

Once you've confirmed the record layout (via csv_correlate and/or
field_probe) you codify it as a small JSON fieldmap (see
references/fieldmap_schema.md for the format and references/
dg388_fieldmap.json for a complete example). This tool emits a single-file
Python parser that:

    * reads the binary file
    * unpacks each record with struct
    * applies any scale factors and decodes dates/times
    * skips blank/invalid records per the rules in the fieldmap
    * emits CSV on stdout (or to a file)
    * has no third-party dependencies

Usage:
    python gen_parser.py fieldmap.json > parser.py
    python gen_parser.py fieldmap.json -o parser.py
"""

import argparse
import json
import sys
from pathlib import Path


# struct format characters for each fieldmap type
STRUCT_CHAR = {
    "u8":  "B", "i8":  "b",
    "u16": "H", "i16": "h",
    "u32": "I", "i32": "i",
    "u64": "Q", "i64": "q",
    "f32": "f", "f64": "d",
}


def build_record_struct(fields, endianness, record_size):
    """
    Build a struct format string that covers the whole record. Handles gaps
    (reserved bytes) by padding with 'x' bytes.

    Bit-packed fields (those with `bit_width`) share a storage slot. All
    bit-packed fields at the same (offset, size, type) are lifted into a
    single synthetic "__bitstore_<offset>" unpack target; each one is then
    extracted with a shift+mask in the decode block.

    Returns:
      (struct_fmt, storage_names, output_fields, bit_extractions)

    - struct_fmt: full struct format string
    - storage_names: names used for zip() with the unpacked tuple (includes
      synthetic __bitstore_ entries for bit-packed storage slots)
    - output_fields: list of field dicts that become CSV columns (includes
      bit-packed fields, excludes synthetic storage slots)
    - bit_extractions: list of dicts describing each bit-field extraction
    """
    prefix = "<" if endianness == "little" else ">"
    pieces = []
    cursor = 0
    storage_names = []
    output_fields = []
    bit_extractions = []

    # Group fields by storage slot (offset, size, type). Pad slots have no
    # grouping since they never have bit_width.
    groups = {}
    for f in fields:
        if f["type"] == "pad":
            key = ("pad", f["offset"], f["size"])
        else:
            key = (f["offset"], f["size"], f["type"])
        groups.setdefault(key, []).append(f)

    ordered_keys = sorted(groups.keys(), key=lambda k: k[1] if k[0] == "pad" else k[0])

    for key in ordered_keys:
        group = groups[key]
        if key[0] == "pad":
            offset = key[1]
            size = key[2]
        else:
            offset, size, typ = key

        if offset > cursor:
            pieces.append(f"{offset - cursor}x")
            cursor = offset
        elif offset < cursor:
            raise ValueError(
                f"field at offset {offset} overlaps earlier field "
                f"(cursor at {cursor})")

        if key[0] == "pad":
            pieces.append(f"{size}x")
            cursor += size
            continue

        any_bits = any("bit_width" in f for f in group)
        if any_bits:
            if not all("bit_width" in f for f in group):
                raise ValueError(
                    f"at offset {offset}: cannot mix bit-packed and "
                    f"whole-storage fields at the same location")
            if typ not in STRUCT_CHAR or typ.startswith("f"):
                raise ValueError(
                    f"bit-packed fields need an integer storage type, "
                    f"got {typ}")
            storage_name = f"__bitstore_{offset}"
            pieces.append(STRUCT_CHAR[typ])
            storage_names.append(storage_name)
            storage_bits = size * 8
            for f in group:
                bw = int(f["bit_width"])
                bo = int(f.get("bit_offset", 0))
                if bw < 1 or bo < 0 or bo + bw > storage_bits:
                    raise ValueError(
                        f"field {f['name']}: bit_offset={bo}, "
                        f"bit_width={bw} doesn't fit in {storage_bits}-bit "
                        f"storage")
                output_fields.append(f)
                bit_extractions.append({
                    "output": f["name"],
                    "storage": storage_name,
                    "bit_offset": bo,
                    "bit_width": bw,
                    "signed": bool(f.get("bit_signed", False)),
                })
            cursor += size
            continue

        # Normal whole-storage field
        if len(group) != 1:
            raise ValueError(
                f"multiple non-bit-packed fields at offset {offset}")
        f = group[0]
        if typ == "bytes" or typ == "utf8":
            pieces.append(f"{size}s")
        elif typ in STRUCT_CHAR:
            pieces.append(STRUCT_CHAR[typ])
        else:
            raise ValueError(f"unknown type {typ}")
        storage_names.append(f["name"])
        output_fields.append(f)
        cursor += size

    if cursor < record_size:
        pieces.append(f"{record_size - cursor}x")

    return prefix + "".join(pieces), storage_names, output_fields, bit_extractions


FIXED_PARSER_TEMPLATE = '''#!/usr/bin/env python3
"""
Auto-generated parser for {format_name}.

{description}

Generated by binary-format-reverser / gen_parser.py from a confirmed
fieldmap. Safe to edit; re-generating will overwrite your edits, so copy
to a new filename first if you customize it.
"""

import csv
import struct
import sys
from pathlib import Path

RECORD_SIZE = {record_size}
RECORD_STRUCT = {record_struct!r}
FILE_HEADER_SIZE = {file_header_size}

STORAGE_NAMES = {storage_names!r}
FIELD_NAMES = {field_names!r}


def parse_file(path):
    """Yield one dict per valid record."""
    data = Path(path).read_bytes()
    if FILE_HEADER_SIZE:
        data = data[FILE_HEADER_SIZE:]

    if len(data) % RECORD_SIZE:
        remainder = len(data) % RECORD_SIZE
        print(f"Warning: trailing {{remainder}} bytes beyond last "
              f"complete record", file=sys.stderr)

    n = len(data) // RECORD_SIZE
    for i in range(n):
        base = i * RECORD_SIZE
        raw = struct.unpack_from(RECORD_STRUCT, data, base)
        values = dict(zip(STORAGE_NAMES, raw))
{bit_block}
{skip_block}
{decode_block}
        yield values


def main():
    if len(sys.argv) < 2:
        print(f"usage: {{sys.argv[0]}} <input.bin> [output.csv]",
              file=sys.stderr)
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 \\
        else Path(in_path).with_suffix(".csv")

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(FIELD_NAMES)
        for rec in parse_file(in_path):
            w.writerow([rec.get(k) for k in FIELD_NAMES])
    print(f"wrote {{out_path}}")


if __name__ == "__main__":
    main()
'''


LENGTH_PREFIXED_PARSER_TEMPLATE = '''#!/usr/bin/env python3
"""
Auto-generated parser for {format_name}.

{description}

Length-prefixed record framing: each record carries its own size in a
dedicated length field. Record sizes vary from record to record.

Generated by binary-format-reverser / gen_parser.py from a confirmed
fieldmap. Safe to edit; re-generating will overwrite your edits, so copy
to a new filename first if you customize it.
"""

import csv
import struct
import sys
from pathlib import Path

FILE_HEADER_SIZE = {file_header_size}

LENGTH_FIELD_OFFSET = {length_field_offset}
LENGTH_FIELD_STRUCT = {length_field_struct!r}
LENGTH_FIELD_SIZE = {length_field_size}
LENGTH_INCLUDES_HEADER = {length_includes_header}
LENGTH_ADDITIONAL_OFFSET = {length_additional_offset}
MIN_RECORD_SIZE = {min_record_size}
MAX_RECORD_SIZE = {max_record_size}

RECORD_STRUCT = {record_struct!r}
RECORD_DECLARED_SIZE = {record_size}

STORAGE_NAMES = {storage_names!r}
FIELD_NAMES = {field_names!r}


def _read_length(data, pos):
    raw = struct.unpack_from(
        LENGTH_FIELD_STRUCT, data, pos + LENGTH_FIELD_OFFSET)[0]
    size = raw + LENGTH_ADDITIONAL_OFFSET
    if not LENGTH_INCLUDES_HEADER:
        size += LENGTH_FIELD_OFFSET + LENGTH_FIELD_SIZE
    return size


def parse_file(path):
    """Yield one dict per variable-sized record."""
    data = Path(path).read_bytes()
    if FILE_HEADER_SIZE:
        data = data[FILE_HEADER_SIZE:]

    pos = 0
    while pos < len(data):
        if len(data) - pos < LENGTH_FIELD_OFFSET + LENGTH_FIELD_SIZE:
            print(f"Warning: {{len(data) - pos}} trailing bytes too short "
                  f"for a length field", file=sys.stderr)
            break
        rec_size = _read_length(data, pos)
        if rec_size < MIN_RECORD_SIZE or rec_size > MAX_RECORD_SIZE:
            print(f"Warning: record at offset {{pos}} has implausible "
                  f"size {{rec_size}} — stopping", file=sys.stderr)
            break
        if pos + rec_size > len(data):
            print(f"Warning: record at offset {{pos}} claims size "
                  f"{{rec_size}} but only {{len(data) - pos}} bytes "
                  f"remain — stopping", file=sys.stderr)
            break

        # Parse declared fields. Fields beyond the record's actual size
        # are reported as None.
        if rec_size >= RECORD_DECLARED_SIZE:
            raw = struct.unpack_from(RECORD_STRUCT, data, pos)
            values = dict(zip(STORAGE_NAMES, raw))
        else:
            values = dict.fromkeys(STORAGE_NAMES, None)
        values["_record_size"] = rec_size
{bit_block}
{skip_block}
{decode_block}
        yield values
        pos += rec_size


def main():
    if len(sys.argv) < 2:
        print(f"usage: {{sys.argv[0]}} <input.bin> [output.csv]",
              file=sys.stderr)
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 \\
        else Path(in_path).with_suffix(".csv")

    columns = FIELD_NAMES + ["_record_size"]
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for rec in parse_file(in_path):
            w.writerow([rec.get(k) for k in columns])
    print(f"wrote {{out_path}}")


if __name__ == "__main__":
    main()
'''


DELIMITED_PARSER_TEMPLATE = '''#!/usr/bin/env python3
"""
Auto-generated parser for {format_name}.

{description}

Delimiter-framed record framing: records are separated by a fixed byte
sequence. Record sizes vary.

Generated by binary-format-reverser / gen_parser.py from a confirmed
fieldmap. Safe to edit; re-generating will overwrite your edits, so copy
to a new filename first if you customize it.
"""

import csv
import struct
import sys
from pathlib import Path

FILE_HEADER_SIZE = {file_header_size}

DELIMITER = {delimiter!r}
DELIMITER_POSITION = {delimiter_position!r}  # "leading" or "trailing"
MIN_RECORD_SIZE = {min_record_size}

RECORD_STRUCT = {record_struct!r}
RECORD_DECLARED_SIZE = {record_size}

STORAGE_NAMES = {storage_names!r}
FIELD_NAMES = {field_names!r}


def _split_records(data):
    """Yield (offset, bytes) for each record."""
    if DELIMITER_POSITION == "leading":
        # Each record begins with DELIMITER.
        idx = 0 if data.startswith(DELIMITER) else data.find(DELIMITER)
        if idx < 0:
            return
        cursor = idx
        while cursor < len(data):
            nxt = data.find(DELIMITER, cursor + len(DELIMITER))
            end = nxt if nxt >= 0 else len(data)
            yield cursor, data[cursor + len(DELIMITER):end]
            if nxt < 0:
                break
            cursor = nxt
    else:  # trailing
        cursor = 0
        while cursor < len(data):
            nxt = data.find(DELIMITER, cursor)
            if nxt < 0:
                if cursor < len(data):
                    yield cursor, data[cursor:]
                break
            yield cursor, data[cursor:nxt]
            cursor = nxt + len(DELIMITER)


def parse_file(path):
    """Yield one dict per delimiter-framed record."""
    data = Path(path).read_bytes()
    if FILE_HEADER_SIZE:
        data = data[FILE_HEADER_SIZE:]

    for offset, rec_bytes in _split_records(data):
        rec_size = len(rec_bytes)
        if rec_size < MIN_RECORD_SIZE:
            continue

        if rec_size >= RECORD_DECLARED_SIZE:
            raw = struct.unpack_from(RECORD_STRUCT, rec_bytes, 0)
            values = dict(zip(STORAGE_NAMES, raw))
        else:
            values = dict.fromkeys(STORAGE_NAMES, None)
        values["_record_size"] = rec_size
{bit_block}
{skip_block}
{decode_block}
        yield values


def main():
    if len(sys.argv) < 2:
        print(f"usage: {{sys.argv[0]}} <input.bin> [output.csv]",
              file=sys.stderr)
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 \\
        else Path(in_path).with_suffix(".csv")

    columns = FIELD_NAMES + ["_record_size"]
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for rec in parse_file(in_path):
            w.writerow([rec.get(k) for k in columns])
    print(f"wrote {{out_path}}")


if __name__ == "__main__":
    main()
'''


def build_skip_block(fieldmap):
    """Generate skip-record-if-blank code from the fieldmap's validation rules."""
    rules = fieldmap.get("skip_blank", {})
    if not rules:
        return ""

    lines = []
    if rules.get("all_zero"):
        # Read raw bytes and check all-zero
        lines.append('        if all(v == 0 or v == b"\\x00" '
                     '* (len(v) if isinstance(v, bytes) else 0) '
                     'for v in values.values()):')
        lines.append('            continue')
    if "field_zero" in rules:
        for fname in rules["field_zero"]:
            lines.append(f'        if values.get({fname!r}) == 0:')
            lines.append('            continue')
    return "\n".join(lines)


def build_bit_block(bit_extractions, storage_names, output_names):
    """Generate bit-field extraction + storage-cleanup code.

    Runs after struct.unpack but before skip_blank checks and encoding
    decodes, so skip_blank rules can reference bit-packed field names.
    """
    if not bit_extractions:
        return "        pass"

    lines = []
    for bx in bit_extractions:
        mask = (1 << bx["bit_width"]) - 1
        lines.append(f'        _raw = values[{bx["storage"]!r}]')
        lines.append(f'        _val = (_raw >> {bx["bit_offset"]}) & 0x{mask:x}')
        if bx["signed"] and bx["bit_width"] > 1:
            sign_bit = 1 << (bx["bit_width"] - 1)
            lines.append(f'        if _val & 0x{sign_bit:x}:')
            lines.append(f'            _val -= 0x{mask + 1:x}')
        lines.append(f'        values[{bx["output"]!r}] = _val')

    # Remove any synthetic storage slots that aren't exported columns.
    storage_to_drop = [s for s in storage_names
                       if s.startswith("__bitstore_") and s not in output_names]
    for s in storage_to_drop:
        lines.append(f'        values.pop({s!r}, None)')

    return "\n".join(lines)


def build_decode_block(fields):
    """Generate post-processing: scale factors, date/time decoding, etc."""
    lines = []
    need_datetime = False
    for f in fields:
        name = f["name"]
        encoding = f.get("encoding")
        scale = f.get("scale")
        bit_scale = f.get("bit_scale")
        if scale and bit_scale:
            raise ValueError(
                f"field {name}: set either scale or bit_scale, not both")
        if scale and scale != 1:
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            values[{name!r}] = '
                         f'values[{name!r}] / {scale}')
        if bit_scale:
            # Q-format fixed-point: divide by 2**bit_scale. Typical values:
            # 8 (Q24.8), 16 (Q16.16), 31 (Q0.31 signed fractional).
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            values[{name!r}] = '
                         f'values[{name!r}] / float(1 << {int(bit_scale)})')
        if encoding == "YYYYMMDD":
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            v = int(values[{name!r}])')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{v//10000:04d}}-{{(v//100)%100:02d}}-{{v%100:02d}}"')
        elif encoding == "HHMMSS":
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            v = int(values[{name!r}])')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{v//10000:02d}}:{{(v//100)%100:02d}}:{{v%100:02d}}"')
        elif encoding == "unix_seconds":
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            values[{name!r}] = '
                         f'datetime.datetime.utcfromtimestamp('
                         f'values[{name!r}]).isoformat() + "Z"')
        elif encoding == "unix_millis":
            # Integer milliseconds since 1970-01-01 UTC.
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _s, _ms = divmod(int(values[{name!r}]), 1000)')
            lines.append(f'            _d = datetime.datetime.utcfromtimestamp(_s)')
            lines.append(f'            values[{name!r}] = '
                         f'_d.isoformat() + f".{{_ms:03d}}Z"')
        elif encoding == "unix_micros":
            # Integer microseconds since 1970-01-01 UTC.
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _s, _us = divmod(int(values[{name!r}]), 1000000)')
            lines.append(f'            _d = datetime.datetime.utcfromtimestamp(_s)')
            lines.append(f'            values[{name!r}] = '
                         f'_d.isoformat() + f".{{_us:06d}}Z"')
        elif encoding == "filetime":
            # Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
            # Delta to Unix epoch in seconds: 11644473600.
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _ticks = int(values[{name!r}])')
            lines.append(f'            _us = _ticks // 10 - 11644473600000000')
            lines.append(f'            _s, _mod = divmod(_us, 1000000)')
            lines.append(f'            _d = datetime.datetime.utcfromtimestamp(_s)')
            lines.append(f'            values[{name!r}] = '
                         f'_d.isoformat() + f".{{_mod:06d}}Z"')
        elif encoding == "mac_seconds":
            # HFS / ISOBMFF: seconds since 1904-01-01 UTC.
            # Delta to Unix epoch: 2082844800.
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _s = int(values[{name!r}]) - 2082844800')
            lines.append(f'            values[{name!r}] = '
                         f'datetime.datetime.utcfromtimestamp(_s).isoformat() + "Z"')
        elif encoding == "gps_seconds":
            # Raw GPS time: seconds since 1980-01-06 UTC.
            # No leap-second correction; GPS time diverges from UTC by ~18s
            # as of 2025. Delta from Unix to GPS epoch: 315964800.
            need_datetime = True
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _s = int(values[{name!r}]) + 315964800')
            lines.append(f'            values[{name!r}] = '
                         f'datetime.datetime.utcfromtimestamp(_s).isoformat() + "Z"')
        elif encoding == "dos_datetime":
            # FAT/DOS packed 32-bit date+time:
            #   bits  0- 4: second/2   (0-29, step 2s)
            #   bits  5-10: minute     (0-59)
            #   bits 11-15: hour       (0-23)
            #   bits 16-20: day        (1-31)
            #   bits 21-24: month      (1-12)
            #   bits 25-31: year - 1980
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _v = int(values[{name!r}])')
            lines.append(f'            _sec  = (_v >>  0) & 0x1f')
            lines.append(f'            _min  = (_v >>  5) & 0x3f')
            lines.append(f'            _hour = (_v >> 11) & 0x1f')
            lines.append(f'            _day  = (_v >> 16) & 0x1f')
            lines.append(f'            _mon  = (_v >> 21) & 0x0f')
            lines.append(f'            _yr   = ((_v >> 25) & 0x7f) + 1980')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{_yr:04d}}-{{_mon:02d}}-{{_day:02d}}T'
                         f'{{_hour:02d}}:{{_min:02d}}:{{_sec*2:02d}}"')
        elif encoding == "bcd":
            # Binary-coded decimal on an integer field: each nibble is a
            # decimal digit 0-9. A u8 0x42 -> 42; a u16 0x1234 -> 1234.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _raw = int(values[{name!r}])')
            lines.append(f'            _hex = f"{{_raw:x}}"')
            lines.append(f'            values[{name!r}] = '
                         f'int(_hex) if all(c <= "9" for c in _hex) else _raw')
        elif encoding == "bcd_date":
            # BCD date on a bytes field. 3 bytes = YY MM DD (20YY assumed).
            # 4 bytes = CC YY MM DD.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _b = values[{name!r}]')
            lines.append(f'            _d = [(x >> 4) * 10 + (x & 0xf) for x in _b]')
            lines.append(f'            if len(_d) == 3:')
            lines.append(f'                _yr, _mo, _dy = 2000 + _d[0], _d[1], _d[2]')
            lines.append(f'            elif len(_d) == 4:')
            lines.append(f'                _yr, _mo, _dy = _d[0] * 100 + _d[1], _d[2], _d[3]')
            lines.append(f'            else:')
            lines.append(f'                _yr = _mo = _dy = 0')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{_yr:04d}}-{{_mo:02d}}-{{_dy:02d}}"')
        elif encoding == "bcd_time":
            # BCD time on a bytes field. 3 bytes = HH MM SS.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _b = values[{name!r}]')
            lines.append(f'            _d = [(x >> 4) * 10 + (x & 0xf) for x in _b]')
            lines.append(f'            _h, _m, _s = (_d + [0, 0, 0])[:3]')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{_h:02d}}:{{_m:02d}}:{{_s:02d}}"')
        elif encoding == "bcd_datetime":
            # BCD datetime on a bytes field. 6 bytes = YY MM DD HH MM SS.
            # 7 bytes = CC YY MM DD HH MM SS.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _b = values[{name!r}]')
            lines.append(f'            _d = [(x >> 4) * 10 + (x & 0xf) for x in _b]')
            lines.append(f'            if len(_d) == 6:')
            lines.append(f'                _yr = 2000 + _d[0]; _off = 1')
            lines.append(f'            elif len(_d) == 7:')
            lines.append(f'                _yr = _d[0] * 100 + _d[1]; _off = 2')
            lines.append(f'            else:')
            lines.append(f'                _yr, _off = 0, 0')
            lines.append(f'            _mo = _d[_off] if _off < len(_d) else 0')
            lines.append(f'            _dy = _d[_off+1] if _off+1 < len(_d) else 0')
            lines.append(f'            _h  = _d[_off+2] if _off+2 < len(_d) else 0')
            lines.append(f'            _mi = _d[_off+3] if _off+3 < len(_d) else 0')
            lines.append(f'            _s  = _d[_off+4] if _off+4 < len(_d) else 0')
            lines.append(f'            values[{name!r}] = '
                         f'f"{{_yr:04d}}-{{_mo:02d}}-{{_dy:02d}}T'
                         f'{{_h:02d}}:{{_mi:02d}}:{{_s:02d}}"')
        elif encoding == "semicircle":
            # Garmin semicircle: signed 32-bit value where 2^31 = 180 deg.
            # 180.0 / 2^31 = 8.381903171539307e-08 degrees per semicircle.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            values[{name!r}] = '
                         f'values[{name!r}] * (180.0 / (1 << 31))')
        elif encoding == "ddmm":
            # NMEA DDMM.MMMM -> decimal degrees. Preserves sign for
            # southern/western hemispheres.
            lines.append(f'        if values[{name!r}] is not None:')
            lines.append(f'            _v = values[{name!r}]')
            lines.append(f'            _sign = -1.0 if _v < 0 else 1.0')
            lines.append(f'            _v = abs(_v)')
            lines.append(f'            _deg = int(_v / 100)')
            lines.append(f'            values[{name!r}] = '
                         f'_sign * (_deg + (_v - _deg * 100) / 60.0)')

    if need_datetime:
        lines.insert(0, "        import datetime")
    return "\n".join(lines) if lines else "        pass"


LENGTH_FIELD_STRUCT_CHAR = {
    ("u8",  "little"): "<B", ("u8",  "big"): ">B",
    ("u16", "little"): "<H", ("u16", "big"): ">H",
    ("u32", "little"): "<I", ("u32", "big"): ">I",
}

LENGTH_FIELD_BYTE_SIZE = {"u8": 1, "u16": 2, "u32": 4}


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("fieldmap", help="JSON fieldmap file")
    ap.add_argument("-o", "--output", help="where to write parser.py")
    args = ap.parse_args()

    fm = json.loads(Path(args.fieldmap).read_text())
    endianness = fm.get("endianness", "little")
    record_size = fm["record_size"]

    struct_fmt, storage_names, value_fields, bit_extractions = \
        build_record_struct(fm["fields"], endianness, record_size)
    field_names = [f["name"] for f in value_fields]

    common_kwargs = dict(
        format_name=fm.get("format_name", "unknown"),
        description=fm.get("description", "").replace('"""', "'''"),
        record_size=record_size,
        record_struct=struct_fmt,
        file_header_size=fm.get("file_header_size", 0),
        storage_names=storage_names,
        field_names=field_names,
        bit_block=build_bit_block(bit_extractions, storage_names, field_names),
        skip_block=build_skip_block(fm),
        decode_block=build_decode_block(value_fields),
    )

    framing = fm.get("record_framing", "fixed")

    if framing == "fixed":
        code = FIXED_PARSER_TEMPLATE.format(**common_kwargs)
    elif framing == "length_prefixed":
        length_type = fm.get("length_field_type", "u16")
        length_endian = fm.get("length_field_endian", endianness)
        if (length_type, length_endian) not in LENGTH_FIELD_STRUCT_CHAR:
            raise ValueError(
                f"unsupported length_field_type/endian: "
                f"{length_type}/{length_endian}")
        length_struct = LENGTH_FIELD_STRUCT_CHAR[(length_type, length_endian)]
        length_size = LENGTH_FIELD_BYTE_SIZE[length_type]
        code = LENGTH_PREFIXED_PARSER_TEMPLATE.format(
            length_field_offset=fm.get("length_field_offset", 0),
            length_field_struct=length_struct,
            length_field_size=length_size,
            length_includes_header=bool(fm.get("length_includes_header", True)),
            length_additional_offset=fm.get("length_additional_offset", 0),
            min_record_size=fm.get("min_record_size", length_size + 1),
            max_record_size=fm.get("max_record_size", 65536),
            **common_kwargs,
        )
    elif framing == "delimited":
        delim = fm.get("delimiter")
        if delim is None:
            raise ValueError(
                "record_framing='delimited' requires 'delimiter' (hex string "
                "or list of ints)")
        if isinstance(delim, str):
            delim_bytes = bytes.fromhex(delim.replace(" ", ""))
        else:
            delim_bytes = bytes(delim)
        code = DELIMITED_PARSER_TEMPLATE.format(
            delimiter=delim_bytes,
            delimiter_position=fm.get("delimiter_position", "trailing"),
            min_record_size=fm.get("min_record_size", 1),
            **common_kwargs,
        )
    else:
        raise ValueError(f"unknown record_framing: {framing}")

    if args.output:
        Path(args.output).write_text(code)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(code)


if __name__ == "__main__":
    main()
