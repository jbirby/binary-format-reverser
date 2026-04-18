# binary-format-reverser

A toolkit for reverse-engineering undocumented record-based binary file formats — fixed-record, length-prefixed, or delimiter-framed, with optional bit-packed sub-byte fields. Produces a runnable Python parser and a README-style format specification from any sample file, with or without a reference export of the decoded data.

Built on the observation that most device-log formats (GPS trackers, sensor loggers, telemetry dumps, game saves, dash-cam metadata) share the same shape: a stream of records — often identically sized, sometimes length-prefixed or delimiter-framed — optionally preceded by a small header. Given that shape, a handful of brute-force tricks can surface most of the fields in minutes instead of days.

## When to use this

**Good fit**

- Proprietary `.bin`, `.dat`, `.log`, `.gpl`, etc. from a device whose PC software has a CSV, GPX, JSON, or KML export you can use as a reference.
- Same as above, but no reference export — black-box mode works too, just slower.
- Anything that looks like a stream of small records — fixed-size or variable-length with a length prefix or delimiter byte. Fitness trackers, dive computers, OBD/CAN loggers, weather stations, drone flight logs, lab instruments, old game saves.
- Formats with bit-packed sub-byte fields (flag words, quality/source enums stuffed into a u8 or u16) — bit scanning and bit-mask parsing are supported.

**Poor fit**

- Container formats (PNG, ZIP, WAV, ELF executables) — these have nested headers and chunks this tool doesn't model. `container_probe.py` will detect them so you don't waste time.
- Self-describing schema formats (protobuf, CBOR, MessagePack).
- Compressed or encrypted payloads — the entropy probe will flag them, but the tool can't decode them.
- Text-heavy formats (JSON, XML dressed up as binary).

## Install

```
git clone https://github.com/jbirby/binary-format-reverser.git
cd binary-format-reverser
```

No dependencies beyond the Python 3 standard library. Every script supports `--help`.

## The four-stage workflow

1. **Reconnaissance** — what's the record size and overall shape?
2. **Hypothesis** — what might each byte mean?
3. **Confirmation** — does the hypothesis hold across every record?
4. **Codification** — write a small fieldmap JSON and generate the parser + spec.

Stages map onto scripts; stages 1-3 are iterative, stage 4 is a one-shot.

## Quickstart with a reference CSV

The fast path. You have `mystery.bin` and a CSV of what it's supposed to decode to.

```bash
# 1. Figure out the record size
python scripts/structure_probe.py mystery.bin

# 2. Brute-force find the fields
python scripts/csv_correlate.py mystery.bin --record-size 28 --csv reference.csv

# 3. Write a fieldmap.json describing the layout
#    (see references/dg388_fieldmap.json for a complete example)

# 4. Generate the parser and spec document
python scripts/gen_parser.py fieldmap.json -o parser.py
python scripts/gen_docs.py   fieldmap.json -o FORMAT.md

# 5. Run the parser
python parser.py mystery.bin decoded.csv
```

`csv_correlate` prints one line per field it identified, like:

```
--- Latitude ---
  100.0%  offset=0x08 (8)  i32 LE  scale=1/10000000
```

Translation: bytes 8-11, little-endian signed 32-bit integer, divided by 10 million, matches the `Latitude` column in the reference on 100% of records. Carry those four facts into the fieldmap and move on.

Matches annotated `transform=ddmm` mean the binary stores NMEA-style `DDMM.MMMM` coordinates rather than decimal degrees — the tool handles the conversion in the generated parser. Matches annotated `unordered (values match but row order differs)` mean the same values appear in both files but in different orders — common when the reference tool puts waypoints before trackpoints while the binary interleaves them.

## Quickstart without a reference (black-box)

```bash
python scripts/structure_probe.py mystery.bin
python scripts/field_probe.py mystery.bin --record-size 28 --scan
```

The scan prints every offset with a field-type interpretation that passes a sanity check: `YYYYMMDD`, `HHMMSS`, `unix_ts`, `coord/1e7`, `coord_deg (float)`, `coord_ddmm (float NMEA)`, `altitude_m`, `speed_kmh`, `heading_deg`, `monotonic↑`, `enum(N)`. Each tag is a hint, not a confirmation.

For targeted follow-up on a promising offset:

```bash
python scripts/field_probe.py mystery.bin --record-size 28 --offset 8 --type i32 --endian LE
```

You'll get min/max/mean/stddev across every record, plus the same heuristic tags, so you can eyeball whether the distribution matches what you'd expect (e.g. altitude in 0-9000 m, speed 0-300 km/h, heading 0-360°).

## Scripts

| Script | Purpose |
| --- | --- |
| `scripts/structure_probe.py` | Rank candidate record sizes by column entropy; extract ASCII/UTF-16 strings; report byte-frequency spikes (fill patterns, erased flash, compressed regions); warn if the file is a recognized container format. |
| `scripts/container_probe.py` | Detect whether a file is a container/chunk format (PNG, ZIP, WAV/RIFF, ELF, MP4, SQLite, pcap, ~40 total) rather than a fixed-record stream. Also tries generic TLV chunk walks to flag chunk-structured formats that aren't in the magic-byte table. Signpost only — does not generate chunk parsers. |
| `scripts/multi_file_diff.py` | Compare several sample files of the same format; find magic bytes, constant flags, and varying fields. |
| `scripts/csv_correlate.py` | Brute-force search over (offset × type × endian × scale × transform) against a reference CSV. Includes NMEA `DDMM` transform and sorted-value fallback for out-of-order references. |
| `scripts/field_probe.py` | Black-box hypothesis tester. Targeted mode (one offset, one type) or scan mode (every offset, every type). |
| `scripts/gen_parser.py` | Emit a stdlib-only Python parser from a fieldmap JSON. Handles scale factors, `YYYYMMDD`, `HHMMSS`, `unix_seconds`, `ddmm`, and skip-blank rules. |
| `scripts/gen_docs.py` | Emit a README-style format spec from the same fieldmap JSON. |
| `scripts/crc_probe.py` | Identify the checksum or CRC algorithm protecting each record (or the file as a whole). Bundles ~20 standard algorithms: SUM-8/16/32, XOR-8, two's-complement-8, CRC-8 (four variants), CRC-16 (seven variants including ARC, MODBUS, CCITT, XMODEM, KERMIT), and CRC-32 (Ethernet, Castagnoli, BZIP2, MPEG-2). Reports any algorithm that matches the candidate window on ≥ 90% of records. |

## Fieldmap schema

See `references/fieldmap_schema.md` for the complete schema and `references/dg388_fieldmap.json` for a worked example. In brief:

```json
{
  "format_name": "My Device GPS Log",
  "endianness": "little",
  "record_size": 28,
  "file_header_size": 0,
  "fields": [
    {"name": "latitude", "offset": 8, "size": 4, "type": "i32",
     "encoding": "degrees", "scale": 10000000, "unit": "°"}
  ]
}
```

Supported field types: `u8`, `i8`, `u16`, `i16`, `u32`, `i32`, `u64`, `i64`, `f32`, `f64`, `bytes`, `utf8`, `pad`.

Supported encodings: `YYYYMMDD`, `HHMMSS`, `unix_seconds`, `unix_millis`, `unix_micros`, `filetime`, `mac_seconds`, `gps_seconds`, `dos_datetime`, `bcd`, `bcd_date`, `bcd_time`, `bcd_datetime`, `semicircle`, `ddmm`, `degrees`, `meters`, `kmh`, `enum`, plus free-form labels for documentation.

Q-format fixed-point is supported two ways: `"scale": 65536` (divide by integer) or `"bit_scale": 16` (divide by `2**N`). The two are mutually exclusive. Use `bit_scale` when the binary stores a signed or unsigned Q.N value and you want the documentation to match the Q-format convention.

## Worked example

`references/dg388_fieldmap.json` is the full fieldmap for the GlobalSat DG-388 GPS data logger — a 28-byte fixed-record format carrying date, time, coordinates (i32 × 1e-7 degrees), altitude, speed, heading, and a record-type flag. Reading that fieldmap alongside `references/fieldmap_schema.md` is the fastest way to understand what the tool expects you to produce.

## Common traps

- **Picking a multiple of the real record size.** `structure_probe` ranks candidates by column entropy, and multiples of the true record size score equally well. Prefer the smallest strongly-scored size.
- **Trusting a 100% match on a constant column.** Any byte interpretation matches `[34.400, 34.400, 34.400, ...]`. Always verify against columns with real variance.
- **Pre-allocated blank records.** Many devices pre-format N records and fill them in as they log. Use `--skip-zero-records` or add a `skip_blank` rule to the fieldmap.
- **Reference data reordered or filtered.** PC tools often sort by timestamp or drop invalid records. The `unordered` fallback catches the sorting case automatically; the filtering case requires manual alignment.
- **Packed fields within what looks like a wider field.** A `uint32` that decodes to huge meaningless numbers is often two `uint16`s packed back to back. `field_probe --scan` will flag the narrow interpretations separately.

## Scope and limitations

This tool handles fixed-record and variable-length binary formats, with optional bit-packed fields inside any storage word. The variable-length support covers two framings: length-prefixed (each record starts with a size field) and delimiter-framed (records separated by a fixed byte sequence). It does not *parse* container/chunk formats (PNG, WAV, ZIP, ELF, MP4, SQLite, pcap, etc.), but `container_probe.py` will *detect* them via magic bytes and generic chunk-walk probing so you don't waste time pointing the wrong tool at them. Compressed or encrypted payloads are out of scope; the entropy probe in `structure_probe` will correctly flag regions that look compressed or encrypted but cannot decode them. Text-mixed formats are also out of scope.

Checksum and CRC fields look like random bytes to the probes that rank record-size candidates or scan for typed fields, so they'll initially be reported as unknown. Once you suspect a trailing field might be a checksum, `crc_probe.py` can identify the algorithm against a catalog of ~20 standard checksums and CRCs.

## Variable-length records

`structure_probe` probes for both framings in addition to fixed records. For length-prefixed files it tries `u8`/`u16`/`u32` length fields at common offsets in both endiannesses and both include-header conventions; any walk that consumes the entire file with plausible record sizes is reported. For delimiter-framed files it ranks candidate delimiter bytes by how regular their spacing is. When you set `record_framing: "length_prefixed"` or `"delimited"` in the fieldmap, `gen_parser.py` emits a parse loop that walks the file accordingly. Each decoded record gains a `_record_size` column so you can see how sizes vary.

## Bit-packed fields

Any numeric field can carry `bit_offset` and `bit_width` keys to indicate it occupies a slice of a larger storage word. Multiple bit-packed fields may share the same `(offset, size, type)`; the parser unpacks the storage word once and extracts each field with a shift+mask. Add `"bit_signed": true` to get two's-complement interpretation. `field_probe.py --bits --offset N --storage u16` sweeps every `(bit_offset, bit_width)` combination within a storage word and ranks candidates by whether they look like a flag, enum, or counter — useful when you suspect bit-packing but don't know the layout yet.

## Contributing

Extensions that would broaden the tool's reach:

- CRC/checksum auto-detection.
- Parser generators for languages other than Python.

## License

Licensed under the MIT License. See [`LICENSE`](LICENSE) for details.
