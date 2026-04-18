# Fieldmap schema

The fieldmap is a single JSON file that both `gen_parser.py` and
`gen_docs.py` consume. It is the single source of truth for the
reverse-engineered format. If something belongs in the parser or the
spec, it belongs here.

## Top-level keys

| Key | Required | Description |
|---|---|---|
| `format_name` | yes | Human-readable name, e.g. `"GlobalSat DG-388 .gpl GPS Track Log"` |
| `description` | recommended | One-paragraph summary of what the format is used for |
| `endianness` | yes | `"little"` or `"big"` |
| `structure` | recommended | Currently `"fixed_record"` is the only fully-supported value |
| `record_framing` | default `"fixed"` | `"fixed"`, `"length_prefixed"`, or `"delimited"` — see below |
| `record_size` | yes | For fixed framing: size of every record. For variable-length framing: the minimum size needed to decode all declared fields. Records smaller than this will yield `None` for out-of-range fields. |
| `file_header_size` | default 0 | Bytes to skip at the start of the file before records begin |
| `skip_blank` | optional | Rules for identifying records to skip (see below) |
| `fields` | yes | List of field objects (see below) |
| `key_details` | optional | List of bullet-point notes worth emphasising in the spec doc |
| `validation` | recommended | How the fieldmap was validated (see below) |
| `provenance` | recommended | Free-text explanation of how the format was decoded |

### Length-prefixed framing

When `record_framing` is `"length_prefixed"`, each record begins with a
size field that tells the parser how long it is. The following keys
configure it:

| Key | Required | Description |
|---|---|---|
| `length_field_type` | default `"u16"` | `"u8"`, `"u16"`, or `"u32"` |
| `length_field_endian` | default = `endianness` | `"little"` or `"big"` |
| `length_field_offset` | default 0 | Byte offset of the length field within the record |
| `length_includes_header` | default `true` | Whether the stored length value includes the length field itself |
| `length_additional_offset` | default 0 | Constant added to the stored value to compute the record size (for "length minus one" conventions) |
| `min_record_size` | default `length_field_size + 1` | Sanity lower bound — walks that produce smaller records are rejected |
| `max_record_size` | default 65536 | Sanity upper bound |

### Delimiter framing

When `record_framing` is `"delimited"`, records are separated by a fixed
byte sequence:

| Key | Required | Description |
|---|---|---|
| `delimiter` | yes | Hex string (e.g. `"7E"`) or list of ints (e.g. `[0x7E]`) giving the delimiter bytes |
| `delimiter_position` | default `"trailing"` | `"trailing"` if the delimiter appears at the end of each record (HDLC-style), `"leading"` if it appears at the start |
| `min_record_size` | default 1 | Records shorter than this (usually empty back-to-back delimiters) are discarded |

## Field objects

Each field in `fields` is:

| Key | Required | Description |
|---|---|---|
| `name` | yes | Identifier used as the CSV column and dict key in the parser |
| `offset` | yes | Byte offset within the record |
| `size` | yes | Size in bytes. For bit-packed fields, this is the size of the underlying storage word that holds the bit field, not the field's own bit width. |
| `type` | yes | One of `u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`f32`/`f64`/`bytes`/`utf8`/`pad` |
| `encoding` | optional | See the encoding table below, or a free-form label |
| `scale` | optional | Divide the decoded integer by this. `null` or `1` = no scaling. Typical values: 10, 100, 1000, 10000000. For power-of-two fixed-point (Q-format), either set `scale` to `2**N` or use `bit_scale` below. |
| `bit_scale` | optional | Divide by `2**N` (N is the value). Idiomatic for Q-format: `bit_scale: 16` is Q16.16, `bit_scale: 31` is Q0.31 signed-fractional. Mutually exclusive with `scale`. |
| `unit` | optional | Display unit, e.g. `"°"`, `"m"`, `"km/h"` |
| `bit_offset` | optional | LSB position of the field within its storage word (bit 0 = least significant). Presence of `bit_offset` or `bit_width` marks the field as bit-packed. |
| `bit_width` | optional | Width of the field in bits. Must satisfy `bit_offset + bit_width <= size * 8`. |
| `bit_signed` | default `false` | Interpret the extracted bits as signed two's complement. |
| `notes` | optional | Human-readable context (shows up in the doc) |

### Encoding transforms

The parser applies these transforms after `scale`/`bit_scale` and after bit-field extraction. Unknown encoding strings are passed through as documentation labels — the value is left as-is.

| Encoding | Input type | Output | Notes |
|---|---|---|---|
| `YYYYMMDD` | integer | `"YYYY-MM-DD"` string | e.g. `20231115` → `"2023-11-15"` |
| `HHMMSS` | integer | `"HH:MM:SS"` string | e.g. `143052` → `"14:30:52"` |
| `unix_seconds` | integer | ISO-8601 UTC string | Seconds since 1970-01-01 |
| `unix_millis` | integer | ISO-8601 UTC string with milliseconds | `u32`/`u64` ms since 1970-01-01 |
| `unix_micros` | integer | ISO-8601 UTC string with microseconds | Typically `u64` µs since 1970-01-01 |
| `filetime` | `u64` | ISO-8601 UTC string with microseconds | Windows FILETIME: 100-ns ticks since 1601-01-01 |
| `mac_seconds` | integer | ISO-8601 UTC string | HFS / ISOBMFF time: seconds since 1904-01-01 |
| `gps_seconds` | integer | ISO-8601 UTC string | Raw GPS time: seconds since 1980-01-06. No leap-second correction; GPS time diverges from UTC by ~18 s as of 2025. |
| `dos_datetime` | `u32` | ISO-8601 local string | FAT packed date+time: `yyyyyyym mmmddddd hhhhhmmm mmmsssss` (year+1980, seconds in 2-s steps) |
| `bcd` | integer | integer | Interprets each nibble as a decimal digit 0-9. `u8 0x42` → `42`; `u16 0x1234` → `1234`. Leaves the raw value if any nibble > 9. |
| `bcd_date` | `bytes` | `"YYYY-MM-DD"` string | 3 bytes: `YY MM DD` (assumes 20YY). 4 bytes: `CC YY MM DD`. |
| `bcd_time` | `bytes` | `"HH:MM:SS"` string | 3 bytes: `HH MM SS` |
| `bcd_datetime` | `bytes` | ISO-8601 string | 6 or 7 bytes; see `bcd_date` / `bcd_time` |
| `semicircle` | `i32` | float degrees | Garmin FIT format: `2**31` = 180°. Multiplies by `180/2**31`. |
| `ddmm` | float / integer | float decimal degrees | NMEA DDMM.MMMM; sign is preserved. |
| `degrees`, `meters`, `kmh`, `enum` | — | pass-through label | Documentation only; no value transform |

### Bit-packed fields

Multiple bit-packed fields may share the same `(offset, size, type)`
storage word; the parser unpacks the storage once and extracts each bit
field by shift and mask. A single storage word cannot mix bit-packed
fields with a non-bit-packed field at the same location. Example
packing 4 fields into a single `u16`:

```json
"fields": [
  {"name": "valid",   "offset": 4, "size": 2, "type": "u16", "bit_offset": 0,  "bit_width": 1},
  {"name": "source",  "offset": 4, "size": 2, "type": "u16", "bit_offset": 1,  "bit_width": 2},
  {"name": "quality", "offset": 4, "size": 2, "type": "u16", "bit_offset": 3,  "bit_width": 3},
  {"name": "channel", "offset": 4, "size": 2, "type": "u16", "bit_offset": 6,  "bit_width": 4}
]
```

Fields are rendered in the spec doc in offset order, so you can define
them in any order in the JSON.

For a fully-padded/reserved byte range, use `"type": "pad"` — it will
be included in the parser's struct format but not emitted as a column.

## `skip_blank` rules

The generated parser skips records matching any of these rules:

```json
"skip_blank": {
  "all_zero": true,                 // skip if every decoded field is 0
  "field_zero": ["date_int"]        // skip if any named field is 0
}
```

Both rules are evaluated before any scale/encoding decoding, so values
are still raw integers at check time.

## `validation` object

```json
"validation": {
  "sample_file": "05111426.gpl",
  "records": 7130,
  "verified_fields": ["latitude", "longitude", "altitude_m", "speed_kmh"],
  "notes": "Verified via csv_correlate at 100% match against the PC tool's CSV."
}
```

This feeds into the spec's `## Validation` section. Be honest — if only
some fields were confirmed against a reference and others are
best-guess, list only the confirmed ones in `verified_fields`.

## `provenance` string

Free-text. One-paragraph description of *how* the format was decoded:
which scripts were run, what reference data was used, which fields
required judgement calls. This is what makes the writeup reusable —
the next person (or Claude in a future session) can see exactly what
work has been done and how confident to be in each field.
