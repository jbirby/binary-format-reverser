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
| `record_size` | yes | Size of one record in bytes |
| `file_header_size` | default 0 | Bytes to skip at the start of the file before records begin |
| `skip_blank` | optional | Rules for identifying records to skip (see below) |
| `fields` | yes | List of field objects (see below) |
| `key_details` | optional | List of bullet-point notes worth emphasising in the spec doc |
| `validation` | recommended | How the fieldmap was validated (see below) |
| `provenance` | recommended | Free-text explanation of how the format was decoded |

## Field objects

Each field in `fields` is:

| Key | Required | Description |
|---|---|---|
| `name` | yes | Identifier used as the CSV column and dict key in the parser |
| `offset` | yes | Byte offset within the record |
| `size` | yes | Size in bytes |
| `type` | yes | One of `u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`f32`/`f64`/`bytes`/`utf8`/`pad` |
| `encoding` | optional | `YYYYMMDD`, `HHMMSS`, `unix_seconds`, `degrees`, `meters`, `kmh`, `enum`, or a free-form label |
| `scale` | optional | Divide the decoded integer by this. `null` or `1` = no scaling. Typical values: 10, 100, 1000, 10000000 |
| `unit` | optional | Display unit, e.g. `"°"`, `"m"`, `"km/h"` |
| `notes` | optional | Human-readable context (shows up in the doc) |

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
