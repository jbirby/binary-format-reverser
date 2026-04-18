---
name: binary-format-reverser
description: >
  Reverse-engineer an unknown or undocumented binary file format and produce
  both a runnable parser and a README-style specification document. Use this
  skill whenever the user has a proprietary binary file (`.bin`, `.dat`,
  custom extensions like `.gpl`, `.rec`, `.log`, sensor-dumps, device data
  logs, firmware output, game-save files, telemetry traces) and wants to
  decode the byte layout. Also use when the user mentions "reverse engineer
  a file format", "figure out what these bytes mean", "parse this
  undocumented format", "decode a binary dump", or is staring at a hex dump
  trying to identify record boundaries and field types. Works in two modes:
  reference-driven (user has a known-good CSV/JSON export of the same data
  to correlate against — the fastest path) or black-box (no reference data,
  relies on entropy, repetition, and hypothesis-driven probing). Even if the
  user just says "I have this weird binary file from my device", this skill
  is almost certainly what they need.
---

# Binary Format Reverser

A skill for decoding proprietary binary file formats and producing the two
artifacts that make the work reusable: a standalone Python parser and a
README-style specification document. The skill codifies the workflow used
to reverse-engineer the GlobalSat DG-388 `.gpl` format (see the
`references/dg388_fieldmap.json` worked example).

## Core idea

Reverse-engineering a binary format is four successive narrowings:

1. **Reconnaissance** — what is the overall shape? (record-based vs.
   header+blocks, record size, endianness, packed vs. aligned)
2. **Hypothesis** — for each region of the record, what type/encoding
   would produce plausible values?
3. **Confirmation** — does the hypothesis hold across all records, and
   (where available) against a reference export?
4. **Codification** — write the parser and the spec.

The bundled scripts automate the fiddly parts of each step so the human
contribution is pattern-spotting and judgement, not `struct.unpack`
bookkeeping.

## The scripts

All scripts live in `scripts/` and have `--help`. They depend only on the
Python 3 standard library.

### Stage 1 — reconnaissance (no reference data needed)

| Script | What it does |
|---|---|
| `structure_probe.py` | Single-file first pass. Ranks candidate record sizes by column-entropy, detects length-prefixed and delimiter-framed variable-length records, extracts ASCII/UTF-16 strings, reports global entropy and byte-frequency spikes (clues for padding, erased flash, compressed/encrypted regions). Prints a warning at the top of its report if the file matches a known container format's magic bytes. |
| `container_probe.py` | Standalone signpost/reconnaissance for container formats (PNG, ZIP, WAV/RIFF, ELF, MP4, SQLite, pcap, etc.). Matches against a dictionary of ~40 common magic signatures and, for unknown formats, tries generic TLV chunk-walk layouts to see whether the file is chunk-structured rather than record-structured. Does not generate chunk parsers — this script only tells you what the file *is*, so you can reach for the right library. |
| `multi_file_diff.py` | Given several sample files of the same format, reports which file-header offsets are constant across files (magic-byte candidates) and which record columns are constant/low-variance vs. varying (reserved bytes, enum flags, numeric fields). |

### Stage 2 — hypothesis testing

| Script | What it does |
|---|---|
| `csv_correlate.py` | **The biggest accelerator** when the user has a known-good CSV/JSON export of the same data. For every CSV column, brute-forces every offset / type / endianness / scale factor (1, 10, 100, ... 1e7) and prints ranked "bytes N-M as type X / scale Y matches column Z at P% of records". Also tries a `ddmm2degrees` transform for NMEA-encoded coordinates, and falls back to sorted-value matching when the reference CSV is in a different row order than the binary (common: many PC exports put waypoints before trackpoints while the binary interleaves them). This turned the DG-388 decode from days into one command. |
| `field_probe.py` | Black-box hypothesis tester. Targeted mode: "at offset 8, assume i32 LE, show me the distribution + whether it looks like a timestamp/coord/enum". Scan mode: tries every reasonable type (integer and float) at every offset and tags anything that looks like YYYYMMDD, HHMMSS, Unix epoch, integer-degrees-with-scale, a small enum, a monotonic counter, a float decimal-degree coordinate, a float NMEA DDMM coordinate, an altitude / speed / heading float, or a low-cardinality enum. Bit-scan mode (`--bits --offset N --storage u16`) sweeps every `(bit_offset, bit_width)` combo within a storage word and surfaces candidates that look like a boolean flag, enum, or counter. |
| `crc_probe.py` | Identify the checksum or CRC algorithm protecting each record, or the whole-file trailer. Sweeps the last 1/2/4 bytes of each record by default (or accepts an explicit `--checksum-offset`/`--checksum-size`/`--data-range`) and tries ~20 standard algorithms: SUM-8/16/32, XOR-8, two's-complement-8, CRC-8 (plus MAXIM/ROHC/ITU), CRC-16 (ARC, MODBUS, CCITT-FALSE, XMODEM, KERMIT, USB, GENIBUS), and CRC-32 (Ethernet, Castagnoli, BZIP2, MPEG-2). Reports any algorithm that matches ≥ 90% of records, and when nothing matches prints the distinct-value cardinality so you can see whether the field behaves like a checksum even if the algorithm isn't in the catalog. |

### Stage 3 — codification

Both generators consume the same `fieldmap.json`. See
`references/fieldmap_schema.md` for the schema and
`references/dg388_fieldmap.json` for a complete worked example.

| Script | What it does |
|---|---|
| `gen_parser.py` | Emits a standalone Python parser (CSV output, stdlib-only, handles scales and YYYYMMDD/HHMMSS/unix-seconds decoding, skips blank records per the fieldmap). Supports three framings: fixed-record, length-prefixed, and delimiter-framed. Bit-packed fields (with `bit_offset`/`bit_width`) are extracted with shift+mask, including signed two's complement for negative counters. |
| `gen_docs.py` | Emits a README-style spec document with the Offset/Size/Type/Field/Encoding table in the style of the DG-388 writeup. |

## Workflow

Step through the stages; don't skip. Every stage informs the next.

### 0. Set up

Put one or more sample files somewhere, and ideally a reference export
(CSV / JSON / GPX / KML) of what the binary is supposed to decode to.
Ask the user what they know about the file: source device, whether they
have reference data, any known semantics ("this is GPS tracks", "this is
logged sensor readings").

If no reference data is available, say so and proceed in black-box mode.
Don't pretend the black-box route is as fast — it isn't.

### 1. Reconnaissance

Run `structure_probe.py <file>` first. Look at:

- **Mean column entropy**: a good fixed-record format usually has several
  low-entropy columns (padding, flags, high bytes of small counters) mixed
  with high-entropy columns (the actual data). Look for the *smallest*
  candidate size among a cluster of similarly-scored sizes — larger sizes
  that are multiples of the true record size will score similarly, but
  the true size is the smallest.
- **String extraction**: ASCII/UTF-16 strings at low offsets suggest a
  file header or magic. Strings distributed throughout suggest a
  text-mixed format. No strings at all is typical of tight telemetry.
- **Byte histogram**: >30% `0x00` often means padded/zero-initialised
  fields; >30% `0xFF` suggests unerased flash fill.

If the user has multiple sample files, run
`multi_file_diff.py file1 file2 ... [--record-size N]`:

- Look at the file-header diff. CONSTANT runs at offset 0 are the magic
  bytes. A header that varies in structured ways (timestamps, IDs) is
  per-file metadata worth parsing.
- Look at the per-record column diff. Columns with 1-2 distinct values
  are flags or padding. Columns with 256 distinct values but 80%+
  dominance of one value are usually "real data mixed with fill pattern"
  (pre-allocated blank records, erased regions).

The reconnaissance output also includes a `Variable-length record detection` section. If any length-prefixed framing consumed the entire file with a plausible record count, or if a delimiter byte shows up with a coefficient of variation below ~0.1, the format is probably not fixed-record. Switch to `record_framing: "length_prefixed"` or `"delimited"` in the fieldmap and proceed with the matching keys (see `references/fieldmap_schema.md`).

At the end of Stage 1 you should know:
- Whether the format is fixed-record, length-prefixed, or delimiter-framed
- Record size (or file header size if not record-based)
- Rough endianness suspicion (from which fields look plausible)
- Which regions are constants/flags vs. data
- Whether the file has blank/pre-allocated records

### 2. Hypothesis — the fast path (reference data available)

If the user has a known-good CSV export of the same data, this is the
single biggest time saver. Example:

```
python scripts/csv_correlate.py file.bin --record-size 28 \
    --csv reference.csv --max-records 200
```

The tool will print, for each numeric CSV column, a ranked list like:

```
---  Latitude ---
  100.0%  offset=0x08 (8)  i32 LE  scale=1/10000000
```

**Read these like a lawyer**: a 100% hit on a column with lots of
variation (like Latitude) is nearly ironclad. A 100% hit on a column
with only a few distinct values (a single-day "Date") is weak evidence —
many byte interpretations will pass. Prefer matches on high-variance
columns first.

**Disambiguate signed vs. unsigned**: csv_correlate will flag both
`u32` and `i32` when all values happen to be positive. If the column
can take negative values (longitudes in the western hemisphere,
temperatures below freezing), the tool will automatically resolve to
the signed type.

**NMEA DDMM coordinates**: if a hit is annotated `transform=ddmm`, the
binary stores the value in NMEA form (DDMM.MMMM — degrees in the
integer part, minutes in the fractional part), not decimal degrees.
This is common in GPS formats derived from NMEA-over-serial loggers
(e.g. Qstarz BL-1000). The tool handles the conversion automatically;
carry the `ddmm` encoding into the fieldmap.

**Out-of-order reference rows**: if a hit is annotated
`unordered (values match but row order differs)`, the tool found the
same set of values in the binary and the CSV but not in matching
positions. Typical cause: the PC export reorders waypoints ahead of
trackpoints while the binary stores them in chronological order.
Treat an unordered-only hit as a strong hint but weaker than an
ordered hit — re-sort the CSV into binary order (using an oracle
byte like a record-type flag) and re-run to upgrade it to an ordered
match before committing to the fieldmap. Use `--ordered-only` to
disable sorted-match fallback entirely.

### 2. Hypothesis — the slow path (black-box)

Without reference data:

```
python scripts/field_probe.py file.bin --record-size 28 --scan \
    [--skip-zero-records]
```

Read the scan tags: `YYYYMMDD`, `HHMMSS`, `unix_ts`, `coord/1e7`
(integer-scaled coordinate), `coord_deg (float)` (float in ±180 range),
`coord_ddmm (float NMEA)` (NMEA DDMM.MMMM double), `altitude_m (float)`,
`speed_kmh (float)`, `heading_deg (float)`, `monotonic↑`, `enum(N)`.
Each tag is a heuristic flag, not a confirmation — a few are common
false-friends (a small-range integer can tag as `HHMMSS` just because
its digits fit the pattern; a float altitude can also tag as
`coord_deg` because 0-180 contains 0-10000 m).

For each promising offset, run targeted probes:

```
python scripts/field_probe.py file.bin --record-size 28 \
    --offset 8 --type i32 --endian LE
```

The targeted output gives you min/max/mean/stddev across every record
plus multiple sanity checks. If the distribution matches what you'd
expect for the field (e.g. altitude: 0-9000m, speed: 0-300 km/h,
heading: 0-360°), you have a confirmed field.

**Don't forget to check both endiannesses.** DG-388-style tight
telemetry is almost always little-endian. Network-protocol and
aerospace formats are often big-endian.

### 3. Confirmation

Before writing the fieldmap, sanity-check each field:

- **Does every record's value make physical sense?** (altitude in sane
  range, speed non-negative, heading 0-360°)
- **Are there fields you haven't assigned?** Leave them as `pad` in the
  fieldmap if they're always zero/one, or label them `unknown` if they
  vary but you can't figure out what they are. Honest "unknown" in the
  fieldmap is better than a guess that propagates into the parser.
- **High-cardinality trailing fields that look random?** Those are often
  checksums or CRCs. Run `crc_probe.py <file> --record-size N` — it
  tries the standard SUM/XOR/CRC algorithms and will name the algorithm
  if one matches. Label it `"encoding": "checksum"` in the fieldmap
  (with a comment naming the algorithm) so the reader knows it's not
  data.
- **If reference data is available, round-trip at least one field at
  full precision** (not the 6-decimal CSV rounding; the original value)
  before calling a field "confirmed".

### 4. Codify

Write `fieldmap.json` following `references/fieldmap_schema.md`. Fill
in the `validation` and `provenance` sections — these are what make
the writeup reusable by somebody else (or by Claude in a future
session) rather than a one-off.

Generate artifacts:

```
python scripts/gen_parser.py fieldmap.json -o parser.py
python scripts/gen_docs.py fieldmap.json -o FORMAT.md
```

Run the generated parser against the original file. If there's
reference data, diff the outputs. If they match, you're done.

For length-prefixed or delimiter-framed fieldmaps, set `record_size`
to the minimum number of bytes needed to decode all declared fields
(not the largest observed record) and let the parser walk the file
using the length field or delimiter. Each emitted record gains a
`_record_size` column so you can spot records smaller than expected.

## When to stop

A decoded format is "done" when:

1. The generated parser round-trips to reference data at full precision
   on at least one sample file, AND
2. The generated parser runs on every other sample file without error or
   unexpected blank records, AND
3. The fieldmap accounts for every byte in the record (data fields, `pad`
   fields, or honest `unknown` fields). No silent holes.

Fields that remain `unknown` are acceptable deliverables as long as
they're documented in the spec. Not every byte of every format can be
decoded without device documentation or firmware access.

## Common traps

- **Picking the wrong record size when multiples of the true size score
  equally well.** `structure_probe.py` explicitly flags this — always
  pick the smallest strongly-scored size.
- **Conflating pre-allocated blank records with the real data.** Many
  devices write a pre-formatted file of N records and fill them in as
  they log. Run `structure_probe.py` first; if global entropy is low
  and a fill pattern (like 0xFF or repeated bytes) dominates, use
  `--skip-zero-records` downstream or add a `skip_blank` rule to the
  fieldmap.
- **Packed fields within what looks like a wider field.** The DG-388
  stored heading (uint16) and record_flag (uint16) in bytes 24-27. At
  first glance that looks like a single uint32, but the uint32
  interpretation produced huge meaningless numbers. `field_probe.py`
  in scan mode will flag the uint16 enum separately from the uint32
  and save you from this.
- **Assuming CSV reference data lines up 1:1 with binary records.**
  PC tools often skip invalid records, reorder by timestamp, or filter
  by GPS fix quality. `csv_correlate.py` now falls back to sorted-value
  matching when ordered matching fails and reports the hit as
  `unordered (values match but row order differs)` — treat these as
  a strong hint and re-sort the CSV into binary order before committing.
  Use `--max-records` on the first few hundred contiguous records where
  alignment is most likely to be clean.
- **Coordinates stored as NMEA DDMM.MMMM doubles.** Several GPS formats
  (Qstarz BL-1000, various NMEA-over-serial loggers) store lat/lon as
  doubles in NMEA form rather than decimal degrees. Linear scaling can
  never match these against a decimal-degrees CSV. `csv_correlate.py`
  auto-tries the `ddmm2degrees` transform and reports hits as
  `transform=ddmm`; carry the `ddmm` encoding into the fieldmap.
- **Trusting a 100% match on a constant column.** Any byte
  interpretation matches `[34.400, 34.400, 34.400, ...]`. Always test
  against a column with real variance.

## Worked example — the DG-388 GPL format

The files in `references/` contain the complete worked example used to
develop this skill. The original reverse-engineering took days of
manual guessing, hex-dump spelunking, and cross-referencing against the
GlobalSat PC tool's CSV, GPX, and KML exports. With this skill, the
four numeric fields (latitude, longitude, altitude, speed) fall out of
one `csv_correlate.py` run at 100% match; heading and record_flag
require one `field_probe.py --scan` plus a targeted verification.
