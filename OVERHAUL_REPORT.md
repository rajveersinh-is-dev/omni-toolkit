# OMNI Toolkit — Overhaul Ledger (`make-it-better`)

> **Date**: 2026-11-18  
> **Repository**: `omni-toolkit` (30-crate Rust workspace + frontend/CLI/TUI/Desktop)  
> **Baseline Commit**: `dc99a7a`

---

## 1. Executive Summary

| Metric | Baseline (Before) | Final (After) | Delta |
|---|---:|---:|---:|
| **Workspace Test Pass Rate** | 112 passed / 0 failed (100%) | **143 passed / 0 failed (100%)** | **+31 test suites & expanded regressions** |
| **Fuzzed Binary Encoders** | 4 encoders | **10 encoders (all base16–base91)** | **+6 encoders fuzzed** |
| **Verified Registered Operations** | 17 / 132 (12.9%) | **129 / 132 (97.7%)** | **+112 operations promoted to `verified` (0 `implemented` remaining)** |
| **Production `.unwrap()` / `.expect()` Calls** | 41 | **0** | **-41 (100% eliminated across `crates/` & `apps/`)** |
| **`cargo clippy --workspace --all-targets -- -D warnings`** | 0 warnings | **0 warnings (exit 0)** | Strict clean build enforced |
| **`cargo fmt --all -- --check`** | FAIL (~300 KB diff) | **PASS (exit 0)** | 100% rustfmt-compliant + CI-enforced |
| **`cargo doc --workspace --no-deps`** | 0 warnings | **0 warnings (exit 0)** | 32 doc targets verified |
| **`omni-desktop --features native-webview`** | Verified | **PASS (exit 0)** | Native WebView feature intact |
| **`node --check frontend/src/app.js`** | Unchecked | **PASS (exit 0)** | Frontend JS syntax verified |
| **RFC 8259 UTF-8 (No-BOM) Docs & Inventory** | UTF-16 / BOM drift | **0 BOM files** | Strictly parseable by `json.loads` / `serde_json` |
| **P0 Panics / Stack Overflows / Infinite Loops / DoS Fixed** | 21 discovered | **0 remaining in audited scope** | **21 P0 bugs fixed & regression-tested** |
| **P1 Logic / Math / Security / Spec Flaws Fixed** | 33 discovered | **0 remaining in audited scope** | **33 P1 flaws fixed & regression-tested** |

### Inventory Status Breakdown (`omni --json inventory`, 132 Operations)

- `verified`: **129** (backed by dedicated positive, negative, and boundary/vector automated tests, including programmatic X.509 v3 DER/PEM and TrueType sfnt binary fixtures)
- `implemented`: **0** (all non-experimental, supported operations are now `verified`)
- `experimental`: **2** (`media.transcode` via host `ffmpeg`, `pdf.ocr` via host `tesseract`)
- `unsupported`: **1** (`crypto.pqc.falcon` — explicitly returns unsupported error)

### Benchmark Verification (In-Process `Instant`, 5 Discarded Warmups, 20 Measured Iterations)

- **Post-Overhaul Dev Benchmark (`cargo run -p omni-benchmarks`, 1 MB payload, exit 0)**:
  - `crypto.hash.sha256`: 15574.1 μs mean (64.21 MB/s)
  - `crypto.hash.blake3`: 429.0 μs mean (2330.81 MB/s)
  - `encode.base64`: 4644.7 μs mean (215.30 MB/s)
  - `checksum.crc32`: 984.5 μs mean (1015.74 MB/s)
  - Confirmed exact Unicode box-table column alignment on `Min (μs)` / `Mean (μs)` / `Median (μs)` headers.
  - *(Note: Earlier unsigned release executable execution was blocked by host Windows Defender `os error 225`; dev benchmark binary executed cleanly with exit 0.)*

---

## 2. Itemized Audit Findings & Resolution Matrix

### P0 — Runtime Panics, Stack Overflows, Infinite Loops & Security/DoS Vulnerabilities

| # | File | Line(s) | Problem Description | Root Cause | Applied Solution |
|---|---|---|---|---|---|
| 1 | `crates/omni-crypto/src/symmetric.rs` | 45, 63, 81 | Immediate panic on IVs shorter than 12 bytes | `Nonce::from_slice(&iv_bytes[..12.min(iv_bytes.len())])` passes `<12` bytes to fixed-size `GenericArray::from_slice` | Validate `iv_bytes.len() < 12` and return `OmniError::Validation` before slicing `&iv_bytes[..12]` |
| 2 | `crates/omni-crypto/src/checksum.rs` | 101–115 | Out-of-bounds panic in `checksum.fletcher32` on every input with `len >= 2` | Loop bound `tlen` counted remaining **bytes** while body incremented `i += 2` (words) | Compute `remaining_words = (bytes.len() - i).div_ceil(2)` and `tlen = remaining_words.min(360)` |
| 3 | `crates/omni-crypto/src/entropy.rs` | 138–150 | Out-of-bounds panic in `LsbSteganographyOp::extract` | Checked `len > carrier_bytes.len() / 8` ignoring the 32 carrier bytes consumed by the 4-byte length header | Validate `len > (carrier_bytes.len() - 32) / 8` |
| 4 | `crates/omni-encoders/src/base_all.rs` | 316 | Arithmetic overflow panic in `encode.base85` decode on `"uuuuu"` | `val: u32 = val * 85 + digit` overflows `u32::MAX` (`85^5 - 1 = 4,437,053,124`) | Accumulate in `u64`, reject `val > u32::MAX as u64`, reject lone trailing byte (`count == 1`) and mid-tuple `'z'` |
| 5 | `crates/omni-binary/src/hex_tools.rs` | 27, 42 | Immediate panic in `binary.hex` when `width == 0` or `word_size == 0` | `bytes.chunks(0)` and `swapped.chunks_exact_mut(0)` panic unconditionally | Validate `width` in `1..=256` and `word_size` in `1..=64` |
| 6 | `crates/omni-firmware/src/extractor.rs` | 50, 121 | Immediate panic when `entropy_chunk_size == 0` | `bytes.chunks(0)` panics | Validate `entropy_chunk_size` in `1..=16_777_216` |
| 7 | `crates/omni-firmware/src/extractor.rs` | 135 | Unbounded GZIP decompression bomb (OOM DoS) during `carve: true` | `GzDecoder::read_to_end` read arbitrary gigabytes into RAM with no ratio or size limit | Stream in 8 KB chunks enforcing `omni_security::ResourceLimits::check_decompression` incrementally |
| 8 | `crates/omni-media/src/audio.rs` | 87, 99 | Infinite CPU hang in `audio.lufs` for `< 4` PCM samples | `hop_size = block_size / 4` evaluates to `0`, causing `start += 0` forever | Enforce `block_size = 17640.min(s2.len()).max(1)` and `hop_size = (block_size / 4).max(1)` |
| 9 | `crates/omni-media/src/audio.rs` | 138, 142 | Infinite CPU hang & div-by-zero in `audio.silence` for `sample_rate <= 0` or `< 20` | `window_size = (sample_rate * 0.05) as usize` becomes `0` | Validate `sample_rate.is_finite() && sample_rate > 0.0` and clamp `window_size.max(1)` |
| 10 | `crates/omni-media/src/audio.rs` | 215, 231 | Division-by-zero panic in `audio.waveform` when `points == 0` | `samples.len() / points` divides by zero | Validate `points` in `1..=100_000` |
| 11 | `crates/omni-media/src/image.rs` | 183–192, 220–234 | Slice out-of-bounds panic on malformed/truncated JPEG segments | `&bytes[i..i + 2 + len]` sliced past `bytes.len()` without bounds or `len < 2` validation | Use `checked_add`, validate `len >= 2 && seg_end <= bytes.len()`, handle standalone markers (`0xD0..=0xD9`, `0x00`, `0x01`, `0xFF` fill) |
| 12 | `crates/omni-media/src/image.rs` | 44–45 | Unbounded image resize OOM DoS (`width=1_000_000`) | Unchecked user-supplied `width`/`height` passed to `resize_exact` | Validate `1..=16_384` per side and `w * h <= 64_000_000` pixels |
| 13 | `crates/omni-filesystems/src/fs_forensics.rs` | 33, 41, 48–51 | Shift overflow panic (`1024u64 << log_block_size`) + multiplication overflow + 4 `.unwrap()` calls | Unvalidated `log_block_size` from untrusted superblock bytes | Reject `log_block_size > 16`, use `saturating_mul`, replace `.try_into().unwrap()` with safe `read_u32_le`/`read_u64_le` |
| 14 | `crates/omni-filesystems/src/serialization.rs` | 71, 130, 139 | Arithmetic overflow panic on adversarial Protobuf varint length or ASN.1 DER length-of-length | `offset + len` overflowed `usize`; ASN.1 accepted up to 127 length bytes | Use `usize::try_from` + `checked_add`, bound ASN.1 `1..=size_of::<usize>()` |
| 15 | `crates/omni-network/src/ip_calc.rs` | 76–79 | Overflow panic when splitting `/0` to `/32` | `2u32.pow(32)` overflows `u32` | Use `1u64 << (t_p - prefix)` and `wrapping_add`, reject multi-slash CIDR strings |
| 16 | `crates/omni-system/src/color.rs` | 11–16 | UTF-8 char-boundary slice panic on 6-byte non-ASCII inputs (e.g. `"€€"`) | Checked `clean.len() == 6` (byte length) then sliced `&clean[0..2]` | Require `clean.len() == 6 && clean.is_ascii()`; also added Tritanopia simulation |
| 17 | `crates/omni-crypto/src/hash.rs` / `crates/omni-code/src/deobfuscate.rs` / `crates/omni-system/src/cron.rs` | 59/70, 52, 26 | Unbounded allocation / CPU DoS (`shake` length, eval-packer `c`, cron range `0-4294967295`) | Missing upper bounds before allocation or iteration | Cap SHAKE output `1..=1_048_576`, eval-packer `c <= 65_536`, validate cron bounds before iterating |
| 18 | `crates/omni-documents/src/diagrams.rs` | 38–58 | **Slice index panic** on reversed brackets (`"]A["`, `"}A{"`, `")A("`) | `s.find('[')` (`idx`) and `s.rfind(']')` (`end`) sliced `s[idx + 1..end]` without verifying `idx < end` | Enforce `idx < end` guard on all three bracket shape delimiters before slicing |
| 19 | `crates/omni-documents/src/math.rs` | 92–184 | **Stack overflow crash** on deeply nested `{...}` / `\sqrt` / `\frac` | Unbounded recursion in `MathParser::parse_seq` and `parse_atom` | Enforce `MAX_MATH_DEPTH = 64` returning `OmniError::Validation` cleanly; also handle escaped symbols (`\{`, `\}`, `\%`, `\\`) |
| 20 | `crates/omni-media/src/container.rs` | 235 | **UTF-8 char-boundary panic** in `media.transcode` `validate_bitrate` (e.g. `"12€"`, `"é"`) | Called `bitrate.split_at(bitrate.len() - 1)` on non-ASCII string | Require `bitrate.is_ascii()` and use `strip_suffix('k')`/`strip_suffix('M')` |
| 21 | `crates/omni-binary/src/disasm.rs` | 32–35 | **Arithmetic underflow / slice panic** when `base_addr` wraps (`u64::MAX`) or exceeds bitness (`x86_32` with `base_addr >= 2^32`) | Computed byte offset via `instr.ip() - base_ip` after `iced_x86` masked/wrapped IP | Record `decoder.position()` before and after `decoder.decode_out` for exact byte-slice bounds |

### P1 — Silent Logic, Data Corruption, Security, Protocol & Unwrap Defects

| # | File | Line(s) | Problem Description | Root Cause | Applied Solution |
|---|---|---|---|---|---|
| 22 | `crates/omni-crypto/src/classical.rs` | 291–422 | **Enigma cipher broken (non-reciprocal)** + odometer stepping instead of historical Enigma I notches | Forward rotor omitted `- b'A'`; stepping used odometer instead of Rotor I/II/III notches (`Q`/`E`/`V`) with double-stepping | Normalized forward rotor bytes, computed inverse rotor tables dynamically, and implemented authentic Enigma I double-stepping (`"AAAAA"` at `AAA` -> `"BDZGO"`) |
| 23 | `crates/omni-crypto/src/classical.rs` | 110–139 | Affine cipher failed on negative `a` or `b` | `(a * i) % 26 == 1` is negative in Rust when `a < 0` | Normalize `a` and `b` via `.rem_euclid(26)` before modular inverse and encryption/decryption |
| 24 | `crates/omni-crypto/src/jwt.rs` | 24, 43–75 | JWT algorithm confusion (`"alg": "none"` verified as HS256), 4-part tokens accepted, `.unwrap()` on tamper | Verification ignored `header["alg"]` and only ran HS256 | Reject `parts.len() > 3`, reject `"alg": "none"`/missing, dispatch `HS256`/`HS384`/`HS512`, remove `.unwrap()` |
| 25 | `crates/omni-crypto/src/signatures.rs` | 61–73 | 4 `.unwrap()` calls in AWS SigV4 + missing OAuth 1.0a advertised in manifest | Direct `.unwrap()` on `HmacSha256::new_from_slice` | Extract fallible `hmac_sha256_bytes` helper and implement OAuth 1.0a `HMAC-SHA1`/`HMAC-SHA256` |
| 26 | `crates/omni-crypto/src/asymmetric.rs` & `kdf.rs` & `pki.rs` | 29, 43, 57, 26 | Unchecked RSA bits, bcrypt cost (`31` hangs), PBKDF2 rounds (`0`/huge), leading whitespace broke PEM detection | Missing range checks and leading whitespace trimming | Enforce RSA `1024..=4096`, bcrypt `4..=16`, PBKDF2 `1..=10_000_000`; skip leading whitespace before `-----BEGIN` |
| 27 | `crates/omni-encoders/src/base_all.rs` & `web_encoders.rs` | 105–233, 135–236 | Base45 truncated `>65535`/`>255`; Base62 dropped leading `0x00`; `\u12\u0041` swallowed `\u0041` and didn't decode UTF-16 surrogate pairs | Missing RFC 9285 bounds, leading-zero count, peek-before-consume, and surrogate pair handling | Enforce Base45 bounds, preserve Base62 leading zeros, peek hex digits, decode `\uD800-\uDBFF\uDC00-\uDFFF` surrogate pairs |
| 28 | `crates/omni-ai/src/vector.rs` & `quantize.rs` & `model_inspect.rs` | 13–24, 72, 74 | `partial_cmp().unwrap()` NaN panic; `1e200` overflowed L2 norm; `header_len as usize` 32-bit truncation | Unscaled squares, `.unwrap()`, and unchecked cast | Reject non-finite values, max-abs scaled norm/cosine, `f64::total_cmp`, `usize::try_from` |
| 29 | `crates/omni-system/src/trace.rs`, `ids.rs`, `cron.rs` | 51, 102, 37, 84 | `<NaN>` duration panic; snowflake epoch overflow; cron `"7/2"` resolved to empty mask | Unfiltered `f64`, unchecked `+`, and unnormalized Sunday `7` in stepped token | Filter finite `>= 0.0`, `total_cmp`, `saturating_add`, normalize `val == 7` to `0` before stepping |
| 30 | `crates/omni-text/src/transpile.rs`, `query.rs`, `strings.rs`, `regex_studio.rs`, `encodings.rs` | Various | 10 `.unwrap()` calls; CSV double-quoting; Soundex `H`/`W` rule; **`text.encodings` `to: "utf-16le"`/`"utf-16be"` silently output UTF-8** | `Value::to_string()` quotes; `encoding_rs::UTF_16LE.encode()` outputs UTF-8 per WHATWG | Unwrap strings cleanly, add `$.` + chained `[i][j]`, fix NARA Soundex, bound regex size 10MB, encode UTF-16LE/BE directly via `encode_utf16()` |
| 31 | `crates/omni-filesystems/src/sql_engine.rs` & `serialization.rs` | 65–119, 232–272, 53 | **JSON column-value scrambling** (`{"-z":1,"a":2}`), duplicate column crash, **`WITH ... DELETE` readonly bypass**, naive `line.split(delimiter)` breaking RFC 4180 quoted CSV/TSV fields/newlines, empty delimiter bug, truncated Protobuf varint emitted fake `0` | Sorted sanitized headers independently of raw keys; string-prefix-only readonly check; naive line splitting without RFC 4180 quote handling; `.unwrap_or(0)` on varint | Derive deduplicated headers in exact `raw_keys` order, parse single-byte CSV/TSV via `csv::ReaderBuilder` (RFC 4180 quotes, `""` escapes, embedded newlines) while preserving custom multi-char delimiters, reject empty delimiter, enforce `PRAGMA query_only = ON` + `stmt.readonly()`, break on truncated varint |
| 32 | `crates/omni-pcap/src/dissect.rs` & `reassemble.rs` | 44–51, 44–50, 104–111 | **Big-endian PCAP files completely misparsed as little-endian**; `reassemble` hardcoded LE & duplicated retransmitted TCP segments; unchecked `ihl`/`tcp_offset` | `u32::from_ne_bytes` mapped swapped magic `0xD4C3B2A1` to `true` (LE); no seq deduplication | Match raw 4-byte wire magic directly in both files, deduplicate overlapping/retransmitted TCP sequence ranges, enforce `checked_add` and `>= 20` headers |
| 33 | `crates/omni-media/src/image.rs` & `geo3d.rs` | 119–197, 38–60, 168–177 | Missing **CIEDE2000** promised in manifest + unvalidated RGB; `geo3d.inspect` dropped negative OBJ indices & accepted `NaN` vertices; `geo3d.shader` marked `"} {"` balanced | Unimplemented Delta-E 2000; `usize` face parse; brace counter ignored negative depth | Implemented exact Sharma-Wu-Dalal (2005) CIEDE2000 + RGB `0..=255` validation; added OBJ negative indices + finite check + fan triangulation; detect negative brace depth |
| 34 | `crates/omni-code/src/ast.rs` & `deobfuscate.rs` | 65–72, 69–82 | `minify` truncated URLs (`"https://..."`) inside string literals; Dean Edwards packer ignored radix `a` for `c > 36` | Regex `//.*` without lexer state; hardcoded decimal for `i >= 36` | Replaced regex with single-pass string-aware comment stripper; implemented full radix-`a` (`2..=62`) packer key encoder |
| 35 | `crates/omni-pdf/src/ops.rs` & `scrubber.rs` & `omni-binary/src/executable.rs` | 39, 33, 36 | PDF rotate accepted non-multiples of 90; PDF scrubber left indirect `/Info` object in body; truncated 4-byte WASM reported as valid | Missing `% 90 == 0` check; didn't remove `/Info` object ID; fabricated `version: 1` for `< 8` bytes | Enforce `degrees % 90 == 0` + `rem_euclid(360)`, delete indirect `/Info` & `/Metadata` objects, require `>= 8` bytes for WASM header |
| 36 | `crates/omni-network/src/dns.rs`, `sockets.rs`, `scanner.rs` | 85, 328, 81, 123 | IPv6 `[::1]:53` failed target validation; DNS reserved label bits ignored; socket echo failed `> 1024B`, reported 5ms instead of 5000ms timeout, wrapped `port as u16`; uncapped scanner ports | Missing bracket strip, reserved bit check, concurrent split I/O, and `u16::try_from` | Strip IPv6 brackets, reject `(len & 0xC0) != 0` non-pointer, concurrent echo with 5000ms timeout, validate `1..=65535`, cap scanner to 1024 ports |
| 37 | `crates/omni-infrastructure/src/iac_security.rs` & `container.rs` | 167, 48 | AWS IAM action matching was case-sensitive & lacked globs/resource scoping; Dockerfile `USER groots` triggered false-positive root error | Case-sensitive equality + substring `upper.contains("ROOT")` | Iterative `*`/`?` glob with case-insensitive `Action` + case-sensitive `Resource`; exact `USER` token parsing |
| 38 | `crates/omni-api/src/lib.rs` & `frontend/src/app.js` | 184–194, 509–538 | **WebSocket `?token=` auth failed for URL-encoded Base64 tokens (`+`, `/`, `=`)**; frontend hex view dumped JSON array text instead of raw `Bytes` | `auth_middleware` skipped percent-decoding query params; `displayOutput` ignored `output.type === 'Bytes'` | Added percent-decoding in `auth_middleware` before constant-time token check; decode & hex-dump raw `Uint8Array` for `Bytes` payloads |
| 39 | `crates/omni-visualization/src/lib.rs` & `omni-security/src/redact.rs` | 75, 162, 5–32 | Unicode table headers misaligned; hex dump padding off by 1 when `bpr % group != 0`; `NaN`/negative chart panic; 7 `.expect()` calls | Byte `.len()`, `(bpr / group) - 1`, unguarded `f64`, panicking `LazyLock` | `.chars().count()`, `bpr.saturating_sub(1) / group`, finite guards, `LazyLock<Option<Regex>>` |
| 40 | `docs/feature-inventory.json`, `TRACEABILITY_MATRIX.md`, `README.md` | byte 0, 68–74 | UTF-8 BOM (`\xef\xbb\xbf`) broke strict JSON parsers (`JSONDecodeError`), stale pre-overhaul counts in `README.md`, and `Multi-Input` column drift in `TRACEABILITY_MATRIX.md` | Generated via PowerShell UTF8-with-BOM and manual summary tables | Regenerated `docs/feature-inventory.json` and `TRACEABILITY_MATRIX.md` (preserving `accepts_multi_input` flags) as pure UTF-8 without BOM from `./target/debug/omni.exe --json inventory` and synchronized `README.md` (`129 verified / 0 implemented / 2 experimental / 1 unsupported`) |

---

## 3. Hardened Test Suite Summary

Raised workspace tests from **112** baseline to **143** (all passing, 0 failed, 0 ignored) and expanded `tests/fuzz/fuzz_test.rs` from 4 to all 10 binary encoders:

- `omni-documents`: `test_font_toolkit_valid_minimal_ttf` & `test_font_toolkit_rejects_empty_and_truncated_fonts` (programmatic TrueType sfnt binary font with valid `head`/`hhea`/`maxp`/`name`/`post` tables & checksums asserting exact metadata + malformed font rejection) + `test_documents_adversarial_slice_and_recursion_guards` (reversed Mermaid brackets `]A[`, `500`-deep brace & `200`-deep `\sqrt` recursion guards, escaped `\{`, LaTeX/Man transcode)
- `omni-media`: `test_ciede2000_reference_vectors_utf8_bitrate_image_and_shader` (Sharma-Wu-Dalal 2005 CIEDE2000 exact reference pairs, UTF-8 bitrate `"12€"`/`"é"` guard, PNG pipeline info/resize/grayscale/rotate/OOM guard, OBJ negative indices & NaN filter, `"} {"` shader brace balance) + `test_media_audio_image_geo3d_edge_regressions`
- `omni-binary`: `test_disasm_base_ip_wrap_and_executable_and_serial_parity` (`x86_32` `base_addr=0x1_0000_0000` & `x86_64` `u64::MAX`, valid vs truncated WASM, 8-E-1 parity counting) + `test_binary_hex_and_serial_zero_param_guards`
- `omni-filesystems`: `test_sql_rfc4180_quoted_csv_tsv_and_custom_delimiters` (RFC 4180 quoted CSV/TSV with embedded commas/tabs, escaped `""` quotes, embedded newlines, SQL `WHERE`/`ORDER BY` filtering, custom `"::"` delimiter, empty input guard) + `test_sql_json_column_alignment_readonly_and_binary_formats` (`{"-z","a"}` column alignment, duplicate sanitized column dedup, `WITH ... DELETE` readonly guard, empty delimiter guard, truncated Protobuf varint, MessagePack & ASN.1 DER) + `test_fs_ext_shift_overflow_and_serialization_overflow_guards`
- `omni-pcap`: `test_pcap_big_endian_and_tcp_retransmit_deduplication` (big-endian PCAP magic `0xA1B2C3D4`, out-of-order + duplicate TCP retransmit deduplication)
- `omni-pdf`: `test_pdf_rotation_validation_indirect_info_scrub_and_malformed_inputs` (non-90° rotation rejection, `-90` -> `270`, indirect `/Info` custom secret object deletion, corrupted PDF rejection across all 3 ops)
- `omni-text`: `test_encodings_utf16le_utf16be_and_windows1252` (exact UTF-16LE/BE byte verification & roundtrip, Windows-1252 `0x80` -> `€`, unknown encoding rejection) + `test_transpiler_csv_no_double_quoting_and_jsonpath_chained_indices`
- `omni-crypto`: `test_x509_inspect_valid_der_and_pem_with_leading_whitespace` & `test_x509_inspect_rejects_empty_and_corrupt_inputs` (programmatic Ed25519-signed X.509 v3 DER & whitespace-prefixed PEM certificate with Subject, Issuer, Serial, Validity, SPKI, and SANs) + `test_enigma_historical_vector_and_double_stepping_and_pki_rejection` (historical Enigma I `AAA` `"AAAAA"` -> `"BDZGO"`, notch double-stepping reciprocity, invalid PEM/DER rejection) + 6 prior hardening suites
- `omni-code`: string-literal URL preservation during `minify`, Dean Edwards base-62 unpacking, OOM packer guard
- `omni-encoders`: `\u12\u0041` non-swallowing & UTF-16 surrogate pair `\ud83d\ude00` decoding + Base85/Base45/Base62 regressions + 10-encoder fuzz suite
- `omni-infrastructure`: case-insensitive AWS IAM action matching + Dockerfile `USER groots` vs `USER root:root`
- `omni-network`: IPv4 `/0 -> /32` split, 8192B echo, invalid port `65537`, WoL 102B magic packet, >1024 port DoS guard, DNS reserved label bit rejection
- `omni-system`: UTF-8 color guard, cron DoS/`29 Feb`/`7/2` Sunday step, trace `<NaN>`/`<inf>`, snowflake `u64::MAX`
- `omni-api`: URL-encoded Base64 WebSocket `?token=` authentication regression
- `omni-visualization`: Unicode box alignment, non-finite charts, non-divisible `bpr=5, group=2` hex dump alignment

---

## 4. Verification Evidence

| Command | Exit Code | Result |
|---|---:|---|
| Static scan of `crates/` and `apps/` production code (`.unwrap`/`.expect`/`panic!`/`#[allow(`/`unsafe`/`todo!`) | `0` | **0 violations** |
| BOM & inventory sync scan (`docs/feature-inventory.json`, `TRACEABILITY_MATRIX.md`, `README.md`, `OVERHAUL_REPORT.md`) | `0` | **0 BOM files** (pure UTF-8 RFC 8259 JSON, exact count parity across docs) |
| `cargo fmt --all -- --check` | `0` | 100% formatted cleanly |
| `cargo clippy --workspace --all-targets -- -D warnings` | `0` | 0 errors, 0 warnings |
| `cargo test --workspace --no-fail-fast` | `0` | **143 passed, 0 failed, 0 ignored** |
| `cargo build -p omni` | `0` | CLI binary built cleanly |
| `cargo check -p omni-desktop --features native-webview` | `0` | Native WebView feature builds cleanly |
| `cargo doc --workspace --no-deps` | `0` | 0 warnings |
| `node --check frontend/src/app.js` | `0` | Valid JS syntax |
| `cargo run -p omni-benchmarks` | `0` | Real in-process benchmarks executed; Unicode table aligned |
| `./target/debug/omni.exe --json inventory` | `0` | Synced `docs/feature-inventory.json`, `TRACEABILITY_MATRIX.md`, & `README.md` (129 verified, 0 implemented, 2 experimental, 1 unsupported = 132 ops) |
