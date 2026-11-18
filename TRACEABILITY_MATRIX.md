# OMNI Feature Traceability Matrix

Generated directly from `omni --json inventory` (`docs/feature-inventory.json`) so documentation stays synchronized with the compiled registry.

## Status Definitions
- `planned`: No working implementation exists.
- `in_progress`: Implementation is incomplete.
- `experimental`: Works with documented external dependencies or constraints (e.g. host `ffmpeg` or `tesseract`).
- `implemented`: Real implementation exists and compiles/executes, with baseline test coverage.
- `verified`: Real implementation verified against dedicated automated unit, security, or end-to-end tests.
- `unsupported`: Explicitly unsupported (returns clear error rather than simulating behavior).

## Summary Counts

| Status | Count |
|---|---:|
| `experimental` | 2 |
| `implemented` | 112 |
| `unsupported` | 1 |
| `verified` | 17 |
| **Total Registered Operations** | **132** |

## Complete Registered Operation Inventory

| Operation ID | Name | Category | Status | Multi-Input | Security | Limitations |
|---|---|---|---|---|---|---|
| `ai.model_inspect` | Model Architecture & GGUF/Safetensors Inspector | AiAndTensors | `verified` | No | `Safe` | Inspects GGUF and HuggingFace Safetensors headers; PyTorch pickle (.pt/.pth) and ONNX graph rendering are not implemented |
| `ai.quantize` | Quantization Simulator & Precision Metrics | AiAndTensors | `implemented` | No | `Safe` | None documented |
| `ai.tokenizer` | BPE Tokenizer Playground (tiktoken) | AiAndTensors | `verified` | No | `Safe` | Supports tiktoken BPE encodings (cl100k_base, o200k_base, p50k_base, r50k_base); SentencePiece/WordPiece/LLaMA model files require external vocabulary loading not bundled here |
| `ai.vector` | Vector Math & Distance Metrics Studio | AiAndTensors | `implemented` | No | `Safe` | None documented |
| `archive.toolkit` | Archive Toolkit & Decompression Bomb Guard | StorageAndFormats | `verified` | No | `Safe` | Supports ZIP, TAR, and GZIP inspection/decompression; BZIP2, XZ, Zstd, 7z, RAR, ISO 9660, VHD, and VMDK are not implemented |
| `audio.lufs` | EBU R128 & ITU-R BS.1770-4 Loudness Meter | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `audio.silence` | Audio Silence & RMS Threshold Detector | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `audio.waveform` | Audio Waveform & Spectral Analyzer | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `binary.disasm` | x86 / x86-64 Disassembler & CFG Generator | BinaryAnalysis | `verified` | No | `Safe` | Supports x86-16, x86-32, and x86-64 instruction sets via iced-x86; ARM, AArch64, RISC-V, and MIPS are not implemented |
| `binary.executable` | Multi-Format Executable & Checksec Inspector | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `binary.hex` | Hex Editor & Bitwise Operations Engine | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `binary.ieee754` | IEEE-754 Floating-Point Visualizer | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `checksum.adler32` | Checksum (ADLER32) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.crc16` | Checksum (CRC16) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.crc32` | Checksum (CRC32) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.crc32_castagnoli` | Checksum (CRC32_CASTAGNOLI) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.crc64` | Checksum (CRC64) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.crc8` | Checksum (CRC8) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.fletcher16` | Checksum (FLETCHER16) | Cryptography | `implemented` | No | `Safe` | None documented |
| `checksum.fletcher32` | Checksum (FLETCHER32) | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.13` | ROT13 | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.18` | ROT18 | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.47` | ROT47 | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.5` | ROT5 | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.affine` | Affine Cipher | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.atbash` | Atbash Cipher | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.enigma` | Enigma Rotor Simulator | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.morse` | Morse Code | Cryptography | `implemented` | No | `Safe` | None documented |
| `cipher.vigenere` | Vigenère Cipher | Cryptography | `implemented` | No | `Safe` | None documented |
| `cloud.container` | Container Forensics & Dockerfile Linter | CloudAndDevOps | `implemented` | No | `Safe` | None documented |
| `cloud.iac` | IaC Security & Cloud IAM Simulator | CloudAndDevOps | `implemented` | No | `Safe` | None documented |
| `code.ast_analysis` | AST Code Analysis & De-obfuscation | TextAndCode | `implemented` | No | `Safe` | None documented |
| `crypto.asymmetric.ed25519` | Ed25519 Digital Signatures | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.asymmetric.rsa` | RSA Toolkit | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.auth_signatures` | Signature & Auth Utilities | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.entropy.lsb_stego` | LSB Steganography Injector & Extractor | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.entropy.shannon` | Shannon Entropy Calculator | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.blake2b` | Hash (BLAKE2B) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.blake2s` | Hash (BLAKE2S) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.blake3` | Hash (BLAKE3) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.md5` | Hash (MD5) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.murmur3` | Hash (MURMUR3) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.ripemd160` | Hash (RIPEMD160) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha1` | Hash (SHA1) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha224` | Hash (SHA224) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha256` | Hash (SHA256) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha384` | Hash (SHA384) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha3_224` | Hash (SHA3_224) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha3_256` | Hash (SHA3_256) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha3_384` | Hash (SHA3_384) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha3_512` | Hash (SHA3_512) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha512` | Hash (SHA512) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha512_224` | Hash (SHA512_224) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.sha512_256` | Hash (SHA512_256) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.shake128` | Hash (SHAKE128) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.shake256` | Hash (SHAKE256) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.xxhash32` | Hash (XXHASH32) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.hash.xxhash64` | Hash (XXHASH64) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.jwt.debugger` | JWT / JWS Debugger | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.pki.x509_inspect` | X.509 Certificate Inspector | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.pqc.falcon` | Post-Quantum (FALCON) | Cryptography | `unsupported` | No | `Safe` | No audited pure-Rust NIST-finalized FN-DSA crate is bundled; operation returns unsupported error rather than simulating cryptography |
| `crypto.pqc.ml_dsa` | Post-Quantum (ML-DSA) | Cryptography | `verified` | No | `Safe` | Uses ML-DSA-65 (NIST Level 3) parameter set with empty context string by default |
| `crypto.pqc.ml_kem` | Post-Quantum (ML-KEM) | Cryptography | `verified` | No | `Safe` | Uses ML-KEM-768 (NIST Level 3) parameter set; secret keys are returned hex-encoded only when explicitly requested via action='keygen' |
| `crypto.pqc.sphincs_plus` | Post-Quantum (SPHINCS_PLUS) | Cryptography | `verified` | No | `Safe` | Uses SLH-DSA-SHA2-128f parameter set; signing is computationally heavier than lattice schemes |
| `crypto.symmetric.aes_128_gcm` | Symmetric Cipher (AES-128-GCM) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.symmetric.aes_256_gcm` | Symmetric Cipher (AES-256-GCM) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.symmetric.chacha20poly1305` | Symmetric Cipher (CHACHA20POLY1305) | Cryptography | `implemented` | No | `Safe` | None documented |
| `crypto.symmetric.rc4` | Symmetric Cipher (RC4) | Cryptography | `implemented` | No | `Safe` | None documented |
| `doc.diagram_compiler` | Diagram-as-Code Compiler (Mermaid / DOT) | DocumentsAndMedia | `verified` | No | `Safe` | Supports Mermaid graph/flowchart syntax and Graphviz DOT directed edges; sequence/Gantt/PlantUML/D2/Vega-Lite are not supported by the built-in offline renderer |
| `doc.font_toolkit` | Font Toolkit & Inspector | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `doc.math_typeset` | Mathematical Typesetting (LaTeX subset -> SVG / MathML) | DocumentsAndMedia | `verified` | No | `Safe` | Supports a practical LaTeX math subset (\frac, \sqrt, ^, _, Greek letters, common operators); full TeX macro expansion and matrices are not supported |
| `doc.transcode` | Document Transcoder | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `encode.base16` | Base16 (Hex) | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base32` | Base32 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base32hex` | Base32Hex | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base45` | Base45 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base58` | Base58 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base62` | Base62 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base64` | Base64 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base64url` | Base64URL | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base85` | Base85 (Ascii85) | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.base91` | Base91 | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.html_entities` | HTML4 / HTML5 Entities | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.octal_escapes` | Octal Escapes | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.punycode` | Punycode / IDNA | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.quoted_printable` | Quoted-Printable | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.unicode_escapes` | Unicode Escapes | Encoders | `implemented` | No | `Safe` | None documented |
| `encode.url` | URL Percent Encoding | Encoders | `implemented` | No | `Safe` | None documented |
| `firmware.extract` | Firmware Signature Scanner & Entropy Mapper | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `fs.forensics` | Filesystem & Partition Forensics | StorageAndFormats | `implemented` | No | `Safe` | None documented |
| `geo3d.inspect` | 3D Mesh & Geometry Inspector | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `geo3d.shader` | Shader AST & Syntax Validator | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `hardware.can` | CAN Bus Log & OBD-II Decoder | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `hardware.serial` | Serial/UART Protocol Inspector | BinaryAnalysis | `implemented` | No | `Safe` | None documented |
| `image.color_space` | Color Space & Delta-E 2000 Engine | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `image.metadata` | Image EXIF & Metadata Forensics | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `image.pipeline` | Multi-Format Image Processor | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `kdf.argon2d` | Password Hash / KDF (ARGON2D) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.argon2i` | Password Hash / KDF (ARGON2I) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.argon2id` | Password Hash / KDF (ARGON2ID) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.bcrypt` | Password Hash / KDF (BCRYPT) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.hkdf` | Password Hash / KDF (HKDF) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.pbkdf2` | Password Hash / KDF (PBKDF2) | Cryptography | `implemented` | No | `Safe` | None documented |
| `kdf.scrypt` | Password Hash / KDF (SCRYPT) | Cryptography | `implemented` | No | `Safe` | None documented |
| `media.probe` | Media Container & Codec Probe | DocumentsAndMedia | `verified` | No | `Safe` | None documented |
| `media.transcode` | FFmpeg Media Transcoder | DocumentsAndMedia | `experimental` | No | `Safe` | Actual media transcoding requires the `ffmpeg` executable to be installed on the host PATH (or supplied via config.ffmpeg_path); Supported codecs are allowlisted (libx264, libx265, libvpx-vp9, libaom-av1, copy, aac, libopus, libmp3lame, flac, pcm_s16le) |
| `net.dns` | DNS Wire Encoder, Decoder & Scoped UDP Resolver | Networking | `verified` | No | `NetworkAccess` | Live UDP queries default to local/private resolvers unless config.allow_external=true is explicitly set; DoH, DoT, DoQ, DNSSEC cryptographic validation, and WHOIS/RDAP are not implemented in this module |
| `net.http_client` | cURL Parser & Multi-Language HTTP Code Generator | Networking | `verified` | No | `Safe` | Offline parser and code generator only; does not transmit live HTTP requests unless an external HTTP client is invoked |
| `net.ip_calc` | CIDR & Subnet Calculator | Networking | `implemented` | No | `Safe` | None documented |
| `net.scanner` | Authorized Lab Network Scanner | Networking | `implemented` | No | `Safe` | None documented |
| `net.socket` | Socket Stream & Latency Tester | Networking | `implemented` | No | `Safe` | None documented |
| `pcap.dissect` | PCAP & PCAPNG Deep Packet Dissector | Networking | `implemented` | No | `Safe` | None documented |
| `pcap.reassemble` | TCP Stream Reassembler & Payload Carver | Networking | `implemented` | No | `Safe` | None documented |
| `pdf.internals` | PDF Structure & Stream Inspector | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `pdf.multitool` | PDF Multi-Tool | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `pdf.ocr` | PDF Text Extractor & Tesseract OCR Runner | DocumentsAndMedia | `experimental` | No | `Safe` | Embedded PDF text extraction reads existing PDF text streams via lopdf (no synthetic bounding boxes); Optical character recognition (mode='tesseract' or raster image input) requires `tesseract` installed on host PATH |
| `pdf.scrubber` | PDF Metadata Sanitizer & Scrubber | DocumentsAndMedia | `implemented` | No | `Safe` | None documented |
| `pipeline.concat` | Pipeline Multi-Input Concatenation | TextAndCode | `verified` | Yes | `Safe` | None documented |
| `pipeline.merge` | Pipeline Multi-Input JSON Merge | TextAndCode | `verified` | Yes | `Safe` | None documented |
| `query.structured` | Structured Query & Extraction (jq / JSONPath) | TextAndCode | `implemented` | No | `Safe` | None documented |
| `storage.binary_formats` | Binary Serialization Decoder (Protobuf/MsgPack/ASN.1) | StorageAndFormats | `implemented` | No | `Safe` | None documented |
| `storage.sql` | In-Memory SQL Analytics Engine (SQLite) | StorageAndFormats | `verified` | No | `Safe` | Backed by embedded in-memory SQLite (DuckDB and Parquet native ingestion are not bundled); Restricted strictly to read-only SELECT/WITH/EXPLAIN queries |
| `system.color` | Color Toolkit & WCAG Contrast Engine | SystemDiagnostics | `implemented` | No | `Safe` | None documented |
| `system.cron` | Cron Parser & Execution Scheduler | SystemDiagnostics | `implemented` | No | `Safe` | None documented |
| `system.flamegraph` | Folded Stack & SVG Flamegraph Generator | SystemDiagnostics | `verified` | No | `Safe` | None documented |
| `system.ids` | Universal Identifier Toolkit | SystemDiagnostics | `implemented` | No | `Safe` | None documented |
| `system.trace` | Syscall & Process Trace Analyzer | SystemDiagnostics | `implemented` | No | `Safe` | None documented |
| `text.diff` | Text Diff & Analysis | TextAndCode | `verified` | Yes | `Safe` | None documented |
| `text.encodings` | Character Encoding Converter | TextAndCode | `implemented` | No | `Safe` | None documented |
| `text.regex_studio` | Regex Studio | TextAndCode | `implemented` | No | `Safe` | None documented |
| `text.string_transformers` | String Transformers & Phonetics | TextAndCode | `implemented` | No | `Safe` | None documented |
| `transpile.structured` | Omni-Format Transpiler | TextAndCode | `implemented` | No | `Safe` | None documented |
