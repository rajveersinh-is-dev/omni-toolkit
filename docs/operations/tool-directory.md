# OMNI Tool Directory (All 64 Tools)

This directory provides the canonical reference for all 64 operations available in OMNI v0.1.0 across all 10 core engineering categories.

---

## Category 1: Universal Encoders & Hashes
1. `encode.base16`: Hexadecimal encoder and decoder.
2. `encode.base32`: RFC 4648 Base32 encoder and decoder with padding options.
3. `encode.base45`: QR-code compatible Base45 encoder and decoder.
4. `encode.base58`: Bitcoin/IPFS Base58 encoder and decoder.
5. `encode.base62`: Alphanumeric Base62 encoder and decoder.
6. `encode.base64`: Standard and URL-safe Base64 encoder and decoder.
7. `encode.base85`: Ascii85 and Adobe Base85 encoder and decoder.
8. `encode.base91`: BasE91 high-density binary-to-text encoder and decoder.
9. `encode.url`: RFC 3986 percent-encoding and decoding.
10. `encode.punycode`: RFC 3492 Internationalized Domain Names (IDN) Punycode converter.
11. `encode.html_entities`: HTML entity encoder and decoder (named and numeric).
12. `encode.quoted_printable`: MIME quoted-printable encoder and decoder.
13. `encode.unicode_escapes`: Unicode escape sequence parser and formatter (`\uXXXX`).
14. `encode.octal_escapes`: Octal and raw byte escape sequence converter.
15. `crypto.hash.sha256`: SHA-256 cryptographic hash computation.
16. `crypto.hash.blake3`: High-performance BLAKE3 cryptographic hash function.
17. `crypto.checksum.crc32`: IEEE 802.3 and Castagnoli CRC-32 checksum calculator.

---

## Category 2: Cryptography & Ciphers
18. `crypto.cipher.rot13`: Classical Caesar ROT-5/13/18/47 substitution ciphers.
19. `crypto.cipher.atbash`: Classical Hebrew Atbash reciprocal substitution cipher.
20. `crypto.cipher.aes_gcm`: Authenticated AES-128 and AES-256 GCM encryption and decryption.
21. `crypto.steganography`: Least Significant Bit (LSB) image payload embedder and extractor.
22. `crypto.entropy`: Shannon entropy calculator and bit randomness estimator.

---

## Category 3: Text & Code Engineering
23. `transpile.structured`: Bidirectional transcoder between JSON, YAML, TOML, CSV, and TSV.
24. `text.diff`: Myers diff algorithm with character-, word-, and line-level delta reporting.
25. `text.regex_studio`: Regular expression analyzer, syntax visualizer, and ReDoS guard.
26. `text.string_transformers`: Case transformations (camel, snake, kebab), slugification, and Soundex.
27. `code.deobfuscator`: Dean Edwards unpacker, hex identifier deobfuscator, and dead-branch optimizer.
28. `code.analyzer`: Multi-language symbol extraction, function counts, and cyclomatic complexity analysis.

---

## Category 4: Documents & PDF Forensics
29. `doc.markdown_to_html`: Markdown parser and HTML generator.
30. `doc.math_typeset`: TeX and MathML formula compiler to vector SVG.
31. `doc.diagram_compiler`: Mermaid and Graphviz diagram-as-code compiler to vector SVG.
32. `pdf.internals`: PDF cross-reference table, object dictionary, and FlateDecode stream inspector.
33. `pdf.multitool`: PDF page rotation, merging, splitting, and form-field extraction.
34. `pdf.scrubber`: Irreversible metadata and `/Info` dictionary sanitization.

---

## Category 5: Media & 3D Processing
35. `media.probe`: MP4 atom box inspector, MKV EBML parser, and WAV chunk analyzer.
36. `media.transcode`: FFmpeg filter graph command builder and codec transcode parameter generator.
37. `audio.lufs`: EBU R128 integrated loudness, momentary max, and true-peak metering.
38. `audio.silence`: Sliding-window RMS silence detector and timestamp segmenter.
39. `audio.waveform`: Audio peak downsampler and waveform visualizer data generator.
40. `geo3d.inspect`: Wavefront OBJ and STL 3D mesh analyzer (vertices, facets, bounding box).
41. `geo3d.shader`: GLSL and WGSL shader syntax validator and uniform reflector.

---

## Category 6: Networking & PCAP Dissection
42. `net.socket`: Low-level TCP and UDP loopback probe and latency benchmark.
43. `net.scanner`: Authorized RFC 1918 private lab port scanner and Wake-on-LAN generator.
44. `net.dns`: RFC 1035 wire packet encoder and decoder for A, AAAA, MX, TXT, and CNAME records.
45. `net.http_client`: cURL command parser and code generator for Rust, Python, Go, and Node.js.
46. `net.ip_calc`: IPv4 and IPv6 CIDR subnet calculator and VLSM splitter.
47. `pcap.dissect`: PCAP and PCAPNG protocol dissector for Ethernet, IPv4, TCP, UDP, ICMP, DNS, and TLS.
48. `pcap.reassemble`: TCP stream reassembler and HTTP payload carver.

---

## Category 7: Binary Analysis & Firmware
49. `binary.hex`: Interactive hex dump viewer, binary diffing, byte swap, and bitwise operations.
50. `binary.ieee754`: IEEE-754 32-bit single and 64-bit double precision float bit visualizer.
51. `binary.executable`: ELF, PE, Mach-O, and WASM binary parser with checksec security analysis.
52. `binary.disasm`: Multi-architecture disassembler (x86/x64) with basic block and CFG generation.
53. `hardware.serial`: UART 8-N-1 / 7-E-1 parity framing simulator and baud timing calculator.
54. `hardware.can`: Linux candump log parser and OBD-II automotive PID diagnostic decoder.
55. `firmware.extract`: Binwalk-compatible signature scanner and block entropy heat mapper.

---

## Category 8: Storage & Filesystems
56. `storage.sql`: In-memory SQLite analytics engine querying CSV, TSV, and JSON tabular data.
57. `storage.binary_formats`: Schema-less Protobuf wire format decoder, MessagePack, and ASN.1 DER parser.
58. `archive.toolkit`: Safe ZIP, TAR, and GZIP creator and extractor with decompression bomb limits.
59. `fs.forensics`: MBR partition table reader, GPT header parser, and ext2/3/4 superblock analyzer.

---

## Category 9: Cloud & Infrastructure
60. `cloud.container`: Dockerfile security linter (CIS benchmarks) and OCI layer bloat auditor.
61. `cloud.iac`: Kubernetes manifest security auditor, Terraform plan analyzer, and IAM policy evaluator.

---

## Category 10: AI, Tensors & System Diagnostics
62. `ai.model_inspect`: GGUF and Safetensors neural model header parser and VRAM estimator.
63. `ai.tokenizer`: Subword token boundary highlighter with visual breakdown and compression ratios.
64. `ai.vector`: High-dimensional vector distance calculator (Cosine, L1, L2, Chebyshev, Top-K).
65. `ai.quantize`: INT8, INT4, and BF16 quantization simulation with error metrics (MSE, SNR, PSNR).
66. `system.trace`: strace and eBPF syscall latency percentile analyzer and file descriptor leak tracker.
67. `system.cron`: 5-field cron syntax parser, human description generator, and upcoming schedule calculator.
68. `system.ids`: UUID v4/v7 generator, ULID timestamp decoder, and Twitter Snowflake deconstructor.
69. `system.color`: WCAG 2.1 color contrast compliance calculator and color blindness simulator.
70. `system.flamegraph`: Folded stack trace parser and interactive vector SVG flamegraph generator.
