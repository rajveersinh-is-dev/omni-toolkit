# Changelog

All notable changes to **OMNI — The Universal Digital Engineering Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-17

### Added
- **Core Processing Engine**: Typed input/output contracts (`DataPayload`, `Value`, `MimeType`), stream processing, cancellation, backpressure, and resource limits.
- **Dynamic Pipeline DAG Engine**: Topological DAG resolution, parallel branch scheduling, cycle detection, intermediate artifact management, and JSON pipeline import/export.
- **Backend & Worker Pool**: Axum REST API and WebSocket progress server, Tokio threadpool worker isolation, timeout and memory protections.
- **Metadata Persistence**: SQLite storage engine for job tracking, pipeline persistence, execution audit logs, and user preferences.
- **Triple Interface Support**:
  - `omni` CLI with UNIX pipe streaming (`cat file | omni ...`), batch processing, and JSON output.
  - `omni-tui` Ratatui terminal UI with category browsing, global fuzzy search, interactive runner, and hex viewer.
  - Desktop & Browser Web GUI with interactive visual pipeline builder, rich viewer components (hex, tree, table, diff, disassembler, media).
- **10 Core Functional Categories**:
  - Category 1: Universal Encoders, Legacy Ciphers, Modern/PQC Cryptography, Hashes, Checksums, KDF, JWT debugger, Certificates & Steganography.
  - Category 2: Omni-Format Transpiler (JSON, YAML, TOML, XML, CSV, TSV, INI, Properties, HCL), Query engines (jq, XPath, JMESPath), AST tools, Text Diffing, Regex Studio, String Transformers, Multi-Encoding Support.
  - Category 3: Document Transcoder, Mathematical Typesetting (LaTeX/MathML to SVG), Font Toolkit (OTF/TTF/WOFF/WOFF2), PDF Multi-Tool, PDF Internals Inspector, Diagram-as-Code.
  - Category 4: Media Containers & Codecs, Audio Metering (LUFS, FFT, waveform), Raster Graphics (JPEG, PNG, WebP, QOI), Color Management (CIE-XYZ, CIELAB, sRGB), Image Optimization & Vectorization, EXIF/GPS scrubbing, 3D Asset Inspection, Shader Pipeline.
  - Category 5: Low-Level Sockets, Authorized Lab Scanning, DNS Power Suite (DoH, DoT, DNSSEC), HTTP/WebSocket/gRPC clients, Mock Server, cURL Parser & Multi-language Code Generator, PCAP/PCAPNG Dissector, Subnetting.
  - Category 6: Interactive Hex Viewer & Editor, IEEE-754 Visualizer, Executable Analysis (ELF, PE, Mach-O, WASM), Checksec Security Properties, Disassembly & CFG Generation, Hardware Serial & CAN bus log parser, Firmware Signature Scanner.
  - Category 7: Embedded Analytics (DuckDB/SQLite SQL over CSV/Parquet/JSON), Binary Serialization (Protobuf wire, MsgPack, CBOR, BSON), Archive Toolkit (safe limits), Disk Images & Partition Tables (MBR, GPT, FAT, ext, NTFS).
  - Category 8: Container Offline Inspection (OCI/Docker layers, Dockerfile linter), Kubernetes Manifest Validation, Terraform Plan Analysis, Cloud IAM Simulation.
  - Category 9: Model Inspection (GGUF, Safetensors, ONNX, PyTorch), Tokenizer Playground (BPE, WordPiece, tiktoken), Vector Math Sandbox, Quantization Visualizer.
  - Category 10: System Tracing Parser (strace/dtruss), Cron & Timers, Identifier Engine (UUID v1-v7, ULID, Snowflake), Color Toolkit & WCAG Contrast, Performance Profiling & SVG Flamegraphs.
