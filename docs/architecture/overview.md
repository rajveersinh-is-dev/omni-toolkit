# OMNI Architecture Overview

OMNI is structured around three foundational pillars engineered for reliability, safety, performance, and extensibility.

```
                                  +-----------------------------+
                                  |       USER INTERFACES       |
                                  |  +-----+  +-----+  +-----+  |
                                  |  | CLI |  | TUI |  | GUI |  |
                                  +--+--+--+--+--+--+--+--+--+--+
                                        |        |        |
                                        v        v        v
                                  +-----------------------------+
                                  |    API / TRANSPORT LAYER    |
                                  |  - Axum REST API (OpenAPI)  |
                                  |  - WebSocket Progress Stream|
                                  |  - In-Process Channel API   |
                                  +--------------+--------------+
                                                 |
                                                 v
+-----------------------------------------------------------------------------------------------+
|                                    OMNI CORE ENGINE                                           |
|                                                                                               |
|  +-----------------------+   +-----------------------+   +---------------------------------+  |
|  |   Operation Registry  |   |   Pipeline Orchestrator|  |       Worker Scheduler          |  |
|  |  - Manifest Catalog   |   |  - DAG Validation     |   |  - Tokio Threadpool Isolation   |  |
|  |  - Type Verification  |   |  - Topological Sort   |   |  - Cooperative Cancellation     |  |
|  |  - Fuzzy Search Index |   |  - Streaming Backpress|   |  - Timeout & Resource Bounds    |  |
|  +-----------+-----------+   +-----------+-----------+   +----------------+----------------+  |
|              |                           |                                |                   |
|              +---------------------------+--------------------------------+                   |
|                                          |                                                    |
|                                          v                                                    |
|                       +--------------------------------------+                                |
|                       |       Domain Operation Crates        |                                |
|                       |  - omni-encoders   - omni-crypto     |                                |
|                       |  - omni-text       - omni-code       |                                |
|                       |  - omni-documents  - omni-pdf        |                                |
|                       |  - omni-media      - omni-network    |                                |
|                       |  - omni-pcap       - omni-binary     |                                |
|                       |  - omni-firmware   - omni-filesystems|                                |
|                       |  - omni-infra      - omni-ai         |                                |
|                       |  - omni-system     - omni-storage    |                                |
|                       +------------------+-------------------+                                |
|                                          |                                                    |
|                                          v                                                    |
|                       +--------------------------------------+                                |
|                       |    Storage & Persistence Layer       |                                |
|                       |  - SQLite Metadata & Job History     |                                |
|                       |  - Ephemeral Zero-Copy File Buffers  |                                |
|                       |  - Safe Sandboxed Artifact Store     |                                |
|                       +--------------------------------------+                                |
+-----------------------------------------------------------------------------------------------+
```

## Pillar A: Unified Processing Engine

Every operation in OMNI adheres to the `Operation` trait defined in `omni-core`. 

### Key Characteristics:
1. **Machine-Readable Manifest**: Exposes unique ID, name, version, input/output MIME types, schema parameters, security level, and streaming capabilities.
2. **Typed Contracts**: Inputs and outputs use `DataPayload`:
   - `Text(String)`
   - `Bytes(Vec<u8>)`
   - `Stream(BoxStream<'static, Result<Bytes, OmniError>>)`
   - `Json(serde_json::Value)`
   - `FileRef(PathBuf)`
3. **Composability**: Operations can be chained into multi-stage DAG pipelines with automated type compatibility verification and backpressure.

---

## Pillar B: Asynchronous Backend & Orchestration

The backend is built with Tokio and Axum:
- **Registry**: Discovers all registered operations across crates, provides instant fuzzy lookup, capability filtering, and JSON schema output.
- **Job Manager**: Tracks execution states (`Pending`, `Running`, `Completed`, `Failed`, `Cancelled`), streams real-time progress via WebSockets, and enforces execution timeouts.
- **Persistence**: Employs SQLite via `rusqlite` for local metadata, history with privacy redaction, and saved pipeline configurations.
- **Security Guardian**: Sanitizes inputs, prevents directory traversal, redacts credentials, and guards against zip bombs.

---

## Pillar C: Three First-Class Interfaces

1. **CLI (`omni`)**:
   - Standard UNIX filter semantics (`cat input.json | omni text query jq '.data' | omni encode base64`).
   - Command hierarchy organized intuitively by domain (`omni crypto`, `omni binary`, `omni net`).
   - Machine-readable JSON output mode (`--json`) for automation.

2. **TUI (`omni-tui`)**:
   - Terminal application powered by Ratatui and Crossterm.
   - Global search, category browser, live hex visualizer, interactive parameter forms, and pipeline runner.

3. **Desktop & Browser GUI (`omni-desktop` & Web)**:
   - Modern, responsive local web interface and desktop shell.
   - Interactive visual node-based pipeline builder with live previews, command palette (`Ctrl+K`), rich inspector views (Hex, AST, PCAP, Media, Disassembly).
