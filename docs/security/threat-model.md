# OMNI Threat Model and Security Architecture

## 1. System Philosophy: Local-First & Zero-Trust Inputs

OMNI is a digital engineering multitool intended for security researchers, systems developers, forensics analysts, and DevOps engineers. Because OMNI processes untrusted binaries, raw network captures, cryptographic secrets, serialized messages, and user-supplied scripts, it operates under a strict **Zero-Trust Input Model**:

> *Every file, stream, buffer, packet capture, certificate, archive, and serialized payload is treated as hostile until validated.*

```
+-----------------------------------------------------------------------------------------+
|                                    USER WORKSTATION                                     |
|                                                                                         |
|  +--------------------+        +--------------------+        +-----------------------+  |
|  |     CLI / TUI      |        |   Web UI / Wry     |        |    REST / WS Client   |  |
|  +---------+----------+        +---------+----------+        +-----------+-----------+  |
|            |                             |                               |              |
|            +-----------------------------+-------------------------------+              |
|                                          |                                              |
|                                          v                                              |
|                       +--------------------------------------+                          |
|                       |        Unified API / IPC Layer       |                          |
|                       +------------------+-------------------+                          |
|                                          |                                              |
|                                          v                                              |
|                       +--------------------------------------+                          |
|                       |        Omni-Security Guardian        |                          |
|                       |  - Scope check (Loopback/Lab only)   |                          |
|                       |  - Path Traversal Guard (safe_join)  |                          |
|                       |  - Resource limits (Time, Mem, File) |                          |
|                       |  - Secret Redactor                   |                          |
|                       +------------------+-------------------+                          |
|                                          |                                              |
|                                          v                                              |
|                       +--------------------------------------+                          |
|                       |       Worker / Execution Engine      |                          |
|                       |  - Isolated threadpool execution     |                          |
|                       |  - Pure algorithmic parsing          |                          |
|                       |  - Streaming backpressure            |                          |
|                       +------------------+-------------------+                          |
|                                          |                                              |
|                                          v                                              |
|                       +--------------------------------------+                          |
|                       |    Local SQLite & Ephemeral Cache    |                          |
|                       +--------------------------------------+                          |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Threat Vectors and Mitigations

### 2.1 Malformed Archives & Decompression Bombs
- **Threat**: Attackers supply gzip/zip/tar archives that expand exponentially (e.g., "zip bombs" yielding terabytes from kilobytes) or contain directory traversal paths (`../../etc/passwd`).
- **Mitigation**:
  - `omni-storage::archives` and `omni-security::safe_extract` enforce strict decompression expansion limits (default: max 500 MB unpacked or 100x ratio limit).
  - Every extracted archive path is canonicalized through `safe_join()`, rejecting paths attempting to escape the temporary extraction root.
  - Symlinks pointing outside target extraction roots are discarded.

### 2.2 Hostile Binary & Packet Payloads
- **Threat**: Malformed ELF/PE binaries or craftily fragmented PCAP packets designed to trigger memory corruption or infinite loops in parsers.
- **Mitigation**:
  - Pure memory-safe Rust implementations throughout all dissectors and binary readers.
  - No C pointer arithmetic on raw inputs without explicit bounds-checked slices (`&[u8]`).
  - Integer overflow checks enabled across all parsing routines.
  - Enforced slice bounds: parsing routines consume structured zero-copy slices that terminate at slice boundaries without panicking.

### 2.3 Cryptographic Key Material Exposure
- **Threat**: Accidental leakage of private keys, symmetric keys, or plaintext in logs, terminal outputs, error messages, or remote network traffic.
- **Mitigation**:
  - Zero default remote transmission: private keys, certificates, and secrets NEVER leave the local process boundary.
  - Structured error logging runs all messages through `omni_security::redact_sensitive()`, which detects and masks PEM headers (`-----BEGIN PRIVATE KEY-----`), high-entropy hex strings, AWS credentials, and Bearer tokens.
  - Sensitive buffers are zeroed out on deallocation where supported (`secrecy` / `zeroize`).

### 2.4 Unauthorized Network Probing
- **Threat**: Accidental or unauthorized scanning of external internet ranges causing abuse flags or unauthorized access alerts.
- **Mitigation**:
  - Diagnostic tools (`omni-network::scanner`) require explicit target validation.
  - Target domains and IPs default strictly to `127.0.0.1`, `::1`, or RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - External target execution requires explicit `--allow-external` or confirmation flags.
  - Rate limiting is strictly enforced to prevent denial-of-service or burst traffic.
  - No evasion, stealth fragmentation, or exploit capabilities are implemented.

### 2.5 Denial of Service via Resource Exhaustion
- **Threat**: Long-running regexes (ReDoS), cyclic graph execution, or massive file uploads locking the UI or crashing the backend.
- **Mitigation**:
  - Regex evaluation limits: PCRE2/Rust `regex` engines run with bounded execution timeouts (default 2,000 ms) and recursion ceilings.
  - Pipeline DAGs are topologically sorted before execution; cycles are rejected immediately during validation.
  - File operations stream via fixed 64 KB chunk buffers rather than loading arbitrary multi-gigabyte files into RAM.
  - Background workers execute on detached Tokio tasks with `tokio::time::timeout` and cooperative cancellation tokens (`tokio_util::sync::CancellationToken`).

---

## 3. Sandboxing & Worker Isolation

Workloads are classified into three security tiers:

1. **Tier 1 (Safe / Pure Compute)**:
   - Encoders, standard ciphers, hashing, mathematical typesetting, color conversions.
   - Executed in-process directly on the worker threadpool.

2. **Tier 2 (Bounded Parsing / Complex Structured Formats)**:
   - PDF parsing, AST tree parsing, image format decoding, model inspection.
   - Executed with explicit byte-allocation caps and task timeouts.

3. **Tier 3 (System & Network I/O)**:
   - Socket listener, port diagnostics, filesystem inspection.
   - Enforces scope checking, loopback default constraints, and strict read-only access.
