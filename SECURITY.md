# Security Policy & Architecture

**OMNI — The Universal Digital Engineering Toolkit** is engineered as a local-first security and forensics platform. All user inputs are treated as untrusted.

---

## 1. Implemented Security Controls

### API & Network Exposure (`crates/omni-api`, `apps/cli`)
- **Explicit CORS Allowlist**: `omni-api` rejects untrusted cross-origin requests and never combines wildcard origins with credentials. Default origins are strictly loopback (`http://127.0.0.1:<port>`, `http://localhost:<port>`, `wry://localhost`).
- **Bearer Authentication**: Constant-time token verification (`Authorization: Bearer <token>` or `X-Omni-Token`) protects API routes and WebSocket upgrades whenever `auth_token` is configured. `omni serve` refuses to bind to non-loopback addresses without `--auth-token` (unless `--allow-unauthenticated-remote` is explicitly passed).
- **Request & Timeout Bounds**: Request bodies are capped by `DefaultBodyLimit` (default 16 MB); client-supplied execution timeouts are clamped to `max_timeout_seconds` (default 120s).
- **WebSocket Isolation**: `/api/v1/ws/jobs` validates auth tokens, enforces a concurrent connection semaphore (`max_ws_connections`), supports strict per-job filtering (`?job_id=<id>`), handles lagged consumers, and bounds per-frame send time.

### Desktop WebView Boundary (`apps/desktop`)
- When built with `--features native-webview`, `omni-desktop` binds to an ephemeral loopback port (`127.0.0.1:0`), generates a per-launch random UUID session token, and installs a `wry` navigation handler restricting navigation strictly to `http://127.0.0.1:<port>`.
- The frontend (`frontend/`) makes zero external network requests (no third-party CDN scripts or external web fonts) and renders API outputs via safe DOM text nodes (`textContent`) rather than unsanitized HTML injection.

### Filesystem & Archive Safety (`crates/omni-security`, `crates/omni-filesystems`)
- **Traversal & Symlink Protection**: `safe_join` and `safe_join_no_symlinks` reject null bytes, `..`, absolute/prefix paths, and canonicalize existing ancestors/components to block symlink escapes outside the sandbox directory.
- **Atomic File Creation**: `safe_create_new_file` uses `OpenOptions::create_new(true)` to prevent accidental overwrites and symlink TOCTOU races.
- **Decompression Bomb Protection**: `ResourceLimits::check_decompression` uses overflow-safe `u128` multiplication (preventing integer-division truncation bypasses) to enforce a 100x expansion ratio cap and 500 MB uncompressed ceiling across GZIP, ZIP, and TAR streams.

### Operation-Specific Guards
- **Network Scope**: `validate_network_target` constrains `net.scanner` and `net.dns` live queries to loopback and RFC 1918 private subnets unless `allow_external: true` is explicitly configured.
- **SQL Read-Only Guard**: `storage.sql` restricts queries to `SELECT` / `WITH` / `EXPLAIN` and rejects `ATTACH`, `DETACH`, and `LOAD_EXTENSION`.
- **Subprocess Safety**: `media.transcode` (`ffmpeg`) and `pdf.ocr` (`tesseract`) invoke executables directly via `tokio::process::Command` with allowlisted parameters and zero shell interpolation.
- **Secret & Path Redaction**: `redact_secrets` and `sanitize_error_message` mask PEM private keys, AWS keys, GitHub tokens, Bearer tokens, secret key-value pairs, and local user home paths before logging or returning errors.

---

## 2. Known Residual Risks & Limitations

- **No OS Kernel Sandboxing**: Worker isolation currently relies on Tokio task boundaries, concurrency semaphores, cancellation/timeouts, and Rust memory safety. OS-level process sandboxing (e.g., Linux `seccomp`/`landlock`, Windows Job Objects/AppContainer) is not yet implemented.
- **External Binaries**: When `ffmpeg` or `tesseract` are installed and executed by the user, those subprocesses run with the user's standard OS permissions (bounded by timeouts and temporary directory cleanup).
- **Local Unauthenticated Mode**: When running `omni serve` on `127.0.0.1` without `--auth-token`, any local process on the same host can call the loopback API. Pass `--auth-token` for multi-user workstations.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in OMNI:
1. Do **not** open a public GitHub issue with exploit details.
2. Contact the maintainer privately or use GitHub Security Advisories for `rajveersinh-is-dev/omni-toolkit`.
3. Provide reproduction steps, affected crate/version, and impact assessment.
