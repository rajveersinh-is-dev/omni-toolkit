# Contributing to OMNI

Thank you for your interest in contributing to **OMNI — The Universal Digital Engineering Toolkit**!

## Core Engineering Principles

1. **Rust-First**: Core logic, backend, pipeline execution, CLI, and TUI must be implemented in clean, safe Rust.
2. **Computational Honesty**: No fake stubs, no hardcoded benchmark values, no mock implementations returning pre-canned responses. Every feature must execute the real algorithm.
3. **Purity & Type Safety**:
   - Zero `panic!()` in code generators and runtime pipelines.
   - Zero unhandled `.unwrap()` on external inputs.
   - Strict compiler warning compliance: code must compile cleanly with `cargo clippy --all-targets -- -D warnings`.
4. **Local-First & Privacy**: Sensitive data must remain on the user's machine. Never send file contents or keys to remote endpoints.
5. **Comprehensive Tests**: Every operation must have unit tests, validation boundary checks, and property/differential tests where applicable.

## Development Workflow

### Prerequisites
- Rust 1.80+ (stable toolchain)
- Node.js 20+ (for frontend web assets)
- Git

### Building the Workspace
```bash
# Check the entire workspace
cargo check

# Run all unit and integration tests
cargo test

# Run linter
cargo clippy --all-targets -- -D warnings

# Build all binaries (CLI, TUI, Desktop)
cargo build --release
```

### Adding a New Operation
1. Create or extend the operation module under the relevant crate (`crates/omni-*`).
2. Implement the `Operation` trait from `omni-core`.
3. Provide a complete `OperationManifest` with schemas, capability tags, input/output types, and documentation.
4. Register the operation in `omni-registry`.
5. Add unit tests and integration tests verifying both valid execution and failure modes.
6. Update `TRACEABILITY_MATRIX.md`.

## Commit Conventions
We use Conventional Commits:
- `feat(crypto)`: add ChaCha20-Poly1305 AEAD operation
- `fix(pipeline)`: resolve topological cycle check in DAG validator
- `docs(api)`: document WebSocket job progress streaming protocol
- `test(pcap)`: add dissection tests for fragmented IPv4 UDP packets
- `perf(engine)`: eliminate intermediate allocations in streaming hex visualizer
