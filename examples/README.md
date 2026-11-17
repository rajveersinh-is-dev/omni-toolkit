# OMNI Code Examples & Recipes

This directory contains standalone, runnable examples demonstrating how to embed OMNI's core crates and pipeline capabilities into your own Rust projects.

---

## Available Examples

1. **`pipeline_composition`**:
   - Demonstrates programmatic construction of a directed acyclic graph (DAG) using `PipelineDefinition` and asynchronous execution via `PipelineExecutor`.
   - Run:
     ```bash
     cargo run -p omni-examples --bin pipeline_composition
     ```

2. **`custom_operation`**:
   - Demonstrates how to create a custom operation implementing `omni_core::Operation`, declaring its `OperationManifest`, and registering it in `OperationRegistry`.
   - Run:
     ```bash
     cargo run -p omni-examples --bin custom_operation
     ```

3. **`streaming_hash`**:
   - Demonstrates calculating SHA-256 and BLAKE3 digests over in-memory byte buffers using `DataPayload::bytes`.
   - Run:
     ```bash
     cargo run -p omni-examples --bin streaming_hash
     ```
