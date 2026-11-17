# OMNI Pipeline Engine

## 1. Concept and Design

The OMNI Pipeline Engine allows users to chain operations into sophisticated processing pipelines.

Examples:
- **PCAP Decryption Pipeline**:
  `PCAP file -> HTTP payload extraction -> AES-GCM decryption -> GZIP decompression -> Protobuf decoding -> JSON output`
- **Reverse Engineering Pipeline**:
  `ELF executable -> Header inspection -> Section extraction -> Symbol analysis -> Disassembly -> Control-Flow Graph -> SVG export`
- **Forensic Media Pipeline**:
  `Raw Disk Image -> Partition table inspection -> Carve JPEG -> EXIF extraction -> GPS coordinate map`

## 2. Pipeline Representation

A pipeline is defined as a Directed Acyclic Graph (DAG) serialized in JSON:

```json
{
  "id": "pcap-extract-decrypt",
  "name": "PCAP Decrypt & Decompress",
  "nodes": [
    {
      "id": "input_pcap",
      "operation_id": "net.pcap_dissect",
      "config": { "filter": "tcp.port == 443" }
    },
    {
      "id": "decrypt_payload",
      "operation_id": "crypto.symmetric",
      "config": { "cipher": "aes-256-gcm", "key": "...", "mode": "decrypt" }
    },
    {
      "id": "decompress_gzip",
      "operation_id": "archive.toolkit",
      "config": { "action": "decompress", "format": "gzip" }
    }
  ],
  "edges": [
    { "from_node": "input_pcap", "to_node": "decrypt_payload" },
    { "from_node": "decrypt_payload", "to_node": "decompress_gzip" }
  ]
}
```

## 3. Validation Rules
Before execution, the pipeline validator verifies:
1. **Acyclicity**: Uses Kahn's algorithm or DFS cycle detection. Cycles produce an immediate validation error.
2. **Type Compatibility**: The output data type (MIME type or `DataType`) of the upstream node must be convertible to the input data type expected by the downstream node.
3. **Configuration Conformance**: Every node's configuration is validated against the operation's JSON schema.
4. **Permissions & Security**: High-privilege operations (e.g., raw sockets) require explicit execution approval.

## 4. Execution Model
- **Parallel Branches**: Independent nodes are executed concurrently using Tokio asynchronous tasks.
- **Backpressure & Streaming**: For stream-capable operations, fixed-capacity channels prevent unconstrained memory accumulation.
- **Cancellation**: A cooperative `CancellationToken` is passed to every node, allowing instantaneous cancellation upon user request or failure in an upstream branch.
