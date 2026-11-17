# Pipeline Composition & DAG Execution

OMNI features a deterministic, directed acyclic graph (DAG) pipeline orchestration engine. Pipelines allow chaining multiple heterogeneous operations (such as hash calculation, base encoding, decompression, and protocol parsing) with strict type validation, cycle detection, and parallel branch execution.

---

## 1. Pipeline Definition Schema

A pipeline is defined in a standard JSON format consisting of an array of `nodes` and directed `edges`:

```json
{
  "id": "hash_and_hex",
  "name": "SHA-256 and Hex Encode",
  "description": "Calculates SHA-256 and converts to hex",
  "nodes": [
    {
      "id": "node_hash",
      "operation_id": "crypto.hash.sha256",
      "config": {}
    },
    {
      "id": "node_hex",
      "operation_id": "encode.base16",
      "config": {}
    }
  ],
  "edges": [
    {
      "from_node": "node_hash",
      "to_node": "node_hex"
    }
  ]
}
```

---

## 2. Validating Pipelines

Before executing a pipeline, validate that there are no circular dependencies and that all node operation IDs exist in the registry:

```bash
omni pipeline validate docs/pipeline-examples/hash_and_hex.json
```

Output:
```
Pipeline is valid. Execution order: ["node_hash", "node_hex"]
```

---

## 3. Executing Pipelines

Pipelines can be executed directly via the CLI, with input provided via standard input or from a file:

```bash
# Provide input from a file
omni pipeline run docs/pipeline-examples/hash_and_hex.json sample.txt

# Or pipe input from stdin and request JSON summary
cat sample.txt | omni --json pipeline run docs/pipeline-examples/hash_and_hex.json
```

The output JSON captures the evaluated output of each node in the DAG:
```json
{
  "node_hash": {
    "type": "Text",
    "data": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
  },
  "node_hex": {
    "type": "Text",
    "data": "35653838343839386461323830343731..."
  }
}
```

---

## 4. Multi-Branch DAG Execution

Pipelines support branching where a single source node feeds multiple downstream operations in parallel. For instance, an input stream can be sent simultaneously to:
1. `crypto.hash.sha256` (checksum calculation)
2. `binary.hex` (hex dump generation)
3. `firmware.extract` (entropy mapping)

Each downstream node executes safely with Tokio threadpool task isolation without data races or shared mutable memory.
