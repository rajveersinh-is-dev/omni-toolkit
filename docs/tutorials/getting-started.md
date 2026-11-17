# Getting Started with OMNI

Welcome to **OMNI — The Universal Digital Engineering Toolkit**. This guide walks you through installation, basic concepts, CLI commands, TUI navigation, and the local web interface.

---

## 1. Prerequisites and Installation

### From Source (Rust Toolchain)
OMNI requires Rust 1.80 or later:

```bash
# Clone the repository
git clone https://github.com/rajveersinh-is-dev/omni-toolkit.git
cd omni-toolkit

# Build release binaries for all interfaces
cargo build --release -p omni -p omni-tui
```

The compiled binaries will be located in `target/release/`:
- `omni`: The high-throughput command-line interface.
- `omni-tui`: The terminal user interface powered by Ratatui.

---

## 2. Using the CLI

### Discovering Operations
OMNI includes 64 built-in operations across 10 distinct categories. To list all available operations:

```bash
omni list
```

To filter operations by category or keyword:
```bash
omni list --category Security
omni list --query sha256
```

To inspect an operation's parameters, schemas, and resource requirements:
```bash
omni info crypto.hash.sha256
```

### Standard Input / Output Streaming
OMNI CLI follows UNIX filter conventions:

```bash
# Calculate SHA-256 digest
echo -n "admin_token" | omni run crypto.hash.sha256

# Base64 encode an image
omni encode base64 --input firmware.bin --output firmware.b64

# Convert JSON to YAML
cat config.json | omni run transpile.structured --config '{"from":"json","to":"yaml"}'
```

---

## 3. Running the Interactive TUI Studio

For rapid interactive debugging in remote SSH sessions or local terminal windows:

```bash
cargo run -p omni-tui
```

### Keyboard Navigation:
- **`[Tab]` / `[Shift+Tab]`**: Cycle focus between Categories, Operations list, Input pane, and Output pane.
- **`[Up]` / `[Down]`**: Navigate lists.
- **`[/]`**: Activate global fuzzy search across all 64 tools.
- **`[Enter]`**: Execute the currently selected operation with the active input payload.
- **`[q]` / `[Esc]`**: Exit search or quit application.

---

## 4. Starting the Web API and Graphical Studio

OMNI embeds an asynchronous Axum web server and WebSocket progress engine:

```bash
omni serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080` in any modern web browser to access:
- **Visual DAG Pipeline Editor**: Drag and connect operations to build complex data processing workflows.
- **Live Hex & Data Inspector**: Interactive viewer with ASCII, UTF-8, and raw binary breakdowns.
- **Real-Time Job Monitor**: Stream job execution progress, timings, and memory consumption over WebSockets.
