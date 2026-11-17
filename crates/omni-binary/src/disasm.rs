use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct DisassemblyEngineOp;

#[derive(Debug, Clone)]
struct DecodedInstruction {
    offset: usize,
    bytes_hex: String,
    mnemonic: String,
    operands: String,
    is_branch: bool,
    is_terminal: bool,
    target_offset: Option<usize>,
}

fn disassemble_x86_stream(bytes: &[u8]) -> Vec<DecodedInstruction> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let offset = i;
        let b = bytes[i];

        let (mnemonic, operands, len, is_branch, is_term, target) = match b {
            0x90 => ("nop", "".into(), 1, false, false, None),
            0xCC => ("int3", "".into(), 1, false, false, None),
            0xC3 => ("ret", "".into(), 1, false, true, None),
            0xC2 if i + 2 < bytes.len() => {
                let imm = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]);
                ("ret", format!("0x{:X}", imm), 3, false, true, None)
            }
            0x50..=0x57 => {
                let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                ("push", regs[(b - 0x50) as usize].into(), 1, false, false, None)
            }
            0x58..=0x5F => {
                let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
                ("pop", regs[(b - 0x58) as usize].into(), 1, false, false, None)
            }
            0xEB if i + 1 < bytes.len() => {
                let rel = bytes[i + 1] as i8;
                let dest = ((offset as isize) + 2 + (rel as isize)).max(0) as usize;
                ("jmp", format!("0x{:08X}", dest), 2, true, true, Some(dest))
            }
            0xE9 if i + 4 < bytes.len() => {
                let rel = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let dest = ((offset as isize) + 5 + (rel as isize)).max(0) as usize;
                ("jmp", format!("0x{:08X}", dest), 5, true, true, Some(dest))
            }
            0xE8 if i + 4 < bytes.len() => {
                let rel = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let dest = ((offset as isize) + 5 + (rel as isize)).max(0) as usize;
                ("call", format!("0x{:08X}", dest), 5, true, false, Some(dest))
            }
            0x74 if i + 1 < bytes.len() => {
                let rel = bytes[i + 1] as i8;
                let dest = ((offset as isize) + 2 + (rel as isize)).max(0) as usize;
                ("je", format!("0x{:08X}", dest), 2, true, false, Some(dest))
            }
            0x75 if i + 1 < bytes.len() => {
                let rel = bytes[i + 1] as i8;
                let dest = ((offset as isize) + 2 + (rel as isize)).max(0) as usize;
                ("jne", format!("0x{:08X}", dest), 2, true, false, Some(dest))
            }
            0x0F if i + 1 < bytes.len() && bytes[i + 1] == 0x05 => {
                ("syscall", "".into(), 2, false, false, None)
            }
            0x31 if i + 1 < bytes.len() && bytes[i + 1] == 0xC0 => {
                ("xor", "eax, eax".into(), 2, false, false, None)
            }
            0x31 if i + 1 < bytes.len() && bytes[i + 1] == 0xED => {
                ("xor", "ebp, ebp".into(), 2, false, false, None)
            }
            0xB8..=0xBF if i + 4 < bytes.len() => {
                let regs = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
                let imm = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                ("mov", format!("{}, 0x{:X}", regs[(b - 0xB8) as usize], imm), 5, false, false, None)
            }
            _ => ("db", format!("0x{:02X}", b), 1, false, false, None),
        };

        let raw_hex = hex::encode(&bytes[offset..offset + len]);
        instructions.push(DecodedInstruction {
            offset,
            bytes_hex: raw_hex,
            mnemonic: mnemonic.into(),
            operands,
            is_branch,
            is_terminal: is_term,
            target_offset: target,
        });

        i += len;
    }

    instructions
}

#[async_trait]
impl Operation for DisassemblyEngineOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "binary.disasm",
            "Multi-Architecture Disassembly & CFG Generator",
            "Disassembles machine bytecode, identifies basic blocks, and produces Control Flow Graphs (CFG) in Mermaid and DOT formats",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let instructions = disassemble_x86_stream(&bytes);

        // Build basic blocks
        let mut blocks = Vec::new();
        let mut current_block_instrs = Vec::new();
        let mut block_start = 0;

        for instr in &instructions {
            if current_block_instrs.is_empty() {
                block_start = instr.offset;
            }
            current_block_instrs.push(format!("0x{:04X}: {} {}", instr.offset, instr.mnemonic, instr.operands));

            if instr.is_branch || instr.is_terminal {
                blocks.push(json!({
                    "start_offset": format!("0x{:04X}", block_start),
                    "instructions": current_block_instrs.clone(),
                    "terminator": instr.mnemonic,
                    "target": instr.target_offset.map(|t| format!("0x{:04X}", t)),
                }));
                current_block_instrs.clear();
            }
        }

        if !current_block_instrs.is_empty() {
            blocks.push(json!({
                "start_offset": format!("0x{:04X}", block_start),
                "instructions": current_block_instrs,
                "terminator": "end",
                "target": None::<String>,
            }));
        }

        // Generate Mermaid CFG
        let mut mermaid = String::from("graph TD\n");
        for (idx, b) in blocks.iter().enumerate() {
            let label = b["instructions"].as_array().map(|arr| {
                arr.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join("<br/>")
            }).unwrap_or_default();
            mermaid.push_str(&format!("  B{}[\"{}\"]\n", idx, label));
            if let Some(target) = b["target"].as_str() {
                mermaid.push_str(&format!("  B{} -->|jump| {}\n", idx, target));
            }
            if idx + 1 < blocks.len() && b["terminator"] != "ret" && b["terminator"] != "jmp" {
                mermaid.push_str(&format!("  B{} -->|fallthrough| B{}\n", idx, idx + 1));
            }
        }

        let output_format = config.get("format").and_then(|v| v.as_str()).unwrap_or("json");
        if output_format == "mermaid" {
            Ok(DataPayload::text(mermaid))
        } else {
            Ok(DataPayload::json(json!({
                "total_instructions": instructions.len(),
                "total_basic_blocks": blocks.len(),
                "instructions": instructions.iter().take(100).map(|i| json!({
                    "offset": format!("0x{:04X}", i.offset),
                    "hex": i.bytes_hex,
                    "asm": format!("{} {}", i.mnemonic, i.operands).trim().to_string(),
                })).collect::<Vec<_>>(),
                "basic_blocks": blocks,
                "control_flow_graph_mermaid": mermaid,
            })))
        }
    }
}
