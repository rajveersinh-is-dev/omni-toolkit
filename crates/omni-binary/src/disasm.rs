use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct DisassemblyEngineOp;

#[derive(Debug, Clone)]
struct DecodedInstruction {
    offset: u64,
    bytes_hex: String,
    asm: String,
    is_branch: bool,
    is_terminal: bool,
    target_offset: Option<u64>,
}

fn disassemble_x86_iced(bytes: &[u8], bitness: u32, base_ip: u64) -> Vec<DecodedInstruction> {
    let mut decoder = Decoder::with_ip(bitness, bytes, base_ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    let mut instructions = Vec::new();
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        let end = decoder.position().min(bytes.len());
        output.clear();
        formatter.format(&instr, &mut output);

        let raw_hex = if start <= end {
            hex::encode(&bytes[start..end])
        } else {
            String::new()
        };

        let flow = instr.flow_control();
        let is_branch = matches!(
            flow,
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Call
                | FlowControl::IndirectBranch
                | FlowControl::IndirectCall
        );
        let is_terminal = matches!(
            flow,
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        );
        let target_offset = match flow {
            FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call => {
                let t = instr.near_branch_target();
                if t != 0 {
                    Some(t)
                } else {
                    None
                }
            }
            _ => None,
        };

        instructions.push(DecodedInstruction {
            offset: instr.ip(),
            bytes_hex: raw_hex,
            asm: output.clone(),
            is_branch,
            is_terminal,
            target_offset,
        });
    }

    instructions
}

#[async_trait]
impl Operation for DisassemblyEngineOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "binary.disasm",
            "x86 / x86-64 Disassembler & CFG Generator",
            "Disassembles x86-16, x86-32, and x86-64 machine code using iced-x86, identifies basic blocks, and outputs Control Flow Graphs (Mermaid/JSON)",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Supports x86-16, x86-32, and x86-64 instruction sets via iced-x86; ARM, AArch64, RISC-V, and MIPS are not implemented".into(),
        ])
        .with_tags(vec!["binary".into(), "disasm".into(), "x86".into(), "cfg".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let arch = config
            .get("arch")
            .and_then(|v| v.as_str())
            .unwrap_or("x86_64");
        let bitness = match arch.to_lowercase().as_str() {
            "x86_64" | "x64" | "amd64" | "64" => 64,
            "x86" | "x86_32" | "i386" | "32" => 32,
            "x86_16" | "16" => 16,
            other => {
                return Err(OmniError::InvalidInput(format!(
                    "Unsupported architecture '{}'. Supported: x86_64, x86_32, x86_16",
                    other
                )));
            }
        };
        let base_ip = config
            .get("base_addr")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_instructions = config
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(500)
            .clamp(1, 10_000) as usize;

        let instructions = disassemble_x86_iced(&bytes, bitness, base_ip);

        // Build basic blocks
        let mut blocks = Vec::new();
        let mut current_block_instrs = Vec::new();
        let mut block_start = base_ip;

        for instr in &instructions {
            if current_block_instrs.is_empty() {
                block_start = instr.offset;
            }
            current_block_instrs.push(format!("0x{:04X}: {}", instr.offset, instr.asm));

            if instr.is_branch || instr.is_terminal {
                let mnemonic = instr.asm.split_whitespace().next().unwrap_or("");
                blocks.push(json!({
                    "start_offset": format!("0x{:04X}", block_start),
                    "instructions": current_block_instrs.clone(),
                    "terminator": mnemonic,
                    "is_terminal": instr.is_terminal,
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
                "is_terminal": true,
                "target": None::<String>,
            }));
        }

        // Generate Mermaid CFG
        let mut mermaid = String::from("graph TD\n");
        for (idx, b) in blocks.iter().enumerate() {
            let label = b["instructions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("<br/>")
                })
                .unwrap_or_default();
            mermaid.push_str(&format!("  B{}[\"{}\"]\n", idx, label));
            if let Some(target) = b["target"].as_str() {
                mermaid.push_str(&format!("  B{} -->|jump| {}\n", idx, target));
            }
            let is_term = b["is_terminal"].as_bool().unwrap_or(false);
            if idx + 1 < blocks.len() && !is_term {
                mermaid.push_str(&format!("  B{} -->|fallthrough| B{}\n", idx, idx + 1));
            }
        }

        let output_format = config
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("json");
        if output_format == "mermaid" {
            Ok(DataPayload::text(mermaid))
        } else {
            Ok(DataPayload::json(json!({
                "architecture": format!("x86_{}", bitness),
                "base_address": format!("0x{:X}", base_ip),
                "total_instructions": instructions.len(),
                "total_basic_blocks": blocks.len(),
                "instructions": instructions.iter().take(max_instructions).map(|i| json!({
                    "offset": format!("0x{:04X}", i.offset),
                    "hex": i.bytes_hex,
                    "asm": i.asm,
                })).collect::<Vec<_>>(),
                "basic_blocks": blocks,
                "control_flow_graph_mermaid": mermaid,
            })))
        }
    }
}
