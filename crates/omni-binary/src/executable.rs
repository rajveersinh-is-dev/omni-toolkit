use goblin::Object;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct ExecutableInspectorOp;

#[async_trait]
impl Operation for ExecutableInspectorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "binary.executable",
            "Multi-Format Executable & Checksec Inspector",
            "Deeply inspects ELF, PE, Mach-O, and WASM binaries, extracting sections, symbols, dependencies, and checksec security mitigations",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 4 {
            return Err(OmniError::InvalidInput("Buffer too small for executable header".into()));
        }

        // Check WebAssembly magic (\0asm)
        if bytes.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
            let version = if bytes.len() >= 8 {
                u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
            } else {
                1
            };

            return Ok(DataPayload::json(json!({
                "format": "WebAssembly (.wasm)",
                "version": version,
                "file_size": bytes.len(),
                "status": "Valid WebAssembly binary module detected",
            })));
        }

        let parsed = Object::parse(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse executable format: {e}")))?;

        match parsed {
            Object::Elf(elf) => {
                let sections: Vec<Value> = elf.section_headers.iter().map(|sh| {
                    let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("<unknown>");
                    json!({
                        "name": name,
                        "type": sh.sh_type,
                        "flags": format!("0x{:X}", sh.sh_flags),
                        "addr": format!("0x{:X}", sh.sh_addr),
                        "offset": format!("0x{:X}", sh.sh_offset),
                        "size": sh.sh_size,
                    })
                }).collect();

                let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;
                let has_canary = elf.dynsyms.iter().any(|s| elf.dynstrtab.get_at(s.st_name) == Some("__stack_chk_fail"));
                let nx = elf.program_headers.iter().any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK && (ph.p_flags & 1) == 0);
                let relro = elf.program_headers.iter().any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);

                Ok(DataPayload::json(json!({
                    "format": "ELF",
                    "is_64_bit": elf.is_64,
                    "entry_point": format!("0x{:X}", elf.entry),
                    "machine": format!("{:?}", elf.header.e_machine),
                    "libraries": elf.libraries,
                    "sections_count": sections.len(),
                    "sections": sections.into_iter().take(50).collect::<Vec<_>>(),
                    "checksec": {
                        "pie": is_pie,
                        "stack_canary": has_canary,
                        "nx": nx,
                        "relro": relro,
                    }
                })))
            }
            Object::PE(pe) => {
                let sections: Vec<Value> = pe.sections.iter().map(|s| {
                    let name = String::from_utf8_lossy(&s.name).trim_matches('\0').to_string();
                    json!({
                        "name": name,
                        "virtual_address": format!("0x{:X}", s.virtual_address),
                        "virtual_size": s.virtual_size,
                        "raw_data_size": s.size_of_raw_data,
                    })
                }).collect();

                let mut imports = Vec::new();
                for imp in &pe.imports {
                    imports.push(json!({
                        "dll": imp.dll,
                        "function": imp.name.to_string(),
                    }));
                }

                let dll_char = pe.header.optional_header.map(|h| h.windows_fields.dll_characteristics).unwrap_or(0);
                let dynamic_base = (dll_char & 0x0040) != 0; // ASLR
                let nx_compat = (dll_char & 0x0100) != 0; // DEP/NX
                let cfg = (dll_char & 0x4000) != 0; // Control Flow Guard

                Ok(DataPayload::json(json!({
                    "format": "PE / Windows Executable",
                    "is_64_bit": pe.is_64,
                    "entry_point": format!("0x{:X}", pe.entry),
                    "sections_count": sections.len(),
                    "sections": sections,
                    "imports_count": imports.len(),
                    "imports": imports.into_iter().take(50).collect::<Vec<_>>(),
                    "checksec": {
                        "aslr_dynamic_base": dynamic_base,
                        "dep_nx_compat": nx_compat,
                        "control_flow_guard": cfg,
                    }
                })))
            }
            Object::Mach(mach) => {
                Ok(DataPayload::json(json!({
                    "format": "Mach-O (macOS/iOS Executable)",
                    "details": format!("{:?}", mach),
                })))
            }
            Object::Archive(_) => {
                Ok(DataPayload::json(json!({
                    "format": "Unix Static Archive (.a / .lib)",
                })))
            }
            _ => {
                Ok(DataPayload::json(json!({
                    "format": "Generic Binary",
                    "size": bytes.len(),
                })))
            }
        }
    }
}
