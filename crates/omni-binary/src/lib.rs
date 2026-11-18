pub mod disasm;
pub mod executable;
pub mod hardware;
pub mod hex_tools;

pub use disasm::DisassemblyEngineOp;
pub use executable::ExecutableInspectorOp;
pub use hardware::{HardwareCanOp, HardwareSerialOp};
pub use hex_tools::{BinaryHexOp, Ieee754VisualizerOp};

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_binary(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(BinaryHexOp))?;
    registry.register(Arc::new(Ieee754VisualizerOp))?;
    registry.register(Arc::new(ExecutableInspectorOp))?;
    registry.register(Arc::new(DisassemblyEngineOp))?;
    registry.register(Arc::new(HardwareSerialOp))?;
    registry.register(Arc::new(HardwareCanOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_ieee754_visualizer() {
        let op = Ieee754VisualizerOp;
        let ctx = ExecutionContext::new("t_ieee");

        let res = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "value": 1.0, "precision": "f32" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["sign_bit"], 0);
        assert_eq!(json["exponent_unbiased"], 0);
        assert_eq!(json["hex"], "0x3F800000");
    }

    #[tokio::test]
    async fn test_disassembly_x86() {
        let op = DisassemblyEngineOp;
        let ctx = ExecutionContext::new("t_disasm");

        // Bytes: 55 (push rbp), 48 89 e5 (mov rbp, rsp), 31 c0 (xor eax, eax), c3 (ret)
        let code = vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0xC3];

        let res = op
            .execute(DataPayload::bytes(code), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert!(json["total_instructions"].as_u64().unwrap() >= 3);
        assert!(json["control_flow_graph_mermaid"]
            .as_str()
            .unwrap()
            .contains("graph TD"));
    }

    #[tokio::test]
    async fn test_can_obd2_decoding() {
        let op = HardwareCanOp;
        let ctx = ExecutionContext::new("t_can");

        // Engine Coolant temp response: Service 41 PID 05 Value 0x55 (85 - 40 = 45 C)
        let candump =
            "(1600000000.123456) can0 7E8#0341055500000000\n(1600000000.123457) can0 123#DEADBEEF";

        let res = op
            .execute(DataPayload::text(candump), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["total_can_frames_parsed"], 2);
        let f0 = &json["frames"][0];
        assert_eq!(f0["obd2_decoded"]["value"], "45 °C");
    }

    #[tokio::test]
    async fn test_binary_hex_and_serial_zero_param_guards() {
        let ctx = ExecutionContext::new("t_bin_edge");
        let hex_op = BinaryHexOp;

        // Valid hexdump, byte_swap, bitwise XOR
        let dump = hex_op
            .execute(
                DataPayload::bytes(b"ABCD"),
                serde_json::json!({ "action": "hexdump", "width": 4 }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(dump.as_str().unwrap().contains("41 42 43 44"));
        let swapped = hex_op
            .execute(
                DataPayload::bytes(vec![0x01, 0x02, 0x03, 0x04]),
                serde_json::json!({ "action": "byte_swap", "word_size": 2 }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(swapped.into_bytes(), vec![0x02, 0x01, 0x04, 0x03]);

        // Zero width / word_size MUST return Validation error, never panic in chunks(0)!
        assert!(hex_op
            .execute(
                DataPayload::bytes(b"AB"),
                serde_json::json!({ "action": "hexdump", "width": 0 }),
                &ctx
            )
            .await
            .is_err());
        assert!(hex_op
            .execute(
                DataPayload::bytes(b"AB"),
                serde_json::json!({ "action": "byte_swap", "word_size": 0 }),
                &ctx
            )
            .await
            .is_err());

        // Zero baud rate MUST return Validation error, never divide by zero!
        assert!(HardwareSerialOp
            .execute(
                DataPayload::bytes(b"A"),
                serde_json::json!({ "baud": 0 }),
                &ctx
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_disasm_base_ip_wrap_and_executable_and_serial_parity() {
        let ctx = ExecutionContext::new("t_bin_deep");

        // 1. Disassembly with base_addr > u32::MAX in x86_32 and base_addr = u64::MAX in x86_64 MUST NOT panic!
        let nops = vec![0x90, 0x90, 0xC3];
        let d32 = DisassemblyEngineOp
            .execute(
                DataPayload::bytes(nops.clone()),
                serde_json::json!({ "arch": "x86_32", "base_addr": 0x1_0000_0000u64 }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(d32["total_instructions"], 3);
        assert_eq!(d32["instructions"][0]["hex"], "90");

        let d64 = DisassemblyEngineOp
            .execute(
                DataPayload::bytes(nops),
                serde_json::json!({ "arch": "x86_64", "base_addr": u64::MAX }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(d64["total_instructions"], 3);

        // 2. ExecutableInspectorOp: valid 8-byte WASM accepted, truncated 4-byte WASM rejected
        let valid_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let wres = ExecutableInspectorOp
            .execute(DataPayload::bytes(valid_wasm), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(wres["version"], 1);

        let trunc_wasm = vec![0x00, 0x61, 0x73, 0x6D];
        assert!(ExecutableInspectorOp
            .execute(DataPayload::bytes(trunc_wasm), serde_json::json!({}), &ctx)
            .await
            .is_err());

        // 3. HardwareSerialOp parity error detection (0x01 has 1 bit -> odd OK, even ERR)
        let sres = HardwareSerialOp
            .execute(
                DataPayload::bytes(vec![0x01, 0x03]),
                serde_json::json!({ "baud": 9600, "parity": "even" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sres["parity_errors_detected"], 1);
        assert_eq!(sres["frame_format"], "8-E-1");
    }
}
