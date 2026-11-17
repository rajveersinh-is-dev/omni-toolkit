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
        assert!(json["control_flow_graph_mermaid"].as_str().unwrap().contains("graph TD"));
    }

    #[tokio::test]
    async fn test_can_obd2_decoding() {
        let op = HardwareCanOp;
        let ctx = ExecutionContext::new("t_can");

        // Engine Coolant temp response: Service 41 PID 05 Value 0x55 (85 - 40 = 45 C)
        let candump = "(1600000000.123456) can0 7E8#0341055500000000\n(1600000000.123457) can0 123#DEADBEEF";

        let res = op
            .execute(DataPayload::text(candump), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["total_can_frames_parsed"], 2);
        let f0 = &json["frames"][0];
        assert_eq!(f0["obd2_decoded"]["value"], "45 °C");
    }
}
