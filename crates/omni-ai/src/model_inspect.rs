use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct ModelInspectorOp;

#[async_trait]
impl Operation for ModelInspectorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "ai.model_inspect",
            "Model Architecture & GGUF/Safetensors Inspector",
            "Parses GGUF and Safetensors headers, computing tensor inventories, parameter counts, and VRAM memory estimates",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 8 {
            return Err(OmniError::InvalidInput("Buffer too small for model header".into()));
        }

        // 1. Check GGUF header (magic 0x46554747 = "GGUF")
        if bytes.starts_with(b"GGUF") {
            let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let tensor_count = if bytes.len() >= 16 {
                u64::from_le_bytes(bytes[8..16].try_into().unwrap())
            } else { 0 };
            let metadata_kv_count = if bytes.len() >= 24 {
                u64::from_le_bytes(bytes[16..24].try_into().unwrap())
            } else { 0 };

            return Ok(DataPayload::json(json!({
                "format": "GGUF (llama.cpp)",
                "version": version,
                "tensor_count": tensor_count,
                "metadata_kv_count": metadata_kv_count,
                "file_size_bytes": bytes.len(),
                "file_size_mb": (bytes.len() as f64 / 1_000_000.0 * 100.0).round() / 100.0,
                "status": "Valid GGUF container header",
            })));
        }

        // 2. Check Safetensors header (first 8 bytes = u64 JSON length)
        let header_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        if header_len > 0 && header_len < bytes.len() && header_len < 100_000_000 {
            if let Ok(header_str) = std::str::from_utf8(&bytes[8..8 + header_len]) {
                if let Ok(parsed_json) = serde_json::from_str::<Value>(header_str) {
                    if let Value::Object(map) = parsed_json {
                        let mut total_params = 0u64;
                        let mut tensors_summary = Vec::new();
                        let metadata = map.get("__metadata__").cloned();

                        for (name, val) in &map {
                            if name == "__metadata__" { continue; }
                            let dtype = val.get("dtype").and_then(|v| v.as_str()).unwrap_or("F32");
                            let shape: Vec<u64> = val.get("shape")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
                                .unwrap_or_default();

                            let params: u64 = if shape.is_empty() { 1 } else { shape.iter().product() };
                            total_params += params;

                            if tensors_summary.len() < 30 {
                                tensors_summary.push(json!({
                                    "tensor": name,
                                    "dtype": dtype,
                                    "shape": shape,
                                    "param_count": params,
                                }));
                            }
                        }

                        let total_billions = (total_params as f64 / 1_000_000_000.0 * 100.0).round() / 100.0;
                        let estimated_vram_fp16_gb = ((total_params * 2) as f64 / 1_073_741_824.0 * 100.0).round() / 100.0;
                        let estimated_vram_q4_gb = ((total_params / 2) as f64 / 1_073_741_824.0 * 100.0).round() / 100.0;

                        return Ok(DataPayload::json(json!({
                            "format": "HuggingFace Safetensors",
                            "header_length_bytes": header_len,
                            "metadata": metadata,
                            "total_tensors": map.len() - if map.contains_key("__metadata__") { 1 } else { 0 },
                            "total_parameters": total_params,
                            "parameters_billions": format!("{}B", total_billions),
                            "estimated_vram_requirements": {
                                "fp16_weights_gb": estimated_vram_fp16_gb,
                                "q4_quantized_gb": estimated_vram_q4_gb,
                                "kv_cache_4k_ctx_gb": 0.5,
                                "kv_cache_32k_ctx_gb": 4.0,
                            },
                            "tensors_sample": tensors_summary,
                        })));
                    }
                }
            }
        }

        // Generic fallback
        Ok(DataPayload::json(json!({
            "format": "Unknown / Raw weights",
            "file_size_bytes": bytes.len(),
            "first_8_bytes_hex": hex::encode(&bytes[..8.min(bytes.len())]),
        })))
    }
}
