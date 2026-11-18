use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct ModelInspectorOp;

#[async_trait]
impl Operation for ModelInspectorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "ai.model_inspect",
            "Model Architecture & GGUF/Safetensors Inspector",
            "Parses GGUF and Safetensors headers, computing tensor inventories, parameter counts, and weight-size VRAM estimates",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Inspects GGUF and HuggingFace Safetensors headers; PyTorch pickle (.pt/.pth) and ONNX graph rendering are not implemented".into(),
        ])
        .with_tags(vec!["ai".into(), "gguf".into(), "safetensors".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 8 {
            return Err(OmniError::InvalidInput(
                "Buffer too small for model header (minimum 8 bytes)".into(),
            ));
        }

        // 1. Check GGUF header (magic "GGUF")
        if bytes.starts_with(b"GGUF") {
            let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let tensor_count = if bytes.len() >= 16 {
                let arr: [u8; 8] = bytes[8..16]
                    .try_into()
                    .map_err(|_| OmniError::InvalidInput("Malformed GGUF tensor count".into()))?;
                u64::from_le_bytes(arr)
            } else {
                0
            };
            let metadata_kv_count = if bytes.len() >= 24 {
                let arr: [u8; 8] = bytes[16..24]
                    .try_into()
                    .map_err(|_| OmniError::InvalidInput("Malformed GGUF KV count".into()))?;
                u64::from_le_bytes(arr)
            } else {
                0
            };

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
        let len_arr: [u8; 8] = bytes[0..8]
            .try_into()
            .map_err(|_| OmniError::InvalidInput("Malformed Safetensors header length".into()))?;
        let header_len = u64::from_le_bytes(len_arr) as usize;
        if header_len > 0
            && header_len < 100_000_000
            && 8usize.saturating_add(header_len) <= bytes.len()
        {
            if let Ok(header_str) = std::str::from_utf8(&bytes[8..8 + header_len]) {
                if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(header_str) {
                    let mut total_params = 0u64;
                    let mut total_weight_bytes = 0u64;
                    let mut tensors_summary = Vec::new();
                    let metadata = map.get("__metadata__").cloned();

                    for (name, val) in &map {
                        if name == "__metadata__" {
                            continue;
                        }
                        let dtype = val.get("dtype").and_then(|v| v.as_str()).unwrap_or("F32");
                        let shape: Vec<u64> = val
                            .get("shape")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();

                        let params: u64 = if shape.is_empty() {
                            1
                        } else {
                            shape.iter().fold(1u64, |acc, &d| acc.saturating_mul(d))
                        };
                        let bytes_per_elem: u64 = match dtype {
                            "F64" | "I64" | "U64" => 8,
                            "F32" | "I32" | "U32" => 4,
                            "F16" | "BF16" | "I16" | "U16" => 2,
                            "I8" | "U8" | "F8_E4M3" | "F8_E5M2" | "BOOL" => 1,
                            _ => 4,
                        };
                        total_params = total_params.saturating_add(params);
                        total_weight_bytes = total_weight_bytes
                            .saturating_add(params.saturating_mul(bytes_per_elem));

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
                    let native_weights_gb =
                        (total_weight_bytes as f64 / 1_073_741_824.0 * 1000.0).round() / 1000.0;
                    let estimated_fp16_gb =
                        ((total_params.saturating_mul(2)) as f64 / 1_073_741_824.0 * 1000.0).round()
                            / 1000.0;
                    let estimated_q4_gb =
                        ((total_params / 2) as f64 / 1_073_741_824.0 * 1000.0).round() / 1000.0;

                    return Ok(DataPayload::json(json!({
                        "format": "HuggingFace Safetensors",
                        "header_length_bytes": header_len,
                        "metadata": metadata,
                        "total_tensors": map.len() - usize::from(map.contains_key("__metadata__")),
                        "total_parameters": total_params,
                        "parameters_billions": format!("{}B", total_billions),
                        "estimated_weight_memory_gb": {
                            "native_dtype_gb": native_weights_gb,
                            "fp16_weights_gb": estimated_fp16_gb,
                            "q4_quantized_gb": estimated_q4_gb,
                        },
                        "tensors_sample": tensors_summary,
                    })));
                }
            }
        }

        Ok(DataPayload::json(json!({
            "format": "Unknown / Raw weights",
            "file_size_bytes": bytes.len(),
            "first_8_bytes_hex": hex::encode(&bytes[..8.min(bytes.len())]),
        })))
    }
}
