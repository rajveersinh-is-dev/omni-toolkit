use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct QuantizeSimulatorOp;

#[async_trait]
impl Operation for QuantizeSimulatorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "ai.quantize",
            "Quantization Simulator & Precision Metrics",
            "Simulates INT8, INT4, and BF16 quantization, calculating MSE, RMSE, SNR, and weight distribution histograms",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["ai".into(), "quantization".into(), "int8".into(), "int4".into(), "bf16".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let val = match input {
            DataPayload::Json(v) => v,
            _ => config,
        };

        let target_prec = val
            .get("precision")
            .and_then(|v| v.as_str())
            .unwrap_or("int8");
        let weights: Vec<f64> = val
            .get("weights")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_f64())
                    .filter(|w| w.is_finite())
                    .collect()
            })
            .unwrap_or_else(|| {
                // Default test Gaussian-like distribution
                (-50..50).map(|i| (i as f64 / 20.0).sin() * 2.5).collect()
            });

        if weights.is_empty() {
            return Err(OmniError::InvalidInput(
                "Weights array cannot be empty (and must contain finite numbers)".into(),
            ));
        }

        let max_abs = weights.iter().map(|w| w.abs()).fold(0.0f64, f64::max);
        let min_val = weights.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_val = weights.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));

        let quantized: Vec<f64> = match target_prec {
            "int8" => {
                let scale = if max_abs > 0.0 { max_abs / 127.0 } else { 1.0 };
                weights
                    .iter()
                    .map(|&w| {
                        let q = (w / scale).round().clamp(-128.0, 127.0);
                        q * scale
                    })
                    .collect()
            }
            "int4" => {
                let scale = if max_abs > 0.0 { max_abs / 7.0 } else { 1.0 };
                weights
                    .iter()
                    .map(|&w| {
                        let q = (w / scale).round().clamp(-8.0, 7.0);
                        q * scale
                    })
                    .collect()
            }
            "bf16" => {
                // BF16 simulation: mask lower 16 bits of FP32
                weights
                    .iter()
                    .map(|&w| {
                        let f = w as f32;
                        let bits = f.to_bits();
                        let bf16_bits = bits & 0xFFFF0000;
                        let out = f32::from_bits(bf16_bits) as f64;
                        if out.is_finite() {
                            out
                        } else {
                            0.0
                        }
                    })
                    .collect()
            }
            other => {
                return Err(OmniError::Validation(format!(
                    "Unsupported precision '{}'. Supported: int8, int4, bf16",
                    other
                )));
            }
        };

        // Error metrics
        let n = weights.len() as f64;
        let mut sum_sq_orig = 0.0f64;
        let mut sum_sq_err = 0.0f64;

        for (w, q) in weights.iter().zip(quantized.iter()) {
            let err = w - q;
            sum_sq_err += err * err;
            sum_sq_orig += w * w;
        }

        let mse = if sum_sq_err.is_finite() {
            sum_sq_err / n
        } else {
            0.0
        };
        let rmse = mse.sqrt();
        let snr_db = if sum_sq_err > 1e-12 && sum_sq_orig > 0.0 && sum_sq_orig.is_finite() {
            10.0 * (sum_sq_orig / sum_sq_err).log10()
        } else {
            100.0
        };
        let psnr_db = if rmse > 1e-12 && max_abs > 0.0 {
            20.0 * (max_abs / rmse).log10()
        } else {
            100.0
        };

        // 10-bin histogram
        let bin_count = 10;
        let range = (max_val - min_val).max(1e-6);
        let mut histogram = vec![0usize; bin_count];

        for &w in &weights {
            let bin = (((w - min_val) / range) * (bin_count as f64)).floor() as usize;
            let bin_clamped = bin.min(bin_count - 1);
            histogram[bin_clamped] += 1;
        }

        Ok(DataPayload::json(json!({
            "target_precision": target_prec.to_uppercase(),
            "elements_count": weights.len(),
            "range": { "min": min_val, "max": max_val, "max_abs": max_abs },
            "reconstruction_metrics": {
                "mse": (mse * 1_000_000.0).round() / 1_000_000.0,
                "rmse": (rmse * 1_000_000.0).round() / 1_000_000.0,
                "snr_db": (snr_db * 100.0).round() / 100.0,
                "psnr_db": (psnr_db * 100.0).round() / 100.0,
            },
            "histogram_10_bins": histogram,
            "sample_quantized": quantized.into_iter().take(10).map(|v| (v * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
        })))
    }
}
