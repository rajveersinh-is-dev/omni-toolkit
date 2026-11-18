pub mod model_inspect;
pub mod quantize;
pub mod tokenizer;
pub mod vector;

pub use model_inspect::ModelInspectorOp;
pub use quantize::QuantizeSimulatorOp;
pub use tokenizer::TokenizerPlaygroundOp;
pub use vector::VectorOperationsOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_ai(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(ModelInspectorOp))?;
    registry.register(Arc::new(TokenizerPlaygroundOp))?;
    registry.register(Arc::new(VectorOperationsOp))?;
    registry.register(Arc::new(QuantizeSimulatorOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_tokenizer_playground() {
        let op = TokenizerPlaygroundOp;
        let ctx = ExecutionContext::new("t_tok");

        let text = "Hello world! <|endoftext|>";
        let res = op
            .execute(DataPayload::text(text), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert!(json["total_tokens"].as_u64().unwrap() >= 3);
        let tokens = json["tokens"].as_array().unwrap();
        assert!(tokens.iter().any(|t| t["is_special"] == true));
    }

    #[tokio::test]
    async fn test_vector_cosine_and_euclidean() {
        let op = VectorOperationsOp;
        let ctx = ExecutionContext::new("t_vec");

        let res = op
            .execute(
                DataPayload::json(serde_json::json!({
                    "a": [1.0, 0.0, 0.0],
                    "b": [1.0, 0.0, 0.0]
                })),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["metrics"]["cosine_similarity"], 1.0);
        assert_eq!(json["metrics"]["euclidean_l2_distance"], 0.0);
    }

    #[tokio::test]
    async fn test_quantize_int8_metrics() {
        let op = QuantizeSimulatorOp;
        let ctx = ExecutionContext::new("t_q");

        let res = op
            .execute(
                DataPayload::json(serde_json::json!({
                    "precision": "int8",
                    "weights": [0.1, -0.5, 1.2, -1.8, 2.0]
                })),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["target_precision"], "INT8");
        assert!(json["reconstruction_metrics"]["snr_db"].as_f64().unwrap() > 30.0);
    }

    #[tokio::test]
    async fn test_vector_top_k_extreme_magnitude_and_quantize_variants() {
        let ctx = ExecutionContext::new("t_ai_edge");
        let vec_op = VectorOperationsOp;

        // Extreme magnitude 1e200 must NOT overflow L2 norm to infinity/NaN!
        let extreme = vec_op
            .execute(
                DataPayload::json(serde_json::json!({
                    "a": [1e200, 0.0],
                    "b": [1e200, 0.0]
                })),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(extreme["metrics"]["cosine_similarity"], 1.0);

        // top_k search ordering
        let topk = vec_op
            .execute(
                DataPayload::json(serde_json::json!({
                    "mode": "top_k",
                    "query": [1.0, 0.0],
                    "corpus": [[0.0, 1.0], [1.0, 0.0], [0.7, 0.7]],
                    "k": 2
                })),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(topk["top_k_results"][0]["corpus_index"], 1);
        assert_eq!(topk["top_k_results"][1]["corpus_index"], 2);

        // Quantize INT4 & BF16 & invalid precision rejection
        let q_op = QuantizeSimulatorOp;
        for prec in ["int4", "bf16"] {
            let out = q_op
                .execute(
                    DataPayload::json(
                        serde_json::json!({ "precision": prec, "weights": [0.0, 0.5, -1.0] }),
                    ),
                    serde_json::json!({}),
                    &ctx,
                )
                .await
                .unwrap()
                .into_json()
                .unwrap();
            assert_eq!(out["target_precision"], prec.to_uppercase());
        }
        assert!(q_op
            .execute(
                DataPayload::json(serde_json::json!({ "precision": "fp99", "weights": [1.0] })),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
    }
}
