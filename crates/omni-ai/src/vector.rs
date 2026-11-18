use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct VectorOperationsOp;

fn dot_product(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| x * y).sum()
}

/// Overflow- and underflow-safe Euclidean (L2) norm using max-magnitude scaling.
fn norm_l2(a: &[f64]) -> f64 {
    let max_abs = a.iter().map(|x| x.abs()).fold(0.0f64, f64::max);
    if max_abs == 0.0 || !max_abs.is_finite() {
        return max_abs;
    }
    let scaled_sq: f64 = a
        .iter()
        .map(|&x| {
            let s = x / max_abs;
            s * s
        })
        .sum();
    max_abs * scaled_sq.sqrt()
}

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let norm_a = norm_l2(a);
    let norm_b = norm_l2(b);
    if norm_a == 0.0 || norm_b == 0.0 || !norm_a.is_finite() || !norm_b.is_finite() {
        return 0.0;
    }
    // Scale inputs by their norms to avoid intermediate overflow in dot_product
    let sim: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x / norm_a) * (y / norm_b))
        .sum();
    sim.clamp(-1.0, 1.0)
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    let max_diff = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x - y).abs())
        .fold(0.0f64, f64::max);
    if max_diff == 0.0 || !max_diff.is_finite() {
        return max_diff;
    }
    let scaled_sq: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| {
            let d = (x - y) / max_diff;
            d * d
        })
        .sum();
    max_diff * scaled_sq.sqrt()
}

fn manhattan_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x - y).abs()).sum()
}

fn chebyshev_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x - y).abs())
        .fold(0.0, f64::max)
}

fn extract_finite_vec(arr: &[Value]) -> OmniResult<Vec<f64>> {
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(v) = item.as_f64() else {
            return Err(OmniError::InvalidInput(
                "Vector elements must be finite JSON numbers".into(),
            ));
        };
        if !v.is_finite() {
            return Err(OmniError::InvalidInput(
                "Vector elements must be finite numbers (NaN/Infinity rejected)".into(),
            ));
        }
        out.push(v);
    }
    Ok(out)
}

fn round4(v: f64) -> f64 {
    if v.is_finite() {
        (v * 10000.0).round() / 10000.0
    } else {
        0.0
    }
}

#[async_trait]
impl Operation for VectorOperationsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "ai.vector",
            "Vector Math & Distance Metrics Studio",
            "Computes Cosine similarity, Euclidean (L2), Manhattan (L1), Chebyshev, and Top-K nearest neighbor search",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["ai".into(), "vectors".into(), "embeddings".into(), "cosine".into()])
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

        let mode = val
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("pairwise");

        if mode == "top_k" {
            let query_arr = val.get("query").and_then(|v| v.as_array()).ok_or_else(|| {
                OmniError::InvalidInput(
                    "top_k requires 'query' vector and 'corpus' array of vectors".into(),
                )
            })?;
            let query = extract_finite_vec(query_arr)?;
            let corpus = val
                .get("corpus")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    OmniError::InvalidInput(
                        "top_k requires 'query' vector and 'corpus' array of vectors".into(),
                    )
                })?;
            let k = val.get("k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

            if query.is_empty() {
                return Err(OmniError::InvalidInput(
                    "top_k requires a non-empty 'query' vector".into(),
                ));
            }

            let mut scored: Vec<(f64, Value)> = Vec::new();
            for (idx, item) in corpus.iter().enumerate() {
                if let Some(arr) = item.as_array() {
                    if let Ok(vec) = extract_finite_vec(arr) {
                        if vec.len() == query.len() {
                            let sim = cosine_similarity(&query, &vec);
                            let dist = euclidean_distance(&query, &vec);
                            scored.push((
                                sim,
                                json!({
                                    "corpus_index": idx,
                                    "cosine_similarity": round4(sim),
                                    "euclidean_distance": round4(dist),
                                }),
                            ));
                        }
                    }
                }
            }

            // Sort by cosine similarity descending using NaN-safe total_cmp
            scored.sort_by(|a, b| b.0.total_cmp(&a.0));

            return Ok(DataPayload::json(json!({
                "mode": "top_k_search",
                "dimension": query.len(),
                "top_k_results": scored.into_iter().take(k).map(|(_, v)| v).collect::<Vec<_>>(),
            })));
        }

        // Pairwise mode
        let a = match val.get("a").and_then(|v| v.as_array()) {
            Some(arr) => extract_finite_vec(arr)?,
            None => Vec::new(),
        };
        let b = match val.get("b").and_then(|v| v.as_array()) {
            Some(arr) => extract_finite_vec(arr)?,
            None => Vec::new(),
        };

        if a.is_empty() || b.is_empty() || a.len() != b.len() {
            return Err(OmniError::InvalidInput(
                "Vectors 'a' and 'b' must have equal, non-zero dimensions".into(),
            ));
        }

        let cos_sim = cosine_similarity(&a, &b);
        let euc_dist = euclidean_distance(&a, &b);
        let man_dist = manhattan_distance(&a, &b);
        let cheb_dist = chebyshev_distance(&a, &b);
        let dot = dot_product(&a, &b);

        Ok(DataPayload::json(json!({
            "dimension": a.len(),
            "metrics": {
                "cosine_similarity": round4(cos_sim),
                "cosine_distance": round4(1.0 - cos_sim),
                "euclidean_l2_distance": round4(euc_dist),
                "manhattan_l1_distance": round4(man_dist),
                "chebyshev_linf_distance": round4(cheb_dist),
                "dot_product": round4(dot),
            }
        })))
    }
}
