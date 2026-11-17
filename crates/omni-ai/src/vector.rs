use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct VectorOperationsOp;

fn dot_product(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| x * y).sum()
}

fn norm_l2(a: &[f64]) -> f64 {
    dot_product(a, a).sqrt()
}

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let norm_a = norm_l2(a);
    let norm_b = norm_l2(b);
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot_product(a, b) / (norm_a * norm_b)
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x - y) * (x - y)).sum::<f64>().sqrt()
}

fn manhattan_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x - y).abs()).sum()
}

fn chebyshev_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x - y).abs()).fold(0.0, f64::max)
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
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let val = match input {
            DataPayload::Json(v) => v,
            _ => config,
        };

        let mode = val.get("mode").and_then(|v| v.as_str()).unwrap_or("pairwise");

        if mode == "top_k" {
            let query: Vec<f64> = val.get("query")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect())
                .unwrap_or_default();

            let corpus = val.get("corpus").and_then(|v| v.as_array());
            let k = val.get("k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

            if query.is_empty() || corpus.is_none() {
                return Err(OmniError::InvalidInput("top_k requires 'query' vector and 'corpus' array of vectors".into()));
            }

            let mut scored = Vec::new();
            for (idx, item) in corpus.unwrap().iter().enumerate() {
                let vec: Vec<f64> = item.as_array().map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect()).unwrap_or_default();
                if vec.len() == query.len() {
                    let sim = cosine_similarity(&query, &vec);
                    let dist = euclidean_distance(&query, &vec);
                    scored.push(json!({
                        "corpus_index": idx,
                        "cosine_similarity": (sim * 10000.0).round() / 10000.0,
                        "euclidean_distance": (dist * 10000.0).round() / 10000.0,
                    }));
                }
            }

            // Sort by cosine similarity descending
            scored.sort_by(|a, b| {
                let sa = a["cosine_similarity"].as_f64().unwrap_or(0.0);
                let sb = b["cosine_similarity"].as_f64().unwrap_or(0.0);
                sb.partial_cmp(&sa).unwrap()
            });

            return Ok(DataPayload::json(json!({
                "mode": "top_k_search",
                "dimension": query.len(),
                "top_k_results": scored.into_iter().take(k).collect::<Vec<_>>(),
            })));
        }

        // Pairwise mode
        let a: Vec<f64> = val.get("a")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect())
            .unwrap_or_default();

        let b: Vec<f64> = val.get("b")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect())
            .unwrap_or_default();

        if a.is_empty() || b.is_empty() || a.len() != b.len() {
            return Err(OmniError::InvalidInput("Vectors 'a' and 'b' must have equal, non-zero dimensions".into()));
        }

        let cos_sim = cosine_similarity(&a, &b);
        let euc_dist = euclidean_distance(&a, &b);
        let man_dist = manhattan_distance(&a, &b);
        let cheb_dist = chebyshev_distance(&a, &b);
        let dot = dot_product(&a, &b);

        Ok(DataPayload::json(json!({
            "dimension": a.len(),
            "metrics": {
                "cosine_similarity": (cos_sim * 10000.0).round() / 10000.0,
                "cosine_distance": ((1.0 - cos_sim) * 10000.0).round() / 10000.0,
                "euclidean_l2_distance": (euc_dist * 10000.0).round() / 10000.0,
                "manhattan_l1_distance": (man_dist * 10000.0).round() / 10000.0,
                "chebyshev_linf_distance": (cheb_dist * 10000.0).round() / 10000.0,
                "dot_product": (dot * 10000.0).round() / 10000.0,
            }
        })))
    }
}
