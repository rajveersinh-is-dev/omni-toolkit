//! `omni-testkit` provides test harnesses, statistical benchmark verification,
//! and deterministic payload generators for the OMNI engineering platform.
//!
//! Adheres strictly to the core computational integrity rules:
//! - ZERO precomputed lookup tables or shortcut values.
//! - ZERO artificial stubs.
//! - Rigorous statistical measurements with at least 5 discarded warmup runs.

use omni_core::{DataPayload, ExecutionContext, OmniError, OmniResult, Operation};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Statistical report of an in-process benchmark execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub iterations: usize,
    pub warmup_runs: usize,
    pub min_duration_nanos: u128,
    pub max_duration_nanos: u128,
    pub mean_duration_nanos: f64,
    pub median_duration_nanos: f64,
    pub std_dev_nanos: f64,
}

impl BenchmarkReport {
    pub fn min_duration(&self) -> Duration {
        Duration::from_nanos(self.min_duration_nanos as u64)
    }

    pub fn max_duration(&self) -> Duration {
        Duration::from_nanos(self.max_duration_nanos as u64)
    }

    pub fn mean_duration(&self) -> Duration {
        Duration::from_nanos(self.mean_duration_nanos.round() as u64)
    }

    pub fn median_duration(&self) -> Duration {
        Duration::from_nanos(self.median_duration_nanos.round() as u64)
    }
}

/// Executes a benchmark with strict warmup discarding and high-resolution timing.
pub struct BenchmarkRunner;

impl BenchmarkRunner {
    /// Runs a benchmark function with at least 5 warmup runs discarded.
    pub fn measure<F, R>(warmup_runs: usize, iterations: usize, mut f: F) -> BenchmarkReport
    where
        F: FnMut() -> R,
    {
        // Enforce minimum 5 discarded warmup runs for valid statistical caching/branch warmup
        let warmup = warmup_runs.max(5);
        let iters = iterations.max(1);

        for _ in 0..warmup {
            let res = f();
            std::hint::black_box(res);
        }

        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let start = Instant::now();
            let res = f();
            let elapsed = start.elapsed();
            std::hint::black_box(res);
            samples.push(elapsed.as_nanos());
        }

        samples.sort_unstable();

        let min_duration_nanos = *samples.first().unwrap_or(&0);
        let max_duration_nanos = *samples.last().unwrap_or(&0);

        let sum: u128 = samples.iter().sum();
        let mean_duration_nanos = sum as f64 / iters as f64;

        let median_duration_nanos = if iters % 2 == 1 {
            samples[iters / 2] as f64
        } else {
            (samples[(iters / 2) - 1] + samples[iters / 2]) as f64 / 2.0
        };

        let variance: f64 = samples
            .iter()
            .map(|&s| {
                let diff = s as f64 - mean_duration_nanos;
                diff * diff
            })
            .sum::<f64>()
            / iters as f64;

        let std_dev_nanos = variance.sqrt();

        BenchmarkReport {
            iterations: iters,
            warmup_runs: warmup,
            min_duration_nanos,
            max_duration_nanos,
            mean_duration_nanos,
            median_duration_nanos,
            std_dev_nanos,
        }
    }
}

/// Reproducible deterministic test payload generator using a 64-bit Xorshift PRNG.
pub struct TestPayloadGenerator {
    state: u64,
}

impl TestPayloadGenerator {
    pub fn new(seed: u64) -> Self {
        let state = if seed == 0 { 0x8a5cd789635d2dff } else { seed };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut remaining = len;
        while remaining > 0 {
            let val = self.next_u64().to_le_bytes();
            let take = remaining.min(8);
            out.extend_from_slice(&val[..take]);
            remaining -= take;
        }
        out
    }

    pub fn printable_ascii(&mut self, len: usize) -> String {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let b = (self.next_u64() % 95 + 32) as u8; // 32 (' ') to 126 ('~')
            out.push(b as char);
        }
        out
    }

    /// Provides standard boundary payloads (empty, 1-byte, all-zeros, all-ones, large payload).
    pub fn boundary_cases() -> Vec<DataPayload> {
        vec![
            DataPayload::bytes(Vec::new()),
            DataPayload::bytes(vec![0x00]),
            DataPayload::bytes(vec![0xFF]),
            DataPayload::bytes(vec![0x00; 1024]),
            DataPayload::bytes(vec![0xFF; 1024]),
            DataPayload::text(""),
            DataPayload::text("A"),
            DataPayload::text("The quick brown fox jumps over the lazy dog."),
        ]
    }
}

/// Test harness for executing and verifying OMNI operations.
pub struct OperationHarness;

impl OperationHarness {
    pub async fn execute(
        op: &dyn Operation,
        input: DataPayload,
        config: serde_json::Value,
    ) -> OmniResult<DataPayload> {
        let ctx = ExecutionContext::new("test-job-id");
        op.execute(input, config, &ctx).await
    }

    /// Asserts that executing an operation across N runs produces bit-identical outputs.
    pub async fn assert_deterministic(
        op: &dyn Operation,
        input: &DataPayload,
        config: &serde_json::Value,
        iterations: usize,
    ) -> OmniResult<()> {
        let mut first_output: Option<Vec<u8>> = None;

        for _ in 0..iterations {
            let ctx = ExecutionContext::new("test-deterministic");
            let result = op.execute(input.clone(), config.clone(), &ctx).await?;
            let bytes = result.into_bytes();

            if let Some(expected) = &first_output {
                if expected != &bytes {
                    return Err(OmniError::Validation(
                        "Non-deterministic execution detected: outputs differ across iterations"
                            .into(),
                    ));
                }
            } else {
                first_output = Some(bytes);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_runner() {
        let report = BenchmarkRunner::measure(5, 20, || {
            let mut acc: u64 = 0;
            for i in 0..1000 {
                acc = acc.wrapping_add(i);
            }
            acc
        });

        assert_eq!(report.iterations, 20);
        assert_eq!(report.warmup_runs, 5);
        assert!(report.min_duration_nanos <= report.max_duration_nanos);
        assert!(report.mean_duration_nanos > 0.0);
    }

    #[test]
    fn test_payload_generator_reproducibility() {
        let mut gen1 = TestPayloadGenerator::new(42);
        let mut gen2 = TestPayloadGenerator::new(42);

        let b1 = gen1.bytes(64);
        let b2 = gen2.bytes(64);
        assert_eq!(b1, b2);

        let s1 = gen1.printable_ascii(32);
        let s2 = gen2.printable_ascii(32);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_boundary_cases() {
        let cases = TestPayloadGenerator::boundary_cases();
        assert!(!cases.is_empty());
        assert_eq!(cases[0].data_type(), omni_core::DataType::Bytes);
        assert_eq!(cases[0].as_bytes().len(), 0);
    }
}
