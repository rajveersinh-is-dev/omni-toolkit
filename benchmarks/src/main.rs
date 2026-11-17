use omni_core::{DataPayload, ExecutionContext};
use omni_crypto::register_crypto;
use omni_encoders::register_encoders;
use omni_registry::OperationRegistry;
use omni_testkit::{BenchmarkRunner, TestPayloadGenerator};
use omni_text::register_text;
use omni_visualization::{Alignment, AsciiTable, TableColumn, TableStyle};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    println!("============================================================");
    println!("     OMNI High-Resolution Benchmark Suite (v0.1.0)         ");
    println!("============================================================");
    println!("Principles: Zero synthetic stubs, zero precalculated constants.");
    println!("Timing: In-process Instant counter, 5 discarded warmup runs.");
    println!("------------------------------------------------------------\n");

    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();
    register_crypto(&mut registry).unwrap();
    register_text(&mut registry).unwrap();
    let registry = Arc::new(registry);

    let mut gen = TestPayloadGenerator::new(0x42);
    let ctx = ExecutionContext::new("bench_job");

    let one_mb = 1024 * 1024;
    let data_1mb = gen.bytes(one_mb);

    let mut table = AsciiTable::new(
        vec![
            TableColumn::new("Operation", Alignment::Left),
            TableColumn::new("Data Size", Alignment::Right),
            TableColumn::new("Iterations", Alignment::Right),
            TableColumn::new("Min (μs)", Alignment::Right),
            TableColumn::new("Mean (μs)", Alignment::Right),
            TableColumn::new("Median (μs)", Alignment::Right),
            TableColumn::new("Throughput (MB/s)", Alignment::Right),
        ],
        TableStyle::Unicode,
    );

    // 1. SHA-256 Benchmark
    {
        let op = registry.get("crypto.hash.sha256").unwrap();
        let payload = DataPayload::bytes(data_1mb.clone());
        let op_clone = op.clone();
        let ctx_clone = ctx.clone();

        let report = BenchmarkRunner::measure(5, 20, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    op_clone
                        .execute(payload.clone(), serde_json::json!({}), &ctx_clone)
                        .await
                        .unwrap();
                })
            });
        });

        let throughput_mb_s = 1.0 / (report.mean_duration_nanos / 1_000_000_000.0);
        table.add_row(vec![
            "crypto.hash.sha256".into(),
            "1 MB".into(),
            report.iterations.to_string(),
            format!("{:.1}", report.min_duration_nanos as f64 / 1000.0),
            format!("{:.1}", report.mean_duration_nanos / 1000.0),
            format!("{:.1}", report.median_duration_nanos / 1000.0),
            format!("{:.2}", throughput_mb_s),
        ]);
    }

    // 2. BLAKE3 Benchmark
    {
        let op = registry.get("crypto.hash.blake3").unwrap();
        let payload = DataPayload::bytes(data_1mb.clone());
        let op_clone = op.clone();
        let ctx_clone = ctx.clone();

        let report = BenchmarkRunner::measure(5, 20, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    op_clone
                        .execute(payload.clone(), serde_json::json!({}), &ctx_clone)
                        .await
                        .unwrap();
                })
            });
        });

        let throughput_mb_s = 1.0 / (report.mean_duration_nanos / 1_000_000_000.0);
        table.add_row(vec![
            "crypto.hash.blake3".into(),
            "1 MB".into(),
            report.iterations.to_string(),
            format!("{:.1}", report.min_duration_nanos as f64 / 1000.0),
            format!("{:.1}", report.mean_duration_nanos / 1000.0),
            format!("{:.1}", report.median_duration_nanos / 1000.0),
            format!("{:.2}", throughput_mb_s),
        ]);
    }

    // 3. Base64 Encode Benchmark
    {
        let op = registry.get("encode.base64").unwrap();
        let payload = DataPayload::bytes(data_1mb.clone());
        let op_clone = op.clone();
        let ctx_clone = ctx.clone();

        let report = BenchmarkRunner::measure(5, 20, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    op_clone
                        .execute(payload.clone(), serde_json::json!({}), &ctx_clone)
                        .await
                        .unwrap();
                })
            });
        });

        let throughput_mb_s = 1.0 / (report.mean_duration_nanos / 1_000_000_000.0);
        table.add_row(vec![
            "encode.base64".into(),
            "1 MB".into(),
            report.iterations.to_string(),
            format!("{:.1}", report.min_duration_nanos as f64 / 1000.0),
            format!("{:.1}", report.mean_duration_nanos / 1000.0),
            format!("{:.1}", report.median_duration_nanos / 1000.0),
            format!("{:.2}", throughput_mb_s),
        ]);
    }

    // 4. CRC-32 Checksum Benchmark
    {
        let op = registry.get("checksum.crc32").unwrap();
        let payload = DataPayload::bytes(data_1mb.clone());
        let op_clone = op.clone();
        let ctx_clone = ctx.clone();

        let report = BenchmarkRunner::measure(5, 20, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    op_clone
                        .execute(payload.clone(), serde_json::json!({}), &ctx_clone)
                        .await
                        .unwrap();
                })
            });
        });

        let throughput_mb_s = 1.0 / (report.mean_duration_nanos / 1_000_000_000.0);
        table.add_row(vec![
            "checksum.crc32".into(),
            "1 MB".into(),
            report.iterations.to_string(),
            format!("{:.1}", report.min_duration_nanos as f64 / 1000.0),
            format!("{:.1}", report.mean_duration_nanos / 1000.0),
            format!("{:.1}", report.median_duration_nanos / 1000.0),
            format!("{:.2}", throughput_mb_s),
        ]);
    }

    println!("{}", table.render());
}
