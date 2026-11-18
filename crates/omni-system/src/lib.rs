pub mod color;
pub mod cron;
pub mod flamegraph;
pub mod ids;
pub mod trace;

pub use color::ColorToolkitOp;
pub use cron::CronEngineOp;
pub use flamegraph::FlamegraphGeneratorOp;
pub use ids::UniversalIdsOp;
pub use trace::SystemTraceOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_system(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(SystemTraceOp))?;
    registry.register(Arc::new(CronEngineOp))?;
    registry.register(Arc::new(UniversalIdsOp))?;
    registry.register(Arc::new(ColorToolkitOp))?;
    registry.register(Arc::new(FlamegraphGeneratorOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_cron_parsing_next_executions() {
        let op = CronEngineOp;
        let ctx = ExecutionContext::new("t_cron");

        let res = op
            .execute(
                DataPayload::text("*/10 * * * *"),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["is_valid"], true);
        let next = json["next_20_executions"].as_array().unwrap();
        assert_eq!(next.len(), 20);
    }

    #[tokio::test]
    async fn test_universal_ids_and_snowflake() {
        let op = UniversalIdsOp;
        let ctx = ExecutionContext::new("t_ids");

        // Generate IDs
        let res = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "generate" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert!(json["uuid_v4_random"].as_str().is_some());
        assert!(json["uuid_v7_time_ordered"].as_str().is_some());
        assert_eq!(json["ulid_lexicographical"].as_str().unwrap().len(), 26);

        // Decode snowflake
        let res_sf = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({
                    "action": "decode_snowflake",
                    "id": "175928847299117063"
                }),
                &ctx,
            )
            .await
            .unwrap();
        let sf_json = res_sf.into_json().unwrap();
        assert!(sf_json["utc_time"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_wcag_contrast() {
        let op = ColorToolkitOp;
        let ctx = ExecutionContext::new("t_color");

        // Black on White
        let res = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "fg": "#000000", "bg": "#FFFFFF" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["contrast_ratio"], 21.0);
        assert_eq!(json["wcag_2_1_compliance"]["aaa_normal_text_7_0"], true);
    }

    #[tokio::test]
    async fn test_strace_parser_fd_leak() {
        let op = SystemTraceOp;
        let ctx = ExecutionContext::new("t_trace");

        let trace_data = r#"
openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3 <0.000020>
read(3, "root:x:0:0...", 4096) = 1024 <0.000015>
openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 4 <0.000025>
close(3) = 0 <0.000010>
"#;

        let res = op
            .execute(DataPayload::text(trace_data), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["has_fd_leaks"], true);
        assert_eq!(json["potential_fd_leaks"][0], 4); // FD 4 was opened but never closed
    }

    #[tokio::test]
    async fn test_system_adversarial_edge_cases() {
        let ctx = ExecutionContext::new("t_sys_edge");

        // 1. Color UTF-8 6-byte non-ASCII regression ("€€" is 6 bytes; MUST NOT panic on slice!)
        let color_op = ColorToolkitOp;
        assert!(color_op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "fg": "€€", "bg": "#FFFFFF" }),
                &ctx
            )
            .await
            .is_err());
        let ok_color = color_op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "fg": "#112233", "bg": "#FFFFFF" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert!(
            ok_color["color_blindness_simulation_fg"]["tritanopia_blue_blind"]
                .as_str()
                .is_some()
        );

        // 2. Cron adversarial DoS range rejected immediately + leap day + Sunday=7 + stepped range
        let cron_op = CronEngineOp;
        assert!(cron_op
            .execute(
                DataPayload::text("0-4294967295 * * * *"),
                serde_json::json!({}),
                &ctx
            )
            .await
            .is_err());
        let leap = cron_op
            .execute(DataPayload::text("0 0 29 2 *"), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(leap["next_20_executions"].as_array().unwrap().len(), 20);
        let sun7 = cron_op
            .execute(
                DataPayload::text("0-30/15 12 * * 7"),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sun7["next_20_executions"].as_array().unwrap().len(), 20);
        // Sunday=7 with step ("7/2") must normalize to 0/2 (Sun, Tue, Thu, Sat) instead of empty mask!
        let sun7_step = cron_op
            .execute(
                DataPayload::text("0 12 * * 7/2"),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(
            sun7_step["next_20_executions"].as_array().unwrap().len(),
            20
        );

        // 3. Trace parser NaN / Inf duration regression (MUST NOT panic in sort!)
        let trace_op = SystemTraceOp;
        let bad_trace = "read(3, \"x\", 1) = 1 <NaN>\nread(3, \"y\", 1) = 1 <inf>\nread(3, \"z\", 1) = 1 <0.001>\n";
        let tres = trace_op
            .execute(DataPayload::text(bad_trace), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(tres["total_trace_lines"], 3);

        // 4. Snowflake u64::MAX epoch overflow regression
        let id_op = UniversalIdsOp;
        let sf = id_op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "decode_snowflake", "id": "175928847299117063", "epoch_ms": u64::MAX }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sf["timestamp_ms"], u64::MAX);
    }
}
