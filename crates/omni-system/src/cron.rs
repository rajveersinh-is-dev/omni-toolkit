use chrono::{Datelike, Duration, TimeZone, Timelike, Utc};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct CronEngineOp;

/// Parses a single cron field into a compact 64-bit bitmask (`bit v` set iff value `v` matches).
/// Supports `*`, `*/step`, `a-b`, `a-b/step`, single values, and comma-separated combinations.
/// For day-of-week (`allow_sunday_seven = true`), value `7` is normalized to `0` (Sunday).
fn parse_field_mask(
    field_str: &str,
    min: u32,
    max: u32,
    allow_sunday_seven: bool,
) -> OmniResult<u64> {
    let mut mask = 0u64;
    let effective_max = if allow_sunday_seven { max.max(7) } else { max };

    let set_val = |m: &mut u64, v: u32| {
        let norm = if allow_sunday_seven && v == 7 { 0 } else { v };
        if norm >= min && norm <= max {
            *m |= 1u64 << norm;
        }
    };

    for part in field_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(OmniError::InvalidInput("Empty token in cron field".into()));
        }

        let (base, step) = if let Some((lhs, step_str)) = part.split_once('/') {
            let s: u32 = step_str
                .parse()
                .map_err(|_| OmniError::InvalidInput("Invalid cron step".into()))?;
            if s == 0 || s > effective_max + 1 {
                return Err(OmniError::InvalidInput(
                    "Cron step must be positive and within field range".into(),
                ));
            }
            (lhs, s)
        } else {
            (part, 1u32)
        };

        if base == "*" {
            let mut v = min;
            while v <= max {
                set_val(&mut mask, v);
                v = v.saturating_add(step);
            }
        } else if let Some((start_s, end_s)) = base.split_once('-') {
            let start: u32 = start_s
                .parse()
                .map_err(|_| OmniError::InvalidInput("Invalid cron range start".into()))?;
            let end: u32 = end_s
                .parse()
                .map_err(|_| OmniError::InvalidInput("Invalid cron range end".into()))?;
            if start < min || end > effective_max || start > end {
                return Err(OmniError::InvalidInput(format!(
                    "Cron range '{start}-{end}' out of valid bounds [{min}..={effective_max}]"
                )));
            }
            let mut v = start;
            while v <= end {
                set_val(&mut mask, v);
                v = v.saturating_add(step);
            }
        } else {
            let val: u32 = base
                .parse()
                .map_err(|_| OmniError::InvalidInput(format!("Unsupported cron token: {base}")))?;
            if val < min || val > effective_max {
                return Err(OmniError::InvalidInput(format!(
                    "Cron value '{val}' out of valid bounds [{min}..={effective_max}]"
                )));
            }
            if step == 1 {
                set_val(&mut mask, val);
            } else {
                let mut v = if allow_sunday_seven && val == 7 {
                    0
                } else {
                    val
                };
                while v <= max {
                    set_val(&mut mask, v);
                    v = v.saturating_add(step);
                }
            }
        }
    }

    if mask == 0 {
        return Err(OmniError::InvalidInput(format!(
            "Field '{field_str}' resolved to zero valid values"
        )));
    }
    Ok(mask)
}

#[inline]
fn mask_has(mask: u64, val: u32) -> bool {
    val < 64 && ((mask >> val) & 1) != 0
}

#[async_trait]
impl Operation for CronEngineOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.cron",
            "Cron Parser & Execution Scheduler",
            "Validates 5-field cron expressions, produces natural language descriptions, and calculates the next 20 execution timestamps",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["system".into(), "cron".into(), "scheduler".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let expr = config
            .get("cron")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| input.as_str().ok().unwrap_or("*/15 * * * *"));

        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(OmniError::InvalidInput(
                "Cron expression must have exactly 5 fields (minute hour day month day-of-week)"
                    .into(),
            ));
        }

        let minutes_mask = parse_field_mask(fields[0], 0, 59, false)?;
        let hours_mask = parse_field_mask(fields[1], 0, 23, false)?;
        let days_mask = parse_field_mask(fields[2], 1, 31, false)?;
        let months_mask = parse_field_mask(fields[3], 1, 12, false)?;
        let dows_mask = parse_field_mask(fields[4], 0, 6, true)?;

        // Start at the next whole minute boundary without panicking
        let now = Utc::now();
        let mut current = now
            .with_second(0)
            .and_then(|dt| dt.with_nanosecond(0))
            .unwrap_or(now)
            + Duration::minutes(1);

        let max_year = now.year() + 100;
        let mut next_executions = Vec::with_capacity(20);
        let mut steps = 0usize;
        let max_steps = 200_000usize;

        while next_executions.len() < 20 && current.year() <= max_year && steps < max_steps {
            steps += 1;
            let mo = current.month();
            if !mask_has(months_mask, mo) {
                let (next_year, next_month) = if mo == 12 {
                    (current.year() + 1, 1)
                } else {
                    (current.year(), mo + 1)
                };
                if let Some(dt) = Utc
                    .with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
                    .single()
                {
                    current = dt;
                    continue;
                }
                break;
            }

            let d = current.day();
            let dow = current.weekday().num_days_from_sunday();
            if !mask_has(days_mask, d) || !mask_has(dows_mask, dow) {
                let next_day = (current + Duration::days(1))
                    .with_hour(0)
                    .and_then(|dt| dt.with_minute(0))
                    .unwrap_or(current + Duration::days(1));
                current = next_day;
                continue;
            }

            let h = current.hour();
            if !mask_has(hours_mask, h) {
                let next_hour = (current + Duration::hours(1))
                    .with_minute(0)
                    .unwrap_or(current + Duration::hours(1));
                current = next_hour;
                continue;
            }

            let m = current.minute();
            if mask_has(minutes_mask, m) {
                next_executions.push(current.to_rfc3339());
            }

            current += Duration::minutes(1);
        }

        let description = format!(
            "At minute {} past hour {} on day-of-month {} in month {} on weekday {}",
            fields[0], fields[1], fields[2], fields[3], fields[4]
        );

        Ok(DataPayload::json(json!({
            "expression": expr,
            "description": description,
            "is_valid": true,
            "next_20_executions": next_executions,
        })))
    }
}
