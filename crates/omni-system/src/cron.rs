use chrono::{Datelike, Duration, Timelike, Utc};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct CronEngineOp;

fn parse_field(field_str: &str, min: u32, max: u32) -> OmniResult<Vec<u32>> {
    let mut values = Vec::new();

    for part in field_str.split(',') {
        let part = part.trim();
        if part == "*" {
            values.extend(min..=max);
        } else if let Some(step_str) = part.strip_prefix("*/") {
            let step: u32 = step_str.parse().map_err(|_| OmniError::InvalidInput("Invalid cron step".into()))?;
            if step == 0 { return Err(OmniError::InvalidInput("Step cannot be zero".into())); }
            for v in (min..=max).step_by(step as usize) {
                values.push(v);
            }
        } else if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u32 = start_s.parse().map_err(|_| OmniError::InvalidInput("Invalid cron range start".into()))?;
            let end: u32 = end_s.parse().map_err(|_| OmniError::InvalidInput("Invalid cron range end".into()))?;
            for v in start..=end {
                if v >= min && v <= max {
                    values.push(v);
                }
            }
        } else if let Ok(val) = part.parse::<u32>() {
            if val >= min && val <= max {
                values.push(val);
            }
        } else {
            return Err(OmniError::InvalidInput(format!("Unsupported cron token: {part}")));
        }
    }

    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        return Err(OmniError::InvalidInput(format!("Field '{field_str}' resolved to zero valid values")));
    }
    Ok(values)
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
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let expr = config.get("cron")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| input.as_str().ok().unwrap_or("*/15 * * * *"));

        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(OmniError::InvalidInput("Cron expression must have exactly 5 fields (minute hour day month day-of-week)".into()));
        }

        let minutes = parse_field(fields[0], 0, 59)?;
        let hours = parse_field(fields[1], 0, 23)?;
        let days = parse_field(fields[2], 1, 31)?;
        let months = parse_field(fields[3], 1, 12)?;
        let dows = parse_field(fields[4], 0, 6)?;

        // Find next 20 execution times starting from now
        let mut current = Utc::now();
        current = current.with_second(0).unwrap().with_nanosecond(0).unwrap() + Duration::minutes(1);

        let mut next_executions = Vec::new();
        let max_iterations = 500000;
        let mut iter = 0;

        while next_executions.len() < 20 && iter < max_iterations {
            iter += 1;
            let m = current.minute();
            let h = current.hour();
            let d = current.day();
            let mo = current.month();
            let dow = current.weekday().num_days_from_sunday();

            if minutes.contains(&m) && hours.contains(&h) && days.contains(&d) && months.contains(&mo) && dows.contains(&dow) {
                next_executions.push(current.to_rfc3339());
            }

            current = current + Duration::minutes(1);
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
