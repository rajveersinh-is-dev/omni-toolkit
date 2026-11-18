use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct FlamegraphGeneratorOp;

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[async_trait]
impl Operation for FlamegraphGeneratorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.flamegraph",
            "Folded Stack & SVG Flamegraph Generator",
            "Parses and aggregates perf/pprof folded stack traces into XML-safe vector SVG flamegraphs",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text, DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["system".into(), "profiling".into(), "flamegraph".into(), "svg".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let text = input.into_text()?;
        // Aggregate duplicate folded stacks deterministically
        let mut aggregated: BTreeMap<Vec<String>, u64> = BTreeMap::new();
        let mut total_samples = 0u64;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((frames_str, count_str)) = trimmed.rsplit_once(' ') {
                if let Ok(count) = count_str.parse::<u64>() {
                    if count == 0 {
                        continue;
                    }
                    let frames: Vec<String> = frames_str
                        .split(';')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !frames.is_empty() {
                        *aggregated.entry(frames).or_insert(0) += count;
                        total_samples = total_samples.saturating_add(count);
                    }
                }
            }
        }

        if aggregated.is_empty() || total_samples == 0 {
            return Err(OmniError::InvalidInput(
                "No valid folded stack trace lines found in input (expected 'frame1;frame2 <count>')".into(),
            ));
        }

        let stacks: Vec<(Vec<String>, u64)> = aggregated.into_iter().collect();
        let max_depth = stacks.iter().map(|(f, _)| f.len()).max().unwrap_or(1);

        let svg_width = 1200.0;
        let row_height = 22.0;
        let svg_height = ((max_depth + 3) as f64 * row_height).max(260.0);

        let mut svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="100%" height="{}">
  <style>
    rect {{ stroke: #1e222b; stroke-width: 1px; rx: 2px; }}
    rect:hover {{ fill: #ff7b72 !important; cursor: pointer; }}
    text {{ fill: #ffffff; font-family: monospace; font-size: 11px; }}
  </style>
  <rect width="{}" height="{}" fill="#0d1117"/>
  <text x="20" y="28" fill="#58a6ff" font-size="16px" font-weight="bold">Flamegraph: {} Total Samples ({} Unique Stacks)</text>
"##,
            svg_width,
            svg_height,
            svg_height,
            svg_width,
            svg_height,
            total_samples,
            stacks.len()
        );

        let colors = ["#f0883e", "#d29922", "#db6d28", "#bd561d", "#e3b341"];
        let mut current_x = 20.0;
        let usable_width = svg_width - 40.0;

        for (idx, (frames, count)) in stacks.iter().enumerate() {
            let width = (usable_width * (*count as f64 / total_samples as f64)).max(2.0);

            for (depth, func) in frames.iter().enumerate() {
                let y = svg_height - 32.0 - (depth as f64 * row_height);
                let color = colors[(depth + idx) % colors.len()];
                let safe_func = escape_xml(func);
                let pct = (*count as f64 / total_samples as f64) * 100.0;

                svg.push_str(&format!(
                    "  <g><title>{} ({} samples, {:.1}%)</title><rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{}\"/>",
                    safe_func, count, pct, current_x, y, width, row_height - 2.0, color
                ));
                if width > 42.0 {
                    svg.push_str(&format!(
                        "<text x=\"{:.1}\" y=\"{:.1}\">{}</text>",
                        current_x + 4.0,
                        y + 14.0,
                        safe_func
                    ));
                }
                svg.push_str("</g>\n");
            }

            current_x += width;
        }

        svg.push_str("</svg>");

        let format = config
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("svg");
        if format == "json" {
            Ok(DataPayload::json(json!({
                "total_samples": total_samples,
                "unique_stacks": stacks.len(),
                "max_stack_depth": max_depth,
            })))
        } else {
            Ok(DataPayload::text(svg))
        }
    }
}
