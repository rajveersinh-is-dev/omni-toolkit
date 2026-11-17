use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct FlamegraphGeneratorOp;

#[async_trait]
impl Operation for FlamegraphGeneratorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.flamegraph",
            "Folded Stack & SVG Flamegraph Generator",
            "Parses perf/pprof folded stack traces and synthesizes interactive vector SVG flamegraph visualizations",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text, DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let text = input.into_text().unwrap_or_default();
        let mut stacks: Vec<(Vec<String>, u64)> = Vec::new();
        let mut total_samples = 0u64;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }

            // Format: "func1;func2;func3 100"
            if let Some((frames_str, count_str)) = trimmed.rsplit_once(' ') {
                if let Ok(count) = count_str.parse::<u64>() {
                    let frames: Vec<String> = frames_str.split(';').map(|s| s.trim().to_string()).collect();
                    stacks.push((frames, count));
                    total_samples += count;
                }
            }
        }

        if stacks.is_empty() || total_samples == 0 {
            return Err(OmniError::InvalidInput("No valid folded stack trace lines found in input".into()));
        }

        // Build SVG visualization
        let svg_width = 1200.0;
        let row_height = 22.0;
        let mut max_depth = 0;

        for (frames, _) in &stacks {
            if frames.len() > max_depth {
                max_depth = frames.len();
            }
        }

        let svg_height = ((max_depth + 2) as f64 * row_height).max(300.0);

        let mut svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="100%" height="{}">
  <style>
    rect {{ stroke: #1e222b; stroke-width: 1px; rx: 2px; }}
    rect:hover {{ fill: #ff7b72 !important; cursor: pointer; }}
    text {{ fill: #ffffff; font-family: monospace; font-size: 11px; }}
  </style>
  <rect width="{}" height="{}" fill="#0d1117"/>
  <text x="20" y="30" fill="#58a6ff" font-size="16px" font-weight="bold">Flamegraph: {} Total Samples</text>
"##,
            svg_width, svg_height, svg_height, svg_width, svg_height, total_samples
        );

        let colors = ["#f0883e", "#d29922", "#db6d28", "#bd561d", "#e3b341"];
        let mut current_x = 20.0;
        let usable_width = svg_width - 40.0;

        for (idx, (frames, count)) in stacks.iter().enumerate() {
            let width = (usable_width * (*count as f64 / total_samples as f64)).max(2.0);

            for (depth, func) in frames.iter().enumerate() {
                let y = svg_height - 40.0 - (depth as f64 * row_height);
                let color = colors[(depth + idx) % colors.len()];

                svg.push_str(&format!(
                    r##"  <rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" fill="{}"/>
  <text x="{:.1}" y="{:.1}">{}</text>
"##,
                    current_x, y, width, row_height - 2.0, color,
                    current_x + 4.0, y + 14.0, if width > 40.0 { func } else { "" }
                ));
            }

            current_x += width;
        }

        svg.push_str("</svg>");

        let format = config.get("format").and_then(|v| v.as_str()).unwrap_or("svg");
        if format == "json" {
            Ok(DataPayload::json(json!({
                "total_samples": total_samples,
                "stack_traces_count": stacks.len(),
                "max_stack_depth": max_depth,
            })))
        } else {
            Ok(DataPayload::text(svg))
        }
    }
}
