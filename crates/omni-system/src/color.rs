use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct ColorToolkitOp;

fn parse_hex_color(hex_str: &str) -> OmniResult<[f64; 3]> {
    let clean = hex_str.trim().trim_start_matches('#');
    if clean.len() != 6 || !clean.is_ascii() {
        return Err(OmniError::InvalidInput(
            "Hex color must be exactly 6 ASCII hex digits (#RRGGBB)".into(),
        ));
    }
    let r = u8::from_str_radix(&clean[0..2], 16)
        .map_err(|e| OmniError::InvalidInput(e.to_string()))? as f64
        / 255.0;
    let g = u8::from_str_radix(&clean[2..4], 16)
        .map_err(|e| OmniError::InvalidInput(e.to_string()))? as f64
        / 255.0;
    let b = u8::from_str_radix(&clean[4..6], 16)
        .map_err(|e| OmniError::InvalidInput(e.to_string()))? as f64
        / 255.0;
    Ok([r, g, b])
}

fn linearize(c: f64) -> f64 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn relative_luminance(rgb: [f64; 3]) -> f64 {
    0.2126 * linearize(rgb[0]) + 0.7152 * linearize(rgb[1]) + 0.0722 * linearize(rgb[2])
}

fn channel_to_u8(v: f64) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u8
}

#[async_trait]
impl Operation for ColorToolkitOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.color",
            "Color Toolkit & WCAG Contrast Engine",
            "Evaluates WCAG 2.1 AA/AAA contrast ratios and simulates Protanopia, Deuteranopia, and Tritanopia color blindness",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["system".into(), "color".into(), "wcag".into(), "accessibility".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let fg_hex = config
            .get("fg")
            .and_then(|v| v.as_str())
            .unwrap_or("#000000");

        let bg_hex = config
            .get("bg")
            .and_then(|v| v.as_str())
            .or_else(|| input.as_str().ok())
            .unwrap_or("#FFFFFF");

        let fg_rgb = parse_hex_color(fg_hex)?;
        let bg_rgb = parse_hex_color(bg_hex)?;

        let l_fg = relative_luminance(fg_rgb);
        let l_bg = relative_luminance(bg_rgb);

        let (lighter, darker) = if l_fg > l_bg {
            (l_fg, l_bg)
        } else {
            (l_bg, l_fg)
        };
        let contrast_ratio = (lighter + 0.05) / (darker + 0.05);

        // Color blindness simulation (Brettel et al. matrix approximations)
        // Protanopia (red deficiency)
        let protanopia_r = 0.56667 * fg_rgb[0] + 0.43333 * fg_rgb[1];
        let protanopia_g = 0.55833 * fg_rgb[0] + 0.44167 * fg_rgb[1];
        let protan_hex = format!(
            "#{:02X}{:02X}{:02X}",
            channel_to_u8(protanopia_r),
            channel_to_u8(protanopia_g),
            channel_to_u8(fg_rgb[2])
        );

        // Deuteranopia (green deficiency)
        let deut_r = 0.625 * fg_rgb[0] + 0.375 * fg_rgb[1];
        let deut_g = 0.70 * fg_rgb[0] + 0.30 * fg_rgb[1];
        let deut_hex = format!(
            "#{:02X}{:02X}{:02X}",
            channel_to_u8(deut_r),
            channel_to_u8(deut_g),
            channel_to_u8(fg_rgb[2])
        );

        // Tritanopia (blue deficiency)
        let trit_r = 0.95 * fg_rgb[0] + 0.05 * fg_rgb[1];
        let trit_g = 0.43333 * fg_rgb[1] + 0.56667 * fg_rgb[2];
        let trit_b = 0.475 * fg_rgb[1] + 0.525 * fg_rgb[2];
        let trit_hex = format!(
            "#{:02X}{:02X}{:02X}",
            channel_to_u8(trit_r),
            channel_to_u8(trit_g),
            channel_to_u8(trit_b)
        );

        Ok(DataPayload::json(json!({
            "foreground": fg_hex,
            "background": bg_hex,
            "contrast_ratio": (contrast_ratio * 100.0).round() / 100.0,
            "wcag_2_1_compliance": {
                "aa_normal_text_4_5": contrast_ratio >= 4.5,
                "aa_large_text_3_0": contrast_ratio >= 3.0,
                "aaa_normal_text_7_0": contrast_ratio >= 7.0,
                "aaa_large_text_4_5": contrast_ratio >= 4.5,
            },
            "color_blindness_simulation_fg": {
                "protanopia_red_blind": protan_hex,
                "deuteranopia_green_blind": deut_hex,
                "tritanopia_blue_blind": trit_hex,
            }
        })))
    }
}
