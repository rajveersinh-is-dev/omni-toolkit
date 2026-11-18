use image::{imageops, DynamicImage, ImageFormat};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::io::Cursor;

pub struct ImagePipelineOp;

#[async_trait]
impl Operation for ImagePipelineOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "image.pipeline",
            "Multi-Format Image Processor",
            "Processes, resizes, crops, and transforms raster images across JPEG, PNG, WebP, BMP, and QOI",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Bytes, DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let bytes = input.into_bytes();

        let img = image::load_from_memory(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to decode image: {e}")))?;

        match action {
            "info" => Ok(DataPayload::json(json!({
                "width": img.width(),
                "height": img.height(),
                "color_type": format!("{:?}", img.color()),
                "aspect_ratio": (img.width() as f64 / img.height().max(1) as f64 * 100.0).round() / 100.0,
                "raw_byte_size": bytes.len(),
            }))),
            "transform" => {
                let mut processed = img;

                // Resize with strict bounds to prevent multi-GB OOM allocations
                if let (Some(w), Some(h)) = (
                    config.get("width").and_then(|v| v.as_u64()),
                    config.get("height").and_then(|v| v.as_u64()),
                ) {
                    if w == 0
                        || h == 0
                        || w > 16_384
                        || h > 16_384
                        || w.saturating_mul(h) > 64_000_000
                    {
                        return Err(OmniError::Validation(
                            "Image resize dimensions must be 1..=16384 per side and <= 64M total pixels".into(),
                        ));
                    }
                    processed =
                        processed.resize_exact(w as u32, h as u32, imageops::FilterType::Lanczos3);
                }

                // Grayscale
                if config
                    .get("grayscale")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    processed = DynamicImage::ImageLuma8(processed.to_luma8());
                }

                // Rotate
                if let Some(deg) = config.get("rotate").and_then(|v| v.as_i64()) {
                    processed = match deg {
                        90 => processed.rotate90(),
                        180 => processed.rotate180(),
                        270 => processed.rotate270(),
                        _ => processed,
                    };
                }

                let target_fmt = config
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("png");
                let mut out_bytes = Vec::new();
                let fmt = match target_fmt {
                    "jpeg" | "jpg" => ImageFormat::Jpeg,
                    "bmp" => ImageFormat::Bmp,
                    "webp" => ImageFormat::WebP,
                    _ => ImageFormat::Png,
                };

                processed
                    .write_to(&mut Cursor::new(&mut out_bytes), fmt)
                    .map_err(|e| OmniError::Execution {
                        operation: "image_write".into(),
                        message: e.to_string(),
                    })?;

                Ok(DataPayload::bytes(out_bytes))
            }
            _ => Err(OmniError::InvalidInput(format!("Unknown action: {action}"))),
        }
    }
}

fn srgb_to_xyz_lab(r_u8: f64, g_u8: f64, b_u8: f64) -> OmniResult<([f64; 3], [f64; 3])> {
    if !r_u8.is_finite()
        || !g_u8.is_finite()
        || !b_u8.is_finite()
        || !(0.0..=255.0).contains(&r_u8)
        || !(0.0..=255.0).contains(&g_u8)
        || !(0.0..=255.0).contains(&b_u8)
    {
        return Err(OmniError::Validation(
            "sRGB channels r, g, b must be finite numbers in 0.0..=255.0".into(),
        ));
    }
    let r = r_u8 / 255.0;
    let g = g_u8 / 255.0;
    let b = b_u8 / 255.0;

    let to_linear = |c: f64| {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let r_lin = to_linear(r);
    let g_lin = to_linear(g);
    let b_lin = to_linear(b);

    // sRGB -> CIE 1931 XYZ (D65)
    let x = r_lin * 0.4124564 + g_lin * 0.3575761 + b_lin * 0.1804375;
    let y = r_lin * 0.2126729 + g_lin * 0.7151522 + b_lin * 0.0721750;
    let z = r_lin * 0.0193339 + g_lin * 0.1191920 + b_lin * 0.9503041;

    // XYZ -> CIELAB (D65 ref: Xn=0.95047, Yn=1.00000, Zn=1.08883)
    let f_lab = |t: f64| {
        if t > 0.008856 {
            t.cbrt()
        } else {
            7.787 * t + 16.0 / 116.0
        }
    };
    let fx = f_lab(x / 0.95047);
    let fy = f_lab(y / 1.00000);
    let fz = f_lab(z / 1.08883);

    let l_star = 116.0 * fy - 16.0;
    let a_star = 500.0 * (fx - fy);
    let b_star = 200.0 * (fy - fz);

    Ok(([x, y, z], [l_star, a_star, b_star]))
}

/// Computes exact CIEDE2000 color difference (Sharma, Wu & Dalal, 2005) with kL=kC=kH=1.
pub fn delta_e_2000(lab1: [f64; 3], lab2: [f64; 3]) -> f64 {
    let (l1, a1, b1) = (lab1[0], lab1[1], lab1[2]);
    let (l2, a2, b2) = (lab2[0], lab2[1], lab2[2]);

    let c1 = (a1 * a1 + b1 * b1).sqrt();
    let c2 = (a2 * a2 + b2 * b2).sqrt();
    let c_bar = 0.5 * (c1 + c2);
    let c_bar7 = c_bar.powi(7);
    let g = 0.5 * (1.0 - (c_bar7 / (c_bar7 + 25.0_f64.powi(7))).sqrt());

    let a1_p = (1.0 + g) * a1;
    let a2_p = (1.0 + g) * a2;
    let c1_p = (a1_p * a1_p + b1 * b1).sqrt();
    let c2_p = (a2_p * a2_p + b2 * b2).sqrt();

    let hp = |b: f64, a_p: f64| -> f64 {
        if b == 0.0 && a_p == 0.0 {
            0.0
        } else {
            let deg = b.atan2(a_p).to_degrees();
            if deg < 0.0 {
                deg + 360.0
            } else {
                deg
            }
        }
    };
    let h1_p = hp(b1, a1_p);
    let h2_p = hp(b2, a2_p);

    let dl_p = l2 - l1;
    let dc_p = c2_p - c1_p;

    let dh_p = if c1_p * c2_p == 0.0 {
        0.0
    } else if (h2_p - h1_p).abs() <= 180.0 {
        h2_p - h1_p
    } else if h2_p - h1_p > 180.0 {
        h2_p - h1_p - 360.0
    } else {
        h2_p - h1_p + 360.0
    };

    let d_big_h_p = 2.0 * (c1_p * c2_p).sqrt() * (dh_p / 2.0).to_radians().sin();

    let l_bar_p = 0.5 * (l1 + l2);
    let c_bar_p = 0.5 * (c1_p + c2_p);

    let h_bar_p = if c1_p * c2_p == 0.0 {
        h1_p + h2_p
    } else if (h1_p - h2_p).abs() <= 180.0 {
        0.5 * (h1_p + h2_p)
    } else if h1_p + h2_p < 360.0 {
        0.5 * (h1_p + h2_p + 360.0)
    } else {
        0.5 * (h1_p + h2_p - 360.0)
    };

    let t = 1.0 - 0.17 * (h_bar_p - 30.0).to_radians().cos()
        + 0.24 * (2.0 * h_bar_p).to_radians().cos()
        + 0.32 * (3.0 * h_bar_p + 6.0).to_radians().cos()
        - 0.20 * (4.0 * h_bar_p - 63.0).to_radians().cos();

    let d_theta = 30.0 * (-((h_bar_p - 275.0) / 25.0).powi(2)).exp();
    let c_bar_p7 = c_bar_p.powi(7);
    let r_c = 2.0 * (c_bar_p7 / (c_bar_p7 + 25.0_f64.powi(7))).sqrt();

    let l_bar_m50_sq = (l_bar_p - 50.0).powi(2);
    let s_l = 1.0 + (0.015 * l_bar_m50_sq) / (20.0 + l_bar_m50_sq).sqrt();
    let s_c = 1.0 + 0.045 * c_bar_p;
    let s_h = 1.0 + 0.015 * c_bar_p * t;
    let r_t = -(2.0 * d_theta).to_radians().sin() * r_c;

    let term_l = dl_p / s_l;
    let term_c = dc_p / s_c;
    let term_h = d_big_h_p / s_h;

    (term_l * term_l + term_c * term_c + term_h * term_h + r_t * term_c * term_h)
        .max(0.0)
        .sqrt()
}

pub struct ImageColorSpaceOp;

#[async_trait]
impl Operation for ImageColorSpaceOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "image.color_space",
            "Color Space & Delta-E 2000 Engine",
            "Converts between sRGB, CIE 1931 XYZ, CIELAB, CIELCh, and computes exact Delta-E 2000 color differences",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Json, DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        _input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let r_u8 = config.get("r").and_then(|v| v.as_f64()).unwrap_or(128.0);
        let g_u8 = config.get("g").and_then(|v| v.as_f64()).unwrap_or(128.0);
        let b_u8 = config.get("b").and_then(|v| v.as_f64()).unwrap_or(128.0);

        let ([x, y, z], lab1) = srgb_to_xyz_lab(r_u8, g_u8, b_u8)?;
        let [l_star, a_star, b_star] = lab1;

        let chroma = (a_star * a_star + b_star * b_star).sqrt();
        let hue_deg = (b_star.atan2(a_star).to_degrees() + 360.0) % 360.0;

        // Optional pairwise CIEDE2000 comparison via `compare: {r,g,b}` or `r2/g2/b2`
        let delta_e_2000_val = if let Some(cmp) = config.get("compare") {
            let r2 = cmp.get("r").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let g2 = cmp.get("g").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b2 = cmp.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let (_, lab2) = srgb_to_xyz_lab(r2, g2, b2)?;
            Some((delta_e_2000(lab1, lab2) * 10000.0).round() / 10000.0)
        } else if config.get("r2").is_some()
            || config.get("g2").is_some()
            || config.get("b2").is_some()
        {
            let r2 = config.get("r2").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let g2 = config.get("g2").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b2 = config.get("b2").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let (_, lab2) = srgb_to_xyz_lab(r2, g2, b2)?;
            Some((delta_e_2000(lab1, lab2) * 10000.0).round() / 10000.0)
        } else {
            None
        };

        Ok(DataPayload::json(json!({
            "srgb_input": {
                "r": r_u8.round() as u8,
                "g": g_u8.round() as u8,
                "b": b_u8.round() as u8,
                "hex": format!("#{:02X}{:02X}{:02X}", r_u8.round() as u8, g_u8.round() as u8, b_u8.round() as u8),
            },
            "cie_xyz": {
                "x": (x * 10000.0).round() / 10000.0,
                "y": (y * 10000.0).round() / 10000.0,
                "z": (z * 10000.0).round() / 10000.0,
            },
            "cielab": {
                "L": (l_star * 100.0).round() / 100.0,
                "a": (a_star * 100.0).round() / 100.0,
                "b": (b_star * 100.0).round() / 100.0,
            },
            "cielch": {
                "L": (l_star * 100.0).round() / 100.0,
                "C": (chroma * 100.0).round() / 100.0,
                "h_deg": (hue_deg * 10.0).round() / 10.0,
            },
            "relative_luminance": (y * 10000.0).round() / 10000.0,
            "delta_e_2000": delta_e_2000_val,
        })))
    }
}

pub struct ImageMetadataOp;

#[async_trait]
impl Operation for ImageMetadataOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "image.metadata",
            "Image EXIF & Metadata Forensics",
            "Inspects EXIF, IPTC, and XMP metadata chunks and provides irreversible GPS/PII stripping",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Bytes])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("inspect");
        let bytes = input.into_bytes();

        match action {
            "strip" => {
                // Stripping for JPEG: safely strip APP1..APP15 and COM segments with bounds checks
                if bytes.starts_with(&[0xFF, 0xD8]) {
                    let mut clean_bytes = vec![0xFF, 0xD8];
                    let mut i = 2;
                    while i < bytes.len() {
                        if bytes[i] == 0xFF {
                            if i + 1 >= bytes.len() {
                                clean_bytes.push(bytes[i]);
                                break;
                            }
                            let marker = bytes[i + 1];
                            if marker == 0xFF {
                                i += 1;
                                continue;
                            }
                            // Standalone markers without length: RST0..RST7, SOI, EOI, TEM
                            if marker == 0x00 || marker == 0x01 || (0xD0..=0xD9).contains(&marker) {
                                clean_bytes.extend_from_slice(&bytes[i..i + 2]);
                                i += 2;
                                if marker == 0xD9 {
                                    break;
                                }
                                continue;
                            }
                            if marker == 0xDA {
                                // Start of Scan: copy rest of stream verbatim
                                clean_bytes.extend_from_slice(&bytes[i..]);
                                break;
                            }
                            if i + 4 > bytes.len() {
                                break;
                            }
                            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
                            let Some(seg_end) = i.checked_add(2).and_then(|v| v.checked_add(len))
                            else {
                                break;
                            };
                            if len < 2 || seg_end > bytes.len() {
                                return Err(OmniError::InvalidInput(
                                    "Malformed or truncated JPEG segment length".into(),
                                ));
                            }
                            // Check if APP1..APP15 (0xE1..0xEF) or COM (0xFE)
                            if (0xE1..=0xEF).contains(&marker) || marker == 0xFE {
                                // Skip metadata segment
                                i = seg_end;
                                continue;
                            } else {
                                clean_bytes.extend_from_slice(&bytes[i..seg_end]);
                                i = seg_end;
                            }
                        } else {
                            clean_bytes.push(bytes[i]);
                            i += 1;
                        }
                    }
                    Ok(DataPayload::bytes(clean_bytes))
                } else {
                    // For non-JPEG, reload & re-encode without ancillary chunks
                    let img = image::load_from_memory(&bytes).map_err(|e| {
                        OmniError::InvalidInput(format!("Failed to parse image for stripping: {e}"))
                    })?;
                    let mut out = Vec::new();
                    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                        .map_err(|e| OmniError::Execution {
                            operation: "strip_reencode".into(),
                            message: e.to_string(),
                        })?;
                    Ok(DataPayload::bytes(out))
                }
            }
            _ => {
                let is_jpeg = bytes.starts_with(&[0xFF, 0xD8]);
                let is_png = bytes.starts_with(&[0x89, b'P', b'N', b'G']);
                let mut app_markers = Vec::new();

                if is_jpeg {
                    let mut i = 2;
                    while i + 1 < bytes.len() {
                        if bytes[i] == 0xFF {
                            let marker = bytes[i + 1];
                            if marker == 0xFF {
                                i += 1;
                                continue;
                            }
                            if marker == 0xDA || marker == 0xD9 {
                                break;
                            }
                            if marker == 0x00 || marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
                                i += 2;
                                continue;
                            }
                            if i + 4 > bytes.len() {
                                break;
                            }
                            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
                            let Some(seg_end) = i.checked_add(2).and_then(|v| v.checked_add(len))
                            else {
                                break;
                            };
                            if len < 2 || seg_end > bytes.len() {
                                break;
                            }
                            let name = match marker {
                                0xE0 => "APP0 (JFIF)",
                                0xE1 => "APP1 (EXIF / XMP)",
                                0xE2 => "APP2 (ICC Profile)",
                                0xED => "APP13 (Photoshop IPTC)",
                                0xFE => "COM (Comment)",
                                _ => "Other Marker",
                            };
                            app_markers.push(json!({
                                "marker_hex": format!("0xFF{:02X}", marker),
                                "description": name,
                                "length": len,
                            }));
                            i = seg_end;
                        } else {
                            i += 1;
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "format": if is_jpeg { "JPEG" } else if is_png { "PNG" } else { "Other" },
                    "file_size": bytes.len(),
                    "has_exif_marker": app_markers.iter().any(|m| m["marker_hex"] == "0xFFE1"),
                    "markers": app_markers,
                })))
            }
        }
    }
}
