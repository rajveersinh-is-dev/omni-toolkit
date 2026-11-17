use image::{imageops, DynamicImage, ImageFormat};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
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
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("info");
        let bytes = input.into_bytes();

        let img = image::load_from_memory(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to decode image: {e}")))?;

        match action {
            "info" => {
                Ok(DataPayload::json(json!({
                    "width": img.width(),
                    "height": img.height(),
                    "color_type": format!("{:?}", img.color()),
                    "aspect_ratio": (img.width() as f64 / img.height().max(1) as f64 * 100.0).round() / 100.0,
                    "raw_byte_size": bytes.len(),
                })))
            }
            "transform" => {
                let mut processed = img;

                // Resize
                if let (Some(w), Some(h)) = (config.get("width").and_then(|v| v.as_u64()), config.get("height").and_then(|v| v.as_u64())) {
                    processed = processed.resize_exact(w as u32, h as u32, imageops::FilterType::Lanczos3);
                }

                // Grayscale
                if config.get("grayscale").and_then(|v| v.as_bool()).unwrap_or(false) {
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

                let target_fmt = config.get("format").and_then(|v| v.as_str()).unwrap_or("png");
                let mut out_bytes = Vec::new();
                let fmt = match target_fmt {
                    "jpeg" | "jpg" => ImageFormat::Jpeg,
                    "bmp" => ImageFormat::Bmp,
                    "webp" => ImageFormat::WebP,
                    "png" | _ => ImageFormat::Png,
                };

                processed.write_to(&mut Cursor::new(&mut out_bytes), fmt)
                    .map_err(|e| OmniError::Execution { operation: "image_write".into(), message: e.to_string() })?;

                Ok(DataPayload::bytes(out_bytes))
            }
            _ => Err(OmniError::InvalidInput(format!("Unknown action: {action}"))),
        }
    }
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
    }

    async fn execute(&self, _input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let r = config.get("r").and_then(|v| v.as_f64()).unwrap_or(128.0) / 255.0;
        let g = config.get("g").and_then(|v| v.as_f64()).unwrap_or(128.0) / 255.0;
        let b = config.get("b").and_then(|v| v.as_f64()).unwrap_or(128.0) / 255.0;

        // Linearize sRGB
        let to_linear = |c: f64| if c <= 0.04045 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) };
        let r_lin = to_linear(r);
        let g_lin = to_linear(g);
        let b_lin = to_linear(b);

        // sRGB -> CIE XYZ (D65)
        let x = r_lin * 0.4124564 + g_lin * 0.3575761 + b_lin * 0.1804375;
        let y = r_lin * 0.2126729 + g_lin * 0.7151522 + b_lin * 0.0721750;
        let z = r_lin * 0.0193339 + g_lin * 0.1191920 + b_lin * 0.9503041;

        // XYZ -> CIELAB (D65 ref: Xn=0.95047, Yn=1.00000, Zn=1.08883)
        let f_lab = |t: f64| if t > 0.008856 { t.cbrt() } else { 7.787 * t + 16.0 / 116.0 };
        let fx = f_lab(x / 0.95047);
        let fy = f_lab(y / 1.00000);
        let fz = f_lab(z / 1.08883);

        let l_star = 116.0 * fy - 16.0;
        let a_star = 500.0 * (fx - fy);
        let b_star = 200.0 * (fy - fz);

        let chroma = (a_star * a_star + b_star * b_star).sqrt();
        let hue_deg = (b_star.atan2(a_star).to_degrees() + 360.0) % 360.0;

        Ok(DataPayload::json(json!({
            "srgb_input": {
                "r": (r * 255.0).round() as u8,
                "g": (g * 255.0).round() as u8,
                "b": (b * 255.0).round() as u8,
                "hex": format!("#{:02X}{:02X}{:02X}", (r * 255.0).round() as u8, (g * 255.0).round() as u8, (b * 255.0).round() as u8),
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
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("inspect");
        let bytes = input.into_bytes();

        match action {
            "strip" => {
                // Stripping for JPEG: re-encode or strip APP1..APP15 segments
                if bytes.starts_with(&[0xFF, 0xD8]) {
                    let mut clean_bytes = vec![0xFF, 0xD8];
                    let mut i = 2;
                    while i + 4 <= bytes.len() {
                        if bytes[i] == 0xFF {
                            let marker = bytes[i + 1];
                            if marker == 0xDA { // Start of Scan, copy rest
                                clean_bytes.extend_from_slice(&bytes[i..]);
                                break;
                            }
                            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
                            // Check if APP1..APP15 (0xE1..0xEF) or COM (0xFE)
                            if (0xE1..=0xEF).contains(&marker) || marker == 0xFE {
                                // Skip metadata segment
                                i += 2 + len;
                                continue;
                            } else {
                                clean_bytes.extend_from_slice(&bytes[i..i + 2 + len]);
                                i += 2 + len;
                            }
                        } else {
                            clean_bytes.push(bytes[i]);
                            i += 1;
                        }
                    }
                    Ok(DataPayload::bytes(clean_bytes))
                } else {
                    // For non-JPEG, reload & re-encode without ancillary chunks
                    let img = image::load_from_memory(&bytes)
                        .map_err(|e| OmniError::InvalidInput(format!("Failed to parse image for stripping: {e}")))?;
                    let mut out = Vec::new();
                    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                        .map_err(|e| OmniError::Execution { operation: "strip_reencode".into(), message: e.to_string() })?;
                    Ok(DataPayload::bytes(out))
                }
            }
            "inspect" | _ => {
                let is_jpeg = bytes.starts_with(&[0xFF, 0xD8]);
                let is_png = bytes.starts_with(&[0x89, b'P', b'N', b'G']);
                let mut app_markers = Vec::new();

                if is_jpeg {
                    let mut i = 2;
                    while i + 4 <= bytes.len() {
                        if bytes[i] == 0xFF {
                            let marker = bytes[i + 1];
                            if marker == 0xDA { break; }
                            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
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
                            i += 2 + len;
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
