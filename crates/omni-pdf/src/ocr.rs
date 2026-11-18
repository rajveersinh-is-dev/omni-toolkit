use lopdf::Document;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub fn detect_tesseract_binary(custom_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = custom_path {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
        return None;
    }
    let bin_name = if cfg!(windows) {
        "tesseract.exe"
    } else {
        "tesseract"
    };
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct PdfOcrLayoutOp;

#[async_trait]
impl Operation for PdfOcrLayoutOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pdf.ocr",
            "PDF Text Extractor & Tesseract OCR Runner",
            "Extracts embedded PDF text layers via lopdf, or executes host Tesseract OCR on raster images (PNG/JPEG/TIFF/BMP) without shell interpolation",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Text])
        .with_status(FeatureStatus::Experimental)
        .with_limitations(vec![
            "Embedded PDF text extraction reads existing PDF text streams via lopdf (no synthetic bounding boxes)".into(),
            "Optical character recognition (mode='tesseract' or raster image input) requires `tesseract` installed on host PATH".into(),
        ])
        .with_tags(vec!["pdf".into(), "ocr".into(), "text".into(), "tesseract".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let output_format = config
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("json");
        let mode = config
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");
        let lang = config.get("lang").and_then(|v| v.as_str()).unwrap_or("eng");
        let bytes = input.into_bytes();

        if bytes.is_empty() {
            return Err(OmniError::InvalidInput(
                "Empty input buffer supplied".into(),
            ));
        }

        let is_pdf = bytes.starts_with(b"%PDF");

        // Optical Character Recognition via host Tesseract binary
        if mode == "tesseract" || (!is_pdf && mode == "auto") {
            if !lang
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '_')
            {
                return Err(OmniError::InvalidInput(format!(
                    "Invalid Tesseract language specification '{}'",
                    lang
                )));
            }

            let custom_bin = config.get("tesseract_path").and_then(|v| v.as_str());
            let tesseract_bin = detect_tesseract_binary(custom_bin).ok_or_else(|| {
                OmniError::Execution {
                    operation: "pdf.ocr".into(),
                    message: "Tesseract OCR executable not found in PATH. Install Tesseract 5 or supply a PDF with embedded text and mode='extract_text'.".into(),
                }
            })?;

            let work_dir = std::env::temp_dir().join(format!("omni_ocr_{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&work_dir).map_err(|e| OmniError::Io(e.to_string()))?;
            let _guard = TempDirGuard(work_dir.clone());

            let in_file = work_dir.join("input_image.bin");
            tokio::fs::write(&in_file, &bytes)
                .await
                .map_err(|e| OmniError::Io(e.to_string()))?;

            let mut child = Command::new(&tesseract_bin)
                .arg(&in_file)
                .arg("stdout")
                .arg("-l")
                .arg(lang)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| OmniError::Execution {
                    operation: "pdf.ocr".into(),
                    message: format!("Failed to spawn tesseract: {e}"),
                })?;

            let mut stdout_pipe = child.stdout.take();
            let mut stderr_pipe = child.stderr.take();
            let status = tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(OmniError::Cancelled);
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(OmniError::Timeout(60_000));
                }
                res = child.wait() => res.map_err(|e| OmniError::Execution {
                    operation: "pdf.ocr".into(),
                    message: e.to_string(),
                })?,
            };

            if !status.success() {
                let mut stderr_bytes = Vec::new();
                if let Some(ref mut pipe) = stderr_pipe {
                    use tokio::io::AsyncReadExt;
                    let _ = pipe.read_to_end(&mut stderr_bytes).await;
                }
                let stderr = String::from_utf8_lossy(&stderr_bytes);
                return Err(OmniError::Execution {
                    operation: "pdf.ocr".into(),
                    message: format!("Tesseract failed ({}): {}", status, stderr.trim()),
                });
            }

            let mut stdout_bytes = Vec::new();
            if let Some(ref mut pipe) = stdout_pipe {
                use tokio::io::AsyncReadExt;
                let _ = pipe.read_to_end(&mut stdout_bytes).await;
            }
            let text = String::from_utf8_lossy(&stdout_bytes).to_string();
            if output_format == "text" {
                return Ok(DataPayload::text(text));
            }
            return Ok(DataPayload::json(json!({
                "engine": "tesseract",
                "language": lang,
                "text": text,
                "character_count": text.chars().count(),
            })));
        }

        // Embedded PDF text extraction via lopdf (no fabricated bounding boxes)
        let doc = Document::load_mem(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse PDF document: {e}")))?;

        let pages = doc.get_pages();
        let mut page_results = Vec::new();
        let mut full_text = String::new();

        for (page_num, _page_id) in pages {
            let extracted = doc.extract_text(&[page_num]).unwrap_or_default();
            let lines: Vec<&str> = extracted.lines().filter(|l| !l.trim().is_empty()).collect();

            page_results.push(json!({
                "page_number": page_num,
                "line_count": lines.len(),
                "lines": lines,
            }));

            full_text.push_str(&format!("--- Page {} ---\n", page_num));
            full_text.push_str(&extracted);
            full_text.push('\n');
        }

        if output_format == "text" {
            Ok(DataPayload::text(full_text))
        } else {
            Ok(DataPayload::json(json!({
                "engine": "lopdf_embedded_text",
                "total_pages": page_results.len(),
                "pages": page_results,
            })))
        }
    }
}
