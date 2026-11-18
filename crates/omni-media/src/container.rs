use byteorder::{LittleEndian, ReadBytesExt};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub struct MediaProbeOp;

#[async_trait]
impl Operation for MediaProbeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "media.probe",
            "Media Container & Codec Probe",
            "Demuxes and analyzes MP4/MOV ISO atoms, MKV/WebM EBML headers, and RIFF/WAV audio chunks",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["media".into(), "mp4".into(), "wav".into(), "mkv".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 12 {
            return Err(OmniError::InvalidInput(
                "Media buffer too small to probe (minimum 12 bytes)".into(),
            ));
        }

        // Check RIFF / WAV by walking subchunks properly until "fmt " is located
        if &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
            let mut pos = 12usize;
            let mut fmt_info: Option<(u16, u16, u32, u16)> = None;
            let mut data_bytes: Option<u32> = None;

            while pos + 8 <= bytes.len() {
                let chunk_id = &bytes[pos..pos + 4];
                let chunk_size = (&bytes[pos + 4..pos + 8])
                    .read_u32::<LittleEndian>()
                    .map_err(|e| OmniError::InvalidInput(e.to_string()))?
                    as usize;
                let payload_start = pos + 8;
                let payload_end = payload_start.saturating_add(chunk_size).min(bytes.len());

                if chunk_id == b"fmt " && payload_end >= payload_start + 16 {
                    let audio_format = (&bytes[payload_start..payload_start + 2])
                        .read_u16::<LittleEndian>()
                        .map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    let channels = (&bytes[payload_start + 2..payload_start + 4])
                        .read_u16::<LittleEndian>()
                        .map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    let sample_rate = (&bytes[payload_start + 4..payload_start + 8])
                        .read_u32::<LittleEndian>()
                        .map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    let bits_per_sample = (&bytes[payload_start + 14..payload_start + 16])
                        .read_u16::<LittleEndian>()
                        .map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    fmt_info = Some((audio_format, channels, sample_rate, bits_per_sample));
                } else if chunk_id == b"data" {
                    data_bytes = Some(chunk_size as u32);
                }

                // RIFF chunks are word-aligned (padded to even byte boundary)
                let padded_size = chunk_size + (chunk_size % 2);
                if padded_size == 0 && chunk_size == 0 {
                    pos = payload_start;
                } else {
                    pos = payload_start.saturating_add(padded_size);
                }
            }

            if let Some((audio_format, channels, sample_rate, bits_per_sample)) = fmt_info {
                return Ok(DataPayload::json(json!({
                    "format": "RIFF/WAV",
                    "media_type": "audio",
                    "audio_format_code": audio_format,
                    "channels": channels,
                    "sample_rate_hz": sample_rate,
                    "bits_per_sample": bits_per_sample,
                    "data_chunk_bytes": data_bytes,
                    "file_size_bytes": bytes.len(),
                })));
            }
        }

        // Check MP4 / MOV (ftyp atom)
        if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
            let mut atoms = Vec::new();
            let mut pos = 0;
            while pos + 8 <= bytes.len() {
                let mut size_buf = [0u8; 4];
                size_buf.copy_from_slice(&bytes[pos..pos + 4]);
                let size = u32::from_be_bytes(size_buf) as usize;
                let atom_type = String::from_utf8_lossy(&bytes[pos + 4..pos + 8]).to_string();

                atoms.push(json!({
                    "offset": pos,
                    "type": atom_type,
                    "size": size,
                }));

                if size < 8 || pos.saturating_add(size) > bytes.len() {
                    break;
                }
                pos += size;
            }

            let major_brand = if bytes.len() >= 12 {
                String::from_utf8_lossy(&bytes[8..12]).to_string()
            } else {
                "Unknown".to_string()
            };

            return Ok(DataPayload::json(json!({
                "format": "ISO Base Media File Format (MP4/MOV)",
                "media_type": "video_container",
                "major_brand": major_brand.trim(),
                "total_atoms_parsed": atoms.len(),
                "atoms": atoms,
                "file_size_bytes": bytes.len(),
            })));
        }

        // Check MKV / WebM (EBML header 0x1A45DFA3)
        if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
            return Ok(DataPayload::json(json!({
                "format": "Matroska / WebM (EBML)",
                "media_type": "multimedia_container",
                "ebml_magic": "0x1A45DFA3",
                "file_size_bytes": bytes.len(),
                "status": "Valid EBML container header detected"
            })));
        }

        Ok(DataPayload::json(json!({
            "format": "Unknown / Raw stream",
            "file_size_bytes": bytes.len(),
            "magic_bytes_hex": hex::encode(&bytes[..std::cmp::min(16, bytes.len())])
        })))
    }
}

/// Safe allowlist validation for FFmpeg parameters (prevents argument/flag injection).
fn validate_codec(codec: &str) -> OmniResult<&str> {
    const ALLOWED: &[&str] = &[
        "libx264",
        "libx265",
        "libvpx-vp9",
        "libaom-av1",
        "copy",
        "aac",
        "libopus",
        "libmp3lame",
        "flac",
        "pcm_s16le",
    ];
    if ALLOWED.contains(&codec) {
        Ok(codec)
    } else {
        Err(OmniError::InvalidInput(format!(
            "Unsupported or disallowed codec '{}'. Allowed: {:?}",
            codec, ALLOWED
        )))
    }
}

fn validate_preset(preset: &str) -> OmniResult<&str> {
    const ALLOWED: &[&str] = &[
        "ultrafast",
        "superfast",
        "veryfast",
        "faster",
        "fast",
        "medium",
        "slow",
        "slower",
        "veryslow",
    ];
    if ALLOWED.contains(&preset) {
        Ok(preset)
    } else {
        Err(OmniError::InvalidInput(format!(
            "Invalid FFmpeg preset '{}'",
            preset
        )))
    }
}

fn validate_container(container: &str) -> OmniResult<&str> {
    const ALLOWED: &[&str] = &["mp4", "mkv", "webm", "mov", "wav", "flac", "mp3", "ogg"];
    if ALLOWED.contains(&container) {
        Ok(container)
    } else {
        Err(OmniError::InvalidInput(format!(
            "Unsupported output container '{}'. Allowed: {:?}",
            container, ALLOWED
        )))
    }
}

fn validate_scale(scale: &str) -> OmniResult<String> {
    let parts: Vec<&str> = scale.split(':').collect();
    if parts.len() != 2 {
        return Err(OmniError::InvalidInput(
            "Scale must be formatted as '<width>:<height>' (e.g. '1280:720' or '1280:-2')".into(),
        ));
    }
    for p in &parts {
        let parsed = p.parse::<i32>().map_err(|_| {
            OmniError::InvalidInput(format!("Scale dimension '{}' must be an integer", p))
        })?;
        if parsed == 0 || !(-2..=16384).contains(&parsed) {
            return Err(OmniError::InvalidInput(format!(
                "Scale dimension {} out of valid range (-2..=16384, non-zero)",
                parsed
            )));
        }
    }
    Ok(format!("scale={}:{}", parts[0], parts[1]))
}

fn validate_bitrate(bitrate: &str) -> OmniResult<&str> {
    if bitrate.is_ascii() && bitrate.len() >= 2 && bitrate.len() <= 8 {
        let num = bitrate
            .strip_suffix('k')
            .or_else(|| bitrate.strip_suffix('M'));
        if let Some(digits) = num {
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                return Ok(bitrate);
            }
        }
    }
    Err(OmniError::InvalidInput(format!(
        "Invalid audio bitrate '{}' (expected e.g. '128k', '192k', '320k')",
        bitrate
    )))
}

/// Resolves the `ffmpeg` binary path safely without invoking a shell.
pub fn detect_ffmpeg_binary(custom_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = custom_path {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
        return None;
    }

    let bin_name = if cfg!(windows) {
        "ffmpeg.exe"
    } else {
        "ffmpeg"
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

pub struct MediaTranscodeOp;

#[async_trait]
impl Operation for MediaTranscodeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "media.transcode",
            "FFmpeg Media Transcoder",
            "Executes real FFmpeg media transcoding via safe direct subprocess invocation (no shell interpolation), or generates validated argument plans when mode='plan'",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes, DataType::Json, DataType::Text], vec![DataType::Bytes, DataType::Json])
        .with_status(FeatureStatus::Experimental)
        .with_limitations(vec![
            "Actual media transcoding requires the `ffmpeg` executable to be installed on the host PATH (or supplied via config.ffmpeg_path)".into(),
            "Supported codecs are allowlisted (libx264, libx265, libvpx-vp9, libaom-av1, copy, aac, libopus, libmp3lame, flac, pcm_s16le)".into(),
        ])
        .with_tags(vec!["media".into(), "ffmpeg".into(), "transcode".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let mode = config
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("execute");
        let vcodec = validate_codec(
            config
                .get("vcodec")
                .and_then(|v| v.as_str())
                .unwrap_or("libx264"),
        )?;
        let acodec = validate_codec(
            config
                .get("acodec")
                .and_then(|v| v.as_str())
                .unwrap_or("aac"),
        )?;
        let crf = config.get("crf").and_then(|v| v.as_u64()).unwrap_or(23);
        if crf > 63 {
            return Err(OmniError::InvalidInput(
                "CRF must be between 0 and 63".into(),
            ));
        }
        let preset = validate_preset(
            config
                .get("preset")
                .and_then(|v| v.as_str())
                .unwrap_or("medium"),
        )?;
        let container = validate_container(
            config
                .get("output_format")
                .and_then(|v| v.as_str())
                .unwrap_or("mp4"),
        )?;
        let input_ext = validate_container(
            config
                .get("input_format")
                .and_then(|v| v.as_str())
                .unwrap_or("mp4"),
        )?;
        let audio_bitrate = validate_bitrate(
            config
                .get("abitrate")
                .and_then(|v| v.as_str())
                .unwrap_or("192k"),
        )?;
        let scale_filter = match config.get("scale").and_then(|v| v.as_str()) {
            Some(s) => Some(validate_scale(s)?),
            None => None,
        };
        let timeout_secs = config
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(60)
            .clamp(1, 300);

        let custom_ffmpeg = config.get("ffmpeg_path").and_then(|v| v.as_str());
        let ffmpeg_bin = detect_ffmpeg_binary(custom_ffmpeg);

        let build_args = |in_path: &Path, out_path: &Path| -> Vec<String> {
            let mut args = vec![
                "-hide_banner".to_string(),
                "-loglevel".to_string(),
                "error".to_string(),
                "-y".to_string(),
                "-i".to_string(),
                in_path.to_string_lossy().to_string(),
            ];
            let audio_only = matches!(container, "wav" | "flac" | "mp3" | "ogg");
            if !audio_only {
                args.extend([
                    "-c:v".to_string(),
                    vcodec.to_string(),
                    "-preset".to_string(),
                    preset.to_string(),
                    "-crf".to_string(),
                    crf.to_string(),
                ]);
                if let Some(ref vf) = scale_filter {
                    args.extend(["-vf".to_string(), vf.clone()]);
                }
            } else {
                args.push("-vn".to_string());
            }
            args.extend(["-c:a".to_string(), acodec.to_string()]);
            if acodec != "copy" && acodec != "flac" && acodec != "pcm_s16le" {
                args.extend(["-b:a".to_string(), audio_bitrate.to_string()]);
            }
            if container == "mp4" || container == "mov" {
                args.extend(["-movflags".to_string(), "+faststart".to_string()]);
            }
            args.push(out_path.to_string_lossy().to_string());
            args
        };

        if mode == "plan" {
            let args = build_args(
                Path::new(&format!("input.{input_ext}")),
                Path::new(&format!("output.{container}")),
            );
            return Ok(DataPayload::json(json!({
                "mode": "plan",
                "ffmpeg_available": ffmpeg_bin.is_some(),
                "ffmpeg_path": ffmpeg_bin.map(|p| p.display().to_string()),
                "argv": args,
                "target_video_codec": vcodec,
                "target_audio_codec": acodec,
                "output_format": container,
                "note": "Command plan only; set mode='execute' with binary media bytes to run actual transcoding."
            })));
        }

        // Actual execution mode: requires ffmpeg binary and real media bytes
        let ffmpeg_path = ffmpeg_bin.ok_or_else(|| {
            OmniError::Execution {
                operation: "media.transcode".into(),
                message: "FFmpeg executable not found in PATH. Install FFmpeg or pass config.mode='plan' to inspect arguments.".into(),
            }
        })?;

        let raw_bytes = input.into_bytes();
        if raw_bytes.is_empty() {
            return Err(OmniError::InvalidInput(
                "Empty media input buffer supplied for transcoding".into(),
            ));
        }

        let work_dir = std::env::temp_dir().join(format!("omni_ffmpeg_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work_dir).map_err(|e| OmniError::Io(e.to_string()))?;
        let _guard = TempDirGuard(work_dir.clone());

        let in_file = work_dir.join(format!("input.{input_ext}"));
        let out_file = work_dir.join(format!("output.{container}"));
        tokio::fs::write(&in_file, &raw_bytes)
            .await
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let args = build_args(&in_file, &out_file);

        let mut child = Command::new(&ffmpeg_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| OmniError::Execution {
                operation: "media.transcode".into(),
                message: format!("Failed to spawn ffmpeg: {e}"),
            })?;

        let mut stderr_pipe = child.stderr.take();
        let status = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(OmniError::Cancelled);
            }
            _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(OmniError::Timeout(timeout_secs * 1000));
            }
            res = child.wait() => res.map_err(|e| OmniError::Execution {
                operation: "media.transcode".into(),
                message: format!("FFmpeg execution error: {e}"),
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
                operation: "media.transcode".into(),
                message: format!("FFmpeg exited with {}: {}", status, stderr.trim()),
            });
        }

        let transcoded = tokio::fs::read(&out_file)
            .await
            .map_err(|e| OmniError::Execution {
                operation: "media.transcode".into(),
                message: format!("Failed to read transcoded output artifact: {e}"),
            })?;

        if transcoded.is_empty() {
            return Err(OmniError::Execution {
                operation: "media.transcode".into(),
                message: "FFmpeg produced an empty output file".into(),
            });
        }

        Ok(DataPayload::bytes(transcoded))
    }
}
