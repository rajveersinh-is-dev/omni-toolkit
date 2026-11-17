use byteorder::{BigEndian, ReadBytesExt};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::io::Cursor;

pub struct MediaProbeOp;

#[async_trait]
impl Operation for MediaProbeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "media.probe",
            "Media Container & Codec Probe",
            "Demuxes and analyzes MP4/MOV ISO atoms, MKV/WebM EBML headers, RIFF/WAV audio metadata, and stream layouts",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 12 {
            return Err(OmniError::InvalidInput("Media buffer too small to probe".into()));
        }

        let mut rdr = Cursor::new(&bytes);

        // Check RIFF / WAV
        if &bytes[0..4] == b"RIFF" && bytes.len() >= 44 && &bytes[8..12] == b"WAVE" {
            rdr.set_position(12);
            let mut subchunk_id = [0u8; 4];
            subchunk_id.copy_from_slice(&rdr.get_ref()[12..16]);
            
            // Look for "fmt " chunk
            let channels = (&bytes[22..24]).read_u16::<BigEndian>().map_err(|e| OmniError::InvalidInput(e.to_string()))?;
            let sample_rate = (&bytes[24..28]).read_u32::<BigEndian>().map_err(|e| OmniError::InvalidInput(e.to_string()))?;
            let bits_per_sample = (&bytes[34..36]).read_u16::<BigEndian>().map_err(|e| OmniError::InvalidInput(e.to_string()))?;

            return Ok(DataPayload::json(json!({
                "format": "RIFF/WAV",
                "media_type": "audio",
                "channels": channels.swap_bytes(), // LE
                "sample_rate_hz": sample_rate.swap_bytes(), // LE
                "bits_per_sample": bits_per_sample.swap_bytes(),
                "file_size_bytes": bytes.len(),
            })));
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

                if size == 0 || size < 8 || pos + size > bytes.len() {
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

        // Generic fallback with signature inspection
        Ok(DataPayload::json(json!({
            "format": "Unknown / Raw stream",
            "file_size_bytes": bytes.len(),
            "magic_bytes_hex": hex::encode(&bytes[..std::cmp::min(16, bytes.len())])
        })))
    }
}

pub struct MediaTranscodeOp;

#[async_trait]
impl Operation for MediaTranscodeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "media.transcode",
            "Media Transcode & Filter Graph Generator",
            "Synthesizes optimized, production-grade FFmpeg filter pipelines with hardware acceleration presets",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Json, DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, _input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let vcodec = config.get("vcodec").and_then(|v| v.as_str()).unwrap_or("libx264");
        let acodec = config.get("acodec").and_then(|v| v.as_str()).unwrap_or("aac");
        let crf = config.get("crf").and_then(|v| v.as_u64()).unwrap_or(23);
        let preset = config.get("preset").and_then(|v| v.as_str()).unwrap_or("medium");
        let hwaccel = config.get("hwaccel").and_then(|v| v.as_str()).unwrap_or("none");
        let scale = config.get("scale").and_then(|v| v.as_str());
        let audio_bitrate = config.get("abitrate").and_then(|v| v.as_str()).unwrap_or("192k");

        let mut filters = Vec::new();
        if let Some(s) = scale {
            filters.push(format!("scale={}", s));
        }

        let filter_arg = if !filters.is_empty() {
            format!(" -vf \"{}\"", filters.join(","))
        } else {
            String::new()
        };

        let hw_arg = match hwaccel {
            "nvenc" => "-hwaccel cuda ",
            "vaapi" => "-hwaccel vaapi -vaapi_device /dev/dri/renderD128 ",
            "videotoolbox" => "-hwaccel videotoolbox ",
            _ => "",
        };

        let command = format!(
            "ffmpeg -hide_banner {} -i input.mp4 -c:v {} -preset {} -crf {}{} -c:a {} -b:a {} -movflags +faststart output.mp4",
            hw_arg, vcodec, preset, crf, filter_arg, acodec, audio_bitrate
        );

        Ok(DataPayload::json(json!({
            "generated_command": command,
            "target_video_codec": vcodec,
            "target_audio_codec": acodec,
            "rate_control": {
                "crf": crf,
                "preset": preset
            },
            "hardware_acceleration": hwaccel,
            "streaming_optimization": "movflags=+faststart"
        })))
    }
}
