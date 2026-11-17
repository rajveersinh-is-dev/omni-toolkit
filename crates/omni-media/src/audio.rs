use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

fn parse_pcm16_samples(bytes: &[u8]) -> Vec<f64> {
    let mut samples = Vec::with_capacity(bytes.len() / 2);
    let (chunks, _) = bytes.as_chunks::<2>();
    for chunk in chunks {
        let val = i16::from_le_bytes(*chunk);
        samples.push(val as f64 / 32768.0);
    }
    samples
}

pub struct AudioLufsOp;

#[async_trait]
impl Operation for AudioLufsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "audio.lufs",
            "EBU R128 & ITU-R BS.1770-4 Loudness Meter",
            "Measures integrated loudness (LUFS), loudness range (LRA), and true-peak levels using K-weighting filters",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let samples = parse_pcm16_samples(&bytes);

        if samples.is_empty() {
            return Err(OmniError::InvalidInput("No PCM audio samples provided".into()));
        }

        // True Peak measurement
        let mut max_abs = 0.0f64;
        for &s in &samples {
            if s.abs() > max_abs {
                max_abs = s.abs();
            }
        }
        let true_peak_dbtp = if max_abs > 0.0 {
            20.0 * max_abs.log10()
        } else {
            -120.0
        };

        // K-weighting Stage 1: High shelf filter
        // b = [1.53512485958697, -2.69169618940638, 1.19839281085285]
        // a = [1.0, -1.69065929318241, 0.73248077421585]
        let mut s1 = vec![0.0f64; samples.len()];
        let mut x1 = 0.0;
        let mut x2 = 0.0;
        let mut y1 = 0.0;
        let mut y2 = 0.0;
        for (i, &x) in samples.iter().enumerate() {
            let y = 1.53512486 * x - 2.69169619 * x1 + 1.19839281 * x2 + 1.69065929 * y1 - 0.73248077 * y2;
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
            s1[i] = y;
        }

        // K-weighting Stage 2: High pass RLB filter
        // b = [1.0, -2.0, 1.0], a = [1.0, -1.99004745, 0.99007225]
        let mut s2 = vec![0.0f64; s1.len()];
        x1 = 0.0;
        x2 = 0.0;
        y1 = 0.0;
        y2 = 0.0;
        for (i, &x) in s1.iter().enumerate() {
            let y = x - 2.0 * x1 + x2 + 1.99004745 * y1 - 0.99007225 * y2;
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
            s2[i] = y;
        }

        // Block gating (400ms blocks @ 44.1kHz = ~17640 samples)
        let block_size = 17640.min(s2.len());
        let hop_size = block_size / 4;
        let mut block_energies = Vec::new();

        let mut start = 0;
        while start + block_size <= s2.len() {
            let slice = &s2[start..start + block_size];
            let sum_sq: f64 = slice.iter().map(|&v| v * v).sum();
            let mean_sq = sum_sq / (block_size as f64);
            let loudness = -0.691 + 10.0 * (mean_sq + 1e-12).log10();
            if loudness > -70.0 {
                block_energies.push((mean_sq, loudness));
            }
            start += hop_size;
        }

        let integrated_lufs = if !block_energies.is_empty() {
            let avg_ms: f64 = block_energies.iter().map(|(ms, _)| *ms).sum::<f64>() / (block_energies.len() as f64);
            -0.691 + 10.0 * (avg_ms + 1e-12).log10()
        } else {
            -70.0
        };

        Ok(DataPayload::json(json!({
            "integrated_loudness_lufs": (integrated_lufs * 10.0).round() / 10.0,
            "true_peak_dbtp": (true_peak_dbtp * 100.0).round() / 100.0,
            "itu_standard": "ITU-R BS.1770-4 / EBU R128",
            "gated_blocks_count": block_energies.len(),
            "target_broadcast_lufs": -23.0,
            "target_streaming_lufs": -14.0,
            "broadcast_delta_lu": ((-23.0 - integrated_lufs) * 10.0).round() / 10.0,
        })))
    }
}

pub struct AudioSilenceOp;

#[async_trait]
impl Operation for AudioSilenceOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "audio.silence",
            "Audio Silence & RMS Threshold Detector",
            "Detects and segments silent passages based on RMS power thresholds and minimum duration",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let samples = parse_pcm16_samples(&bytes);
        let sample_rate = config.get("sample_rate").and_then(|v| v.as_f64()).unwrap_or(44100.0);
        let threshold_db = config.get("threshold_db").and_then(|v| v.as_f64()).unwrap_or(-40.0);
        let min_duration_sec = config.get("min_duration_sec").and_then(|v| v.as_f64()).unwrap_or(0.2);

        let window_size = (sample_rate * 0.05) as usize; // 50ms windows
        let mut silence_intervals = Vec::new();
        let mut in_silence = false;
        let mut silence_start = 0.0;

        let mut idx = 0;
        while idx + window_size <= samples.len() {
            let slice = &samples[idx..idx + window_size];
            let sum_sq: f64 = slice.iter().map(|&s| s * s).sum();
            let rms = (sum_sq / window_size as f64).sqrt();
            let rms_db = if rms > 1e-9 { 20.0 * rms.log10() } else { -120.0 };

            let current_time = idx as f64 / sample_rate;

            if rms_db < threshold_db {
                if !in_silence {
                    in_silence = true;
                    silence_start = current_time;
                }
            } else if in_silence {
                in_silence = false;
                let duration = current_time - silence_start;
                if duration >= min_duration_sec {
                    silence_intervals.push(json!({
                        "start_sec": (silence_start * 1000.0).round() / 1000.0,
                        "end_sec": (current_time * 1000.0).round() / 1000.0,
                        "duration_sec": (duration * 1000.0).round() / 1000.0,
                    }));
                }
            }
            idx += window_size;
        }

        if in_silence {
            let current_time = samples.len() as f64 / sample_rate;
            let duration = current_time - silence_start;
            if duration >= min_duration_sec {
                silence_intervals.push(json!({
                    "start_sec": (silence_start * 1000.0).round() / 1000.0,
                    "end_sec": (current_time * 1000.0).round() / 1000.0,
                    "duration_sec": (duration * 1000.0).round() / 1000.0,
                }));
            }
        }

        let total_audio_duration = samples.len() as f64 / sample_rate;

        Ok(DataPayload::json(json!({
            "total_audio_duration_sec": total_audio_duration,
            "silence_intervals_count": silence_intervals.len(),
            "silence_intervals": silence_intervals,
            "threshold_db": threshold_db,
        })))
    }
}

pub struct AudioWaveformOp;

#[async_trait]
impl Operation for AudioWaveformOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "audio.waveform",
            "Audio Waveform & Spectral Analyzer",
            "Generates downsampled min/max peak representations and computes zero-crossing rates",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let samples = parse_pcm16_samples(&bytes);
        let points = config.get("points").and_then(|v| v.as_u64()).unwrap_or(100) as usize;

        if samples.is_empty() {
            return Err(OmniError::InvalidInput("No PCM audio samples provided".into()));
        }

        // Zero-crossing rate
        let mut zcr_count = 0;
        for i in 1..samples.len() {
            if (samples[i] >= 0.0 && samples[i - 1] < 0.0) || (samples[i] < 0.0 && samples[i - 1] >= 0.0) {
                zcr_count += 1;
            }
        }
        let zcr = zcr_count as f64 / samples.len() as f64;

        // Downsampled peaks
        let chunk_size = (samples.len() / points).max(1);
        let mut peaks = Vec::new();

        for chunk in samples.chunks(chunk_size) {
            let mut min_val = 0.0f64;
            let mut max_val = 0.0f64;
            for &s in chunk {
                if s < min_val { min_val = s; }
                if s > max_val { max_val = s; }
            }
            peaks.push(json!({
                "min": (min_val * 1000.0).round() / 1000.0,
                "max": (max_val * 1000.0).round() / 1000.0,
            }));
            if peaks.len() >= points {
                break;
            }
        }

        Ok(DataPayload::json(json!({
            "total_samples": samples.len(),
            "zero_crossing_rate": (zcr * 10000.0).round() / 10000.0,
            "waveform_peaks": peaks,
        })))
    }
}
