pub mod audio;
pub mod container;
pub mod geo3d;
pub mod image;

pub use audio::{AudioLufsOp, AudioSilenceOp, AudioWaveformOp};
pub use container::{MediaProbeOp, MediaTranscodeOp};
pub use geo3d::{Geo3dInspectOp, Geo3dShaderOp};
pub use image::{ImageColorSpaceOp, ImageMetadataOp, ImagePipelineOp};

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_media(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(MediaProbeOp))?;
    registry.register(Arc::new(MediaTranscodeOp))?;
    registry.register(Arc::new(AudioLufsOp))?;
    registry.register(Arc::new(AudioSilenceOp))?;
    registry.register(Arc::new(AudioWaveformOp))?;
    registry.register(Arc::new(ImagePipelineOp))?;
    registry.register(Arc::new(ImageColorSpaceOp))?;
    registry.register(Arc::new(ImageMetadataOp))?;
    registry.register(Arc::new(Geo3dInspectOp))?;
    registry.register(Arc::new(Geo3dShaderOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_color_space_cielab() {
        let op = ImageColorSpaceOp;
        let ctx = ExecutionContext::new("t_color");

        let res = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "r": 255, "g": 0, "b": 0 }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        // Red in CIELAB has high positive a*
        assert!(json["cielab"]["a"].as_f64().unwrap() > 50.0);
        assert_eq!(json["srgb_input"]["hex"], "#FF0000");
    }

    #[tokio::test]
    async fn test_audio_lufs_and_waveform() {
        // Generate 1 second of 440Hz sine wave as 16-bit PCM
        let sample_rate = 44100;
        let mut pcm_bytes = Vec::with_capacity(sample_rate * 2);
        for i in 0..sample_rate {
            let t = i as f64 / sample_rate as f64;
            let sample = (0.5 * (2.0 * std::f64::consts::PI * 440.0 * t).sin() * 32767.0) as i16;
            pcm_bytes.extend_from_slice(&sample.to_le_bytes());
        }

        let lufs_op = AudioLufsOp;
        let ctx = ExecutionContext::new("t_audio");
        let lufs_res = lufs_op
            .execute(DataPayload::bytes(pcm_bytes.clone()), serde_json::json!({}), &ctx)
            .await
            .unwrap();
        let lufs_json = lufs_res.into_json().unwrap();
        assert!(lufs_json["true_peak_dbtp"].as_f64().unwrap() < 0.0);

        let wave_op = AudioWaveformOp;
        let wave_res = wave_op
            .execute(DataPayload::bytes(pcm_bytes), serde_json::json!({ "points": 20 }), &ctx)
            .await
            .unwrap();
        let wave_json = wave_res.into_json().unwrap();
        assert_eq!(wave_json["waveform_peaks"].as_array().unwrap().len(), 20);
    }

    #[tokio::test]
    async fn test_geo3d_obj_parsing() {
        let obj_data = r#"
v 0.0 0.0 0.0
v 1.0 0.0 0.0
v 0.0 1.0 0.0
f 1 2 3
"#;
        let op = Geo3dInspectOp;
        let ctx = ExecutionContext::new("t_3d");

        let res = op
            .execute(DataPayload::text(obj_data), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["vertex_count"], 3);
        assert_eq!(json["face_count"], 1);
        assert_eq!(json["surface_area"], 0.5);
    }
}
