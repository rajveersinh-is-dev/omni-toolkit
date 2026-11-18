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
            .execute(
                DataPayload::bytes(pcm_bytes.clone()),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap();
        let lufs_json = lufs_res.into_json().unwrap();
        assert!(lufs_json["true_peak_dbtp"].as_f64().unwrap() < 0.0);

        let wave_op = AudioWaveformOp;
        let wave_res = wave_op
            .execute(
                DataPayload::bytes(pcm_bytes),
                serde_json::json!({ "points": 20 }),
                &ctx,
            )
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

    #[tokio::test]
    async fn test_media_audio_image_geo3d_edge_regressions() {
        let ctx = ExecutionContext::new("t_media_edge");

        // 1. AudioLufsOp with 2 samples (4 bytes) previously infinite-looped because hop_size == 0!
        let tiny_pcm = vec![0x00, 0x10, 0x00, 0x20];
        let lufs = AudioLufsOp
            .execute(
                DataPayload::bytes(tiny_pcm.clone()),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap();
        assert!(lufs.into_json().unwrap()["integrated_loudness_lufs"].is_number());

        // 2. AudioSilenceOp with sample_rate=0 (rejected) and sample_rate=10 (no infinite loop!)
        assert!(AudioSilenceOp
            .execute(
                DataPayload::bytes(tiny_pcm.clone()),
                serde_json::json!({ "sample_rate": 0 }),
                &ctx
            )
            .await
            .is_err());
        let sil = AudioSilenceOp
            .execute(
                DataPayload::bytes(vec![0u8; 200]),
                serde_json::json!({ "sample_rate": 10.0 }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert!(sil["silence_intervals_count"].as_u64().unwrap() >= 1);

        // 3. AudioWaveformOp with points=0 must return Validation error, never divide-by-zero panic
        assert!(AudioWaveformOp
            .execute(
                DataPayload::bytes(tiny_pcm),
                serde_json::json!({ "points": 0 }),
                &ctx
            )
            .await
            .is_err());

        // 4. ImageMetadataOp with truncated/malformed JPEG segment length MUST NOT panic!
        let malformed_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF, 0x01, 0x02];
        assert!(ImageMetadataOp
            .execute(
                DataPayload::bytes(malformed_jpeg.clone()),
                serde_json::json!({ "action": "strip" }),
                &ctx
            )
            .await
            .is_err());
        let insp = ImageMetadataOp
            .execute(
                DataPayload::bytes(malformed_jpeg),
                serde_json::json!({ "action": "inspect" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(insp["format"], "JPEG");

        // 5. Geo3D quad face area (2x2 square = area 4.0)
        let quad_obj = "v 0 0 0\nv 2 0 0\nv 2 2 0\nv 0 2 0\nf 1 2 3 4\n";
        let qres = Geo3dInspectOp
            .execute(DataPayload::text(quad_obj), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(qres["surface_area"], 4.0);
    }

    #[tokio::test]
    async fn test_ciede2000_reference_vectors_utf8_bitrate_image_and_shader() {
        let ctx = ExecutionContext::new("t_media_deep");

        // 1. Exact Sharma, Wu & Dalal (2005) CIEDE2000 reference test pairs (Table 1)
        let de1 = crate::image::delta_e_2000([50.0, 2.6772, -79.7751], [50.0, 0.0, -82.7485]);
        assert!(
            (de1 - 2.0425).abs() < 0.0005,
            "CIEDE2000 pair 1 mismatch: {de1}"
        );
        let de2 = crate::image::delta_e_2000([50.0, 3.1571, -77.2803], [50.0, 0.0, -82.7485]);
        assert!(
            (de2 - 2.8615).abs() < 0.0005,
            "CIEDE2000 pair 2 mismatch: {de2}"
        );
        let de_zero = crate::image::delta_e_2000([50.0, 10.0, -20.0], [50.0, 10.0, -20.0]);
        assert!(de_zero.abs() < 1e-12);

        // ImageColorSpaceOp pairwise Delta-E 2000 + sRGB range validation
        let cs = ImageColorSpaceOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({
                    "r": 255, "g": 0, "b": 0,
                    "compare": { "r": 0, "g": 255, "b": 0 }
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert!(cs["delta_e_2000"].as_f64().unwrap() > 80.0);
        assert!(ImageColorSpaceOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "r": -5, "g": 0, "b": 0 }),
                &ctx,
            )
            .await
            .is_err());

        // 2. MediaTranscodeOp UTF-8 bitrate MUST NOT panic on char boundary!
        for bad_bitrate in ["12€", "é", "k", "999999999k"] {
            assert!(MediaTranscodeOp
                .execute(
                    DataPayload::text(""),
                    serde_json::json!({ "mode": "plan", "abitrate": bad_bitrate }),
                    &ctx,
                )
                .await
                .is_err());
        }
        let plan = MediaTranscodeOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "mode": "plan", "abitrate": "192k", "scale": "1280:720" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(plan["mode"], "plan");

        // 3. ImagePipelineOp real PNG encode -> info -> resize/grayscale/rotate -> OOM guard
        let mut png_bytes = Vec::new();
        let img = ::image::DynamicImage::new_rgb8(4, 2);
        img.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            ::image::ImageFormat::Png,
        )
        .unwrap();
        let info = ImagePipelineOp
            .execute(
                DataPayload::bytes(png_bytes.clone()),
                serde_json::json!({ "action": "info" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(info["width"], 4);
        assert_eq!(info["height"], 2);
        let transformed = ImagePipelineOp
            .execute(
                DataPayload::bytes(png_bytes.clone()),
                serde_json::json!({
                    "action": "transform",
                    "width": 8,
                    "height": 6,
                    "grayscale": true,
                    "rotate": 90,
                    "format": "png"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        let out_img = ::image::load_from_memory(&transformed).unwrap();
        assert_eq!((out_img.width(), out_img.height()), (6, 8));
        assert!(ImagePipelineOp
            .execute(
                DataPayload::bytes(png_bytes),
                serde_json::json!({ "action": "transform", "width": 50000, "height": 50000 }),
                &ctx,
            )
            .await
            .is_err());

        // 4. Geo3dInspectOp negative relative indices + NaN filtering
        let rel_obj = "v NaN 0 0\nv 0 0 0\nv 2 0 0\nv 0 2 0\nf -3 -2 -1\n";
        let rel_res = Geo3dInspectOp
            .execute(DataPayload::text(rel_obj), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(rel_res["vertex_count"], 3);
        assert_eq!(rel_res["surface_area"], 2.0);

        // 5. Geo3dShaderOp "} {" must be detected as unbalanced!
        let bad_shader = Geo3dShaderOp
            .execute(
                DataPayload::text("void main() } {"),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(bad_shader["syntax_balanced_braces"], false);
    }
}
