use omni_core::{DataPayload, ExecutionContext};
use omni_encoders::register_encoders;
use omni_registry::OperationRegistry;
use omni_testkit::TestPayloadGenerator;

#[tokio::test]
async fn test_fuzz_encoders_and_decoders() {
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();

    let mut gen = TestPayloadGenerator::new(0xdeadbeef);
    let ctx = ExecutionContext::new("fuzz_job");

    let binary_encoder_ops = [
        "encode.base16",
        "encode.base32",
        "encode.base32hex",
        "encode.base45",
        "encode.base58",
        "encode.base62",
        "encode.base64",
        "encode.base64url",
        "encode.base85",
        "encode.base91",
    ];

    // 1. Fuzz binary encoders on arbitrary pseudo-random byte buffers
    for size in [0, 1, 7, 16, 64, 255, 1024] {
        let raw = gen.bytes(size);
        let payload = DataPayload::bytes(raw.clone());

        for &op_id in &binary_encoder_ops {
            let op = registry.get(op_id).expect("Operation must exist");

            // Encode
            let encode_res = op
                .execute(payload.clone(), serde_json::json!({}), &ctx)
                .await;
            assert!(
                encode_res.is_ok(),
                "Encoding {} bytes failed for {}",
                size,
                op_id
            );
            let encoded = encode_res.unwrap();

            // Decode back
            let decode_res = op
                .execute(encoded, serde_json::json!({ "decode": true }), &ctx)
                .await;
            assert!(decode_res.is_ok(), "Decoding failed for {}", op_id);
            let decoded = decode_res.unwrap();

            assert_eq!(
                decoded.into_bytes(),
                raw,
                "Roundtrip mismatch for {}",
                op_id
            );
        }
    }

    // 2. Fuzz text encoders on generated UTF-8 strings
    let text_encoder_ops = [
        "encode.url",
        "encode.html_entities",
        "encode.unicode_escapes",
    ];
    for size in [0, 1, 10, 50, 200] {
        let text = gen.printable_ascii(size);
        let payload = DataPayload::text(&text);

        for &op_id in &text_encoder_ops {
            let op = registry.get(op_id).expect("Operation must exist");

            // Encode
            let encode_res = op
                .execute(payload.clone(), serde_json::json!({}), &ctx)
                .await;
            assert!(
                encode_res.is_ok(),
                "Encoding {} chars failed for {}",
                size,
                op_id
            );
            let encoded = encode_res.unwrap();

            // Decode back
            let decode_res = op
                .execute(encoded, serde_json::json!({ "decode": true }), &ctx)
                .await;
            assert!(decode_res.is_ok(), "Decoding failed for {}", op_id);
            let decoded = decode_res.unwrap();

            assert_eq!(
                decoded.as_str().unwrap(),
                &text,
                "Text roundtrip mismatch for {}",
                op_id
            );
        }
    }

    // 3. Fuzz decoders with completely random byte sequences (ensuring NO panics)
    for _ in 0..50 {
        let garbage = gen.bytes(128);
        let garbage_payload = DataPayload::bytes(garbage);

        for &op_id in &binary_encoder_ops {
            let op = registry.get(op_id).unwrap();
            // Should gracefully return an Err or decoded bytes, but NEVER panic!
            let _ = op
                .execute(
                    garbage_payload.clone(),
                    serde_json::json!({ "decode": true }),
                    &ctx,
                )
                .await;
        }
    }
}
