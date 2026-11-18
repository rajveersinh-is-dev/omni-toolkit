use omni_core::{DataPayload, ExecutionContext};
use omni_crypto::register_crypto;
use omni_encoders::register_encoders;
use omni_registry::OperationRegistry;
use omni_text::register_text;

#[tokio::test]
async fn test_empty_input_regression() {
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();
    register_crypto(&mut registry).unwrap();
    register_text(&mut registry).unwrap();

    let ctx = ExecutionContext::new("regression_empty");

    // 1. Empty string hash must match standard empty SHA-256
    let sha256 = registry.get("crypto.hash.sha256").unwrap();
    let empty_payload = DataPayload::text("");
    let hash_out = sha256
        .execute(empty_payload.clone(), serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert_eq!(
        hash_out.as_str().unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // 2. Empty string base64
    let base64 = registry.get("encode.base64").unwrap();
    let b64_out = base64
        .execute(empty_payload.clone(), serde_json::json!({}), &ctx)
        .await
        .unwrap();
    assert_eq!(b64_out.as_str().unwrap(), "");

    // 3. Empty text diff
    let diff = registry.get("text.diff").unwrap();
    let diff_out = diff
        .execute(empty_payload, serde_json::json!({ "original": "" }), &ctx)
        .await
        .unwrap();
    assert_eq!(diff_out.as_str().unwrap(), "");
}

#[tokio::test]
async fn test_multibyte_utf8_regression() {
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();
    let ctx = ExecutionContext::new("regression_utf8");

    let multibyte_str = "🦀 Rocket 🚀 日本語 ñoño";
    let payload = DataPayload::text(multibyte_str);

    let base64 = registry.get("encode.base64").unwrap();
    let encoded = base64
        .execute(payload, serde_json::json!({}), &ctx)
        .await
        .unwrap();

    let decoded = base64
        .execute(encoded, serde_json::json!({ "decode": true }), &ctx)
        .await
        .unwrap();
    assert_eq!(decoded.as_str().unwrap(), multibyte_str);
}
