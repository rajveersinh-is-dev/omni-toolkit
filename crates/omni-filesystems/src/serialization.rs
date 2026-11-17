use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct BinaryFormatsOp;

#[derive(Debug, Clone, serde::Serialize)]
struct ProtobufField {
    field_number: u32,
    wire_type: u8,
    wire_type_name: String,
    value: Value,
}

fn parse_varint(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    while *offset < bytes.len() {
        let b = bytes[*offset];
        *offset += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn parse_protobuf_wire(bytes: &[u8], depth: usize) -> Vec<ProtobufField> {
    if depth > 10 { return Vec::new(); }
    let mut fields = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let key = match parse_varint(bytes, &mut offset) {
            Some(k) => k,
            None => break,
        };

        let wire_type = (key & 0x07) as u8;
        let field_num = (key >> 3) as u32;

        let (wire_name, field_val) = match wire_type {
            0 => {
                let v = parse_varint(bytes, &mut offset).unwrap_or(0);
                ("varint", json!(v))
            }
            1 => {
                if offset + 8 <= bytes.len() {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&bytes[offset..offset + 8]);
                    offset += 8;
                    let u = u64::from_le_bytes(b);
                    let f = f64::from_bits(u);
                    ("64-bit", json!({ "u64": u, "f64": f }))
                } else {
                    break;
                }
            }
            2 => {
                let len = match parse_varint(bytes, &mut offset) {
                    Some(l) => l as usize,
                    None => break,
                };
                if offset + len <= bytes.len() {
                    let slice = &bytes[offset..offset + len];
                    offset += len;

                    // Check if UTF-8 string
                    if let Ok(s) = std::str::from_utf8(slice) {
                        ("length-delimited", json!({ "string": s }))
                    } else {
                        // Attempt recursive sub-message parse
                        let sub = parse_protobuf_wire(slice, depth + 1);
                        if !sub.is_empty() {
                            ("length-delimited (embedded)", json!({ "embedded_message": sub }))
                        } else {
                            ("length-delimited", json!({ "bytes_hex": hex::encode(slice) }))
                        }
                    }
                } else {
                    break;
                }
            }
            5 => {
                if offset + 4 <= bytes.len() {
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&bytes[offset..offset + 4]);
                    offset += 4;
                    let u = u32::from_le_bytes(b);
                    let f = f32::from_bits(u);
                    ("32-bit", json!({ "u32": u, "f32": f }))
                } else {
                    break;
                }
            }
            _ => ("unknown", json!({ "unsupported_wire_type": wire_type })),
        };

        fields.push(ProtobufField {
            field_number: field_num,
            wire_type,
            wire_type_name: wire_name.into(),
            value: field_val,
        });
    }

    fields
}

fn parse_asn1_der(bytes: &[u8], offset: &mut usize) -> Option<Value> {
    if *offset >= bytes.len() { return None; }
    let tag = bytes[*offset];
    *offset += 1;

    if *offset >= bytes.len() { return None; }
    let len_byte = bytes[*offset];
    *offset += 1;

    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if *offset + num_bytes > bytes.len() { return None; }
        let mut l = 0usize;
        for _ in 0..num_bytes {
            l = (l << 8) | (bytes[*offset] as usize);
            *offset += 1;
        }
        l
    };

    if *offset + len > bytes.len() { return None; }
    let value_bytes = &bytes[*offset..*offset + len];
    *offset += len;

    let tag_name = match tag {
        0x01 => "BOOLEAN",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x0C => "UTF8String",
        0x13 => "PrintableString",
        0x16 => "IA5String",
        0x17 => "UTCTime",
        0x18 => "GeneralizedTime",
        0x30 => "SEQUENCE",
        0x31 => "SET",
        _ => "OTHER",
    };

    Some(json!({
        "tag_hex": format!("0x{:02X}", tag),
        "tag_type": tag_name,
        "is_constructed": (tag & 0x20) != 0,
        "length": len,
        "value_hex": hex::encode(value_bytes),
        "string_repr": std::str::from_utf8(value_bytes).ok(),
    }))
}

#[async_trait]
impl Operation for BinaryFormatsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "storage.binary_formats",
            "Binary Serialization Decoder (Protobuf/MsgPack/ASN.1)",
            "Decodes schema-less Protobuf wire format, MessagePack binaries, and ASN.1 DER hierarchies into structured JSON",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let format = config.get("format").and_then(|v| v.as_str()).unwrap_or("protobuf");
        let bytes = input.into_bytes();

        match format {
            "msgpack" | "messagepack" => {
                let val: Value = rmp_serde::from_slice(&bytes)
                    .map_err(|e| OmniError::InvalidInput(format!("MessagePack decode failed: {e}")))?;
                Ok(DataPayload::json(json!({
                    "format": "MessagePack",
                    "data": val,
                })))
            }
            "asn1" | "der" => {
                let mut offset = 0;
                let mut elements = Vec::new();
                while let Some(elem) = parse_asn1_der(&bytes, &mut offset) {
                    elements.push(elem);
                    if offset >= bytes.len() { break; }
                }
                Ok(DataPayload::json(json!({
                    "format": "ASN.1 DER",
                    "total_elements": elements.len(),
                    "elements": elements,
                })))
            }
            "protobuf" | _ => {
                let fields = parse_protobuf_wire(&bytes, 0);
                Ok(DataPayload::json(json!({
                    "format": "Protobuf (Wire Format)",
                    "fields_count": fields.len(),
                    "fields": fields,
                })))
            }
        }
    }
}
