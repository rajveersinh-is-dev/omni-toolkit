use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest, SecurityClassification,
};
use omni_security::validate_network_target;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub struct DnsPowerSuiteOp;

fn encode_dns_query(domain: &str, qtype: u16) -> OmniResult<Vec<u8>> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(OmniError::InvalidInput(format!(
            "Invalid DNS domain name '{}'",
            domain
        )));
    }

    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[0x12, 0x34]); // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(OmniError::InvalidInput(format!(
                "Invalid DNS label '{}' in domain '{}'",
                label, domain
            )));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    Ok(packet)
}

/// Decodes a potentially compressed RFC 1035 domain name with pointer-cycle protection.
fn decode_dns_name(buf: &[u8], start_offset: usize) -> OmniResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start_offset;
    let mut jumped = false;
    let mut next_offset = start_offset;
    let mut hops = 0usize;

    loop {
        if hops > 32 {
            return Err(OmniError::Security(
                "DNS compression pointer loop detected".into(),
            ));
        }
        if offset >= buf.len() {
            return Err(OmniError::InvalidInput(
                "Unexpected end of DNS packet while decoding domain name".into(),
            ));
        }
        let len = buf[offset];
        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err(OmniError::InvalidInput(
                    "Truncated DNS compression pointer".into(),
                ));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (buf[offset + 1] as usize);
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            hops += 1;
        } else if (len & 0xC0) != 0 {
            return Err(OmniError::InvalidInput(format!(
                "Invalid DNS label length octet 0x{:02X} (reserved bits set)",
                len
            )));
        } else {
            let label_len = len as usize;
            let start = offset + 1;
            let end = start + label_len;
            if end > buf.len() {
                return Err(OmniError::InvalidInput("Truncated DNS label".into()));
            }
            labels.push(String::from_utf8_lossy(&buf[start..end]).into_owned());
            offset = end;
        }
    }

    Ok((labels.join("."), next_offset))
}

fn parse_dns_packet(buf: &[u8]) -> OmniResult<Value> {
    if buf.len() < 12 {
        return Err(OmniError::InvalidInput(
            "DNS packet header too short (minimum 12 bytes)".into(),
        ));
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let rcode = flags & 0x000F;

    let is_response = (flags & 0x8000) != 0;
    let authoritative = (flags & 0x0400) != 0;
    let truncated = (flags & 0x0200) != 0;
    let recursion_available = (flags & 0x0080) != 0;

    let mut questions = Vec::new();
    let mut offset = 12usize;

    for _ in 0..qdcount {
        let (qname, next) = decode_dns_name(buf, offset)?;
        offset = next;
        if offset + 4 > buf.len() {
            return Err(OmniError::InvalidInput(
                "Truncated DNS question entry".into(),
            ));
        }
        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;
        questions.push(json!({ "name": qname, "type_code": qtype, "class": qclass }));
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        let (aname, next) = decode_dns_name(buf, offset)?;
        offset = next;
        if offset + 10 > buf.len() {
            break;
        }
        let atype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _aclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        let Some(rdata_end) = offset.checked_add(rdlength) else {
            break;
        };
        if rdata_end > buf.len() {
            break;
        }
        let rdata_start = offset;
        let rdata = &buf[rdata_start..rdata_end];

        let (type_name, value_str) = match atype {
            1 if rdlength == 4 => (
                "A",
                Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
            ),
            28 if rdlength == 16 => {
                let arr: [u8; 16] = rdata.try_into().unwrap_or([0; 16]);
                ("AAAA", Ipv6Addr::from(arr).to_string())
            }
            2 => {
                let (ns, _) = decode_dns_name(buf, rdata_start)?;
                ("NS", ns)
            }
            5 => {
                let (cname, _) = decode_dns_name(buf, rdata_start)?;
                ("CNAME", cname)
            }
            12 => {
                let (ptr, _) = decode_dns_name(buf, rdata_start)?;
                ("PTR", ptr)
            }
            15 if rdlength >= 3 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (exchange, _) = decode_dns_name(buf, rdata_start + 2)?;
                ("MX", format!("{} {}", pref, exchange))
            }
            16 => {
                // TXT records consist of one or more length-prefixed character-strings
                let mut parts = Vec::new();
                let mut pos = 0;
                while pos < rdata.len() {
                    let slen = rdata[pos] as usize;
                    pos += 1;
                    let end = (pos + slen).min(rdata.len());
                    parts.push(String::from_utf8_lossy(&rdata[pos..end]).into_owned());
                    pos = end;
                }
                ("TXT", parts.join(""))
            }
            _ => ("UNKNOWN", hex::encode(rdata)),
        };

        answers.push(json!({
            "name": aname,
            "type": type_name,
            "type_code": atype,
            "ttl_seconds": ttl,
            "data": value_str,
        }));

        offset += rdlength;
    }

    let rcode_meaning = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    };

    Ok(json!({
        "transaction_id": format!("0x{:04X}", id),
        "is_response": is_response,
        "rcode": rcode,
        "rcode_meaning": rcode_meaning,
        "authoritative": authoritative,
        "truncated": truncated,
        "recursion_available": recursion_available,
        "question_count": qdcount,
        "questions": questions,
        "answer_count": ancount,
        "answers": answers,
    }))
}

#[async_trait]
impl Operation for DnsPowerSuiteOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.dns",
            "DNS Wire Encoder, Decoder & Scoped UDP Resolver",
            "Constructs and decodes RFC 1035 DNS wire packets (A, AAAA, CNAME, MX, NS, PTR, TXT with compression) and executes scoped UDP queries",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
        .with_security(SecurityClassification::NetworkAccess)
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Live UDP queries default to local/private resolvers unless config.allow_external=true is explicitly set".into(),
            "DoH, DoT, DoQ, DNSSEC cryptographic validation, and WHOIS/RDAP are not implemented in this module".into(),
        ])
        .with_tags(vec!["network".into(), "dns".into(), "rfc1035".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");

        // Only parse as raw binary DNS wire packet when input is explicitly Bytes or action=='parse'
        if action == "parse" || matches!(input, DataPayload::Bytes(_)) {
            let bytes = input.into_bytes();
            let parsed = parse_dns_packet(&bytes)?;
            return Ok(DataPayload::json(parsed));
        }

        let domain = config
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| input.as_str().ok().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".to_string());

        let qtype_str = config
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("A")
            .to_uppercase();
        let qtype = match qtype_str.as_str() {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            other => {
                return Err(OmniError::InvalidInput(format!(
                    "Unsupported DNS record type '{}'",
                    other
                )));
            }
        };

        let query_wire = encode_dns_query(&domain, qtype)?;

        if action == "encode" || config.get("server").is_none() {
            return Ok(DataPayload::json(json!({
                "mode": "wire_encode",
                "domain": domain,
                "query_type": qtype_str,
                "query_packet_size_bytes": query_wire.len(),
                "query_wire_hex": hex::encode(&query_wire),
                "decoded_preview": parse_dns_packet(&query_wire)?,
            })));
        }

        let server = config
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1:53");
        let allow_external = config
            .get("allow_external")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let host_raw = if server.starts_with('[') {
            server
                .split_once(']')
                .map(|(h, _)| h.trim_start_matches('['))
                .unwrap_or(server)
        } else {
            server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
        };
        validate_network_target(host_raw, allow_external)?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| OmniError::Execution {
                operation: "dns_bind".into(),
                message: e.to_string(),
            })?;

        socket
            .send_to(&query_wire, server)
            .await
            .map_err(|e| OmniError::Execution {
                operation: "dns_send".into(),
                message: e.to_string(),
            })?;

        let mut resp_buf = vec![0u8; 4096];
        let timeout_ms = config
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(1500)
            .clamp(50, 10_000);

        match timeout(
            Duration::from_millis(timeout_ms),
            socket.recv_from(&mut resp_buf),
        )
        .await
        {
            Ok(Ok((n, _src))) => {
                let parsed = parse_dns_packet(&resp_buf[..n])?;
                Ok(DataPayload::json(parsed))
            }
            Ok(Err(e)) => Err(OmniError::Execution {
                operation: "dns_recv".into(),
                message: e.to_string(),
            }),
            Err(_) => Err(OmniError::Timeout(timeout_ms)),
        }
    }
}
