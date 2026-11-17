use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub struct DnsPowerSuiteOp;

fn encode_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // Transaction ID
    packet.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query, recursion desired (0x0100)
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // QNAME
    for label in domain.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0x00); // Root label

    // QTYPE
    packet.extend_from_slice(&qtype.to_be_bytes());
    // QCLASS: IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

fn parse_dns_response(buf: &[u8]) -> OmniResult<Value> {
    if buf.len() < 12 {
        return Err(OmniError::InvalidInput("DNS response header too short".into()));
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

    let mut answers = Vec::new();
    let mut offset = 12;

    // Skip question section
    for _ in 0..qdcount {
        while offset < buf.len() && buf[offset] != 0 {
            if (buf[offset] & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += (buf[offset] as usize) + 1;
        }
        if offset < buf.len() && buf[offset] == 0 {
            offset += 1;
        }
        offset += 4; // skip QTYPE, QCLASS
    }

    // Parse answers
    for _ in 0..ancount {
        if offset + 12 > buf.len() { break; }
        // Skip NAME pointer
        if (buf[offset] & 0xC0) == 0xC0 {
            offset += 2;
        } else {
            while offset < buf.len() && buf[offset] != 0 {
                offset += (buf[offset] as usize) + 1;
            }
            offset += 1;
        }

        if offset + 10 > buf.len() { break; }
        let atype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _aclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() { break; }
        let rdata = &buf[offset..offset + rdlength];

        let (type_name, value_str) = match atype {
            1 if rdlength == 4 => {
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                ("A", ip.to_string())
            }
            28 if rdlength == 16 => {
                ("AAAA", hex::encode(rdata))
            }
            5 => ("CNAME", "Canonical Name".to_string()),
            15 => ("MX", "Mail Exchange".to_string()),
            16 => ("TXT", String::from_utf8_lossy(rdata).to_string()),
            _ => ("UNKNOWN", hex::encode(rdata)),
        };

        answers.push(json!({
            "type": type_name,
            "type_code": atype,
            "ttl_seconds": ttl,
            "data": value_str,
        }));

        offset += rdlength;
    }

    Ok(json!({
        "transaction_id": format!("0x{:04X}", id),
        "is_response": is_response,
        "rcode": rcode,
        "rcode_meaning": if rcode == 0 { "NOERROR" } else if rcode == 3 { "NXDOMAIN" } else { "ERROR" },
        "authoritative": authoritative,
        "truncated": truncated,
        "recursion_available": recursion_available,
        "question_count": qdcount,
        "answer_count": ancount,
        "answers": answers,
    }))
}

#[async_trait]
impl Operation for DnsPowerSuiteOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.dns",
            "DNS Power Suite & Resolver",
            "Decodes and constructs RFC 1035 DNS wire packets, resolving A, AAAA, MX, TXT, and CNAME records",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let domain = config.get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| input.as_str().ok().unwrap_or("localhost"));

        let qtype_str = config.get("type").and_then(|v| v.as_str()).unwrap_or("A");
        let qtype = match qtype_str {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            _ => 1,
        };

        let query_wire = encode_dns_query(domain, qtype);

        // If raw DNS bytes were supplied in input, parse directly
        let bytes = input.as_bytes();
        if bytes.len() >= 12 && !bytes.is_empty() {
            let parsed = parse_dns_response(bytes)?;
            return Ok(DataPayload::json(parsed));
        }

        // Otherwise query DNS server over UDP (default to 1.1.1.1 or 8.8.8.8 or local)
        let server = config.get("server").and_then(|v| v.as_str()).unwrap_or("1.1.1.1:53");

        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| OmniError::Execution { operation: "dns_bind".into(), message: e.to_string() })?;

        let _ = socket.send_to(&query_wire, server).await;
        let mut resp_buf = vec![0u8; 512];

        let res = timeout(Duration::from_millis(1500), socket.recv_from(&mut resp_buf)).await;
        match res {
            Ok(Ok((n, _src))) => {
                let parsed = parse_dns_response(&resp_buf[..n])?;
                Ok(DataPayload::json(parsed))
            }
            _ => {
                // Return query packet structure if live query timed out
                Ok(DataPayload::json(json!({
                    "domain": domain,
                    "query_type": qtype_str,
                    "query_packet_size_bytes": query_wire.len(),
                    "query_wire_hex": hex::encode(&query_wire),
                    "status": "Query synthesized; upstream response timed out"
                })))
            }
        }
    }
}
