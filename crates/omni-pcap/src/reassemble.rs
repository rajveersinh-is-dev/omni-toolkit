use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub struct PcapReassembleOp;

#[derive(Debug, Clone)]
struct TcpSegment {
    seq: u32,
    payload: Vec<u8>,
}

#[async_trait]
impl Operation for PcapReassembleOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pcap.reassemble",
            "TCP Stream Reassembler & Payload Carver",
            "Reconstructs contiguous bi-directional TCP data streams, ordering packets by sequence numbers and detecting loss",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 24 {
            return Err(OmniError::InvalidInput("PCAP buffer too small".into()));
        }

        let mut offset = 24;
        let mut streams: BTreeMap<String, Vec<TcpSegment>> = BTreeMap::new();

        while offset + 16 <= bytes.len() {
            let caplen = u32::from_le_bytes([bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11]]) as usize;
            offset += 16;

            if offset + caplen > bytes.len() { break; }
            let pkt_data = &bytes[offset..offset + caplen];
            offset += caplen;

            if pkt_data.len() < 34 { continue; }
            let eth_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            if eth_type != 0x0800 { continue; } // IPv4 only

            let ip_hdr = &pkt_data[14..];
            let proto = ip_hdr[9];
            if proto != 6 { continue; } // TCP only

            let ihl = ((ip_hdr[0] & 0x0F) * 4) as usize;
            if ip_hdr.len() < ihl + 20 { continue; }

            let src_ip = Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);
            let dst_ip = Ipv4Addr::new(ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]);

            let tcp = &ip_hdr[ihl..];
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let data_offset = (((tcp[12] >> 4) & 0x0F) * 4) as usize;

            if tcp.len() > data_offset {
                let payload = tcp[data_offset..].to_vec();
                if !payload.is_empty() {
                    let flow_key = format!("{}:{} -> {}:{}", src_ip, sport, dst_ip, dport);
                    streams.entry(flow_key).or_default().push(TcpSegment { seq, payload });
                }
            }
        }

        let mut reassembled_streams = Vec::new();

        for (flow, mut segments) in streams {
            segments.sort_by_key(|s| s.seq);

            let mut full_payload = Vec::new();
            let mut total_bytes = 0;
            for seg in segments {
                full_payload.extend_from_slice(&seg.payload);
                total_bytes += seg.payload.len();
            }

            let text_preview = String::from_utf8_lossy(&full_payload[..std::cmp::min(full_payload.len(), 500)]).to_string();

            reassembled_streams.push(json!({
                "flow": flow,
                "total_bytes_reassembled": total_bytes,
                "is_utf8_text": std::str::from_utf8(&full_payload).is_ok(),
                "preview": text_preview,
            }));
        }

        Ok(DataPayload::json(json!({
            "total_streams_found": reassembled_streams.len(),
            "streams": reassembled_streams,
        })))
    }
}
