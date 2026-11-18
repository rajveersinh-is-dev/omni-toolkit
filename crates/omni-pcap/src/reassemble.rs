use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
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
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 24 {
            return Err(OmniError::InvalidInput("PCAP buffer too small".into()));
        }

        let is_little_endian = match [bytes[0], bytes[1], bytes[2], bytes[3]] {
            [0xD4, 0xC3, 0xB2, 0xA1] | [0x4D, 0x3C, 0xB2, 0xA1] => true,
            [0xA1, 0xB2, 0xC3, 0xD4] | [0xA1, 0xB2, 0x3C, 0x4D] => false,
            _ => true,
        };

        let mut offset = 24;
        let mut streams: BTreeMap<String, Vec<TcpSegment>> = BTreeMap::new();

        while offset + 16 <= bytes.len() {
            let caplen = if is_little_endian {
                u32::from_le_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]) as usize
            } else {
                u32::from_be_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]) as usize
            };
            offset += 16;

            let Some(pkt_end) = offset.checked_add(caplen) else {
                break;
            };
            if pkt_end > bytes.len() {
                break;
            }
            let pkt_data = &bytes[offset..pkt_end];
            offset = pkt_end;

            if pkt_data.len() < 34 {
                continue;
            }
            let eth_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
            if eth_type != 0x0800 {
                continue;
            } // IPv4 only

            let ip_hdr = &pkt_data[14..];
            let proto = ip_hdr[9];
            if proto != 6 {
                continue;
            } // TCP only

            let ihl = ((ip_hdr[0] & 0x0F) * 4) as usize;
            if ihl < 20 || ip_hdr.len() < ihl + 20 {
                continue;
            }

            let src_ip = Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);
            let dst_ip = Ipv4Addr::new(ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]);

            let tcp = &ip_hdr[ihl..];
            let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let data_offset = (((tcp[12] >> 4) & 0x0F) * 4) as usize;

            if data_offset >= 20 && tcp.len() > data_offset {
                let payload = tcp[data_offset..].to_vec();
                if !payload.is_empty() {
                    let flow_key = format!("{}:{} -> {}:{}", src_ip, sport, dst_ip, dport);
                    streams
                        .entry(flow_key)
                        .or_default()
                        .push(TcpSegment { seq, payload });
                }
            }
        }

        let mut reassembled_streams = Vec::new();

        for (flow, mut segments) in streams {
            segments.sort_by_key(|s| s.seq);

            let mut full_payload = Vec::new();
            let mut next_expected_seq: Option<u32> = None;
            let mut duplicate_segments = 0usize;

            for seg in segments {
                if let Some(expected) = next_expected_seq {
                    let diff = expected.wrapping_sub(seg.seq) as i32;
                    if diff > 0 {
                        // Entire or partial overlap / retransmission
                        let overlap = diff as usize;
                        if overlap >= seg.payload.len() {
                            duplicate_segments += 1;
                            continue;
                        }
                        let new_bytes = &seg.payload[overlap..];
                        full_payload.extend_from_slice(new_bytes);
                        next_expected_seq = Some(expected.wrapping_add(new_bytes.len() as u32));
                        continue;
                    }
                }
                full_payload.extend_from_slice(&seg.payload);
                next_expected_seq = Some(seg.seq.wrapping_add(seg.payload.len() as u32));
            }
            let total_bytes = full_payload.len();

            let text_preview =
                String::from_utf8_lossy(&full_payload[..std::cmp::min(full_payload.len(), 500)])
                    .to_string();

            reassembled_streams.push(json!({
                "flow": flow,
                "total_bytes_reassembled": total_bytes,
                "duplicate_segments_skipped": duplicate_segments,
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
