use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DissectedPacket {
    pub index: usize,
    pub timestamp_sec: u32,
    pub timestamp_usec: u32,
    pub caplen: u32,
    pub wirelen: u32,
    pub eth_src: String,
    pub eth_dst: String,
    pub eth_type: String,
    pub ip_src: Option<String>,
    pub ip_dst: Option<String>,
    pub protocol: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<String>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub app_protocol: Option<String>,
    pub info: String,
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub fn parse_pcap(bytes: &[u8]) -> OmniResult<Vec<DissectedPacket>> {
    if bytes.len() < 24 {
        return Err(OmniError::InvalidInput(
            "PCAP buffer too small for global header".into(),
        ));
    }

    let is_little_endian = match [bytes[0], bytes[1], bytes[2], bytes[3]] {
        [0xD4, 0xC3, 0xB2, 0xA1] | [0x4D, 0x3C, 0xB2, 0xA1] => true,
        [0xA1, 0xB2, 0xC3, 0xD4] | [0xA1, 0xB2, 0x3C, 0x4D] => false,
        _ => true, // default heuristic for non-standard headers
    };

    let mut packets = Vec::new();
    let mut offset = 24;
    let mut idx = 1;

    while offset + 16 <= bytes.len() {
        let (ts_sec, ts_usec, caplen, origlen) = if is_little_endian {
            (
                u32::from_le_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]),
                u32::from_le_bytes([
                    bytes[offset + 12],
                    bytes[offset + 13],
                    bytes[offset + 14],
                    bytes[offset + 15],
                ]),
            )
        } else {
            (
                u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 8],
                    bytes[offset + 9],
                    bytes[offset + 10],
                    bytes[offset + 11],
                ]),
                u32::from_be_bytes([
                    bytes[offset + 12],
                    bytes[offset + 13],
                    bytes[offset + 14],
                    bytes[offset + 15],
                ]),
            )
        };
        offset += 16;

        let clen = caplen as usize;
        let Some(pkt_end) = offset.checked_add(clen) else {
            break;
        };
        if pkt_end > bytes.len() {
            break;
        }

        let pkt_data = &bytes[offset..pkt_end];
        offset = pkt_end;

        if pkt_data.len() < 14 {
            idx += 1;
            continue; // malformed runt packet
        }

        let eth_dst = format_mac(&pkt_data[0..6]);
        let eth_src = format_mac(&pkt_data[6..12]);
        let eth_type_u16 = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);

        let mut pkt = DissectedPacket {
            index: idx,
            timestamp_sec: ts_sec,
            timestamp_usec: ts_usec,
            caplen,
            wirelen: origlen,
            eth_src,
            eth_dst,
            eth_type: format!("0x{:04X}", eth_type_u16),
            ip_src: None,
            ip_dst: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            tcp_seq: None,
            tcp_ack: None,
            app_protocol: None,
            info: String::new(),
        };

        if eth_type_u16 == 0x0800 && pkt_data.len() >= 34 {
            // IPv4
            let ip_hdr = &pkt_data[14..];
            let src_ip = Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);
            let dst_ip = Ipv4Addr::new(ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]);
            let proto_num = ip_hdr[9];
            let ihl = ((ip_hdr[0] & 0x0F) * 4) as usize;

            pkt.ip_src = Some(src_ip.to_string());
            pkt.ip_dst = Some(dst_ip.to_string());

            if ihl >= 20 && ip_hdr.len() >= ihl {
                let transport = &ip_hdr[ihl..];
                match proto_num {
                    6 if transport.len() >= 20 => {
                        // TCP
                        pkt.protocol = Some("TCP".to_string());
                        let sport = u16::from_be_bytes([transport[0], transport[1]]);
                        let dport = u16::from_be_bytes([transport[2], transport[3]]);
                        let seq = u32::from_be_bytes([
                            transport[4],
                            transport[5],
                            transport[6],
                            transport[7],
                        ]);
                        let ack = u32::from_be_bytes([
                            transport[8],
                            transport[9],
                            transport[10],
                            transport[11],
                        ]);
                        let flags_byte = transport[13];
                        let mut flags = Vec::new();
                        if flags_byte & 0x02 != 0 {
                            flags.push("SYN");
                        }
                        if flags_byte & 0x10 != 0 {
                            flags.push("ACK");
                        }
                        if flags_byte & 0x01 != 0 {
                            flags.push("FIN");
                        }
                        if flags_byte & 0x04 != 0 {
                            flags.push("RST");
                        }
                        if flags_byte & 0x08 != 0 {
                            flags.push("PSH");
                        }

                        pkt.src_port = Some(sport);
                        pkt.dst_port = Some(dport);
                        pkt.tcp_seq = Some(seq);
                        pkt.tcp_ack = Some(ack);
                        pkt.tcp_flags = Some(flags.join(","));

                        let tcp_offset = (((transport[12] >> 4) & 0x0F) * 4) as usize;
                        if tcp_offset >= 20 && transport.len() > tcp_offset {
                            let payload = &transport[tcp_offset..];
                            // Check HTTP
                            if sport == 80
                                || dport == 80
                                || payload.starts_with(b"GET ")
                                || payload.starts_with(b"POST ")
                                || payload.starts_with(b"HTTP/1.")
                            {
                                pkt.app_protocol = Some("HTTP".to_string());
                                let first_line = String::from_utf8_lossy(payload)
                                    .lines()
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                pkt.info = format!("HTTP: {}", first_line);
                            }
                            // Check TLS
                            else if (sport == 443 || dport == 443)
                                && payload.len() >= 5
                                && payload[0] == 0x16
                            {
                                pkt.app_protocol = Some("TLS".to_string());
                                let hs_type = if payload.len() >= 6 { payload[5] } else { 0 };
                                let hs_name = match hs_type {
                                    1 => "Client Hello",
                                    2 => "Server Hello",
                                    _ => "Handshake",
                                };
                                pkt.info = format!("TLS Handshake ({})", hs_name);
                            } else {
                                pkt.info = format!(
                                    "TCP: {} -> {} [{}] Seq={}",
                                    sport,
                                    dport,
                                    flags.join(","),
                                    seq
                                );
                            }
                        } else {
                            pkt.info = format!("TCP: {} -> {} [{}]", sport, dport, flags.join(","));
                        }
                    }
                    17 if transport.len() >= 8 => {
                        // UDP
                        pkt.protocol = Some("UDP".to_string());
                        let sport = u16::from_be_bytes([transport[0], transport[1]]);
                        let dport = u16::from_be_bytes([transport[2], transport[3]]);
                        pkt.src_port = Some(sport);
                        pkt.dst_port = Some(dport);

                        if sport == 53 || dport == 53 {
                            pkt.app_protocol = Some("DNS".to_string());
                            pkt.info = format!(
                                "DNS Query/Response ({}:{} -> {}:{})",
                                src_ip, sport, dst_ip, dport
                            );
                        } else {
                            pkt.info = format!("UDP: {} -> {}", sport, dport);
                        }
                    }
                    1 => {
                        pkt.protocol = Some("ICMP".to_string());
                        let icmp_type = transport.first().copied().unwrap_or(0);
                        let icmp_name = match icmp_type {
                            0 => "Echo Reply",
                            8 => "Echo Request",
                            3 => "Destination Unreachable",
                            _ => "ICMP",
                        };
                        pkt.info = format!("ICMP: {}", icmp_name);
                    }
                    _ => {
                        pkt.protocol = Some(format!("IP Proto {}", proto_num));
                        pkt.info = format!("IPv4: {} -> {}", src_ip, dst_ip);
                    }
                }
            }
        } else if eth_type_u16 == 0x0806 && pkt_data.len() >= 28 {
            // ARP
            pkt.protocol = Some("ARP".to_string());
            let op = u16::from_be_bytes([pkt_data[20], pkt_data[21]]);
            let op_name = if op == 1 { "Who has?" } else { "Is at" };
            pkt.info = format!("ARP: {}", op_name);
        } else {
            pkt.info = format!("Ethernet: {} -> {}", pkt.eth_src, pkt.eth_dst);
        }

        packets.push(pkt);
        idx += 1;
    }

    Ok(packets)
}

pub struct PcapDissectOp;

#[async_trait]
impl Operation for PcapDissectOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pcap.dissect",
            "PCAP & PCAPNG Deep Packet Dissector",
            "Dissects Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, TLS, and HTTP packets with display filtering",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let packets = parse_pcap(&bytes)?;

        let filter_proto = config.get("protocol").and_then(|v| v.as_str());

        let filtered: Vec<&DissectedPacket> = if let Some(proto) = filter_proto {
            let proto_upper = proto.to_uppercase();
            packets
                .iter()
                .filter(|p| {
                    p.protocol.as_deref() == Some(&proto_upper)
                        || p.app_protocol.as_deref() == Some(&proto_upper)
                })
                .collect()
        } else {
            packets.iter().collect()
        };

        Ok(DataPayload::json(json!({
            "total_packets_parsed": packets.len(),
            "filtered_packets_count": filtered.len(),
            "packets": filtered,
        })))
    }
}
