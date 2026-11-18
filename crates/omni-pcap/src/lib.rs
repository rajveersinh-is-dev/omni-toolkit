pub mod dissect;
pub mod reassemble;

pub use dissect::{parse_pcap, DissectedPacket, PcapDissectOp};
pub use reassemble::PcapReassembleOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_pcap(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(PcapDissectOp))?;
    registry.register(Arc::new(PcapReassembleOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    fn create_test_pcap() -> Vec<u8> {
        let mut pcap = Vec::new();
        // Global header (24 bytes, LE)
        pcap.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]); // Magic
        pcap.extend_from_slice(&[0x02, 0x00, 0x04, 0x00]); // v2.4
        pcap.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Zone
        pcap.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Sigfigs
        pcap.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00]); // Snaplen 65535
        pcap.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // LinkType: Ethernet (1)

        // Construct Ethernet + IPv4 + TCP packet
        let mut pkt_data = Vec::new();
        // Ethernet: Dst (6B), Src (6B), EtherType (0x0800 IPv4)
        pkt_data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt_data.extend_from_slice(&[0x08, 0x00]);

        // IPv4 (20 bytes): 192.168.1.100 -> 192.168.1.1 (TCP proto 6)
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ip_len = (20 + 20 + payload.len()) as u16;
        pkt_data.extend_from_slice(&[0x45, 0x00]); // IPv4, IHL=5
        pkt_data.extend_from_slice(&ip_len.to_be_bytes());
        pkt_data.extend_from_slice(&[0x12, 0x34, 0x40, 0x00]); // ID, Flags (DF)
        pkt_data.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // TTL=64, Proto=TCP, Chksum
        pkt_data.extend_from_slice(&[192, 168, 1, 100]); // Src IP
        pkt_data.extend_from_slice(&[192, 168, 1, 1]); // Dst IP

        // TCP (20 bytes): sport 45678, dport 80, seq 1000, ack 500
        pkt_data.extend_from_slice(&[0xB2, 0x6E]); // Sport 45678
        pkt_data.extend_from_slice(&[0x00, 0x50]); // Dport 80
        pkt_data.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // Seq 1000
        pkt_data.extend_from_slice(&[0x00, 0x00, 0x01, 0xF4]); // Ack 500
        pkt_data.extend_from_slice(&[0x50, 0x18, 0x20, 0x00]); // Offset 5 (20B), PSH+ACK, Window 8192
        pkt_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Checksum, Urgent
        pkt_data.extend_from_slice(payload);

        let caplen = pkt_data.len() as u32;

        // Packet header (16 bytes, LE)
        pcap.extend_from_slice(&1700000000u32.to_le_bytes()); // ts_sec
        pcap.extend_from_slice(&123456u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&caplen.to_le_bytes());
        pcap.extend_from_slice(&caplen.to_le_bytes());
        pcap.extend_from_slice(&pkt_data);

        pcap
    }

    #[tokio::test]
    async fn test_pcap_dissection() {
        let pcap_bytes = create_test_pcap();
        let op = PcapDissectOp;
        let ctx = ExecutionContext::new("t_pcap");

        let res = op
            .execute(DataPayload::bytes(pcap_bytes), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["total_packets_parsed"], 1);
        let pkt = &json["packets"][0];
        assert_eq!(pkt["protocol"], "TCP");
        assert_eq!(pkt["app_protocol"], "HTTP");
        assert_eq!(pkt["ip_src"], "192.168.1.100");
        assert_eq!(pkt["ip_dst"], "192.168.1.1");
        assert_eq!(pkt["dst_port"], 80);
    }

    #[tokio::test]
    async fn test_pcap_reassembly() {
        let pcap_bytes = create_test_pcap();
        let op = PcapReassembleOp;
        let ctx = ExecutionContext::new("t_reassemble");

        let res = op
            .execute(DataPayload::bytes(pcap_bytes), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["total_streams_found"], 1);
        let stream = &json["streams"][0];
        assert!(stream["preview"]
            .as_str()
            .unwrap()
            .contains("GET /index.html"));
    }

    #[tokio::test]
    async fn test_pcap_big_endian_and_tcp_retransmit_deduplication() {
        let ctx = ExecutionContext::new("t_pcap_be");

        // Build big-endian PCAP (magic 0xA1B2C3D4 on wire) with 2 packets:
        // seq 1000 "HELLO" followed by duplicate retransmit seq 1000 "HELLO" and seq 1005 "_WORLD"
        let make_tcp_frame = |seq: u32, payload: &[u8]| -> Vec<u8> {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            pkt.extend_from_slice(&[0x08, 0x00]);
            let ip_len = (20 + 20 + payload.len()) as u16;
            pkt.extend_from_slice(&[0x45, 0x00]);
            pkt.extend_from_slice(&ip_len.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]);
            pkt.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
            pkt.extend_from_slice(&12345u16.to_be_bytes());
            pkt.extend_from_slice(&8080u16.to_be_bytes());
            pkt.extend_from_slice(&seq.to_be_bytes());
            pkt.extend_from_slice(&0u32.to_be_bytes());
            pkt.extend_from_slice(&[0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
            pkt.extend_from_slice(payload);
            pkt
        };

        let mut be_pcap = Vec::new();
        be_pcap.extend_from_slice(&[0xA1, 0xB2, 0xC3, 0xD4]); // Big-endian magic
        be_pcap.extend_from_slice(&[0x00, 0x02, 0x00, 0x04]);
        be_pcap.extend_from_slice(&[0u8; 8]);
        be_pcap.extend_from_slice(&65535u32.to_be_bytes());
        be_pcap.extend_from_slice(&1u32.to_be_bytes());

        for (seq, data) in [
            (1005u32, b"_WORLD".as_slice()),
            (1000u32, b"HELLO".as_slice()),
            (1000u32, b"HELLO".as_slice()), // duplicate retransmit
        ] {
            let frame = make_tcp_frame(seq, data);
            let clen = frame.len() as u32;
            be_pcap.extend_from_slice(&1700000000u32.to_be_bytes());
            be_pcap.extend_from_slice(&0u32.to_be_bytes());
            be_pcap.extend_from_slice(&clen.to_be_bytes());
            be_pcap.extend_from_slice(&clen.to_be_bytes());
            be_pcap.extend_from_slice(&frame);
        }

        let dis = PcapDissectOp
            .execute(
                DataPayload::bytes(be_pcap.clone()),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(dis["total_packets_parsed"], 3);

        let re = PcapReassembleOp
            .execute(DataPayload::bytes(be_pcap), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(re["total_streams_found"], 1);
        assert_eq!(re["streams"][0]["preview"], "HELLO_WORLD");
        assert_eq!(re["streams"][0]["total_bytes_reassembled"], 11);
        assert_eq!(re["streams"][0]["duplicate_segments_skipped"], 1);
    }
}
