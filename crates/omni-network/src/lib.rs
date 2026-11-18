pub mod dns;
pub mod http_client;
pub mod ip_calc;
pub mod scanner;
pub mod sockets;

pub use dns::DnsPowerSuiteOp;
pub use http_client::HttpClientStudioOp;
pub use ip_calc::IpCalcOp;
pub use scanner::LabScannerOp;
pub use sockets::SocketToolOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_network(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(IpCalcOp))?;
    registry.register(Arc::new(LabScannerOp))?;
    registry.register(Arc::new(DnsPowerSuiteOp))?;
    registry.register(Arc::new(HttpClientStudioOp))?;
    registry.register(Arc::new(SocketToolOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_ip_calc_subnet() {
        let op = IpCalcOp;
        let ctx = ExecutionContext::new("t_ip");

        let res = op
            .execute(
                DataPayload::text("192.168.10.0/24"),
                serde_json::json!({ "split_to_prefix": 26 }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["netmask"], "255.255.255.0");
        assert_eq!(json["broadcast_address"], "192.168.10.255");
        assert_eq!(json["usable_hosts"], 254);
        assert_eq!(json["reverse_dns_ptr"], "0.10.168.192.in-addr.arpa");

        let splits = json["split_subnets"].as_array().unwrap();
        assert_eq!(splits.len(), 4);
        assert_eq!(splits[0], "192.168.10.0/26");
        assert_eq!(splits[3], "192.168.10.192/26");
    }

    #[tokio::test]
    async fn test_curl_code_generation() {
        let op = HttpClientStudioOp;
        let ctx = ExecutionContext::new("t_curl");

        let curl = "curl -X POST https://api.example.com/v1/auth -H 'Content-Type: application/json' -d '{\"user\":\"alice\"}'";
        let res = op
            .execute(DataPayload::text(curl), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["parsed_request"]["method"], "POST");
        let rust = json["code_generation"]["rust_reqwest"].as_str().unwrap();
        assert!(rust.contains("reqwest::Method::POST"));
        assert!(rust.contains("https://api.example.com/v1/auth"));
    }

    #[tokio::test]
    async fn test_socket_echo_latency() {
        let op = SocketToolOp;
        let ctx = ExecutionContext::new("t_sock");

        let res = op
            .execute(
                DataPayload::bytes(b"HELLO_SOCKET".to_vec()),
                serde_json::json!({ "action": "echo_test" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["payload_matches"], true);
    }

    #[tokio::test]
    async fn test_ip_calc_zero_prefix_split_and_large_socket_echo() {
        let ctx = ExecutionContext::new("t_net_edge");

        // 1. /0 split to /32 previously panicked with 2u32.pow(32) overflow!
        let res = IpCalcOp
            .execute(
                DataPayload::text("0.0.0.0/0"),
                serde_json::json!({ "split_to_prefix": 32 }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(res["split_subnets"].as_array().unwrap().len(), 64);

        // Malformed double-slash CIDR rejected
        assert!(IpCalcOp
            .execute(
                DataPayload::text("10.0.0.0/8/16"),
                serde_json::json!({}),
                &ctx
            )
            .await
            .is_err());

        // 2. Socket echo with 8192-byte payload (previously failed > 1024 bytes!)
        let large_payload = vec![0x42u8; 8192];
        let sock_res = SocketToolOp
            .execute(
                DataPayload::bytes(large_payload),
                serde_json::json!({ "action": "echo_test" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sock_res["payload_matches"], true);
        assert_eq!(sock_res["payload_bytes_received"], 8192);

        // 3. SocketToolOp rejects out-of-range TCP port (65537 or 0)
        assert!(SocketToolOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "probe", "target": "127.0.0.1", "port": 65537 }),
                &ctx,
            )
            .await
            .is_err());

        // 4. LabScannerOp WoL magic packet (6*0xFF + 16*MAC = 102 bytes) + >1024 port DoS guard
        let wol = LabScannerOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "wol", "mac": "AA:BB:CC:DD:EE:FF" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(wol["magic_packet_size_bytes"], 102);
        let too_many: Vec<u16> = (1..=1025).collect();
        assert!(LabScannerOp
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "scan", "target": "127.0.0.1", "ports": too_many }),
                &ctx,
            )
            .await
            .is_err());

        // 5. DnsPowerSuiteOp rejects reserved label length bits (0x40/0x80)
        let mut bad_dns = vec![0u8; 16];
        bad_dns[5] = 1; // QDCOUNT = 1
        bad_dns[12] = 0x80; // invalid reserved label octet
        assert!(DnsPowerSuiteOp
            .execute(
                DataPayload::bytes(bad_dns),
                serde_json::json!({ "action": "parse" }),
                &ctx,
            )
            .await
            .is_err());
    }
}
