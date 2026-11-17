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
}
