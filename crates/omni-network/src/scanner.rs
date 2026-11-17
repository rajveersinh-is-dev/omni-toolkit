use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use omni_security::validate_network_target;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct LabScannerOp;

#[async_trait]
impl Operation for LabScannerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.scanner",
            "Authorized Lab Network Scanner",
            "Performs TCP connect probes, banner grabbing, and Wake-on-LAN generation strictly scoped to loopback and private subnets",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Json, DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, _input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("scan");

        match action {
            "wol" => {
                let mac_str = config.get("mac").and_then(|v| v.as_str()).unwrap_or("00:11:22:33:44:55");
                let mac_clean: String = mac_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if mac_clean.len() != 12 {
                    return Err(OmniError::InvalidInput("MAC address must contain 12 hex digits".into()));
                }

                let mac_bytes = hex::decode(mac_clean)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid MAC hex: {e}")))?;

                // Construct Wake-on-LAN magic packet: 6x 0xFF followed by 16x MAC
                let mut packet = vec![0xFFu8; 6];
                for _ in 0..16 {
                    packet.extend_from_slice(&mac_bytes);
                }

                Ok(DataPayload::json(json!({
                    "action": "wake_on_lan",
                    "target_mac": mac_str,
                    "magic_packet_size_bytes": packet.len(),
                    "magic_packet_hex": hex::encode(&packet),
                    "status": "Magic packet assembled successfully"
                })))
            }
            _ => {
                let target = config.get("target").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                validate_network_target(target, false)?;

                let default_ports = vec![80, 443, 8080, 22, 53, 3000];
                let ports: Vec<u16> = config.get("ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|p| p.as_u64().map(|n| n as u16)).collect())
                    .unwrap_or(default_ports);

                let timeout_ms = config.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(200);
                let mut results = Vec::new();

                for port in ports {
                    let addr = format!("{}:{}", target, port);
                    let connect_future = TcpStream::connect(&addr);
                    let start = std::time::Instant::now();

                    let res = timeout(Duration::from_millis(timeout_ms), connect_future).await;
                    let latency_ms = start.elapsed().as_micros() as f64 / 1000.0;

                    match res {
                        Ok(Ok(mut stream)) => {
                            // Attempt quick banner grab
                            let mut buf = [0u8; 128];
                            let banner = match timeout(Duration::from_millis(50), stream.read(&mut buf)).await {
                                Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
                                _ => String::new(),
                            };

                            results.push(json!({
                                "port": port,
                                "state": "open",
                                "latency_ms": latency_ms,
                                "banner": if banner.is_empty() { None } else { Some(banner) }
                            }));
                        }
                        Ok(Err(_)) => {
                            results.push(json!({
                                "port": port,
                                "state": "closed",
                                "latency_ms": latency_ms,
                            }));
                        }
                        Err(_) => {
                            results.push(json!({
                                "port": port,
                                "state": "filtered/timeout",
                                "latency_ms": timeout_ms,
                            }));
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "target": target,
                    "ports_scanned": results.len(),
                    "results": results,
                })))
            }
        }
    }
}
