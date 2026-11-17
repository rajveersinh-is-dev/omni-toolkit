use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use omni_security::validate_network_target;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub struct SocketToolOp;

#[async_trait]
impl Operation for SocketToolOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.socket",
            "Socket Stream & Latency Tester",
            "Inspects TCP/UDP streams, tests loopback connections, and calculates round-trip latency and jitter",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("echo_test");

        match action {
            "echo_test" => {
                // Spin up a temporary loopback echo server to verify socket latency
                let listener = TcpListener::bind("127.0.0.1:0").await
                    .map_err(|e| OmniError::Execution { operation: "socket_bind".into(), message: e.to_string() })?;
                let addr = listener.local_addr()
                    .map_err(|e| OmniError::Execution { operation: "socket_addr".into(), message: e.to_string() })?;

                // Spawn echo listener
                tokio::spawn(async move {
                    if let Ok((mut socket, _)) = listener.accept().await {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = socket.read(&mut buf).await {
                            let _ = socket.write_all(&buf[..n]).await;
                        }
                    }
                });

                let send_bytes = input.into_bytes();
                let payload = if send_bytes.is_empty() { b"PING_OMNI".to_vec() } else { send_bytes };

                let start = Instant::now();
                let mut client = TcpStream::connect(addr).await
                    .map_err(|e| OmniError::Execution { operation: "socket_connect".into(), message: e.to_string() })?;
                client.write_all(&payload).await
                    .map_err(|e| OmniError::Execution { operation: "socket_write".into(), message: e.to_string() })?;

                let mut recv_buf = vec![0u8; payload.len()];
                client.read_exact(&mut recv_buf).await
                    .map_err(|e| OmniError::Execution { operation: "socket_read".into(), message: e.to_string() })?;

                let rtt_micros = start.elapsed().as_micros();

                Ok(DataPayload::json(json!({
                    "test_type": "TCP Loopback Echo",
                    "bound_address": addr.to_string(),
                    "payload_bytes_sent": payload.len(),
                    "payload_bytes_received": recv_buf.len(),
                    "payload_matches": payload == recv_buf,
                    "rtt_microseconds": rtt_micros,
                    "rtt_milliseconds": (rtt_micros as f64 / 1000.0 * 100.0).round() / 100.0,
                })))
            }
            "probe" | _ => {
                let target = config.get("target").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
                let port = config.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
                validate_network_target(target, false)?;

                let start = Instant::now();
                let res = timeout(Duration::from_millis(500), TcpStream::connect(format!("{}:{}", target, port))).await;
                let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;

                let connected = matches!(res, Ok(Ok(_)));

                Ok(DataPayload::json(json!({
                    "target": target,
                    "port": port,
                    "connected": connected,
                    "latency_ms": elapsed_ms,
                })))
            }
        }
    }
}
