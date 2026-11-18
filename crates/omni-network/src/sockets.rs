use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
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
        .with_status(FeatureStatus::Verified)
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
            .unwrap_or("echo_test");

        match action {
            "echo_test" => {
                // Spin up a temporary loopback echo server to verify socket latency
                let listener =
                    TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| OmniError::Execution {
                            operation: "socket_bind".into(),
                            message: e.to_string(),
                        })?;
                let addr = listener.local_addr().map_err(|e| OmniError::Execution {
                    operation: "socket_addr".into(),
                    message: e.to_string(),
                })?;

                // Spawn echo listener capable of echoing arbitrary-length payloads cleanly
                tokio::spawn(async move {
                    if let Ok(Ok((mut socket, _))) =
                        timeout(Duration::from_secs(5), listener.accept()).await
                    {
                        let mut buf = [0u8; 4096];
                        loop {
                            match timeout(Duration::from_secs(5), socket.read(&mut buf)).await {
                                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                                Ok(Ok(n)) => {
                                    if socket.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });

                let send_bytes = input.into_bytes();
                let payload = if send_bytes.is_empty() {
                    b"PING_OMNI".to_vec()
                } else {
                    send_bytes
                };

                let start = Instant::now();
                let client = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                    .await
                    .map_err(|_| OmniError::Timeout(5_000))?
                    .map_err(|e| OmniError::Execution {
                        operation: "socket_connect".into(),
                        message: e.to_string(),
                    })?;

                // Write and read concurrently to avoid TCP buffer deadlock on large payloads
                let (mut reader, mut writer) = client.into_split();
                let payload_clone = payload.clone();
                let write_task = tokio::spawn(async move {
                    writer.write_all(&payload_clone).await?;
                    writer.shutdown().await
                });

                let mut recv_buf = vec![0u8; payload.len()];
                timeout(Duration::from_secs(5), reader.read_exact(&mut recv_buf))
                    .await
                    .map_err(|_| OmniError::Timeout(5_000))?
                    .map_err(|e| OmniError::Execution {
                        operation: "socket_read".into(),
                        message: e.to_string(),
                    })?;

                let _ = write_task.await;

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
            _ => {
                let target = config
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("127.0.0.1");
                let port_u64 = config.get("port").and_then(|v| v.as_u64()).unwrap_or(80);
                let port = u16::try_from(port_u64)
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| {
                        OmniError::Validation(format!(
                            "Invalid TCP port '{port_u64}' (must be 1..=65535)"
                        ))
                    })?;
                validate_network_target(target, false)?;

                let start = Instant::now();
                let res = timeout(
                    Duration::from_millis(500),
                    TcpStream::connect(format!("{}:{}", target, port)),
                )
                .await;
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
