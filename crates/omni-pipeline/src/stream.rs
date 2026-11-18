//! Bounded asynchronous streaming pipeline primitives with explicit backpressure,
//! cancellation propagation, and clean stream closure.

use omni_core::{ExecutionContext, OmniError, OmniResult};
use std::future::Future;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BoundedStreamConfig {
    /// Maximum number of chunks buffered in-flight between stages (enforces backpressure).
    pub channel_capacity: usize,
    /// Maximum allowed bytes per individual chunk.
    pub max_chunk_bytes: usize,
}

impl Default for BoundedStreamConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 16,
            max_chunk_bytes: 4 * 1024 * 1024, // 4 MB per chunk
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunk {
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

/// Runs a bounded streaming transformation stage reading from `rx`, applying `transform`,
/// and writing into a newly returned bounded receiver `mpsc::Receiver<OmniResult<StreamChunk>>`.
/// Respects backpressure (blocks producer when downstream buffer is full) and cancellation.
pub fn spawn_stream_stage<F, Fut>(
    mut rx: mpsc::Receiver<OmniResult<StreamChunk>>,
    config: BoundedStreamConfig,
    ctx: ExecutionContext,
    mut transform: F,
) -> mpsc::Receiver<OmniResult<StreamChunk>>
where
    F: FnMut(StreamChunk) -> Fut + Send + 'static,
    Fut: Future<Output = OmniResult<StreamChunk>> + Send,
{
    let cap = config.channel_capacity.max(1);
    let max_bytes = config.max_chunk_bytes;
    let (tx, out_rx) = mpsc::channel(cap);

    tokio::spawn(async move {
        loop {
            let maybe_item = tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    let _ = tx.send(Err(OmniError::Cancelled)).await;
                    break;
                }
                item = rx.recv() => item,
            };

            let Some(item) = maybe_item else {
                // Upstream closed cleanly
                break;
            };

            let chunk = match item {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            };

            if chunk.bytes.len() > max_bytes {
                let _ = tx
                    .send(Err(OmniError::Security(format!(
                        "Stream chunk {} ({} bytes) exceeds max chunk limit ({} bytes)",
                        chunk.sequence,
                        chunk.bytes.len(),
                        max_bytes
                    ))))
                    .await;
                break;
            }

            let transformed = tokio::select! {
                biased;
                _ = ctx.cancelled() => Err(OmniError::Cancelled),
                res = transform(chunk) => res,
            };

            let is_err = transformed.is_err();
            let send_res = tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    let _ = tx.try_send(Err(OmniError::Cancelled));
                    break;
                }
                res = tx.send(transformed) => res,
            };

            if send_res.is_err() || is_err {
                // Downstream consumer dropped or stage errored
                break;
            }
        }
    });

    out_rx
}

/// Splits a byte slice into bounded chunks fed into a bounded channel with backpressure.
pub fn spawn_chunk_producer(
    data: Vec<u8>,
    chunk_size: usize,
    config: BoundedStreamConfig,
    ctx: ExecutionContext,
) -> mpsc::Receiver<OmniResult<StreamChunk>> {
    let cap = config.channel_capacity.max(1);
    let csize = chunk_size.max(1);
    let (tx, rx) = mpsc::channel(cap);

    tokio::spawn(async move {
        for (seq, slice) in data.chunks(csize).enumerate() {
            if ctx.is_cancelled() {
                let _ = tx.send(Err(OmniError::Cancelled)).await;
                break;
            }
            let chunk = StreamChunk {
                sequence: seq as u64,
                bytes: slice.to_vec(),
            };
            let send_res = tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    let _ = tx.try_send(Err(OmniError::Cancelled));
                    break;
                }
                res = tx.send(Ok(chunk)) => res,
            };
            if send_res.is_err() {
                break;
            }
        }
    });

    rx
}
