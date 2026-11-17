use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub percent: f32,
    pub stage: String,
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
    pub message: String,
}

#[derive(Clone)]
pub struct ExecutionContext {
    pub job_id: String,
    cancellation_flag: Arc<AtomicBool>,
    progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
}

impl ExecutionContext {
    pub fn new(job_id: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            cancellation_flag: Arc::new(AtomicBool::new(false)),
            progress_tx: None,
        }
    }

    pub fn with_progress(mut self, tx: mpsc::Sender<ProgressUpdate>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation_flag.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancellation_flag.store(true, Ordering::Relaxed);
    }

    pub async fn report_progress(&self, percent: f32, stage: impl Into<String>, message: impl Into<String>) {
        if let Some(tx) = &self.progress_tx {
            let _ = tx.send(ProgressUpdate {
                percent,
                stage: stage.into(),
                bytes_processed: 0,
                total_bytes: None,
                message: message.into(),
            }).await;
        }
    }
}
