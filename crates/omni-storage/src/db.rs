use chrono::Utc;
use omni_core::{OmniError, OmniResult};
use omni_pipeline::PipelineDefinition;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    pub operation_or_pipeline_id: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
}

pub struct DatabaseManager {
    conn: Mutex<Connection>,
}

impl DatabaseManager {
    pub fn open_in_memory() -> OmniResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| OmniError::Io(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_schema()?;
        Ok(mgr)
    }

    pub fn open(path: impl AsRef<Path>) -> OmniResult<Self> {
        let conn = Connection::open(path).map_err(|e| OmniError::Io(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_schema()?;
        Ok(mgr)
    }

    fn init_schema(&self) -> OmniResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                duration_ms INTEGER,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS pipelines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                definition_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| OmniError::Io(format!("Failed to initialize database schema: {e}")))?;
        Ok(())
    }

    pub fn insert_job(&self, job_id: &str, operation_id: &str) -> OmniResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO jobs (id, operation_id, status, created_at) VALUES (?1, ?2, 'running', ?3)",
            params![job_id, operation_id, now],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn finish_job(
        &self,
        job_id: &str,
        status: &str,
        duration_ms: i64,
        error_message: Option<&str>,
    ) -> OmniResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE jobs SET status = ?1, finished_at = ?2, duration_ms = ?3, error_message = ?4 WHERE id = ?5",
            params![status, now, duration_ms, error_message, job_id],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn get_job(&self, job_id: &str) -> OmniResult<Option<JobRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, operation_id, status, created_at, finished_at, duration_ms, error_message FROM jobs WHERE id = ?1")
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let mut rows = stmt
            .query_map(params![job_id], |row| {
                Ok(JobRecord {
                    id: row.get(0)?,
                    operation_or_pipeline_id: row.get(1)?,
                    status: row.get(2)?,
                    created_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get(5)?,
                    error_message: row.get(6)?,
                })
            })
            .map_err(|e| OmniError::Io(e.to_string()))?;

        if let Some(row) = rows.next() {
            Ok(Some(row.map_err(|e| OmniError::Io(e.to_string()))?))
        } else {
            Ok(None)
        }
    }

    pub fn save_pipeline(&self, pipeline: &PipelineDefinition) -> OmniResult<()> {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(pipeline)
            .map_err(|e| OmniError::Validation(format!("Serialization failed: {e}")))?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO pipelines (id, name, description, definition_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                definition_json = excluded.definition_json,
                updated_at = excluded.updated_at",
            params![
                pipeline.id,
                pipeline.name,
                pipeline.description,
                json,
                now
            ],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn get_pipeline(&self, pipeline_id: &str) -> OmniResult<Option<PipelineDefinition>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT definition_json FROM pipelines WHERE id = ?1")
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let mut rows = stmt
            .query_map(params![pipeline_id], |row| row.get::<_, String>(0))
            .map_err(|e| OmniError::Io(e.to_string()))?;

        if let Some(res) = rows.next() {
            let json = res.map_err(|e| OmniError::Io(e.to_string()))?;
            let pipeline: PipelineDefinition = serde_json::from_str(&json)
                .map_err(|e| OmniError::Validation(format!("Deserialization error: {e}")))?;
            Ok(Some(pipeline))
        } else {
            Ok(None)
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> OmniResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> OmniResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let mut rows = stmt
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|e| OmniError::Io(e.to_string()))?;

        if let Some(res) = rows.next() {
            Ok(Some(res.map_err(|e| OmniError::Io(e.to_string()))?))
        } else {
            Ok(None)
        }
    }
}
