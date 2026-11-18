use chrono::Utc;
use omni_core::{OmniError, OmniResult};
use omni_pipeline::PipelineDefinition;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub updated_at: String,
}

pub struct DatabaseManager {
    conn: Mutex<Connection>,
}

impl DatabaseManager {
    fn lock_conn(&self) -> OmniResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| OmniError::Internal(format!("Database lock poisoned: {e}")))
    }

    pub fn open_in_memory() -> OmniResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| OmniError::Io(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_schema(false)?;
        Ok(mgr)
    }

    pub fn open(path: impl AsRef<Path>) -> OmniResult<Self> {
        let conn = Connection::open(path).map_err(|e| OmniError::Io(e.to_string()))?;
        let mgr = Self {
            conn: Mutex::new(conn),
        };
        mgr.init_schema(true)?;
        Ok(mgr)
    }

    fn init_schema(&self, enable_wal: bool) -> OmniResult<()> {
        let conn = self.lock_conn()?;
        if enable_wal {
            let _ = conn.pragma_update(None, "journal_mode", "WAL");
        }
        let _ = conn.pragma_update(None, "busy_timeout", 5000);
        let _ = conn.pragma_update(None, "foreign_keys", "ON");

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

            CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);

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

    /// Marks any jobs left in `'running'` or `'queued'` state from a previous ungraceful shutdown
    /// as `'interrupted'` during startup recovery.
    pub fn recover_interrupted_jobs(&self) -> OmniResult<usize> {
        let conn = self.lock_conn()?;
        let now = Utc::now().to_rfc3339();
        let updated = conn
            .execute(
                "UPDATE jobs SET status = 'interrupted', finished_at = ?1, error_message = COALESCE(error_message, 'Process terminated before job completion') WHERE status IN ('running', 'queued')",
                params![now],
            )
            .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(updated)
    }

    pub fn insert_job(&self, job_id: &str, operation_id: &str) -> OmniResult<()> {
        self.insert_job_with_status(job_id, operation_id, "running")
    }

    pub fn insert_job_with_status(
        &self,
        job_id: &str,
        operation_id: &str,
        status: &str,
    ) -> OmniResult<()> {
        let conn = self.lock_conn()?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO jobs (id, operation_id, status, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![job_id, operation_id, status, now],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn update_job_status(&self, job_id: &str, status: &str) -> OmniResult<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE jobs SET status = ?1 WHERE id = ?2",
            params![status, job_id],
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
        let conn = self.lock_conn()?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE jobs SET status = ?1, finished_at = ?2, duration_ms = ?3, error_message = ?4 WHERE id = ?5",
            params![status, now, duration_ms, error_message, job_id],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn get_job(&self, job_id: &str) -> OmniResult<Option<JobRecord>> {
        let conn = self.lock_conn()?;
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

    pub fn list_jobs(&self, limit: usize) -> OmniResult<Vec<JobRecord>> {
        let conn = self.lock_conn()?;
        let capped = limit.clamp(1, 500) as i64;
        let mut stmt = conn
            .prepare("SELECT id, operation_id, status, created_at, finished_at, duration_ms, error_message FROM jobs ORDER BY created_at DESC LIMIT ?1")
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let rows = stmt
            .query_map(params![capped], |row| {
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

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OmniError::Io(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn save_pipeline(&self, pipeline: &PipelineDefinition) -> OmniResult<()> {
        let conn = self.lock_conn()?;
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
        let conn = self.lock_conn()?;
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

    pub fn list_pipelines(&self) -> OmniResult<Vec<PipelineSummary>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT id, name, description, updated_at FROM pipelines ORDER BY updated_at DESC")
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(PipelineSummary {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })
            .map_err(|e| OmniError::Io(e.to_string()))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| OmniError::Io(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn delete_pipeline(&self, pipeline_id: &str) -> OmniResult<bool> {
        let conn = self.lock_conn()?;
        let affected = conn
            .execute("DELETE FROM pipelines WHERE id = ?1", params![pipeline_id])
            .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(affected > 0)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> OmniResult<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> OmniResult<Option<String>> {
        let conn = self.lock_conn()?;
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
