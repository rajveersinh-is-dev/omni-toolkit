pub mod db;
pub mod temp;

pub use db::{DatabaseManager, JobRecord};
pub use temp::TempFileManager;

#[cfg(test)]
mod tests {
    use super::*;
    use omni_pipeline::PipelineDefinition;

    #[test]
    fn test_db_job_lifecycle() {
        let db = DatabaseManager::open_in_memory().unwrap();
        db.insert_job("job_123", "crypto.hash").unwrap();

        let job = db.get_job("job_123").unwrap().unwrap();
        assert_eq!(job.id, "job_123");
        assert_eq!(job.status, "running");

        db.finish_job("job_123", "completed", 42, None).unwrap();
        let job = db.get_job("job_123").unwrap().unwrap();
        assert_eq!(job.status, "completed");
        assert_eq!(job.duration_ms, Some(42));
    }

    #[test]
    fn test_db_pipeline_persistence() {
        let db = DatabaseManager::open_in_memory().unwrap();
        let mut pipe = PipelineDefinition::new("p1", "My Saved Pipeline");
        pipe.add_node("n1", "encode.base64", serde_json::json!({}));

        db.save_pipeline(&pipe).unwrap();

        let loaded = db.get_pipeline("p1").unwrap().unwrap();
        assert_eq!(loaded.id, "p1");
        assert_eq!(loaded.name, "My Saved Pipeline");
        assert_eq!(loaded.nodes.len(), 1);
    }

    #[test]
    fn test_temp_file_creation() {
        let mgr = TempFileManager::new().unwrap();
        let path = mgr.create_temp_file("test", ".txt", b"hello temp").unwrap();
        assert!(path.exists());
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, "hello temp");
    }
}
