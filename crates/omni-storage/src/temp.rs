use omni_core::{OmniError, OmniResult};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub struct TempFileManager {
    dir: TempDir,
}

impl TempFileManager {
    pub fn new() -> OmniResult<Self> {
        let dir = TempDir::new().map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn create_temp_file(
        &self,
        prefix: &str,
        suffix: &str,
        content: &[u8],
    ) -> OmniResult<PathBuf> {
        let filename = format!("{}_{}{}", prefix, uuid::Uuid::new_v4(), suffix);
        let file_path = self.dir.path().join(filename);
        std::fs::write(&file_path, content).map_err(|e| OmniError::Io(e.to_string()))?;
        Ok(file_path)
    }
}
