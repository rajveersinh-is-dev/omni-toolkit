use omni_core::{OmniError, OmniResult};
use std::path::{Component, Path, PathBuf};

pub fn safe_join(base: &Path, user_path: &Path) -> OmniResult<PathBuf> {
    for component in user_path.components() {
        match component {
            Component::ParentDir => {
                return Err(OmniError::Security(format!(
                    "Path traversal attempt detected in: {}",
                    user_path.display()
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(OmniError::Security(format!(
                    "Absolute paths not permitted in relative extraction: {}",
                    user_path.display()
                )));
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    let joined = base.join(user_path);
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_join_valid() {
        let base = Path::new("/tmp/sandbox");
        let rel = Path::new("sub/file.txt");
        let joined = safe_join(base, rel).unwrap();
        assert!(joined.starts_with(base));
    }

    #[test]
    fn test_safe_join_traversal_rejected() {
        let base = Path::new("/tmp/sandbox");
        let evil = Path::new("../evil.txt");
        assert!(safe_join(base, evil).is_err());
    }
}
