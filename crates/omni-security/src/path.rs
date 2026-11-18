use omni_core::{OmniError, OmniResult};
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};

/// Validates lexical components and enforces canonical filesystem boundary checks
/// so neither `..` traversal nor symlinks can escape `base`.
pub fn safe_join(base: &Path, user_path: &Path) -> OmniResult<PathBuf> {
    safe_join_impl(base, user_path, false)
}

/// Strict variant that additionally rejects ANY symlink encountered anywhere along
/// `user_path` inside `base` (recommended for untrusted archive extraction).
pub fn safe_join_no_symlinks(base: &Path, user_path: &Path) -> OmniResult<PathBuf> {
    safe_join_impl(base, user_path, true)
}

fn safe_join_impl(base: &Path, user_path: &Path, reject_all_symlinks: bool) -> OmniResult<PathBuf> {
    let raw = user_path.to_string_lossy();
    if raw.contains('\0') {
        return Err(OmniError::Security(
            "Null byte detected in filesystem path".into(),
        ));
    }

    let mut clean_rel = PathBuf::new();
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
                    "Absolute paths not permitted in relative path: {}",
                    user_path.display()
                )));
            }
            Component::Normal(seg) => {
                clean_rel.push(seg);
            }
            Component::CurDir => {}
        }
    }

    // If base exists on disk, perform real canonical / symlink boundary enforcement
    if base.exists() {
        let canonical_base = fs::canonicalize(base).map_err(|e| {
            OmniError::Security(format!(
                "Failed to canonicalize sandbox base directory: {e}"
            ))
        })?;

        let mut cursor = canonical_base.clone();
        for component in clean_rel.components() {
            if let Component::Normal(seg) = component {
                cursor.push(seg);

                if let Ok(meta) = fs::symlink_metadata(&cursor) {
                    if meta.file_type().is_symlink() {
                        if reject_all_symlinks {
                            return Err(OmniError::Security(format!(
                                "Symlink not permitted inside restricted sandbox path: {}",
                                user_path.display()
                            )));
                        }
                        let resolved = fs::canonicalize(&cursor).map_err(|_| {
                            OmniError::Security(format!(
                                "Dangling or unresolvable symlink rejected: {}",
                                user_path.display()
                            ))
                        })?;
                        if !resolved.starts_with(&canonical_base) {
                            return Err(OmniError::Security(format!(
                                "Symlink escape attempt detected for path: {}",
                                user_path.display()
                            )));
                        }
                        cursor = resolved;
                    }
                }
            }
        }

        // Verify deepest existing ancestor still resolves within canonical_base
        let mut ancestor = cursor.as_path();
        while !ancestor.exists() {
            match ancestor.parent() {
                Some(p) => ancestor = p,
                None => break,
            }
        }
        if ancestor.exists() {
            let resolved_ancestor = fs::canonicalize(ancestor).map_err(|e| {
                OmniError::Security(format!("Failed to canonicalize path ancestor: {e}"))
            })?;
            if !resolved_ancestor.starts_with(&canonical_base) {
                return Err(OmniError::Security(format!(
                    "Resolved path escapes sandbox boundary: {}",
                    user_path.display()
                )));
            }
        }

        return Ok(cursor);
    }

    Ok(base.join(clean_rel))
}

/// Atomically creates a brand-new file inside `base` without following symlinks or overwriting existing files.
pub fn safe_create_new_file(base: &Path, user_path: &Path) -> OmniResult<(PathBuf, File)> {
    let target = safe_join_no_symlinks(base, user_path)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| OmniError::Io(e.to_string()))?;
        // Re-verify after directory creation to guard against races
        let _ = safe_join_no_symlinks(base, user_path)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| OmniError::Io(format!("Failed to safely create file: {e}")))?;
    Ok((target, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_join_valid() {
        let base = std::env::temp_dir().join("omni_safe_join_valid_test");
        let _ = fs::create_dir_all(&base);
        let rel = Path::new("sub/file.txt");
        let joined = safe_join(&base, rel).unwrap();
        let canonical_base = fs::canonicalize(&base).unwrap();
        assert!(joined.starts_with(&canonical_base));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_safe_join_traversal_and_absolute_and_null_rejected() {
        let base = Path::new("/tmp/sandbox");
        assert!(safe_join(base, Path::new("../evil.txt")).is_err());
        assert!(safe_join(base, Path::new("a/../../evil.txt")).is_err());
        assert!(safe_join(base, Path::new("/etc/passwd")).is_err());
        assert!(safe_join(base, Path::new("foo\0bar.txt")).is_err());
    }

    #[test]
    fn test_safe_create_new_prevents_overwrite() {
        let base = std::env::temp_dir().join(format!("omni_create_new_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let (p, _f) = safe_create_new_file(&base, Path::new("nested/a.txt")).unwrap();
        assert!(p.exists());
        // Second call must fail rather than silently overwriting
        assert!(safe_create_new_file(&base, Path::new("nested/a.txt")).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_symlink_escape_rejected() {
        let root = std::env::temp_dir().join(format!("omni_symlink_test_{}", std::process::id()));
        let sandbox = root.join("sandbox");
        let outside = root.join("outside");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret.txt");
        fs::write(&secret, b"top-secret").unwrap();

        let link_path = sandbox.join("escape_link");

        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&outside, &link_path).is_ok();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(&outside, &link_path).is_ok();

        if created {
            // Attempting to traverse through symlink pointing outside sandbox MUST fail!
            let res = safe_join(&sandbox, Path::new("escape_link/secret.txt"));
            assert!(
                res.is_err(),
                "Symlink escape into outside directory must be rejected"
            );
            let strict_res = safe_join_no_symlinks(&sandbox, Path::new("escape_link/secret.txt"));
            assert!(strict_res.is_err());
        }

        let _ = fs::remove_dir_all(&root);
    }
}
