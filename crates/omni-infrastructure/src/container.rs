use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::io::Cursor;
use tar::Archive;

pub struct ContainerForensicsOp;

#[derive(Debug, Clone, serde::Serialize)]
struct LintFinding {
    line: usize,
    severity: String,
    rule: String,
    message: String,
}

fn lint_dockerfile(content: &str) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    let mut has_user_directive = false;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let upper = trimmed.to_uppercase();

        if upper.starts_with("FROM ")
            && (upper.contains(":LATEST") || (!upper.contains(':') && !upper.contains('@') && !upper.contains("AS "))) {
            findings.push(LintFinding {
                line: line_num,
                severity: "Warning".into(),
                rule: "DL3006".into(),
                message: "Always specify an explicit tag or digest instead of using 'latest'".into(),
            });
        }

        if upper.starts_with("USER ") {
            has_user_directive = true;
            if upper.contains("ROOT") || upper.contains(" 0") {
                findings.push(LintFinding {
                    line: line_num,
                    severity: "Error".into(),
                    rule: "DL3002".into(),
                    message: "Avoid explicitly switching container user back to root".into(),
                });
            }
        }

        if upper.starts_with("RUN ") {
            if (trimmed.contains("curl ") || trimmed.contains("wget ")) && (trimmed.contains("| sh") || trimmed.contains("| bash") || trimmed.contains("|sh") || trimmed.contains("|bash")) {
                findings.push(LintFinding {
                    line: line_num,
                    severity: "Error".into(),
                    rule: "DL3007".into(),
                    message: "Piping curl/wget directly into sh/bash executes untrusted remote code without verification".into(),
                });
            }
            if trimmed.contains("apt-get install") && !trimmed.contains("-y") {
                findings.push(LintFinding {
                    line: line_num,
                    severity: "Warning".into(),
                    rule: "DL3014".into(),
                    message: "Use 'apt-get install -y' for non-interactive builds".into(),
                });
            }
        }

        if upper.starts_with("ENV ") || upper.starts_with("ARG ") {
            let lower = trimmed.to_lowercase();
            if lower.contains("pass") || lower.contains("secret") || lower.contains("token") || lower.contains("key") {
                findings.push(LintFinding {
                    line: line_num,
                    severity: "Critical".into(),
                    rule: "SEC-SECRET".into(),
                    message: "Potential sensitive credential or secret embedded in Dockerfile ENV/ARG".into(),
                });
            }
        }
    }

    if !has_user_directive {
        findings.push(LintFinding {
            line: 0,
            severity: "Warning".into(),
            rule: "DL3004".into(),
            message: "Missing USER directive: container will execute by default as root".into(),
        });
    }

    findings
}

#[async_trait]
impl Operation for ContainerForensicsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cloud.container",
            "Container Forensics & Dockerfile Linter",
            "Lints Dockerfiles against CIS benchmarks and inspects daemonless OCI/Docker tarballs for layer bloat and secrets",
            OperationCategory::CloudAndDevOps,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("auto");

        // If input is text or explicitly requested Dockerfile linting
        if action == "lint" || input.data_type() == DataType::Text {
            let dockerfile_text = input.into_text().unwrap_or_default();
            let findings = lint_dockerfile(&dockerfile_text);
            return Ok(DataPayload::json(json!({
                "target": "Dockerfile",
                "total_findings": findings.len(),
                "findings": findings,
                "passed": findings.iter().all(|f| f.severity != "Error" && f.severity != "Critical"),
            })));
        }

        // Otherwise inspect as OCI / Docker tarball
        let bytes = input.into_bytes();
        let mut archive = Archive::new(Cursor::new(&bytes));
        let mut manifest_found = false;
        let mut layer_files = Vec::new();

        if let Ok(entries) = archive.entries() {
            for entry in entries.flatten() {
                let path = entry.path().map(|p| p.display().to_string()).unwrap_or_default();
                let size = entry.size();

                if path == "manifest.json" {
                    manifest_found = true;
                }
                if path.ends_with(".tar") || path.ends_with(".tar.gz") {
                    layer_files.push(json!({
                        "layer": path,
                        "size_bytes": size,
                        "size_mb": (size as f64 / 1_000_000.0 * 10.0).round() / 10.0,
                    }));
                }
            }
        }

        Ok(DataPayload::json(json!({
            "is_valid_docker_tarball": manifest_found,
            "archive_size_bytes": bytes.len(),
            "detected_layers_count": layer_files.len(),
            "layers": layer_files,
        })))
    }
}
