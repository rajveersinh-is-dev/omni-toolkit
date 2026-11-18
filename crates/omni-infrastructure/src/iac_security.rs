use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

/// Iterative O(N*M) glob wildcard matcher supporting `*` and `?` for AWS/GCP IAM actions and ARNs.
fn iam_wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub struct IacSecurityOp;

#[derive(Debug, Clone, serde::Serialize)]
struct SecurityIssue {
    resource: String,
    severity: String,
    policy: String,
    remediation: String,
}

#[async_trait]
impl Operation for IacSecurityOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cloud.iac",
            "IaC Security & Cloud IAM Simulator",
            "Audits Kubernetes manifests, parses Terraform plans for destructive changes, and simulates AWS/GCP IAM policies with wildcard Action and Resource matching",
            OperationCategory::CloudAndDevOps,
        )
        .with_types(vec![DataType::Json, DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cloud".into(), "iac".into(), "k8s".into(), "terraform".into(), "iam".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let mode = config.get("mode").and_then(|v| v.as_str()).unwrap_or("k8s");
        let val = match input {
            DataPayload::Json(v) => v,
            DataPayload::Text(s) => serde_json::from_str(&s)
                .map_err(|e| OmniError::InvalidInput(format!("Invalid JSON input: {e}")))?,
            _ => {
                return Err(OmniError::InvalidInput(
                    "Expected JSON or text input".into(),
                ))
            }
        };

        match mode {
            "terraform" => {
                let mut creates = 0;
                let mut updates = 0;
                let mut deletes = 0;
                let mut high_risk_deletions = Vec::new();

                if let Some(changes) = val.get("resource_changes").and_then(|v| v.as_array()) {
                    for r in changes {
                        let address = r
                            .get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let r_type = r.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let actions = r
                            .get("change")
                            .and_then(|c| c.get("actions"))
                            .and_then(|a| a.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                            .unwrap_or_default();

                        if actions.contains(&"delete") {
                            deletes += 1;
                            if r_type.contains("db")
                                || r_type.contains("database")
                                || r_type.contains("rds")
                                || r_type.contains("s3")
                                || r_type.contains("bucket")
                            {
                                high_risk_deletions.push(json!({
                                    "address": address,
                                    "type": r_type,
                                    "risk": "Destruction of stateful data persistence asset",
                                }));
                            }
                        } else if actions.contains(&"create") {
                            creates += 1;
                        } else if actions.contains(&"update") {
                            updates += 1;
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "engine": "Terraform Plan Security Analyzer",
                    "total_changes": creates + updates + deletes,
                    "creates": creates,
                    "updates": updates,
                    "deletes": deletes,
                    "has_high_risk_deletions": !high_risk_deletions.is_empty(),
                    "high_risk_deletions": high_risk_deletions,
                })))
            }
            "iam" => {
                let action_to_check = config
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("s3:GetObject");
                let resource_to_check = config
                    .get("resource")
                    .and_then(|v| v.as_str())
                    .unwrap_or("arn:aws:s3:::my-bucket/*");

                let mut decision = "ImplicitDeny";
                let mut matched_rule = None;

                if let Some(statements) = val.get("Statement").and_then(|v| v.as_array()) {
                    for stmt in statements {
                        let effect = stmt
                            .get("Effect")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Allow");
                        let actions = match stmt.get("Action") {
                            Some(Value::String(s)) => vec![s.as_str()],
                            Some(Value::Array(arr)) => {
                                arr.iter().filter_map(|v| v.as_str()).collect()
                            }
                            _ => Vec::new(),
                        };

                        let resources = match stmt.get("Resource") {
                            Some(Value::String(s)) => Some(vec![s.as_str()]),
                            Some(Value::Array(arr)) => {
                                Some(arr.iter().filter_map(|v| v.as_str()).collect())
                            }
                            _ => None,
                        };

                        let action_lower = action_to_check.to_ascii_lowercase();
                        let action_matches = actions
                            .iter()
                            .any(|&a| iam_wildcard_match(&a.to_ascii_lowercase(), &action_lower));
                        let resource_matches = match resources {
                            Some(res_list) => res_list
                                .iter()
                                .any(|&r| iam_wildcard_match(r, resource_to_check)),
                            None => true,
                        };

                        if action_matches && resource_matches {
                            if effect == "Deny" {
                                decision = "ExplicitDeny";
                                matched_rule = Some(stmt.clone());
                                break; // Explicit deny immediately overrides all allows
                            } else if effect == "Allow" && decision != "ExplicitDeny" {
                                decision = "Allow";
                                matched_rule = Some(stmt.clone());
                            }
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "engine": "AWS/GCP IAM Policy Simulator",
                    "evaluated_action": action_to_check,
                    "evaluated_resource": resource_to_check,
                    "access_decision": decision,
                    "matched_statement": matched_rule,
                })))
            }
            _ => {
                let mut issues = Vec::new();
                let kind = val
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let metadata_name = val
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unnamed");

                let spec = val.get("spec").cloned().unwrap_or(Value::Null);

                // Check PodSpec
                let pod_spec = spec
                    .get("template")
                    .and_then(|t| t.get("spec"))
                    .unwrap_or(&spec);

                if pod_spec
                    .get("hostNetwork")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    issues.push(SecurityIssue {
                        resource: format!("{}/{}", kind, metadata_name),
                        severity: "High".into(),
                        policy: "K8S-001 (hostNetwork)".into(),
                        remediation: "Disable hostNetwork to isolate pod network namespace".into(),
                    });
                }

                if pod_spec
                    .get("hostPID")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    issues.push(SecurityIssue {
                        resource: format!("{}/{}", kind, metadata_name),
                        severity: "High".into(),
                        policy: "K8S-002 (hostPID)".into(),
                        remediation:
                            "Disable hostPID to prevent container from inspecting host processes"
                                .into(),
                    });
                }

                if let Some(containers) = pod_spec.get("containers").and_then(|c| c.as_array()) {
                    for c in containers {
                        let c_name = c.get("name").and_then(|v| v.as_str()).unwrap_or("c");
                        let sec_ctx = c.get("securityContext");

                        let is_priv = sec_ctx
                            .and_then(|s| s.get("privileged"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if is_priv {
                            issues.push(SecurityIssue {
                                resource: format!("{}/{}[{}]", kind, metadata_name, c_name),
                                severity: "Critical".into(),
                                policy: "K8S-003 (Privileged Container)".into(),
                                remediation: "Set securityContext.privileged to false; privileged mode grants root host capabilities".into(),
                            });
                        }

                        let read_only_root = sec_ctx
                            .and_then(|s| s.get("readOnlyRootFilesystem"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !read_only_root {
                            issues.push(SecurityIssue {
                                resource: format!("{}/{}[{}]", kind, metadata_name, c_name),
                                severity: "Medium".into(),
                                policy: "K8S-004 (readOnlyRootFilesystem)".into(),
                                remediation: "Mount root filesystem as read-only to prevent persistent tampering".into(),
                            });
                        }

                        let has_limits = c.get("resources").and_then(|r| r.get("limits")).is_some();
                        if !has_limits {
                            issues.push(SecurityIssue {
                                resource: format!("{}/{}[{}]", kind, metadata_name, c_name),
                                severity: "Low".into(),
                                policy: "K8S-005 (Resource Limits)".into(),
                                remediation: "Specify resources.limits.cpu and memory to protect node against DoS".into(),
                            });
                        }
                    }
                }

                // Check RBAC
                if kind.contains("Role") {
                    if let Some(rules) = val.get("rules").and_then(|r| r.as_array()) {
                        for rule in rules {
                            let verbs = rule.get("verbs").and_then(|v| v.as_array());
                            let resources = rule.get("resources").and_then(|r| r.as_array());

                            let has_wildcard_verb = verbs
                                .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
                                .unwrap_or(false);
                            let targets_secrets = resources
                                .map(|arr| {
                                    arr.iter().any(|r| {
                                        r.as_str() == Some("secrets") || r.as_str() == Some("*")
                                    })
                                })
                                .unwrap_or(false);

                            if has_wildcard_verb && targets_secrets {
                                issues.push(SecurityIssue {
                                    resource: format!("{}/{}", kind, metadata_name),
                                    severity: "Critical".into(),
                                    policy: "K8S-RBAC-001 (Overprivileged Role)".into(),
                                    remediation: "Avoid wildcard '*' verbs over secrets. Scope permissions to least privilege".into(),
                                });
                            }
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "engine": "Kubernetes Manifest Security Audit",
                    "resource_kind": kind,
                    "resource_name": metadata_name,
                    "total_issues": issues.len(),
                    "issues": issues,
                    "security_score": (100.0 - (issues.len() as f64 * 15.0)).max(0.0),
                })))
            }
        }
    }
}
