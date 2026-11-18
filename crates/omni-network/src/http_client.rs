use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct HttpClientStudioOp;

#[derive(Debug, Clone)]
struct CurlCommand {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
}

/// Quote-aware shell-like tokenizer for cURL commands (handles single/double quotes and spaces inside values).
fn tokenize_curl(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_curl(cmd: &str) -> OmniResult<CurlCommand> {
    let tokens = tokenize_curl(cmd);
    if tokens.is_empty() {
        return Err(OmniError::InvalidInput("Empty cURL command".into()));
    }

    let mut method = "GET".to_string();
    let mut url = String::new();
    let mut headers = BTreeMap::new();
    let mut body = None;

    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        if t == "-X" || t == "--request" {
            if i + 1 < tokens.len() {
                method = tokens[i + 1].to_uppercase();
                i += 2;
                continue;
            }
        } else if t == "-H" || t == "--header" {
            if i + 1 < tokens.len() {
                if let Some((k, v)) = tokens[i + 1].split_once(':') {
                    headers.insert(k.trim().to_string(), v.trim().to_string());
                }
                i += 2;
                continue;
            }
        } else if t == "-d" || t == "--data" || t == "--data-raw" || t == "--data-binary" {
            if i + 1 < tokens.len() {
                body = Some(tokens[i + 1].clone());
                if method == "GET" {
                    method = "POST".to_string();
                }
                i += 2;
                continue;
            }
        } else if t.starts_with("http://") || t.starts_with("https://") {
            url = t.to_string();
        }
        i += 1;
    }

    if url.is_empty() {
        return Err(OmniError::InvalidInput(
            "cURL command must contain an http:// or https:// URL".into(),
        ));
    }

    Ok(CurlCommand {
        method,
        url,
        headers,
        body,
    })
}

fn generate_rust_code(c: &CurlCommand) -> String {
    let mut lines = vec![
        "use reqwest::Client;".to_string(),
        "\n#[tokio::main]".to_string(),
        "async fn main() -> Result<(), Box<dyn std::error::Error>> {".to_string(),
        "    let client = Client::new();".to_string(),
        format!(
            "    let res = client.request(reqwest::Method::{}, {:?})",
            c.method, c.url
        ),
    ];
    for (k, v) in &c.headers {
        lines.push(format!("        .header({:?}, {:?})", k, v));
    }
    if let Some(b) = &c.body {
        lines.push(format!("        .body({:?})", b));
    }
    lines.push("        .send()".to_string());
    lines.push("        .await?;".to_string());
    lines.push("    println!(\"Status: {}\", res.status());".to_string());
    lines.push("    println!(\"Body: {}\", res.text().await?);".to_string());
    lines.push("    Ok(())".to_string());
    lines.push("}".to_string());
    lines.join("\n")
}

fn generate_python_code(c: &CurlCommand) -> String {
    let mut lines = vec!["import httpx".to_string(), "\nheaders = {".to_string()];
    for (k, v) in &c.headers {
        lines.push(format!("    {:?}: {:?},", k, v));
    }
    lines.push("}".to_string());
    let data_arg = match &c.body {
        Some(b) => format!(", content={:?}", b),
        None => String::new(),
    };
    lines.push(format!(
        "response = httpx.request({:?}, {:?}, headers=headers{})",
        c.method, c.url, data_arg
    ));
    lines.push("print(f\"Status: {response.status_code}\")".to_string());
    lines.push("print(response.text)".to_string());
    lines.join("\n")
}

fn generate_go_code(c: &CurlCommand) -> String {
    let mut lines = vec![
        "package main".to_string(),
        "\nimport (".to_string(),
        "    \"fmt\"".to_string(),
        "    \"io\"".to_string(),
        "    \"net/http\"".to_string(),
    ];
    if c.body.is_some() {
        lines.push("    \"strings\"".to_string());
    }
    lines.push(")".to_string());
    lines.push("\nfunc main() {".to_string());
    let body_expr = match &c.body {
        Some(b) => format!("strings.NewReader({:?})", b),
        None => "nil".to_string(),
    };
    lines.push(format!(
        "    req, err := http.NewRequest({:?}, {:?}, {})",
        c.method, c.url, body_expr
    ));
    lines.push("    if err != nil { panic(err) }".to_string());
    for (k, v) in &c.headers {
        lines.push(format!("    req.Header.Set({:?}, {:?})", k, v));
    }
    lines.push("    resp, err := http.DefaultClient.Do(req)".to_string());
    lines.push("    if err != nil { panic(err) }".to_string());
    lines.push("    defer resp.Body.Close()".to_string());
    lines.push("    body, _ := io.ReadAll(resp.Body)".to_string());
    lines.push("    fmt.Println(resp.Status, string(body))".to_string());
    lines.push("}".to_string());
    lines.join("\n")
}

fn generate_node_code(c: &CurlCommand) -> String {
    let mut lines = vec![
        format!("const response = await fetch({:?}, {{", c.url),
        format!("  method: {:?},", c.method),
        "  headers: {".to_string(),
    ];
    for (k, v) in &c.headers {
        lines.push(format!("    {:?}: {:?},", k, v));
    }
    lines.push("  },".to_string());
    if let Some(b) = &c.body {
        lines.push(format!("  body: {:?},", b));
    }
    lines.push("});".to_string());
    lines.push("const data = await response.text();\nconsole.log(data);".to_string());
    lines.join("\n")
}

#[async_trait]
impl Operation for HttpClientStudioOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "net.http_client",
            "cURL Parser & Multi-Language HTTP Code Generator",
            "Parses cURL commands (quote-aware) and generates HTTP client code for Rust (reqwest), Python (httpx), Go (net/http), and Node.js (fetch)",
            OperationCategory::Networking,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Offline parser and code generator only; does not transmit live HTTP requests unless an external HTTP client is invoked".into(),
        ])
        .with_tags(vec!["network".into(), "http".into(), "curl".into(), "codegen".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let curl_str = config
            .get("curl")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| input.as_str().ok().map(|s| s.to_string()))
            .ok_or_else(|| OmniError::InvalidInput("Missing cURL command string".into()))?;

        let parsed = parse_curl(&curl_str)?;

        Ok(DataPayload::json(json!({
            "parsed_request": {
                "method": parsed.method,
                "url": parsed.url,
                "headers": parsed.headers,
                "body": parsed.body,
            },
            "code_generation": {
                "rust_reqwest": generate_rust_code(&parsed),
                "python_httpx": generate_python_code(&parsed),
                "go_net_http": generate_go_code(&parsed),
                "node_fetch": generate_node_code(&parsed),
            }
        })))
    }
}
