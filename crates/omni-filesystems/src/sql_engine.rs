use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Value};

pub struct EmbeddedSqlOp;

fn strip_sql_single_quoted_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut in_quote = false;
    while let Some(c) = chars.next() {
        if in_quote {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                } else {
                    in_quote = false;
                    out.push(' ');
                }
            }
        } else if c == '\'' {
            in_quote = true;
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn validate_readonly_query(query: &str) -> OmniResult<()> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(OmniError::InvalidInput(
            "SQL query must not be empty".into(),
        ));
    }
    let first_token = trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if !matches!(first_token.as_str(), "SELECT" | "WITH" | "EXPLAIN") {
        return Err(OmniError::Security(
            "Only read-only SELECT / WITH / EXPLAIN queries are permitted in storage.sql".into(),
        ));
    }
    // Reject ATTACH/DETACH/LOAD_EXTENSION regardless of whitespace/newlines outside string literals
    let stripped = strip_sql_single_quoted_literals(trimmed);
    let has_forbidden = stripped
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| {
            tok.eq_ignore_ascii_case("ATTACH")
                || tok.eq_ignore_ascii_case("DETACH")
                || tok.eq_ignore_ascii_case("LOAD_EXTENSION")
        });
    if has_forbidden {
        return Err(OmniError::Security(
            "Disallowed SQL statement (ATTACH/DETACH/LOAD_EXTENSION) rejected".into(),
        ));
    }
    Ok(())
}

fn sanitize_unique_headers<'a, I>(raw_headers: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for (i, raw) in raw_headers.into_iter().enumerate() {
        let base: String = raw
            .trim()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let base = if base.is_empty() {
            format!("col_{}", i)
        } else {
            base
        };
        let mut candidate = base.clone();
        let mut suffix = 1usize;
        while !seen.insert(candidate.to_lowercase()) {
            candidate = format!("{}_{}", base, suffix);
            suffix += 1;
        }
        result.push(candidate);
    }
    result
}

fn strip_leading_blank_lines(text: &str) -> &str {
    let mut rest = text.strip_prefix('\u{feff}').unwrap_or(text);
    while let Some(nl_pos) = rest.find('\n') {
        if rest[..nl_pos].trim().is_empty() {
            rest = &rest[nl_pos + 1..];
        } else {
            break;
        }
    }
    rest
}

fn parse_multi_byte_rfc4180(input: &str, delimiter: &str) -> Vec<Vec<String>> {
    let bytes = input.as_bytes();
    let delim = delimiter.as_bytes();
    let allow_quotes = !delimiter.contains('"');
    let mut records = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let mut record = Vec::new();
        loop {
            let mut field = String::new();
            if allow_quotes && i < bytes.len() && bytes[i] == b'"' {
                i += 1; // opening quote
                let mut seg_start = i;
                while i < bytes.len() {
                    if bytes[i] == b'"' {
                        field.push_str(&input[seg_start..i]);
                        if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                            field.push('"');
                            i += 2;
                            seg_start = i;
                        } else {
                            i += 1; // closing quote
                            seg_start = i;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                if seg_start < i {
                    field.push_str(&input[seg_start..i]);
                }
                // Consume any trailing non-delimiter bytes up to delimiter or EOL
                let tail_start = i;
                while i < bytes.len()
                    && !bytes[i..].starts_with(delim)
                    && bytes[i] != b'\n'
                    && bytes[i] != b'\r'
                {
                    i += 1;
                }
                if tail_start < i {
                    field.push_str(&input[tail_start..i]);
                }
            } else {
                let start = i;
                while i < bytes.len()
                    && !bytes[i..].starts_with(delim)
                    && bytes[i] != b'\n'
                    && bytes[i] != b'\r'
                {
                    i += 1;
                }
                field.push_str(&input[start..i]);
            }
            record.push(field);

            if i < bytes.len() && bytes[i..].starts_with(delim) {
                i += delim.len();
                continue;
            }
            if i < bytes.len() && bytes[i] == b'\r' {
                i += 1;
                if i < bytes.len() && bytes[i] == b'\n' {
                    i += 1;
                }
            } else if i < bytes.len() && bytes[i] == b'\n' {
                i += 1;
            }
            break;
        }
        records.push(record);
    }

    records
}

fn parse_tabular_records(
    text: &str,
    delimiter: &str,
) -> OmniResult<(Vec<String>, Vec<Vec<String>>)> {
    let trimmed = strip_leading_blank_lines(text);
    if trimmed.trim().is_empty() {
        return Err(OmniError::InvalidInput(
            "No tabular data provided to query".into(),
        ));
    }

    if delimiter.len() == 1 {
        let delim_byte = delimiter.as_bytes()[0];
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(delim_byte)
            .has_headers(false)
            .flexible(true)
            .quoting(delim_byte != b'"')
            .from_reader(trimmed.as_bytes());

        let mut records = rdr.records();
        let first = records
            .next()
            .transpose()
            .map_err(|e| OmniError::InvalidInput(format!("CSV header parse error: {e}")))?
            .ok_or_else(|| OmniError::InvalidInput("No tabular data provided to query".into()))?;

        let raw_headers: Vec<String> = first.iter().map(str::to_string).collect();
        if raw_headers.is_empty() {
            return Err(OmniError::InvalidInput(
                "No tabular data provided to query".into(),
            ));
        }

        let mut rows = Vec::new();
        for rec in records {
            let record =
                rec.map_err(|e| OmniError::InvalidInput(format!("CSV row parse error: {e}")))?;
            if raw_headers.len() > 1
                && record.len() == 1
                && record.get(0).is_some_and(|s| s.trim().is_empty())
            {
                continue;
            }
            rows.push(record.iter().map(str::to_string).collect());
        }
        Ok((raw_headers, rows))
    } else {
        let mut parsed = parse_multi_byte_rfc4180(trimmed, delimiter).into_iter();
        let raw_headers = parsed
            .next()
            .ok_or_else(|| OmniError::InvalidInput("No tabular data provided to query".into()))?;
        if raw_headers.is_empty() {
            return Err(OmniError::InvalidInput(
                "No tabular data provided to query".into(),
            ));
        }
        let rows: Vec<Vec<String>> = parsed
            .filter(|rec| {
                !(raw_headers.len() > 1 && rec.len() == 1 && rec[0].trim().is_empty())
                    && !(rec.len() == 1 && rec[0].is_empty() && raw_headers.len() == 1)
            })
            .collect();
        Ok((raw_headers, rows))
    }
}

#[async_trait]
impl Operation for EmbeddedSqlOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "storage.sql",
            "In-Memory SQL Analytics Engine (SQLite)",
            "Executes read-only analytical SQL queries over dynamically ingested CSV, TSV, or JSON array tabular data using in-memory SQLite",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Backed by embedded in-memory SQLite (DuckDB and Parquet native ingestion are not bundled)".into(),
            "Restricted strictly to read-only SELECT/WITH/EXPLAIN queries".into(),
        ])
        .with_tags(vec!["sql".into(), "sqlite".into(), "csv".into(), "analytics".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let query = config
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("SELECT * FROM data LIMIT 20");
        validate_readonly_query(query)?;

        let delimiter = config
            .get("delimiter")
            .and_then(|v| v.as_str())
            .unwrap_or(",");
        if delimiter.is_empty() || delimiter.contains('\n') || delimiter.contains('\r') {
            return Err(OmniError::Validation(
                "CSV/TSV 'delimiter' must not be empty or contain CR/LF line terminators".into(),
            ));
        }

        let conn = Connection::open_in_memory().map_err(|e| OmniError::Execution {
            operation: "sqlite_open".into(),
            message: e.to_string(),
        })?;

        // Support JSON array of objects OR CSV/TSV text ingestion
        let json_rows: Option<Vec<serde_json::Map<String, Value>>> = match &input {
            DataPayload::Json(Value::Array(arr)) => {
                Some(arr.iter().filter_map(|v| v.as_object().cloned()).collect())
            }
            DataPayload::Text(s) if s.trim_start().starts_with('[') => {
                serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(s).ok()
            }
            _ => None,
        };

        if let Some(objects) = json_rows {
            if objects.is_empty() {
                return Err(OmniError::InvalidInput(
                    "JSON array contains zero rows".into(),
                ));
            }
            let raw_keys: Vec<String> = {
                let mut ks: Vec<String> = objects[0].keys().cloned().collect();
                ks.sort();
                ks
            };
            if raw_keys.is_empty() {
                return Err(OmniError::InvalidInput(
                    "JSON objects contain zero columns".into(),
                ));
            }
            // Derive column names in the exact same order as raw_keys so values never scramble
            let headers = sanitize_unique_headers(raw_keys.iter().map(|s| s.as_str()));

            let cols_def = headers
                .iter()
                .map(|h| format!("\"{}\" TEXT", h))
                .collect::<Vec<_>>()
                .join(", ");
            conn.execute(&format!("CREATE TABLE data ({})", cols_def), [])
                .map_err(|e| OmniError::Execution {
                    operation: "create_table".into(),
                    message: e.to_string(),
                })?;

            let placeholders = vec!["?"; headers.len()].join(", ");
            let insert_sql = format!("INSERT INTO data VALUES ({})", placeholders);
            let mut stmt = conn
                .prepare(&insert_sql)
                .map_err(|e| OmniError::Execution {
                    operation: "prepare_insert".into(),
                    message: e.to_string(),
                })?;

            for obj in &objects {
                let str_vals: Vec<String> = raw_keys
                    .iter()
                    .map(|k| match obj.get(k) {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Null) | None => String::new(),
                        Some(other) => other.to_string(),
                    })
                    .collect();
                let params: Vec<&dyn rusqlite::ToSql> =
                    str_vals.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                stmt.execute(rusqlite::params_from_iter(params))
                    .map_err(|e| OmniError::Execution {
                        operation: "insert_row".into(),
                        message: e.to_string(),
                    })?;
            }
        } else {
            let text = input.into_text()?;
            let (raw_headers, data_rows) = parse_tabular_records(&text, delimiter)?;
            let headers = sanitize_unique_headers(raw_headers.iter().map(String::as_str));

            let cols_def = headers
                .iter()
                .map(|h| format!("\"{}\" TEXT", h))
                .collect::<Vec<_>>()
                .join(", ");
            conn.execute(&format!("CREATE TABLE data ({})", cols_def), [])
                .map_err(|e| OmniError::Execution {
                    operation: "create_table".into(),
                    message: e.to_string(),
                })?;

            let placeholders = vec!["?"; headers.len()].join(", ");
            let insert_sql = format!("INSERT INTO data VALUES ({})", placeholders);
            let mut stmt = conn
                .prepare(&insert_sql)
                .map_err(|e| OmniError::Execution {
                    operation: "prepare_insert".into(),
                    message: e.to_string(),
                })?;

            let empty_str = "";
            for row_vals in &data_rows {
                let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(headers.len());
                for i in 0..headers.len() {
                    if let Some(val) = row_vals.get(i) {
                        params.push(val);
                    } else {
                        params.push(&empty_str);
                    }
                }
                stmt.execute(rusqlite::params_from_iter(params))
                    .map_err(|e| OmniError::Execution {
                        operation: "insert_row".into(),
                        message: e.to_string(),
                    })?;
            }
        }

        // Enforce strict engine-level read-only mode before preparing/executing user SQL
        conn.execute_batch("PRAGMA query_only = ON;")
            .map_err(|e| OmniError::Execution {
                operation: "sqlite_readonly".into(),
                message: e.to_string(),
            })?;

        // Execute read-only analytical query
        let mut query_stmt = conn
            .prepare(query)
            .map_err(|e| OmniError::InvalidInput(format!("SQL syntax error: {e}")))?;
        if !query_stmt.readonly() {
            return Err(OmniError::Security(
                "Only strictly read-only SQL queries are permitted in storage.sql".into(),
            ));
        }

        let col_count = query_stmt.column_count();
        let col_names: Vec<String> = query_stmt
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut rows = query_stmt.query([]).map_err(|e| OmniError::Execution {
            operation: "execute_query".into(),
            message: e.to_string(),
        })?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().map_err(|e| OmniError::Execution {
            operation: "fetch_row".into(),
            message: e.to_string(),
        })? {
            let mut row_map = serde_json::Map::new();
            for (i, name) in col_names.iter().enumerate().take(col_count) {
                let raw_ref = row.get_ref(i).map_err(|e| OmniError::Execution {
                    operation: "column_read".into(),
                    message: e.to_string(),
                })?;
                let val = match raw_ref {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                    ValueRef::Blob(b) => json!(hex::encode(b)),
                };
                row_map.insert(name.clone(), val);
            }
            results.push(Value::Object(row_map));
        }

        Ok(DataPayload::json(json!({
            "query": query,
            "columns": col_names,
            "row_count": results.len(),
            "rows": results,
        })))
    }
}
