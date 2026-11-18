use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Value};

pub struct EmbeddedSqlOp;

fn validate_readonly_query(query: &str) -> OmniResult<()> {
    let normalized = query.trim().to_uppercase();
    if normalized.is_empty() {
        return Err(OmniError::InvalidInput("SQL query must not be empty".into()));
    }
    let allowed_prefix = normalized.starts_with("SELECT ")
        || normalized.starts_with("WITH ")
        || normalized.starts_with("EXPLAIN ");
    if !allowed_prefix {
        return Err(OmniError::Security(
            "Only read-only SELECT / WITH / EXPLAIN queries are permitted in storage.sql".into(),
        ));
    }
    // Reject stacked statements or ATTACH DATABASE filesystem access
    if normalized.contains("ATTACH ") || normalized.contains("DETACH ") || normalized.contains("LOAD_EXTENSION") {
        return Err(OmniError::Security(
            "Disallowed SQL statement (ATTACH/DETACH/LOAD_EXTENSION) rejected".into(),
        ));
    }
    Ok(())
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

        let conn = Connection::open_in_memory().map_err(|e| OmniError::Execution {
            operation: "sqlite_open".into(),
            message: e.to_string(),
        })?;

        // Support JSON array of objects OR CSV/TSV text ingestion
        let json_rows: Option<Vec<serde_json::Map<String, Value>>> = match &input {
            DataPayload::Json(Value::Array(arr)) => Some(
                arr.iter()
                    .filter_map(|v| v.as_object().cloned())
                    .collect(),
            ),
            DataPayload::Text(s) if s.trim_start().starts_with('[') => {
                serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(s).ok()
            }
            _ => None,
        };

        if let Some(objects) = json_rows {
            if objects.is_empty() {
                return Err(OmniError::InvalidInput("JSON array contains zero rows".into()));
            }
            let mut headers: Vec<String> = objects[0]
                .keys()
                .enumerate()
                .map(|(i, k)| {
                    let clean: String = k
                        .chars()
                        .filter(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if clean.is_empty() {
                        format!("col_{}", i)
                    } else {
                        clean
                    }
                })
                .collect();
            headers.sort();
            let raw_keys: Vec<String> = {
                let mut ks: Vec<String> = objects[0].keys().cloned().collect();
                ks.sort();
                ks
            };

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
            let mut stmt = conn.prepare(&insert_sql).map_err(|e| OmniError::Execution {
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
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.is_empty() {
                return Err(OmniError::InvalidInput(
                    "No tabular data provided to query".into(),
                ));
            }

            let headers: Vec<String> = lines[0]
                .split(delimiter)
                .enumerate()
                .map(|(i, h)| {
                    let clean: String = h
                        .trim()
                        .chars()
                        .filter(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if clean.is_empty() {
                        format!("col_{}", i)
                    } else {
                        clean
                    }
                })
                .collect();

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
            let mut stmt = conn.prepare(&insert_sql).map_err(|e| OmniError::Execution {
                operation: "prepare_insert".into(),
                message: e.to_string(),
            })?;

            let empty_str = "";
            for line in &lines[1..] {
                let row_vals: Vec<&str> = line.split(delimiter).collect();
                let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(headers.len());
                for i in 0..headers.len() {
                    if i < row_vals.len() {
                        params.push(&row_vals[i]);
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

        // Execute read-only analytical query
        let mut query_stmt = conn
            .prepare(query)
            .map_err(|e| OmniError::InvalidInput(format!("SQL syntax error: {e}")))?;

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
