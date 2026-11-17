use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Value};

pub struct EmbeddedSqlOp;

#[async_trait]
impl Operation for EmbeddedSqlOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "storage.sql",
            "In-Memory SQL Analytics Engine",
            "Executes analytical SQL queries over dynamically ingested CSV, TSV, or JSON tabular data using in-memory SQLite",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let query = config.get("query").and_then(|v| v.as_str()).unwrap_or("SELECT * FROM data LIMIT 20");
        let delimiter = config.get("delimiter").and_then(|v| v.as_str()).unwrap_or(",");

        let text = input.into_text().unwrap_or_default();
        let conn = Connection::open_in_memory()
            .map_err(|e| OmniError::Execution { operation: "sqlite_open".into(), message: e.to_string() })?;

        // Ingest CSV/TSV
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            return Err(OmniError::InvalidInput("No tabular data provided to query".into()));
        }

        let header_line = lines[0];
        let headers: Vec<String> = header_line.split(delimiter)
            .enumerate()
            .map(|(i, h)| {
                let clean: String = h.trim().chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
                if clean.is_empty() { format!("col_{}", i) } else { clean }
            })
            .collect();

        // Create table
        let cols_def = headers.iter().map(|h| format!("\"{}\" TEXT", h)).collect::<Vec<_>>().join(", ");
        conn.execute(&format!("CREATE TABLE data ({})", cols_def), [])
            .map_err(|e| OmniError::Execution { operation: "create_table".into(), message: e.to_string() })?;

        // Insert rows
        let placeholders = vec!["?"; headers.len()].join(", ");
        let insert_sql = format!("INSERT INTO data VALUES ({})", placeholders);
        let mut stmt = conn.prepare(&insert_sql)
            .map_err(|e| OmniError::Execution { operation: "prepare_insert".into(), message: e.to_string() })?;

        let empty_str = "";
        for line in &lines[1..] {
            let row_vals: Vec<&str> = line.split(delimiter).collect();
            let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();
            for i in 0..headers.len() {
                if i < row_vals.len() {
                    params.push(&row_vals[i]);
                } else {
                    params.push(&empty_str);
                }
            }
            stmt.execute(rusqlite::params_from_iter(params))
                .map_err(|e| OmniError::Execution { operation: "insert_row".into(), message: e.to_string() })?;
        }
        drop(stmt);

        // Run query
        let mut query_stmt = conn.prepare(query)
            .map_err(|e| OmniError::InvalidInput(format!("SQL Syntax error: {e}")))?;

        let col_count = query_stmt.column_count();
        let col_names: Vec<String> = query_stmt.column_names().iter().map(|s| s.to_string()).collect();

        let mut rows = query_stmt.query([])
            .map_err(|e| OmniError::Execution { operation: "execute_query".into(), message: e.to_string() })?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().map_err(|e| OmniError::Execution { operation: "fetch_row".into(), message: e.to_string() })? {
            let mut row_map = serde_json::Map::new();
            for (i, name) in col_names.iter().enumerate().take(col_count) {
                let val = match row.get_ref(i).unwrap() {
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
