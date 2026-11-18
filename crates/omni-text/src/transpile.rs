use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct TranspilerOp;

fn value_to_tabular_cell(val: &Value) -> String {
    match val {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn write_delimited(arr: &[Value], delimiter: u8, op_name: &str) -> OmniResult<String> {
    let mut wtr = csv::WriterBuilder::new()
        .delimiter(delimiter)
        .from_writer(Vec::new());
    if let Some(Value::Object(first_obj)) = arr.first() {
        let headers: Vec<&String> = first_obj.keys().collect();
        wtr.write_record(&headers)
            .map_err(|e| OmniError::Execution {
                operation: op_name.into(),
                message: e.to_string(),
            })?;
        for item in arr {
            if let Value::Object(obj) = item {
                let row: Vec<String> = headers
                    .iter()
                    .map(|&h| obj.get(h).map(value_to_tabular_cell).unwrap_or_default())
                    .collect();
                wtr.write_record(&row).map_err(|e| OmniError::Execution {
                    operation: op_name.into(),
                    message: e.to_string(),
                })?;
            }
        }
    }
    let bytes = wtr.into_inner().map_err(|e| OmniError::Execution {
        operation: op_name.into(),
        message: e.to_string(),
    })?;
    String::from_utf8(bytes).map_err(|e| OmniError::Execution {
        operation: op_name.into(),
        message: e.to_string(),
    })
}

#[async_trait]
impl Operation for TranspilerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "transpile.structured",
            "Omni-Format Transpiler",
            "Converts structured documents bidirectionally between JSON, YAML, TOML, CSV, and TSV",
            OperationCategory::TextAndCode,
        )
        .with_types(
            vec![DataType::Text, DataType::Json],
            vec![DataType::Text, DataType::Json],
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec![
            "transpile".into(),
            "json".into(),
            "yaml".into(),
            "toml".into(),
            "csv".into(),
            "tsv".into(),
        ])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let from_format = config
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("json")
            .to_lowercase();
        let to_format = config
            .get("to")
            .and_then(|v| v.as_str())
            .unwrap_or("yaml")
            .to_lowercase();

        let raw_text = input.into_text()?;

        // Parse into intermediate JSON Value
        let intermediate_val: Value = match from_format.as_str() {
            "json" | "jsonc" | "json5" => serde_json::from_str(&raw_text)
                .map_err(|e| OmniError::InvalidInput(format!("JSON parse error: {e}")))?,
            "yaml" | "yml" => serde_yaml::from_str(&raw_text)
                .map_err(|e| OmniError::InvalidInput(format!("YAML parse error: {e}")))?,
            "toml" => toml::from_str(&raw_text)
                .map_err(|e| OmniError::InvalidInput(format!("TOML parse error: {e}")))?,
            "csv" => {
                let mut rdr = csv::Reader::from_reader(raw_text.as_bytes());
                let headers = rdr
                    .headers()
                    .map_err(|e| OmniError::InvalidInput(e.to_string()))?
                    .clone();
                let mut records = Vec::new();
                for result in rdr.records() {
                    let record = result.map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    let mut map = serde_json::Map::new();
                    for (h, field) in headers.iter().zip(record.iter()) {
                        map.insert(h.to_string(), Value::String(field.to_string()));
                    }
                    records.push(Value::Object(map));
                }
                Value::Array(records)
            }
            "tsv" => {
                let mut rdr = csv::ReaderBuilder::new()
                    .delimiter(b'\t')
                    .from_reader(raw_text.as_bytes());
                let headers = rdr
                    .headers()
                    .map_err(|e| OmniError::InvalidInput(e.to_string()))?
                    .clone();
                let mut records = Vec::new();
                for result in rdr.records() {
                    let record = result.map_err(|e| OmniError::InvalidInput(e.to_string()))?;
                    let mut map = serde_json::Map::new();
                    for (h, field) in headers.iter().zip(record.iter()) {
                        map.insert(h.to_string(), Value::String(field.to_string()));
                    }
                    records.push(Value::Object(map));
                }
                Value::Array(records)
            }
            _ => serde_json::from_str(&raw_text).map_err(|e| {
                OmniError::InvalidInput(format!("Unknown source format '{from_format}': {e}"))
            })?,
        };

        // Serialize intermediate value to target format
        let output_text = match to_format.as_str() {
            "json" => serde_json::to_string_pretty(&intermediate_val).map_err(|e| {
                OmniError::Execution {
                    operation: "json_out".into(),
                    message: e.to_string(),
                }
            })?,
            "json_min" => {
                serde_json::to_string(&intermediate_val).map_err(|e| OmniError::Execution {
                    operation: "json_min_out".into(),
                    message: e.to_string(),
                })?
            }
            "yaml" | "yml" => {
                serde_yaml::to_string(&intermediate_val).map_err(|e| OmniError::Execution {
                    operation: "yaml_out".into(),
                    message: e.to_string(),
                })?
            }
            "toml" => {
                toml::to_string_pretty(&intermediate_val).map_err(|e| OmniError::Execution {
                    operation: "toml_out".into(),
                    message: e.to_string(),
                })?
            }
            "csv" => {
                if let Value::Array(arr) = &intermediate_val {
                    write_delimited(arr, b',', "csv_out")?
                } else {
                    return Err(OmniError::Validation(
                        "CSV export requires an array of JSON objects".into(),
                    ));
                }
            }
            "tsv" => {
                if let Value::Array(arr) = &intermediate_val {
                    write_delimited(arr, b'\t', "tsv_out")?
                } else {
                    return Err(OmniError::Validation(
                        "TSV export requires an array of JSON objects".into(),
                    ));
                }
            }
            _ => serde_json::to_string_pretty(&intermediate_val).map_err(|e| {
                OmniError::Execution {
                    operation: "json_out".into(),
                    message: e.to_string(),
                }
            })?,
        };

        Ok(DataPayload::text(output_text))
    }
}
