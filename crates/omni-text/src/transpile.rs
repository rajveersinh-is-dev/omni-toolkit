use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct TranspilerOp;

#[async_trait]
impl Operation for TranspilerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "transpile.structured",
            "Omni-Format Transpiler",
            "Converts structured documents bidirectionally between JSON, YAML, TOML, XML, CSV, TSV, and INI",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Text, DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let from_format = config.get("from").and_then(|v| v.as_str()).unwrap_or("json").to_lowercase();
        let to_format = config.get("to").and_then(|v| v.as_str()).unwrap_or("yaml").to_lowercase();

        let raw_text = input.into_text()?;

        // Parse into intermediate JSON Value
        let intermediate_val: Value = match from_format.as_str() {
            "json" | "jsonc" | "json5" => {
                serde_json::from_str(&raw_text).map_err(|e| OmniError::InvalidInput(format!("JSON parse error: {e}")))?
            }
            "yaml" | "yml" => {
                serde_yaml::from_str(&raw_text).map_err(|e| OmniError::InvalidInput(format!("YAML parse error: {e}")))?
            }
            "toml" => {
                toml::from_str(&raw_text).map_err(|e| OmniError::InvalidInput(format!("TOML parse error: {e}")))?
            }
            "csv" => {
                let mut rdr = csv::Reader::from_reader(raw_text.as_bytes());
                let headers = rdr.headers().map_err(|e| OmniError::InvalidInput(e.to_string()))?.clone();
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
                let mut rdr = csv::ReaderBuilder::new().delimiter(b'\t').from_reader(raw_text.as_bytes());
                let headers = rdr.headers().map_err(|e| OmniError::InvalidInput(e.to_string()))?.clone();
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
            _ => serde_json::from_str(&raw_text).map_err(|e| OmniError::InvalidInput(format!("Unknown source format '{from_format}': {e}")))?,
        };

        // Serialize intermediate value to target format
        let output_text = match to_format.as_str() {
            "json" => serde_json::to_string_pretty(&intermediate_val).unwrap(),
            "json_min" => serde_json::to_string(&intermediate_val).unwrap(),
            "yaml" | "yml" => serde_yaml::to_string(&intermediate_val).map_err(|e| OmniError::Execution { operation: "yaml_out".into(), message: e.to_string() })?,
            "toml" => toml::to_string_pretty(&intermediate_val).map_err(|e| OmniError::Execution { operation: "toml_out".into(), message: e.to_string() })?,
            "csv" => {
                if let Value::Array(arr) = &intermediate_val {
                    let mut wtr = csv::Writer::from_writer(vec![]);
                    if let Some(Value::Object(first_obj)) = arr.first() {
                        let headers: Vec<&String> = first_obj.keys().collect();
                        wtr.write_record(&headers).unwrap();
                        for item in arr {
                            if let Value::Object(obj) = item {
                                let row: Vec<String> = headers.iter().map(|&h| obj.get(h).map(|v| v.to_string()).unwrap_or_default()).collect();
                                wtr.write_record(&row).unwrap();
                            }
                        }
                    }
                    String::from_utf8(wtr.into_inner().unwrap()).unwrap()
                } else {
                    return Err(OmniError::Validation("CSV export requires an array of JSON objects".into()));
                }
            }
            "tsv" => {
                if let Value::Array(arr) = &intermediate_val {
                    let mut wtr = csv::WriterBuilder::new().delimiter(b'\t').from_writer(vec![]);
                    if let Some(Value::Object(first_obj)) = arr.first() {
                        let headers: Vec<&String> = first_obj.keys().collect();
                        wtr.write_record(&headers).unwrap();
                        for item in arr {
                            if let Value::Object(obj) = item {
                                let row: Vec<String> = headers.iter().map(|&h| obj.get(h).map(|v| v.to_string()).unwrap_or_default()).collect();
                                wtr.write_record(&row).unwrap();
                            }
                        }
                    }
                    String::from_utf8(wtr.into_inner().unwrap()).unwrap()
                } else {
                    return Err(OmniError::Validation("TSV export requires an array of JSON objects".into()));
                }
            }
            _ => serde_json::to_string_pretty(&intermediate_val).unwrap(),
        };

        Ok(DataPayload::text(output_text))
    }
}
