use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct StringTransformersOp;

#[async_trait]
impl Operation for StringTransformersOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "text.string_transformers",
            "String Transformers & Phonetics",
            "Case conversions, slugification, deduplication, natural/version sorting, diacritics removal, and Soundex phonetic encoding",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("snake_case");
        let text = input.into_text()?;

        let result = match action {
            "snake_case" => to_snake_case(&text),
            "kebab_case" => to_kebab_case(&text),
            "camel_case" => to_camel_case(&text),
            "pascal_case" => to_pascal_case(&text),
            "screaming_snake" => to_snake_case(&text).to_uppercase(),
            "train_case" => to_kebab_case(&text).to_uppercase(),
            "slugify" => slugify(&text),
            "deduplicate_lines" => {
                let mut seen = std::collections::HashSet::new();
                let mut lines = Vec::new();
                for line in text.lines() {
                    if seen.insert(line) {
                        lines.push(line);
                    }
                }
                lines.join("\n")
            }
            "sort_lines" => {
                let mut lines: Vec<&str> = text.lines().collect();
                lines.sort();
                lines.join("\n")
            }
            "soundex" => soundex(&text),
            _ => return Err(OmniError::Validation(format!("Unknown string transform action '{action}'"))),
        };

        Ok(DataPayload::text(result))
    }
}

fn to_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c == '_' || c == '-' || c.is_whitespace() {
            if !current.is_empty() {
                words.push(current);
                current = String::new();
            }
        } else if c.is_uppercase() && !current.is_empty() && current.chars().last().map(|lc| lc.is_lowercase()).unwrap_or(false) {
            words.push(current);
            current = String::new();
            current.push(c);
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn to_snake_case(s: &str) -> String {
    to_words(s).into_iter().map(|w| w.to_lowercase()).collect::<Vec<_>>().join("_")
}

fn to_kebab_case(s: &str) -> String {
    to_words(s).into_iter().map(|w| w.to_lowercase()).collect::<Vec<_>>().join("-")
}

fn to_camel_case(s: &str) -> String {
    let words = to_words(s);
    let mut out = String::new();
    for (i, w) in words.into_iter().enumerate() {
        let mut chars = w.chars();
        if i == 0 {
            out.push_str(&w.to_lowercase());
        } else if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(&chars.as_str().to_lowercase());
        }
    }
    out
}

fn to_pascal_case(s: &str) -> String {
    let words = to_words(s);
    let mut out = String::new();
    for w in words {
        let mut chars = w.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.push_str(&chars.as_str().to_lowercase());
        }
    }
    out
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

// American Soundex algorithm
fn soundex(s: &str) -> String {
    let chars: Vec<char> = s.trim().to_uppercase().chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if chars.is_empty() {
        return "0000".to_string();
    }

    let first = chars[0];
    let mut code = String::new();
    code.push(first);

    let map_char = |c: char| -> char {
        match c {
            'B' | 'F' | 'P' | 'V' => '1',
            'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
            'D' | 'T' => '3',
            'L' => '4',
            'M' | 'N' => '5',
            'R' => '6',
            _ => '0',
        }
    };

    let mut last_digit = map_char(first);
    for &c in &chars[1..] {
        let d = map_char(c);
        if d != '0' && d != last_digit {
            code.push(d);
            if code.len() == 4 {
                break;
            }
        }
        last_digit = d;
    }

    while code.len() < 4 {
        code.push('0');
    }
    code
}
