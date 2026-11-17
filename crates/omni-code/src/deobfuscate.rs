use regex::Regex;
use std::collections::HashMap;

pub struct Deobfuscator;

impl Deobfuscator {
    /// Resolves hexadecimal character escapes (e.g. \x68\x65\x6c\x6c\x6f -> hello)
    pub fn resolve_hex_escapes(code: &str) -> String {
        let re = Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap();
        re.replace_all(code, |caps: &regex::Captures| {
            if let Ok(b) = u8::from_str_radix(&caps[1], 16) {
                if (32..=126).contains(&b) {
                    return (b as char).to_string();
                }
            }
            caps[0].to_string()
        }).to_string()
    }

    /// Normalizes obfuscated identifiers (like _0x4a12, _0x5b3c) into clean numbered variables (v_1, v_2)
    pub fn normalize_hex_identifiers(code: &str) -> (String, usize) {
        let re = Regex::new(r"\b_0x[0-9a-fA-F]{4,8}\b").unwrap();
        let mut id_map: HashMap<String, String> = HashMap::new();
        let mut counter = 1;

        for m in re.find_iter(code) {
            let id = m.as_str().to_string();
            if let std::collections::hash_map::Entry::Vacant(e) = id_map.entry(id) {
                e.insert(format!("v_{}", counter));
                counter += 1;
            }
        }

        let replaced = re.replace_all(code, |caps: &regex::Captures| {
            id_map.get(&caps[0]).cloned().unwrap_or_else(|| caps[0].to_string())
        }).to_string();

        (replaced, id_map.len())
    }

    /// Unpacks Dean Edwards JavaScript packed scripts: eval(function(p,a,c,k,e,d)...)
    pub fn unpack_eval_packer(code: &str) -> Option<String> {
        let pattern = Regex::new(r"(?s)eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)\s*\{.*?\}\s*\(\s*'([^']*)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'([^']*)'\.split\('\|'\)").ok()?;
        
        if let Some(caps) = pattern.captures(code) {
            let payload = caps.get(1)?.as_str();
            let _a: usize = caps.get(2)?.as_str().parse().ok()?;
            let c: usize = caps.get(3)?.as_str().parse().ok()?;
            let keywords: Vec<&str> = caps.get(4)?.as_str().split('|').collect();

            let mut lookup: HashMap<String, String> = HashMap::new();
            for i in (0..c).rev() {
                let key = if i < 36 {
                    std::char::from_digit(i as u32, 36)?.to_string()
                } else {
                    format!("{}", i)
                };
                let val = if i < keywords.len() && !keywords[i].is_empty() {
                    keywords[i].to_string()
                } else {
                    key.clone()
                };
                lookup.insert(key, val);
            }

            let word_re = Regex::new(r"\b\w+\b").ok()?;
            let unpacked = word_re.replace_all(payload, |w: &regex::Captures| {
                let token = &w[0];
                if let Some(sub) = lookup.get(token) {
                    sub.clone()
                } else {
                    token.to_string()
                }
            });

            return Some(unpacked.to_string());
        }

        None
    }
}
