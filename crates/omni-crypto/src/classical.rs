use omni_core::{
    async_trait, DataPayload, ExecutionContext, FeatureStatus, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

// ======================== ROT5 / ROT13 / ROT18 / ROT47 ========================
pub struct RotOp {
    pub variant: String,
}

#[async_trait]
impl Operation for RotOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!("cipher.{}", self.variant.to_lowercase()),
            format!("ROT{}", self.variant),
            format!("Classical Caesar rotation cipher (ROT{})", self.variant),
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec![
            "cipher".into(),
            "classical".into(),
            format!("rot{}", self.variant),
        ])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let s = input.into_text()?;
        let out: String = match self.variant.as_str() {
            "5" => s
                .chars()
                .map(|c| {
                    if c.is_ascii_digit() {
                        let d = c as u8 - b'0';
                        ((d + 5) % 10 + b'0') as char
                    } else {
                        c
                    }
                })
                .collect(),
            "13" => s
                .chars()
                .map(|c| {
                    if c.is_ascii_lowercase() {
                        (((c as u8 - b'a' + 13) % 26) + b'a') as char
                    } else if c.is_ascii_uppercase() {
                        (((c as u8 - b'A' + 13) % 26) + b'A') as char
                    } else {
                        c
                    }
                })
                .collect(),
            "18" => s
                .chars()
                .map(|c| {
                    if c.is_ascii_digit() {
                        ((c as u8 - b'0' + 5) % 10 + b'0') as char
                    } else if c.is_ascii_lowercase() {
                        (((c as u8 - b'a' + 13) % 26) + b'a') as char
                    } else if c.is_ascii_uppercase() {
                        (((c as u8 - b'A' + 13) % 26) + b'A') as char
                    } else {
                        c
                    }
                })
                .collect(),
            "47" => s
                .chars()
                .map(|c| {
                    let code = c as u32;
                    if (33..=126).contains(&code) {
                        char::from_u32(33 + ((code + 14) % 94)).unwrap_or(c)
                    } else {
                        c
                    }
                })
                .collect(),
            _ => s,
        };
        Ok(DataPayload::text(out))
    }
}

// ======================== ATBASH ========================
pub struct AtbashOp;
#[async_trait]
impl Operation for AtbashOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cipher.atbash",
            "Atbash Cipher",
            "Classical substitution cipher reversing the alphabet (A <-> Z, B <-> Y)",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cipher".into(), "classical".into(), "atbash".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let s = input.into_text()?;
        let out: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    (b'z' - (c as u8 - b'a')) as char
                } else if c.is_ascii_uppercase() {
                    (b'Z' - (c as u8 - b'A')) as char
                } else {
                    c
                }
            })
            .collect();
        Ok(DataPayload::text(out))
    }
}

// ======================== AFFINE CIPHER ========================
pub struct AffineOp;
#[async_trait]
impl Operation for AffineOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cipher.affine",
            "Affine Cipher",
            "Affine monoalphabetic substitution cipher: E(x) = (a*x + b) mod 26",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cipher".into(), "classical".into(), "affine".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let raw_a = config.get("a").and_then(|v| v.as_i64()).unwrap_or(5);
        let raw_b = config.get("b").and_then(|v| v.as_i64()).unwrap_or(8);
        let a = raw_a.rem_euclid(26);
        let b = raw_b.rem_euclid(26);
        let decode = config
            .get("decode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Find modular multiplicative inverse of a mod 26
        let mut a_inv = None;
        for i in 1..26 {
            if (a * i) % 26 == 1 {
                a_inv = Some(i);
                break;
            }
        }
        let a_inv = a_inv.ok_or_else(|| {
            OmniError::Validation(format!("Parameter 'a' ({raw_a}) must be coprime with 26"))
        })?;

        let s = input.into_text()?;
        let out: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let is_upper = c.is_ascii_uppercase();
                    let base = if is_upper { b'A' } else { b'a' } as i64;
                    let x = c as i64 - base;
                    let res = if decode {
                        (a_inv * (x - b)).rem_euclid(26)
                    } else {
                        (a * x + b).rem_euclid(26)
                    };
                    (base + res) as u8 as char
                } else {
                    c
                }
            })
            .collect();
        Ok(DataPayload::text(out))
    }
}

// ======================== VIGENÈRE CIPHER ========================
pub struct VigenereOp;
#[async_trait]
impl Operation for VigenereOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cipher.vigenere",
            "Vigenère Cipher",
            "Polyalphabetic substitution cipher using a keyword",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cipher".into(), "classical".into(), "vigenere".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let key = config
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("KEY")
            .to_ascii_uppercase();
        let decode = config
            .get("decode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if key.is_empty() {
            return Err(OmniError::Validation("Key cannot be empty".into()));
        }

        let key_bytes: Vec<i64> = key
            .bytes()
            .filter(|b| b.is_ascii_alphabetic())
            .map(|b| (b - b'A') as i64)
            .collect();
        if key_bytes.is_empty() {
            return Err(OmniError::Validation(
                "Key must contain alphabetic characters".into(),
            ));
        }

        let s = input.into_text()?;
        let mut key_idx = 0;
        let out: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let is_upper = c.is_ascii_uppercase();
                    let base = if is_upper { b'A' } else { b'a' } as i64;
                    let shift = key_bytes[key_idx % key_bytes.len()];
                    key_idx += 1;
                    let x = c as i64 - base;
                    let res = if decode {
                        (x - shift + 26).rem_euclid(26)
                    } else {
                        (x + shift).rem_euclid(26)
                    };
                    (base + res) as u8 as char
                } else {
                    c
                }
            })
            .collect();
        Ok(DataPayload::text(out))
    }
}

// ======================== MORSE CODE ========================
pub struct MorseOp;
#[async_trait]
impl Operation for MorseOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cipher.morse",
            "Morse Code",
            "Encodes text into International Morse code (dots and dashes) and decodes it",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cipher".into(), "classical".into(), "morse".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let decode = config
            .get("decode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        const TABLE: &[(char, &str)] = &[
            ('A', ".-"),
            ('B', "-..."),
            ('C', "-.-."),
            ('D', "-.."),
            ('E', "."),
            ('F', "..-."),
            ('G', "--."),
            ('H', "...."),
            ('I', ".."),
            ('J', ".---"),
            ('K', "-.-"),
            ('L', ".-.."),
            ('M', "--"),
            ('N', "-."),
            ('O', "---"),
            ('P', ".--."),
            ('Q', "--.-"),
            ('R', ".-."),
            ('S', "..."),
            ('T', "-"),
            ('U', "..-"),
            ('V', "...-"),
            ('W', ".--"),
            ('X', "-..-"),
            ('Y', "-.--"),
            ('Z', "--.."),
            ('0', "-----"),
            ('1', ".----"),
            ('2', "..---"),
            ('3', "...--"),
            ('4', "....-"),
            ('5', "....."),
            ('6', "-...."),
            ('7', "--..."),
            ('8', "---.."),
            ('9', "----."),
            ('.', ".-.-.-"),
            (',', "--..--"),
            ('?', "..--.."),
        ];

        let s = input.into_text()?;
        if decode {
            let mut words_out = Vec::new();
            for word in s.split(" / ") {
                let mut word_str = String::new();
                for symbol in word.split_whitespace() {
                    if let Some(&(ch, _)) = TABLE.iter().find(|&&(_, code)| code == symbol) {
                        word_str.push(ch);
                    }
                }
                words_out.push(word_str);
            }
            Ok(DataPayload::text(words_out.join(" ")))
        } else {
            let mut encoded_words = Vec::new();
            for word in s.split_whitespace() {
                let mut codes = Vec::new();
                for ch in word.to_ascii_uppercase().chars() {
                    if let Some(&(_, code)) = TABLE.iter().find(|&&(c, _)| c == ch) {
                        codes.push(code);
                    }
                }
                encoded_words.push(codes.join(" "));
            }
            Ok(DataPayload::text(encoded_words.join(" / ")))
        }
    }
}

/// Computes the inverse permutation of a 26-letter Enigma rotor wiring dynamically.
fn invert_rotor(wiring: &[u8; 26]) -> [usize; 26] {
    let mut inv = [0usize; 26];
    for (i, &b) in wiring.iter().enumerate() {
        let idx = (b.saturating_sub(b'A') as usize) % 26;
        inv[idx] = i;
    }
    inv
}

// ======================== ENIGMA SIMULATOR ========================
pub struct EnigmaOp;
#[async_trait]
impl Operation for EnigmaOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "cipher.enigma",
            "Enigma Rotor Simulator",
            "Accurate Enigma I / M3 electromechanical rotor cipher simulation",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["cipher".into(), "classical".into(), "enigma".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        // Rotor wirings (I, II, III) and Reflector B
        const ROTOR_I: &[u8; 26] = b"EKMFLGDQVZNTOWYHXUSPAIBRCJ";
        const ROTOR_II: &[u8; 26] = b"AJDKSIRUXBLHWTMCQGZNPYFVOE";
        const ROTOR_III: &[u8; 26] = b"BDFHJLCPRTXVZNYEIWGAKMUSQO";
        const REFLECTOR_B: &[u8; 26] = b"YRUHQSLDPXNGOKMIEBFZCWVJAT";

        let inv_i = invert_rotor(ROTOR_I);
        let inv_ii = invert_rotor(ROTOR_II);
        let inv_iii = invert_rotor(ROTOR_III);

        // Authentic Enigma I turnover notch positions: Rotor I = Q (16), Rotor II = E (4), Rotor III = V (21)
        const NOTCH_II: usize = (b'E' - b'A') as usize;
        const NOTCH_III: usize = (b'V' - b'A') as usize;

        let mut r1_pos = (config.get("pos1").and_then(|v| v.as_u64()).unwrap_or(0) % 26) as usize;
        let mut r2_pos = (config.get("pos2").and_then(|v| v.as_u64()).unwrap_or(0) % 26) as usize;
        let mut r3_pos = (config.get("pos3").and_then(|v| v.as_u64()).unwrap_or(0) % 26) as usize;

        let s = input.into_text()?;
        let mut out = String::with_capacity(s.len());

        for c in s.to_ascii_uppercase().chars() {
            if !c.is_ascii_alphabetic() {
                out.push(c);
                continue;
            }

            // Authentic Enigma I / M3 stepping with middle-rotor double-stepping
            let r2_at_notch = r2_pos == NOTCH_II;
            let r3_at_notch = r3_pos == NOTCH_III;
            if r2_at_notch {
                r1_pos = (r1_pos + 1) % 26;
                r2_pos = (r2_pos + 1) % 26;
            } else if r3_at_notch {
                r2_pos = (r2_pos + 1) % 26;
            }
            r3_pos = (r3_pos + 1) % 26;

            let mut val = (c as u8 - b'A') as usize;

            // Forward through rotors III -> II -> I (properly normalized relative to 'A')
            val = ((ROTOR_III[(val + r3_pos) % 26] - b'A') as usize + 26 - r3_pos) % 26;
            val = ((ROTOR_II[(val + r2_pos) % 26] - b'A') as usize + 26 - r2_pos) % 26;
            val = ((ROTOR_I[(val + r1_pos) % 26] - b'A') as usize + 26 - r1_pos) % 26;

            // Reflector (involutory permutation: R(R(x)) == x, R(x) != x)
            val = (REFLECTOR_B[val] - b'A') as usize;

            // Backward through inverse rotors I -> II -> III
            val = (inv_i[(val + r1_pos) % 26] + 26 - r1_pos) % 26;
            val = (inv_ii[(val + r2_pos) % 26] + 26 - r2_pos) % 26;
            val = (inv_iii[(val + r3_pos) % 26] + 26 - r3_pos) % 26;

            out.push((b'A' + val as u8) as char);
        }

        Ok(DataPayload::text(out))
    }
}
