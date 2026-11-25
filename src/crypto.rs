//! Field decryption: `base64( 0x04 0x01 | nonce[24] | secretbox )`.
//!
//! Termius encrypts each sensitive field with libsodium `crypto_secretbox`
//! (XSalsa20-Poly1305) under the 32-byte local key. The envelope is a 2-byte
//! version header, a 24-byte nonce, then the Poly1305-authenticated ciphertext.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Nonce, XSalsa20Poly1305};

use crate::v8::Value;

const HEADER: [u8; 2] = [0x04, 0x01];
const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 16;
const MIN_LEN: usize = HEADER.len() + NONCE_LEN + MAC_LEN;

/// Decryptor holding the initialized secretbox cipher.
pub struct Decryptor {
    cipher: XSalsa20Poly1305,
    pub ok: u64,
    pub fail: u64,
}

impl Decryptor {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!("local key must be 32 bytes, got {}", key.len()));
        }
        Ok(Self {
            cipher: XSalsa20Poly1305::new(key.into()),
            ok: 0,
            fail: 0,
        })
    }

    /// Decrypt a single field. Non-encrypted values are returned unchanged.
    pub fn field(&mut self, value: &str) -> String {
        match self.try_field(value) {
            Some(plain) => {
                self.ok += 1;
                plain
            }
            None => value.to_string(),
        }
    }

    fn try_field(&mut self, value: &str) -> Option<String> {
        if value.len() < 24 || !value.len().is_multiple_of(4) {
            return None;
        }
        let raw = STANDARD.decode(value).ok()?;
        if raw.len() < MIN_LEN || raw[..2] != HEADER {
            return None;
        }
        let nonce = Nonce::from_slice(&raw[2..2 + NONCE_LEN]);
        match self.cipher.decrypt(nonce, &raw[2 + NONCE_LEN..]) {
            Ok(pt) => Some(String::from_utf8_lossy(&pt).into_owned()),
            Err(_) => {
                self.fail += 1;
                None
            }
        }
    }

    /// Recursively decrypt every string inside a value.
    pub fn walk(&mut self, v: &Value) -> Value {
        match v {
            Value::Str(s) => Value::Str(self.field(s)),
            Value::Object(m) => {
                let mut out = std::collections::BTreeMap::new();
                for (k, val) in m {
                    out.insert(k.clone(), self.walk(val));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| self.walk(x)).collect()),
            other => other.clone(),
        }
    }
}
