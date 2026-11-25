//! Local-key retrieval.
//!
//! Resolution order: explicit base64 arg, key file, `TERMIUS_LOCAL_KEY` env
//! var, then the OS credential store. On Windows the key lives in Credential
//! Manager under target `Termius/localKey` (the blob is the UTF-8 bytes of a
//! base64 string). No account password is involved.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Candidate Windows Credential Manager targets, in priority order.
const WIN_TARGETS: &[&str] = &["Termius/localKey", "termius/localKey", "termius-app/localKey"];

/// Decode a base64 local key and verify it is 32 bytes.
pub fn decode_key(b64: &str) -> Result<Vec<u8>, String> {
    let key = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("local key is not valid base64: {e}"))?;
    if key.len() != 32 {
        return Err(format!("local key must decode to 32 bytes, got {}", key.len()));
    }
    Ok(key)
}

/// Resolve the local key from the first available source.
pub fn resolve(
    inline: Option<&str>,
    key_file: Option<&str>,
) -> Result<(Vec<u8>, &'static str), String> {
    if let Some(b64) = inline {
        return Ok((decode_key(b64)?, "--local-key"));
    }
    if let Some(path) = key_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read key file {path}: {e}"))?;
        return Ok((decode_key(&text)?, "--local-key-file"));
    }
    if let Ok(b64) = std::env::var("TERMIUS_LOCAL_KEY") {
        return Ok((decode_key(&b64)?, "TERMIUS_LOCAL_KEY"));
    }
    #[cfg(windows)]
    {
        for target in WIN_TARGETS {
            if let Some(b64) = windows_cred::read(target) {
                if let Ok(key) = decode_key(&b64) {
                    return Ok((key, "Windows Credential Manager"));
                }
            }
        }
    }
    let _ = WIN_TARGETS; // silence unused on non-windows
    Err("local key not found: pass --local-key / --local-key-file, set \
         TERMIUS_LOCAL_KEY, or run on the machine where Termius stored it"
        .to_string())
}

#[cfg(windows)]
mod windows_cred {
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    /// Read a generic credential blob and return it as a UTF-8 string.
    pub fn read(target: &str) -> Option<String> {
        let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `wide` is a valid null-terminated UTF-16 string; on success
        // `cred_ptr` points to a buffer we free with `CredFree`.
        unsafe {
            if CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) == 0 {
                return None;
            }
            let cred = &*cred_ptr;
            let size = cred.CredentialBlobSize as usize;
            let bytes = std::slice::from_raw_parts(cred.CredentialBlob, size).to_vec();
            CredFree(cred_ptr as *const _);
            String::from_utf8(bytes).ok().map(|s| s.trim().to_string())
        }
    }
}
