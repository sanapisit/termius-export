//! Convert an unencrypted PuTTY `.ppk` (RSA) to an OpenSSH private key.
//!
//! Only `ssh-rsa` keys with `Encryption: none` are converted. Passphrase-
//! protected keys are reported as skipped — the user converts those in the
//! PuTTYgen GUI. No MAC verification is done; we only re-encode key material.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Outcome of a conversion attempt.
pub enum Convert {
    /// OpenSSH private key text (PEM, `-----BEGIN OPENSSH PRIVATE KEY-----`).
    Ok(String),
    /// Not converted, with a human-readable reason.
    Skip(String),
}

/// Convert PPK text to an OpenSSH private key, or explain why it was skipped.
pub fn ppk_to_openssh(text: &str) -> Convert {
    let normalized = text.replace("\r\n", "\n");
    let mut encryption = "";
    let mut comment = String::new();
    let mut alg = "";
    let mut public_blob: Option<Vec<u8>> = None;
    let mut private_blob: Option<Vec<u8>> = None;

    let lines: Vec<&str> = normalized.split('\n').collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some((key, val)) = line.split_once(':') {
            let val = val.trim();
            match key {
                k if k.starts_with("PuTTY-User-Key-File") => alg = val,
                "Encryption" => encryption = val,
                "Comment" => comment = val.to_string(),
                "Public-Lines" | "Private-Lines" => {
                    let n: usize = val.parse().unwrap_or(0);
                    let blob: String = lines[i + 1..(i + 1 + n).min(lines.len())].concat();
                    let decoded = STANDARD.decode(blob.trim()).unwrap_or_default();
                    if key == "Public-Lines" {
                        public_blob = Some(decoded);
                    } else {
                        private_blob = Some(decoded);
                    }
                    i += n;
                }
                _ => {}
            }
        }
        i += 1;
    }

    if alg.is_empty() {
        return Convert::Skip("not a PuTTY key".into());
    }
    if encryption != "none" {
        return Convert::Skip(format!("passphrase-protected ({encryption})"));
    }
    if !alg.contains("ssh-rsa") {
        return Convert::Skip(format!("unsupported key type: {alg}"));
    }
    let (Some(pub_blob), Some(priv_blob)) = (public_blob, private_blob) else {
        return Convert::Skip("missing key material".into());
    };

    match build_openssh(&pub_blob, &priv_blob, &comment) {
        Some(pem) => Convert::Ok(pem),
        None => Convert::Skip("could not parse RSA parameters".into()),
    }
}

fn read_field<'a>(b: &'a [u8], o: &mut usize) -> Option<&'a [u8]> {
    if *o + 4 > b.len() {
        return None;
    }
    let n = u32::from_be_bytes([b[*o], b[*o + 1], b[*o + 2], b[*o + 3]]) as usize;
    *o += 4;
    let end = o.checked_add(n)?;
    let slice = b.get(*o..end)?;
    *o = end;
    Some(slice)
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Encode a positive big-endian integer as an SSH mpint.
fn put_mpint(out: &mut Vec<u8>, raw: &[u8]) {
    let mut start = 0;
    while start < raw.len() && raw[start] == 0 {
        start += 1;
    }
    let value = &raw[start..];
    if value.is_empty() {
        put_string(out, &[]);
        return;
    }
    if value[0] & 0x80 != 0 {
        let mut padded = Vec::with_capacity(value.len() + 1);
        padded.push(0);
        padded.extend_from_slice(value);
        put_string(out, &padded);
    } else {
        put_string(out, value);
    }
}

fn build_openssh(pub_blob: &[u8], priv_blob: &[u8], comment: &str) -> Option<String> {
    // Public blob: "ssh-rsa", e, n
    let mut po = 0;
    let _alg = read_field(pub_blob, &mut po)?;
    let e = read_field(pub_blob, &mut po)?;
    let n = read_field(pub_blob, &mut po)?;
    // Private blob: d, p, q, iqmp
    let mut so = 0;
    let d = read_field(priv_blob, &mut so)?;
    let p = read_field(priv_blob, &mut so)?;
    let q = read_field(priv_blob, &mut so)?;
    let iqmp = read_field(priv_blob, &mut so)?;

    // Rebuild the public key blob in canonical form.
    let mut pubkey = Vec::new();
    put_string(&mut pubkey, b"ssh-rsa");
    put_mpint(&mut pubkey, e);
    put_mpint(&mut pubkey, n);

    // Private section: checkint x2, key, comment, padding.
    let mut priv_section = Vec::new();
    let check: u32 = 0xA5A5_A5A5;
    priv_section.extend_from_slice(&check.to_be_bytes());
    priv_section.extend_from_slice(&check.to_be_bytes());
    put_string(&mut priv_section, b"ssh-rsa");
    put_mpint(&mut priv_section, n);
    put_mpint(&mut priv_section, e);
    put_mpint(&mut priv_section, d);
    put_mpint(&mut priv_section, iqmp);
    put_mpint(&mut priv_section, p);
    put_mpint(&mut priv_section, q);
    put_string(&mut priv_section, comment.as_bytes());
    let mut pad: u8 = 1;
    while priv_section.len() % 8 != 0 {
        priv_section.push(pad);
        pad += 1;
    }

    // Outer container.
    let mut blob = Vec::new();
    blob.extend_from_slice(b"openssh-key-v1\0");
    put_string(&mut blob, b"none"); // cipher
    put_string(&mut blob, b"none"); // kdf
    put_string(&mut blob, b""); // kdf options
    blob.extend_from_slice(&1u32.to_be_bytes()); // key count
    put_string(&mut blob, &pubkey);
    put_string(&mut blob, &priv_section);

    let b64 = STANDARD.encode(&blob);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).ok()?);
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    Some(pem)
}
