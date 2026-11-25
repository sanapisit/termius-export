//! termius-export — offline exporter for a local Termius install.
//!
//! Reads the local key from the OS credential store, parses Termius's IndexedDB
//! (V8 structured clone), decrypts fields (XSalsa20-Poly1305), and writes an
//! `ssh_config`, a CSV, optional JSON, and the private-key files. No Termius
//! account password is required.

mod cred;
mod crypto;
mod model;
mod ppk;
mod v8;

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;

use crypto::Decryptor;
use model::{Host, Resolved};

#[derive(Parser, Debug)]
#[command(name = "termius-export", version, about)]
struct Args {
    /// Termius LevelDB dir (or Termius data root). Defaults to the local install.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Output directory.
    #[arg(long, default_value = "termius_export")]
    out: PathBuf,

    /// 32-byte local key, base64.
    #[arg(long)]
    local_key: Option<String>,

    /// File containing the base64 local key.
    #[arg(long)]
    local_key_file: Option<String>,

    /// Also write passwords into the CSV and dump private-key files.
    #[arg(long)]
    include_secrets: bool,

    /// Also write the fully decrypted records as JSON.
    #[arg(long)]
    json: bool,
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    let data_dir = resolve_data_dir(args.data_dir)?;
    let (key, key_source) = cred::resolve(args.local_key.as_deref(), args.local_key_file.as_deref())?;
    println!("local key: {key_source}");
    println!("data dir:  {}", data_dir.display());

    let data = read_leveldb(&data_dir)?;
    let raw_records = v8::scan_records(&data);

    let mut dec = Decryptor::new(&key)?;
    let records: Vec<v8::Value> = raw_records.iter().map(|r| dec.walk(r)).collect();
    println!(
        "records: {}   decrypted fields: {} (failed {})",
        records.len(),
        dec.ok,
        dec.fail
    );
    if dec.ok == 0 {
        return Err("no fields decrypted — the local key is likely wrong".into());
    }

    let resolved = model::resolve(&records);
    println!("hosts: {}   keys: {}", resolved.hosts.len(), resolved.keys.len());

    fs::create_dir_all(&args.out).map_err(|e| format!("cannot create {}: {e}", args.out.display()))?;
    write_ssh_config(&args.out, &resolved, args.include_secrets)?;
    write_csv(&args.out, &resolved.hosts, args.include_secrets)?;
    if args.include_secrets {
        write_keys(&args.out, &resolved)?;
    }
    if args.json {
        let json = serde_json::to_string_pretty(&records_to_json(&records))
            .map_err(|e| e.to_string())?;
        fs::write(args.out.join("records.json"), json).map_err(|e| e.to_string())?;
    }

    print_table(&resolved.hosts);
    println!("\nwritten to {}", args.out.display());
    if !args.include_secrets {
        println!("(pass --include-secrets to also export passwords and private keys)");
    }
    Ok(())
}

/// Find the LevelDB dir: use `data_dir` if it holds `.log`/`.ldb`, else look
/// under it, else fall back to the default install location.
fn resolve_data_dir(arg: Option<PathBuf>) -> Result<PathBuf, String> {
    let candidates = match arg {
        Some(p) => vec![p.clone(), p.join("IndexedDB/file__0.indexeddb.leveldb")],
        None => vec![default_data_dir()?],
    };
    for c in &candidates {
        if has_leveldb(c) {
            return Ok(c.clone());
        }
    }
    Err(format!(
        "no LevelDB files (*.log/*.ldb) under {}",
        candidates[0].display()
    ))
}

fn default_data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA").map_err(|_| "APPDATA not set")?;
        Ok(PathBuf::from(appdata).join("Termius/IndexedDB/file__0.indexeddb.leveldb"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
        Ok(PathBuf::from(home)
            .join("Library/Application Support/Termius/IndexedDB/file__0.indexeddb.leveldb"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
        Ok(PathBuf::from(home).join(".config/Termius/IndexedDB/file__0.indexeddb.leveldb"))
    }
}

fn has_leveldb(dir: &Path) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.ends_with(".log") || name.ends_with(".ldb")
    })
}

/// Read every `.log`/`.ldb` file and concatenate the bytes.
fn read_leveldb(dir: &Path) -> Result<Vec<u8>, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "log" || x == "ldb")
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    let mut data = Vec::new();
    for f in files {
        match fs::read(&f) {
            Ok(mut bytes) => data.append(&mut bytes),
            Err(e) => eprintln!("warning: skipping {}: {e}", f.display()),
        }
    }
    if data.is_empty() {
        return Err("no data read from LevelDB files".into());
    }
    Ok(data)
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in s.trim().chars() {
        if ch.is_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "host".into()
    } else {
        out
    }
}

fn write_ssh_config(out: &Path, r: &Resolved, secrets: bool) -> Result<(), String> {
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut lines = vec![
        "# Exported from a local Termius install by termius-export".to_string(),
        "# Append to ~/.ssh/config and adjust IdentityFile paths.".to_string(),
        "# Password-auth hosts: see hosts.csv.".to_string(),
        String::new(),
    ];
    for h in &r.hosts {
        let mut name = slug(&h.label);
        let base = name.clone();
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}-{n}");
            n += 1;
        }
        lines.push(format!("Host {name}"));
        if !h.group.is_empty() {
            lines.push(format!("    # group: {}", h.group));
        }
        lines.push(format!("    HostName {}", h.address));
        if !h.username.is_empty() {
            lines.push(format!("    User {}", h.username));
        }
        if h.port != 22 {
            lines.push(format!("    Port {}", h.port));
        }
        if !h.key_label.is_empty() {
            if secrets {
                lines.push(format!("    IdentityFile ~/.ssh/termius-keys/{}", h.key_label));
            } else {
                lines.push(format!("    # key in Termius: {}", h.key_label));
            }
        }
        lines.push(String::new());
    }
    fs::write(out.join("ssh_config"), lines.join("\n")).map_err(|e| e.to_string())
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_csv(out: &Path, hosts: &[Host], secrets: bool) -> Result<(), String> {
    let mut rows =
        vec!["label,address,port,username,password,key_label,group".to_string()];
    for h in hosts {
        let pw = if secrets { h.password.as_str() } else { "" };
        rows.push(
            [
                &h.label,
                &h.address,
                &h.port.to_string(),
                &h.username,
                pw,
                &h.key_label,
                &h.group,
            ]
            .iter()
            .map(|s| csv_field(s))
            .collect::<Vec<_>>()
            .join(","),
        );
    }
    fs::write(out.join("hosts.csv"), rows.join("\n")).map_err(|e| e.to_string())
}

fn write_keys(out: &Path, r: &Resolved) -> Result<(), String> {
    if r.keys.is_empty() {
        return Ok(());
    }
    let dir = out.join("keys");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for k in &r.keys {
        let name = slug(&k.label);
        fs::write(dir.join(&name), &k.private_key).map_err(|e| e.to_string())?;
        if let Some(pub_key) = &k.public_key {
            fs::write(dir.join(format!("{name}.pub")), pub_key).map_err(|e| e.to_string())?;
        }
        // Convert PuTTY .ppk keys to an OpenSSH private key alongside the original.
        if k.private_key.starts_with("PuTTY-User-Key-File") {
            let openssh_name = format!("{}.key", name.trim_end_matches(".ppk"));
            match ppk::ppk_to_openssh(&k.private_key) {
                ppk::Convert::Ok(pem) => {
                    fs::write(dir.join(&openssh_name), pem).map_err(|e| e.to_string())?;
                    println!("converted {name} -> {openssh_name}");
                }
                ppk::Convert::Skip(reason) => {
                    println!("keep {name} as .ppk ({reason})");
                }
            }
        }
    }
    Ok(())
}

fn records_to_json(records: &[v8::Value]) -> serde_json::Value {
    serde_json::Value::Array(records.iter().map(value_to_json).collect())
}

fn value_to_json(v: &v8::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        v8::Value::Null => J::Null,
        v8::Value::Bool(b) => J::Bool(*b),
        v8::Value::Int(i) => J::Number((*i).into()),
        v8::Value::Double(d) => serde_json::Number::from_f64(*d).map(J::Number).unwrap_or(J::Null),
        v8::Value::Str(s) => J::String(s.clone()),
        v8::Value::Object(m) => {
            J::Object(m.iter().map(|(k, val)| (k.clone(), value_to_json(val))).collect())
        }
        v8::Value::Array(a) => J::Array(a.iter().map(value_to_json).collect()),
    }
}

fn print_table(hosts: &[Host]) {
    println!("\n{:<26}{:<34}AUTH", "LABEL", "USER@HOST:PORT");
    for h in hosts {
        let user = if h.username.is_empty() {
            String::new()
        } else {
            format!("{}@", h.username)
        };
        let loc = format!("{user}{}:{}", h.address, h.port);
        let auth = if !h.key_label.is_empty() {
            format!("key:{}", h.key_label)
        } else if !h.password.is_empty() {
            "password".into()
        } else {
            "-".into()
        };
        let label: String = h.label.chars().take(25).collect();
        println!("{label:<26}{loc:<34}{auth}");
    }
}
