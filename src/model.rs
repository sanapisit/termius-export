//! Turn decrypted records into resolved hosts and key files.
//!
//! Termius splits a connection across several object stores (host, identity,
//! ssh_config, group, ssh_key). Records that belong together share the same
//! `local_id`, which is the join key used here.

use std::collections::BTreeMap;

use crate::v8::Value;

/// One resolved host, ready for `ssh_config`/CSV output.
pub struct Host {
    pub label: String,
    pub address: String,
    pub port: i64,
    pub username: String,
    pub password: String,
    pub key_label: String,
    pub group: String,
}

/// A private key stored in Termius.
pub struct Key {
    pub label: String,
    pub private_key: String,
    pub public_key: Option<String>,
}

/// Resolution output.
pub struct Resolved {
    pub hosts: Vec<Host>,
    pub keys: Vec<Key>,
}

fn updated_at(v: &Value) -> &str {
    v.get("updated_at").and_then(Value::as_str).unwrap_or("")
}

/// Insert keeping the record with the greatest `updated_at` per key.
fn put<'a>(map: &mut BTreeMap<String, &'a Value>, key: Option<String>, rec: &'a Value) {
    let Some(key) = key else { return };
    match map.get(&key) {
        Some(existing) if updated_at(existing) >= updated_at(rec) => {}
        _ => {
            map.insert(key, rec);
        }
    }
}

fn lid_key(v: &Value) -> Option<String> {
    v.get("local_id").and_then(Value::key_string)
}

fn id_key(v: &Value) -> Option<String> {
    v.get("id").and_then(Value::key_string)
}

/// Resolve a `{local_id, id}` reference against local-id and id indexes.
fn deref<'a>(
    r: Option<&Value>,
    by_lid: &BTreeMap<String, &'a Value>,
    by_id: &BTreeMap<String, &'a Value>,
) -> Option<&'a Value> {
    let r = r?;
    if let Some(k) = r.get("local_id").and_then(Value::key_string) {
        if let Some(v) = by_lid.get(&k) {
            return Some(*v);
        }
    }
    if let Some(k) = r.get("id").and_then(Value::key_string) {
        if let Some(v) = by_id.get(&k) {
            return Some(*v);
        }
    }
    None
}

fn is_group(r: &Value) -> bool {
    r.has("label")
        && !r.has("address")
        && !r.has("username")
        && !r.has("private_key")
        && !r.has("public_key")
        && !r.has("hostnames")
        && !r.has("port")
        && !r.has("script")
        && (r.has("parent_group") || r.has("sharing_mode") || r.has("ssh_config"))
}

pub fn resolve(records: &[Value]) -> Resolved {
    let mut hosts: BTreeMap<String, &Value> = BTreeMap::new();
    let mut ident: BTreeMap<String, &Value> = BTreeMap::new();
    let mut sshc: BTreeMap<String, &Value> = BTreeMap::new();
    let mut key_lid: BTreeMap<String, &Value> = BTreeMap::new();
    let mut key_id: BTreeMap<String, &Value> = BTreeMap::new();
    let mut grp_id: BTreeMap<String, &Value> = BTreeMap::new();
    let mut grp_lid: BTreeMap<String, &Value> = BTreeMap::new();

    for r in records {
        if r.has("address") && r.has("label") {
            put(&mut hosts, lid_key(r), r);
        }
        if r.has("username") && !r.has("address") && !r.has("user_id") {
            put(&mut ident, lid_key(r), r);
        }
        if r.has("port") && r.has("identity") {
            put(&mut sshc, lid_key(r), r);
        }
        if r.has("private_key") {
            put(&mut key_lid, lid_key(r), r);
            put(&mut key_id, id_key(r), r);
        }
        if is_group(r) {
            put(&mut grp_id, id_key(r), r);
            put(&mut grp_lid, lid_key(r), r);
        }
    }

    // Collect unique key files by (label, content prefix).
    let mut seen_keys: BTreeMap<String, ()> = BTreeMap::new();
    let mut keys: Vec<Key> = Vec::new();
    for kr in key_lid.values() {
        let pk = kr.get("private_key").and_then(Value::as_str).unwrap_or("");
        if pk.is_empty() {
            continue;
        }
        let label = kr
            .get("label")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("key")
            .to_string();
        let dedup = format!("{label}|{}", &pk[..pk.len().min(32)]);
        if seen_keys.insert(dedup, ()).is_some() {
            continue;
        }
        keys.push(Key {
            label,
            private_key: pk.to_string(),
            public_key: kr
                .get("public_key")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        });
    }

    let group_chain = |h: &Value| -> String {
        let mut names: Vec<String> = Vec::new();
        let mut cur = deref(h.get("group"), &grp_lid, &grp_id);
        let mut guard = 0;
        while let Some(g) = cur {
            guard += 1;
            if guard > 16 {
                break;
            }
            if let Some(n) = g.get("label").and_then(Value::as_str) {
                if !n.is_empty() {
                    names.push(n.to_string());
                }
            }
            cur = deref(g.get("parent_group"), &grp_lid, &grp_id);
        }
        names.reverse();
        names.join(" / ")
    };

    let mut out: Vec<Host> = Vec::new();
    for (k, h) in &hosts {
        let address = h.get("address").and_then(Value::as_str).unwrap_or("");
        let label = h.get("label").and_then(Value::as_str).unwrap_or("");
        if address.is_empty() || label.trim().is_empty() {
            continue;
        }
        let idn = ident.get(k).copied();
        let sc = sshc.get(k).copied();
        let username = idn
            .and_then(|i| i.get("username"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let password = idn
            .and_then(|i| i.get("password"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let port = sc.and_then(|s| s.get("port")).and_then(Value::as_i64).unwrap_or(22);
        let key_label = idn
            .and_then(|i| deref(i.get("ssh_key"), &key_lid, &key_id))
            .and_then(|kr| kr.get("label"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(Host {
            label: label.to_string(),
            address: address.to_string(),
            port,
            username,
            password,
            key_label,
            group: group_chain(h),
        });
    }

    out.sort_by(|a, b| (&a.group, &a.label).cmp(&(&b.group, &b.label)));
    Resolved { hosts: out, keys }
}
