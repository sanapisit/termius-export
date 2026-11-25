//! Minimal V8 `ValueSerializer` deserializer.
//!
//! Chromium stores IndexedDB values using V8's structured-clone format. This
//! reader supports only the tags Termius emits (objects, arrays, strings,
//! numbers, booleans, null/undefined, dates). Object back-references (`^`) are
//! resolved to `Value::Null`; Termius records never rely on them for the scalar
//! fields we extract.

use std::collections::BTreeMap;

/// A decoded structured-clone value.
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Double(f64),
    Str(String),
    Object(BTreeMap<String, Value>),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Double(d) => Some(*d as i64),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// A stable key usable for maps (from an `id`/`local_id` field value).
    pub fn key_string(&self) -> Option<String> {
        match self {
            Value::Int(i) => Some(format!("i{i}")),
            Value::Str(s) => Some(format!("s{s}")),
            _ => None,
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

type PResult<T> = Result<T, ()>;

impl<'a> Reader<'a> {
    fn u8(&mut self) -> PResult<u8> {
        let v = *self.b.get(self.i).ok_or(())?;
        self.i += 1;
        Ok(v)
    }

    fn peek(&self) -> PResult<u8> {
        self.b.get(self.i).copied().ok_or(())
    }

    fn varint(&mut self) -> PResult<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err(());
            }
        }
        Ok(result)
    }

    fn zigzag(&mut self) -> PResult<i64> {
        let n = self.varint()?;
        Ok(((n >> 1) as i64) ^ -((n & 1) as i64))
    }

    fn bytes(&mut self, n: usize) -> PResult<&'a [u8]> {
        let end = self.i.checked_add(n).ok_or(())?;
        let slice = self.b.get(self.i..end).ok_or(())?;
        self.i = end;
        Ok(slice)
    }

    fn value(&mut self) -> PResult<Value> {
        let tag = self.u8()?;
        match tag {
            b'_' | b'0' => Ok(Value::Null),       // undefined / null
            b'T' => Ok(Value::Bool(true)),
            b'F' => Ok(Value::Bool(false)),
            b'I' => Ok(Value::Int(self.zigzag()?)),
            b'U' => Ok(Value::Int(self.varint()? as i64)),
            b'N' | b'D' => {
                // double / date: 8-byte little-endian f64
                let raw = self.bytes(8)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(raw);
                Ok(Value::Double(f64::from_le_bytes(arr)))
            }
            b'"' => {
                // one-byte (latin1) string
                let n = self.varint()? as usize;
                let raw = self.bytes(n)?;
                Ok(Value::Str(raw.iter().map(|&c| c as char).collect()))
            }
            b'S' => {
                // utf-8 string
                let n = self.varint()? as usize;
                let raw = self.bytes(n)?;
                Ok(Value::Str(String::from_utf8_lossy(raw).into_owned()))
            }
            b'c' => {
                // two-byte (utf-16le) string
                let n = self.varint()? as usize;
                let raw = self.bytes(n)?;
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                Ok(Value::Str(String::from_utf16_lossy(&units)))
            }
            b'o' => {
                // object: (key value)* '{' propertyCount
                let mut map = BTreeMap::new();
                loop {
                    if self.peek()? == b'{' {
                        self.i += 1;
                        self.varint()?; // property count
                        break;
                    }
                    let key = self.value()?;
                    let val = self.value()?;
                    if let Value::Str(k) = key {
                        map.insert(k, val);
                    }
                }
                Ok(Value::Object(map))
            }
            b'A' => {
                // dense array: count (value)* '$' propCount length
                let count = self.varint()? as usize;
                let mut arr = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    arr.push(self.value()?);
                }
                loop {
                    if self.peek()? == b'$' {
                        self.i += 1;
                        self.varint()?;
                        self.varint()?;
                        break;
                    }
                    self.value()?; // trailing property key
                    self.value()?; // trailing property value
                }
                Ok(Value::Array(arr))
            }
            b'a' => {
                // sparse array: length (key value)* '@' propCount length
                self.varint()?;
                let mut arr: Vec<Value> = Vec::new();
                loop {
                    if self.peek()? == b'@' {
                        self.i += 1;
                        self.varint()?;
                        self.varint()?;
                        break;
                    }
                    let key = self.value()?;
                    let val = self.value()?;
                    if let Value::Int(idx) = key {
                        if idx >= 0 {
                            let idx = idx as usize;
                            if idx < 100_000 {
                                while arr.len() <= idx {
                                    arr.push(Value::Null);
                                }
                                arr[idx] = val;
                            }
                        }
                    }
                }
                Ok(Value::Array(arr))
            }
            b'^' => {
                // object reference — not needed for scalar extraction
                self.varint()?;
                Ok(Value::Null)
            }
            _ => Err(()),
        }
    }
}

/// Parse one serialized value that starts at `start` with `FF <ver> 6F ...`.
fn parse_at(data: &[u8], start: usize) -> Option<Value> {
    let mut r = Reader { b: data, i: start };
    if r.u8().ok()? != 0xff {
        return None;
    }
    r.varint().ok()?; // version
    if r.peek().ok()? != b'o' {
        return None;
    }
    match r.value() {
        Ok(v @ Value::Object(_)) => Some(v),
        _ => None,
    }
}

/// Scan raw LevelDB bytes and return every top-level object record.
///
/// Termius object-store values begin with `FF <ver> 6F 22` (version, object,
/// first one-byte-string key). `.log` files and the `.ldb` blocks in question
/// are uncompressed, so a byte scan recovers every record without a full
/// LevelDB/SSTable parse.
pub fn scan_records(data: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    if data.len() < 4 {
        return out;
    }
    for i in 0..data.len() - 3 {
        if data[i] == 0xff
            && (0x0d..=0x13).contains(&data[i + 1])
            && data[i + 2] == b'o'
            && data[i + 3] == b'"'
        {
            if let Some(v) = parse_at(data, i) {
                if let Value::Object(ref m) = v {
                    if !m.is_empty() {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}
