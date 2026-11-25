# termius-export

ดึง host / credential / private key ออกจาก **Termius ที่ติดตั้งในเครื่อง** แบบ offline
โดย**ไม่ต้องใช้ password บัญชี Termius**

เขียนด้วย Rust ไม่ต้องให้ Termius เปิดอยู่ ไม่ต้องต่อเน็ต

## กระบวนการ

1. อ่าน **local key** (32 byte) จาก OS credential store
   - Windows: Credential Manager target `Termius/localKey`
   - หรือ `--local-key` / `--local-key-file` / env `TERMIUS_LOCAL_KEY`
2. อ่าน IndexedDB (LevelDB) ของ Termius แล้วแกะ **V8 ValueSerializer** เอง
3. ถอดแต่ละ field ที่เป็น `base64( 0x04 0x01 | nonce[24] | secretbox )`
   ด้วย **XSalsa20-Poly1305** (libsodium secretbox) → crate `crypto_secretbox`
4. จับคู่ host ↔ identity ↔ ssh_config ↔ group ↔ key ด้วย `local_id` ร่วม
5. เขียน `ssh_config`, `hosts.csv`, key files

## Build

```powershell
cargo build --release
```

ได้ไบนารีที่ `target/release/termius-export.exe`

## ใช้งาน

```powershell
# ปลอดภัย: เขียนเฉพาะ ssh_config + ตาราง (ไม่มี password/key)
termius-export --out termius_export

# ครบ: รวม password ใน CSV และ dump private key ลง keys/
termius-export --out termius_export --include-secrets

# ดูข้อมูลดิบทั้งหมด (debug)
termius-export --out termius_export --include-secrets --json
```

### Options

| flag | ความหมาย |
|---|---|
| `--data-dir <PATH>` | โฟลเดอร์ LevelDB (หรือ Termius data root) — ปกติ auto |
| `--out <DIR>` | โฟลเดอร์ผลลัพธ์ (default `termius_export`) |
| `--local-key <BASE64>` | ใส่ local key เอง (base64 32 byte) |
| `--local-key-file <PATH>` | อ่าน local key จากไฟล์ |
| `--include-secrets` | เขียน password + dump private key |
| `--json` | เขียน `records.json` (ข้อมูลถอดครบ) |

local key ยังหาเองได้จาก PowerShell:

```powershell
# (ตัวอย่างดึง localKey มาใส่ env ถ้า credential store อ่านไม่ออก)
$env:TERMIUS_LOCAL_KEY = "<base64-32-byte>"
```

## ผลลัพธ์

- `ssh_config` — เอาไปต่อ `~/.ssh/config`; host ที่ใช้ key จะมี `IdentityFile` (เมื่อ `--include-secrets`)
- `hosts.csv` — label, address, port, username, password, key, group
- `keys/` — private key ตามที่ Termius เก็บ (`.pem` = OpenSSH, `.ppk` = PuTTY)
  - `.ppk` (RSA) ที่**ไม่มี passphrase** จะถูกแปลงเป็น OpenSSH ให้อัตโนมัติ (ไฟล์ `.key` คู่กัน) ใช้กับ `ssh -i` ได้เลย
  - `.ppk` ที่**มี passphrase** จะไม่แปลง (คง .ppk) — แปลงเองใน PuTTYgen GUI (Load → Export OpenSSH key)

## โครงสร้างโค้ด

| ไฟล์ | หน้าที่ |
|---|---|
| `src/cred.rs` | อ่าน local key จาก Credential Manager / env / ไฟล์ |
| `src/v8.rs` | V8 ValueSerializer deserializer + สแกน record |
| `src/crypto.rs` | ถอด secretbox แต่ละ field |
| `src/ppk.rs` | แปลง PuTTY `.ppk` (RSA, ไม่มี passphrase) → OpenSSH private key |
| `src/model.rs` | จับคู่ความสัมพันธ์ด้วย `local_id` |
| `src/main.rs` | CLI + เขียนไฟล์ |

## ⚠️ ความปลอดภัย

- `--include-secrets` เขียน **private key + password เป็น plaintext** — เก็บให้ดี, อย่า commit
  (`.gitignore` กันไฟล์ secret ไว้ให้แล้ว)
- เครื่องมือนี้แค่ใช้สิทธิ์ของ user เจ้าของเครื่องอ่าน local key ที่ Termius cache ไว้เอง
  ไม่ได้เจาะอะไร — ใช้กับบัญชี/เครื่องของตัวเองเท่านั้น

## License

MIT
