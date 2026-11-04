//! Persistent data for DevEcho Network Scanner.
//!
//! Nothing is written to disk until something is actually saved.
//! Settings & data:  %APPDATA%\DevEcho Network Scanner\   (Linux: ~/.config/devecho-network-scanner/)
//!     oui.csv          downloaded IEEE vendor list (optional - a copy is also built into the .exe)
//!     devices.csv      your labels, keyed by MAC address
//!     dhcp_names.dat   hostnames heard by the DHCP listener, keyed by MAC address
//!     settings.txt     theme / threads (not counted as user data)
//! Saved scans, backups & snapshots:  Documents\DevEcho Network Scanner\

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const EMBEDDED_OUI: &str = include_str!(concat!(env!("OUT_DIR"), "/oui_embedded.txt"));

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_dir())
}

fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}

fn appdata_base() -> Option<PathBuf> {
    if cfg!(windows) {
        env_dir("APPDATA")
    } else {
        env_dir("HOME").map(|p| p.join(".config"))
    }
}

fn documents_base() -> Option<PathBuf> {
    let home = if cfg!(windows) { env_dir("USERPROFILE") } else { env_dir("HOME") };
    home.map(|p| p.join("Documents"))
}

/// Where labels, settings and the downloaded vendor list live. Not created until needed.
pub fn data_dir() -> PathBuf {
    let name = if cfg!(windows) { "DevEcho Network Scanner" } else { "devecho-network-scanner" };
    appdata_base().map(|p| p.join(name)).unwrap_or_else(exe_dir)
}

/// Where exports and snapshots go. Not created until needed.
pub fn output_dir() -> PathBuf {
    documents_base().map(|p| p.join("DevEcho Network Scanner")).unwrap_or_else(data_dir)
}

pub fn ensure(dir: &Path) -> PathBuf {
    let _ = std::fs::create_dir_all(dir);
    dir.to_path_buf()
}

fn legacy_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(b) = appdata_base() {
        for n in if cfg!(windows) { ["OG Network Scanner", "Myriameter Scanner", "MyriaScan"] } else { ["og-network-scanner", "myriameter-scanner", "myriascan"] } {
            v.push(b.join(n));
        }
    }
    v
}

fn legacy_output_dirs() -> Vec<PathBuf> {
    documents_base().map(|d| vec![d.join("OG Network Scanner"), d.join("Myriameter Scanner"), d.join("MyriaScan")]).unwrap_or_default()
}

pub fn oui_path() -> PathBuf {
    data_dir().join("oui.csv")
}

/// Labels file: DPAPI-encrypted on Windows (devices.dat), plain CSV elsewhere.
pub fn devices_path() -> PathBuf {
    data_dir().join(if crate::platform::labels_encrypted_at_rest() { "devices.dat" } else { "devices.csv" })
}

fn legacy_devices_csv() -> PathBuf {
    data_dir().join("devices.csv")
}

fn settings_path() -> PathBuf {
    data_dir().join("settings.txt")
}

/// One-off: bring across data from MyriaScan / the old LAN Scanner.
pub fn migrate_old_files() {
    if data_dir().exists() {
        return;
    }
    for old in legacy_dirs() {
        if old.is_dir() && std::fs::rename(&old, data_dir()).is_ok() {
            return;
        }
    }
    let old = exe_dir();
    for (from, to) in [("oui.csv", oui_path()), ("lanscan_names.csv", devices_path())] {
        if old.join(from).exists() {
            ensure(&data_dir());
            let _ = std::fs::copy(old.join(from), to);
        }
    }
}

// ------------------------------------------------------------------ CSV
pub fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, q) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => q = !q,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

pub fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ------------------------------------------------------------------ vendors
pub enum OuiSource {
    Downloaded,
    BuiltIn,
    None,
}

/// Prefers a downloaded copy (newer), falls back to the copy built into the .exe.
pub fn load_oui() -> (HashMap<String, String>, OuiSource) {
    let mut m = HashMap::new();
    if let Ok(bytes) = std::fs::read(oui_path()) {
        for line in String::from_utf8_lossy(&bytes).lines() {
            let f = csv_fields(line);
            if f.len() >= 3 && f[1].len() == 6 {
                m.insert(f[1].to_uppercase(), f[2].trim().to_string());
            }
        }
        if !m.is_empty() {
            return (m, OuiSource::Downloaded);
        }
    }
    for line in EMBEDDED_OUI.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    let src = if m.is_empty() { OuiSource::None } else { OuiSource::BuiltIn };
    (m, src)
}

pub fn has_builtin_oui() -> bool {
    !EMBEDDED_OUI.is_empty()
}

/// Uses the curl.exe built into Windows 10/11 (and every Linux), so no TLS library is needed.
pub fn download_oui() -> Result<(), String> {
    let tmp = ensure(&data_dir()).join("oui.csv.tmp");
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-fsSL", "-A", "Mozilla/5.0 DevEcho-Network-Scanner", "-o"]).arg(&tmp).arg(OUI_URL);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let st = cmd.status().map_err(|e| format!("curl not found ({})", e))?;
    if !st.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err("download failed - no internet connection?".into());
    }
    std::fs::rename(&tmp, oui_path()).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ labels & notes
#[derive(Clone, Default)]
pub struct DeviceInfo {
    pub label: String,
    pub notes: String,
    pub last_ip: String, // where it was last seen - lets the label follow if a MAC lookup fails
}

fn parse_devices(s: &str) -> HashMap<String, DeviceInfo> {
    let mut m = HashMap::new();
    for line in s.lines() {
        let f = csv_fields(line);
        if f.len() >= 2 && !f[0].trim().is_empty() {
            m.insert(
                f[0].trim().to_lowercase(),
                DeviceInfo {
                    label: f[1].trim().to_string(),
                    notes: f.get(2).map(|s| s.trim().to_string()).unwrap_or_default(),
                    last_ip: f.get(3).map(|s| s.trim().to_string()).unwrap_or_default(),
                },
            );
        }
    }
    m
}

fn devices_csv(d: &HashMap<String, DeviceInfo>) -> String {
    let mut v: Vec<_> = d.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v.iter().map(|(k, i)| format!("{},{},{},{}\n", csv_escape(k), csv_escape(&i.label), csv_escape(&i.notes), csv_escape(&i.last_ip))).collect()
}

pub fn load_devices() -> HashMap<String, DeviceInfo> {
    if crate::platform::labels_encrypted_at_rest() {
        if let Ok(blob) = std::fs::read(devices_path()) {
            if let Some(plain) = crate::platform::unprotect(&blob) {
                let plain = Zeroizing::new(plain);
                return parse_devices(&String::from_utf8_lossy(&plain));
            }
            return HashMap::new();
        }
        // one-off upgrade: plain devices.csv -> encrypted devices.dat, then shred the plain copy
        if let Ok(s) = std::fs::read_to_string(legacy_devices_csv()) {
            let m = parse_devices(&s);
            if save_devices(&m).is_ok() {
                let _ = secure_erase_file(&legacy_devices_csv());
            }
            return m;
        }
        return HashMap::new();
    }
    std::fs::read_to_string(devices_path()).map(|s| parse_devices(&s)).unwrap_or_default()
}

pub fn save_devices(d: &HashMap<String, DeviceInfo>) -> std::io::Result<()> {
    if d.is_empty() {
        // nothing left to keep - don't leave an empty file behind
        if devices_path().exists() {
            let _ = secure_erase_file(&devices_path());
        }
        return Ok(());
    }
    ensure(&data_dir());
    let plain = Zeroizing::new(devices_csv(d));
    let bytes: Vec<u8> = if crate::platform::labels_encrypted_at_rest() {
        crate::platform::protect(plain.as_bytes()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Windows encryption (DPAPI) failed"))?
    } else {
        plain.as_bytes().to_vec()
    };
    let tmp = devices_path().with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, devices_path())
}

// ------------------------------------------------------------------ hostnames heard by the DHCP listener
/// MAC -> hostname, DPAPI-encrypted on Windows like the labels. Lives in the data folder, so
/// "Erase all data" removes it with everything else.
fn dhcp_path() -> PathBuf {
    data_dir().join(if crate::platform::labels_encrypted_at_rest() { "dhcp_names.dat" } else { "dhcp_names.csv" })
}

pub fn load_dhcp_names() -> HashMap<String, String> {
    let Ok(blob) = std::fs::read(dhcp_path()) else { return HashMap::new() };
    let plain = if crate::platform::labels_encrypted_at_rest() {
        match crate::platform::unprotect(&blob) {
            Some(p) => Zeroizing::new(p),
            None => return HashMap::new(),
        }
    } else {
        Zeroizing::new(blob)
    };
    String::from_utf8_lossy(&plain)
        .lines()
        .filter_map(|l| {
            let f = csv_fields(l);
            (f.len() >= 2 && !f[0].trim().is_empty() && !f[1].trim().is_empty()).then(|| (f[0].trim().to_lowercase(), f[1].trim().to_string()))
        })
        .collect()
}

pub fn save_dhcp_names(m: &HashMap<String, String>) -> std::io::Result<()> {
    if m.is_empty() {
        if dhcp_path().exists() {
            let _ = secure_erase_file(&dhcp_path());
        }
        return Ok(());
    }
    ensure(&data_dir());
    let mut v: Vec<_> = m.iter().collect();
    v.sort();
    let plain = Zeroizing::new(v.iter().map(|(k, h)| format!("{},{}\n", csv_escape(k), csv_escape(h))).collect::<String>());
    let bytes: Vec<u8> = if crate::platform::labels_encrypted_at_rest() {
        crate::platform::protect(plain.as_bytes()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Windows encryption (DPAPI) failed"))?
    } else {
        plain.as_bytes().to_vec()
    };
    let tmp = dhcp_path().with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, dhcp_path())
}

// ------------------------------------------------------------------ password encryption (saved scans)
// File: magic[8] | m_kib u32 | t u32 | p u32 | salt[16] | nonce[12] | AES-256-GCM(ciphertext+tag)
// Key = Argon2id(password, salt). The whole header is authenticated (AAD), so tampering is detected.

fn derive_key(pw: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>, String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m, t, p, Some(32)).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pw, salt, &mut *key).map_err(|e| e.to_string())?;
    Ok(key)
}

pub const MAGIC_SCAN: &[u8; 8] = b"MYRSCN01";

/// Encrypt any text with a password (Argon2id key, AES-256-GCM, header authenticated).
pub fn encrypt_blob(magic: &[u8; 8], plain: &str, password: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload};
    use aes_gcm::Aes256Gcm;
    let (m, t, p) = (65_536u32, 3u32, 1u32); // 64 MiB, 3 passes
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password.as_bytes(), &salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|e| e.to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut out = Vec::with_capacity(64 + plain.len());
    out.extend_from_slice(magic);
    for v in [m, t, p] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let ct = cipher.encrypt(&nonce, Payload { msg: plain.as_bytes(), aad: &out }).map_err(|_| "encryption failed".to_string())?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_blob(magic: &[u8; 8], data: &[u8], password: &str) -> Result<Zeroizing<String>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    const HDR: usize = 8 + 12 + 16 + 12;
    if data.len() < HDR + 16 || &data[..8] != magic {
        return Err("This isn't a saved DevEcho Network Scanner scan.".into());
    }
    let u = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let (m, t, p) = (u(8), u(12), u(16));
    // Only accept at least the strength this program creates (64 MiB, 3 passes), and cap it so a
    // crafted file can't demand gigabytes of memory.
    if !(65_536..=262_144).contains(&m) || !(3..=10).contains(&t) || !(1..=4).contains(&p) {
        return Err("This file uses unsupported encryption settings, or it's damaged.".into());
    }
    let key = derive_key(password.as_bytes(), &data[20..36], m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&data[36..48]), Payload { msg: &data[HDR..], aad: &data[..HDR] })
            .map_err(|_| "Wrong password, or the file has been damaged or altered.".to_string())?,
    );
    Ok(Zeroizing::new(String::from_utf8_lossy(&plain).into_owned()))
}

// ------------------------------------------------------------------ secure erase
/// Fast non-cryptographic random bytes for overwriting (xorshift64*, seeded from time + address).
fn noise(buf: &mut [u8], seed: &mut u64) {
    for chunk in buf.chunks_mut(8) {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        let v = seed.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

fn seed() -> u64 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
    let a = &t as *const u64 as u64;
    (t ^ a.rotate_left(17)) | 1
}

/// Overwrite with random data, then zeros (each flushed to disk), truncate,
/// rename to a random name so the original file name doesn't linger, then delete.
pub fn secure_erase_file(path: &Path) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let len = std::fs::metadata(path)?.len();
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut s = seed();
        for pass in 0..2 {
            f.seek(SeekFrom::Start(0))?;
            let mut left = len;
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                if pass == 0 {
                    noise(&mut buf[..n], &mut s);
                } else {
                    buf[..n].fill(0);
                }
                f.write_all(&buf[..n])?;
                left -= n as u64;
            }
            f.sync_all()?;
        }
        f.set_len(0)?;
        f.sync_all()?;
    }
    let mut name = [0u8; 12];
    noise(&mut name, &mut seed());
    let rnd: String = name.iter().map(|b| (b'a' + b % 26) as char).collect();
    let tmp = path.with_file_name(rnd);
    std::fs::rename(path, &tmp)?;
    std::fs::remove_file(tmp)
}

fn files_in(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                files_in(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

fn is_export(p: &Path) -> bool {
    p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("DevEcho_") || n.starts_with("OG_") || n.starts_with("Myriameter_") || n.starts_with("MyriaScan_")).unwrap_or(false)
}

/// Files that count as user data (theme/threads settings deliberately excluded).
pub fn user_data_files() -> Vec<PathBuf> {
    let mut all = Vec::new();
    files_in(&data_dir(), &mut all);
    for d in legacy_dirs() {
        files_in(&d, &mut all);
    }
    // settings and the public IEEE vendor list are not user data
    let mut v: Vec<PathBuf> = all
        .into_iter()
        .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n != "settings.txt" && !n.starts_with("oui.csv")).unwrap_or(true))
        .collect();
    let mut ex = Vec::new();
    for d in std::iter::once(output_dir()).chain(legacy_output_dirs()) {
        files_in(&d, &mut ex);
    }
    v.extend(ex.into_iter().filter(|p| is_export(p)));
    let old = exe_dir();
    if old.join("lanscan_names.csv").exists() && old != data_dir() {
        v.push(old.join("lanscan_names.csv"));
    }
    v
}


/// Encrypted saved scans (.mls) - and label backups (.mlb) left by older versions - in the save folders plus any extra paths.
pub fn saved_files(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for d in std::iter::once(output_dir()).chain(legacy_output_dirs()) {
        files_in(&d, &mut all);
    }
    all.extend(extra.iter().filter(|p| p.exists()).cloned());
    all.sort();
    all.dedup();
    all.into_iter().filter(|p| p.extension().map(|e| e == "mls" || e == "mlb").unwrap_or(false)).collect()
}

/// Securely erase all user data. Returns (files erased, failures). Settings and the vendor list are kept.
pub fn secure_erase_all(also_saved: &[PathBuf]) -> (usize, Vec<String>) {
    let (mut ok, mut bad) = (0, Vec::new());
    for t in user_data_files().into_iter().chain(also_saved.iter().cloned()) {
        match secure_erase_file(&t) {
            Ok(_) => ok += 1,
            Err(e) => bad.push(format!("{} ({})", t.display(), e)),
        }
    }
    // remove folders that are now empty - never touches anything else
    for d in std::iter::once(output_dir()).chain(legacy_output_dirs()).chain(legacy_dirs()).chain(std::iter::once(data_dir())) {
        let _ = std::fs::remove_dir(&d);
    }
    (ok, bad)
}

// ------------------------------------------------------------------ settings
pub fn load_settings() -> HashMap<String, String> {
    std::fs::read_to_string(settings_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect()
}

pub fn save_settings(s: &HashMap<String, String>) {
    let mut v: Vec<_> = s.iter().collect();
    v.sort();
    let body: String = v.iter().map(|(k, val)| format!("{}={}\n", k, val)).collect();
    ensure(&data_dir());
    let _ = std::fs::write(settings_path(), body);
}

// ------------------------------------------------------------------ time & PNG
#[cfg(any(windows, feature = "wincheck"))]
#[allow(non_snake_case, dead_code)]
fn local_time() -> Option<(i64, i64, i64, i64, i64, i64)> {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        y: u16,
        mo: u16,
        dow: u16,
        d: u16,
        h: u16,
        mi: u16,
        s: u16,
        ms: u16,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocalTime(t: *mut SystemTime);
    }
    let mut t = SystemTime::default();
    unsafe { GetLocalTime(&mut t) };
    Some((t.y as i64, t.mo as i64, t.d as i64, t.h as i64, t.mi as i64, t.s as i64))
}

fn utc_time() -> (i64, i64, i64, i64, i64, i64) {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// "20261026_213045" - local time on Windows, UTC elsewhere.
pub fn timestamp() -> String {
    #[cfg(windows)]
    let t = local_time().unwrap_or_else(utc_time);
    #[cfg(not(windows))]
    let t = utc_time();
    format!("{:04}{:02}{:02}_{:02}{:02}{:02}", t.0, t.1, t.2, t.3, t.4, t.5)
}

pub fn save_png(path: &Path, w: usize, h: usize, rgba: &[u8]) -> Result<(), String> {
    let f = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut wr = enc.write_header().map_err(|e| e.to_string())?;
    wr.write_image_data(rgba).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv() {
        let f = csv_fields(r#"MA-L,4419B6,"Hangzhou Hikvision Digital Technology Co.,Ltd.",CN"#);
        assert_eq!(f[2], "Hangzhou Hikvision Digital Technology Co.,Ltd.");
        assert_eq!(csv_fields(&csv_escape("a \"b\", c"))[0], "a \"b\", c");
    }
    #[test]
    fn ts() {
        assert_eq!(timestamp().len(), 15);
    }
    #[test]
    fn erase() {
        let p = std::env::temp_dir().join("myriascan_erase_test.txt");
        std::fs::write(&p, b"secret secret secret").unwrap();
        secure_erase_file(&p).unwrap();
        assert!(!p.exists());
        assert!(std::fs::read_dir(std::env::temp_dir()).unwrap().flatten().all(|e| e.metadata().map(|m| m.len() != 20).unwrap_or(true) || !e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_lowercase())));
    }
    #[test]
    fn png_roundtrip() {
        let p = std::env::temp_dir().join("myriascan_test.png");
        save_png(&p, 2, 2, &[255u8; 16]).unwrap();
        assert!(std::fs::metadata(&p).unwrap().len() > 20);
    }
}
