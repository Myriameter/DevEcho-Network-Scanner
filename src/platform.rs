//! Small Windows helpers without extra crates: native file dialogs and clipboard clearing.

use std::path::PathBuf;

/// Hash of some text, so we can recognise our own clipboard contents without keeping a copy.
pub fn text_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

#[cfg(any(windows, feature = "wincheck"))]
#[allow(non_snake_case, dead_code)]
mod win {
    use std::ffi::c_void;
    use std::path::PathBuf;

    #[repr(C)]
    struct OpenFileNameW {
        l_struct_size: u32,
        hwnd_owner: isize,
        h_instance: isize,
        lpstr_filter: *const u16,
        lpstr_custom_filter: *mut u16,
        n_max_cust_filter: u32,
        n_filter_index: u32,
        lpstr_file: *mut u16,
        n_max_file: u32,
        lpstr_file_title: *mut u16,
        n_max_file_title: u32,
        lpstr_initial_dir: *const u16,
        lpstr_title: *const u16,
        flags: u32,
        n_file_offset: u16,
        n_file_extension: u16,
        lpstr_def_ext: *const u16,
        l_cust_data: isize,
        lpfn_hook: *const c_void,
        lp_template_name: *const u16,
        pv_reserved: *mut c_void,
        dw_reserved: u32,
        flags_ex: u32,
    }

    #[link(name = "comdlg32")]
    extern "system" {
        fn GetSaveFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn GetOpenFileNameW(ofn: *mut OpenFileNameW) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hwnd: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn GetClipboardData(format: u32) -> isize;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(h: isize) -> *const u16;
        fn GlobalUnlock(h: isize) -> i32;
        fn LocalFree(h: *mut c_void) -> *mut c_void;
    }

    #[repr(C)]
    struct DataBlob {
        len: u32,
        data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(input: *const DataBlob, descr: *const u16, entropy: *const DataBlob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, out: *mut DataBlob) -> i32;
        fn CryptUnprotectData(input: *const DataBlob, descr: *mut *mut u16, entropy: *const DataBlob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, out: *mut DataBlob) -> i32;
    }

    const ENTROPY: &[u8] = b"Myriameter.uk network scanner labels v1";

    /// DPAPI: encrypt for the current Windows user (CRYPTPROTECT_UI_FORBIDDEN).
    pub fn dpapi(data: &[u8], protect: bool) -> Option<Vec<u8>> {
        let input = DataBlob { len: data.len() as u32, data: data.as_ptr() as *mut u8 };
        let ent = DataBlob { len: ENTROPY.len() as u32, data: ENTROPY.as_ptr() as *mut u8 };
        let mut out = DataBlob { len: 0, data: std::ptr::null_mut() };
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), &ent, std::ptr::null_mut(), std::ptr::null_mut(), 1, &mut out)
            }
        };
        if ok == 0 || out.data.is_null() {
            return None;
        }
        let v = unsafe { std::slice::from_raw_parts(out.data, out.len as usize).to_vec() };
        unsafe {
            std::ptr::write_bytes(out.data, 0, out.len as usize); // don't leave plaintext in the freed buffer
            LocalFree(out.data as *mut c_void);
        }
        Some(v)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn file_dialog(save: bool, title: &str, default_name: &str, start_dir: &std::path::Path, ext: &str, desc: &str) -> Option<PathBuf> {
        let filter: Vec<u16> = format!("{} (*.{})\0*.{}\0All files (*.*)\0*.*\0\0", desc, ext, ext).encode_utf16().collect();
        let mut file = vec![0u16; 1024];
        for (i, c) in default_name.encode_utf16().take(1000).enumerate() {
            file[i] = c;
        }
        let (title_w, dir_w, ext_w) = (wide(title), wide(&start_dir.to_string_lossy()), wide(ext));
        let mut ofn: OpenFileNameW = unsafe { std::mem::zeroed() };
        ofn.l_struct_size = std::mem::size_of::<OpenFileNameW>() as u32;
        ofn.lpstr_filter = filter.as_ptr();
        ofn.n_filter_index = 1;
        ofn.lpstr_file = file.as_mut_ptr();
        ofn.n_max_file = file.len() as u32;
        ofn.lpstr_initial_dir = dir_w.as_ptr();
        ofn.lpstr_title = title_w.as_ptr();
        ofn.lpstr_def_ext = ext_w.as_ptr();
        // OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | (save: OFN_OVERWRITEPROMPT, open: OFN_FILEMUSTEXIST)
        ofn.flags = 0x8 | 0x800 | if save { 0x2 } else { 0x1000 };
        let ok = unsafe { if save { GetSaveFileNameW(&mut ofn) } else { GetOpenFileNameW(&mut ofn) } };
        if ok == 0 {
            return None;
        }
        let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
        Some(PathBuf::from(String::from_utf16_lossy(&file[..len])))
    }

    /// Empty the clipboard only if it still holds the text we put there (identified by hash).
    pub fn clear_clipboard_if(hash: u64) -> bool {
        unsafe {
            if OpenClipboard(0) == 0 {
                return false;
            }
            let mut ours = false;
            let h = GetClipboardData(13); // CF_UNICODETEXT
            if h != 0 {
                let p = GlobalLock(h);
                if !p.is_null() {
                    let mut n = 0;
                    while *p.add(n) != 0 && n < 4_000_000 {
                        n += 1;
                    }
                    let text = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                    ours = super::text_hash(&text) == hash;
                    GlobalUnlock(h);
                }
            }
            if ours {
                EmptyClipboard();
            }
            CloseClipboard();
            ours
        }
    }
}

/// Native Save dialog (Windows). Elsewhere: a default path in the output folder.
pub fn save_dialog(title: &str, default_name: &str, start_dir: &std::path::Path, ext: &str, desc: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    return win::file_dialog(true, title, default_name, start_dir, ext, desc);
    #[cfg(not(windows))]
    {
        let _ = (title, ext, desc);
        Some(start_dir.join(default_name))
    }
}

/// Native Open dialog (Windows). Elsewhere: the newest file with that extension in the output folder.
pub fn open_dialog(title: &str, start_dir: &std::path::Path, ext: &str, desc: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    return win::file_dialog(false, title, "", start_dir, ext, desc);
    #[cfg(not(windows))]
    {
        let _ = (title, desc);
        std::fs::read_dir(start_dir)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == ext).unwrap_or(false))
            .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
    }
}

/// Clears the clipboard if it still holds our text. Returns true if it was cleared.
pub fn clear_clipboard_if(hash: u64) -> bool {
    #[cfg(windows)]
    return win::clear_clipboard_if(hash);
    #[cfg(not(windows))]
    {
        let _ = hash;
        false
    }
}

/// Encrypt/decrypt bytes so only this Windows user on this PC can read them (DPAPI).
/// Returns None where unsupported (non-Windows) or on failure.
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    #[cfg(windows)]
    return win::dpapi(data, true);
    #[cfg(not(windows))]
    {
        let _ = data;
        None
    }
}

pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    #[cfg(windows)]
    return win::dpapi(data, false);
    #[cfg(not(windows))]
    {
        let _ = data;
        None
    }
}

pub fn labels_encrypted_at_rest() -> bool {
    cfg!(windows)
}

/// Open a URL in the default browser.
pub fn open_url(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).creation_flags(0x0800_0000).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Show a file in Explorer (selected), or open its folder elsewhere.
pub fn reveal(path: &std::path::Path) {
    #[cfg(windows)]
    {
        // raw_arg: Explorer needs /select,"C:\path with spaces\file" exactly, unescaped
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("explorer").raw_arg(format!("/select,\"{}\"", path.display())).spawn();
    }
    #[cfg(not(windows))]
    {
        if let Some(dir) = path.parent() {
            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
        }
    }
}

/// Launch VLC on a stream URL, if VLC is installed.
pub fn open_in_vlc(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Some(exe) = find_vlc() {
            let _ = std::process::Command::new(exe).arg(url).creation_flags(0x0800_0000).spawn();
            return;
        }
        let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).creation_flags(0x0800_0000).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("vlc").arg(url).spawn().or_else(|_| std::process::Command::new("xdg-open").arg(url).spawn());
    }
}

/// Fetch an HTTP snapshot image (no auth). Returns the raw bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn find_vlc() -> Option<String> {
    #[cfg(windows)]
    {
        for exe in [r"C:\Program Files\VideoLAN\VLC\vlc.exe", r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"] {
            if std::path::Path::new(exe).exists() {
                return Some(exe.to_string());
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("which").arg("vlc").output().ok().filter(|o| o.status.success()).map(|_| "vlc".to_string())
    }
}
