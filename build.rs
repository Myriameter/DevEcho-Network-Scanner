//! If oui.csv (IEEE vendor list) sits next to Cargo.toml at build time, bake a compact copy
//! into the .exe so manufacturer lookups work with no internet connection at all.
use std::{env, fs, path::PathBuf};

fn fields(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut q) = (Vec::new(), String::new(), false);
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        match (c, q) {
            ('"', true) if it.peek() == Some(&'"') => { cur.push('"'); it.next(); }
            ('"', _) => q = !q,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// The same green radar as the window icon, at any size.
fn radar(n: usize) -> Vec<u8> {
    let mut rgba = vec![0u8; n * n * 4];
    let c = (n as f32 - 1.0) / 2.0;
    let k = n as f32 / 64.0;
    for y in 0..n {
        for x in 0..n {
            let (dx, dy) = ((x as f32 - c) / k, (y as f32 - c) / k);
            let r = (dx * dx + dy * dy).sqrt();
            let mut px = [0u8, 0, 0, 0];
            if r <= 31.5 {
                px = [12, 26, 17, 255];
                let ring = |rad: f32| (r - rad).abs() < 1.3;
                if dy < 0.0 && dx > 0.0 && (dy.atan2(dx) + 0.8).abs() < 0.35 && r < 30.0 {
                    px = [20, 110, 50, 255];
                }
                if ring(30.0) || ring(20.0) || ring(10.0) || (dx.abs() < 0.9 && r < 30.0) || (dy.abs() < 0.9 && r < 30.0) {
                    px = [61, 255, 122, 255];
                }
                let (bx, by) = (dx - 11.0, dy + 9.0);
                if (bx * bx + by * by).sqrt() < 3.6 {
                    px = [216, 255, 228, 255];
                }
            }
            rgba[(y * n + x) * 4..(y * n + x) * 4 + 4].copy_from_slice(&px);
        }
    }
    rgba
}

/// Multi-size .ico (PNG-compressed entries, supported since Windows Vista).
fn write_ico(path: &std::path::Path) {
    let sizes = [16usize, 24, 32, 48, 64, 128, 256];
    let pngs: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&n| {
            let mut out = Vec::new();
            let mut e = png::Encoder::new(&mut out, n as u32, n as u32);
            e.set_color(png::ColorType::Rgba);
            e.set_depth(png::BitDepth::Eight);
            e.write_header().unwrap().write_image_data(&radar(n)).unwrap();
            out
        })
        .collect();
    let mut ico = vec![0u8, 0, 1, 0];
    ico.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len();
    for (i, &n) in sizes.iter().enumerate() {
        let b = if n >= 256 { 0 } else { n as u8 };
        ico.extend_from_slice(&[b, b, 0, 0, 1, 0, 32, 0]);
        ico.extend_from_slice(&(pngs[i].len() as u32).to_le_bytes());
        ico.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += pngs[i].len();
    }
    for p in &pngs {
        ico.extend_from_slice(p);
    }
    fs::write(path, ico).unwrap();
}

fn main() {
    // Icon + version info in Explorer / Task Manager (Windows builds only; never fails the build).
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico = PathBuf::from(env::var("OUT_DIR").unwrap()).join("app.ico");
        write_ico(&ico);
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico.to_str().unwrap())
            .set("ProductName", "DevEcho Network Scanner")
            .set("FileDescription", "DevEcho Network Scanner")
            .set("CompanyName", "Myriameter.uk")
            .set("LegalCopyright", "Copyright \u{00A9} Myriameter.uk 2026")
            .set("OriginalFilename", "devecho-network-scanner.exe")
            .set("InternalName", "devecho-network-scanner");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Icon/version resource skipped: {}", e);
        }
    }

    println!("cargo:rerun-if-changed=oui.csv");
    println!("cargo:rerun-if-changed=build.rs");
    let mut s = String::new();
    if let Ok(b) = fs::read("oui.csv") {
        for line in String::from_utf8_lossy(&b).lines() {
            let f = fields(line);
            if f.len() >= 3 && f[1].len() == 6 && f[1].chars().all(|c| c.is_ascii_hexdigit()) {
                s.push_str(&f[1].to_uppercase());
                s.push('\t');
                s.push_str(f[2].trim().replace(['\t', '\n'], " ").as_str());
                s.push('\n');
            }
        }
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("oui_embedded.txt");
    fs::write(out, s).unwrap();
}
