//! DevEcho Network Scanner v1.4 - fast LAN reconnaissance with a GUI.
//! Windows: native adapter API + SendARP + ICMP API. Linux: parallel ping + ARP table.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod platform;
mod scan;
mod store;

use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke, TextStyle};
use egui::{pos2, vec2, Align2, Rect};
use egui_extras::{Column, TableBuilder};
use scan::{Adapter, Echo, PortState, Video};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use store::DeviceInfo;
use zeroize::Zeroize;

const APP: &str = "DevEcho Network Scanner v1.4";
const CLIP_SECS: u64 = 30;
const MIN_PW: usize = 10;
const PAD: f32 = 8.0;
const HEAD: [&str; 6] = ["IP address", "Label", "Hostname", "Manufacturer", "MAC address", "Ping"];
const C_IP: usize = 0;
const C_LABEL: usize = 1;
const C_HOST: usize = 2;
const C_VENDOR: usize = 3;
const C_MAC: usize = 4;
const C_PING: usize = 5;
const THIS_PC: &str = "This PC";
const GATEWAY: &str = "Gateway";
const ROW_H: f32 = 24.0;

const THREADS_HELP: &str = "How many addresses are checked at the same time. 256 covers a whole /24 network in one wave of about 3 seconds. Raise it for bigger networks (for example 1024 for a /22), or lower it on a slow PC or to be gentler on the network. Name lookups are not affected.";
const NAMES_HELP: &str = "Choose where device hostnames come from. When sources agree the name is shown once; when they differ, each is shown, best source first.";
const DHCP_HELP: &str = "Passively listens on UDP port 67 for DHCP broadcasts when they *join* the network. It never sends anything. Windows may ask you to allow it through the firewall when activated.";
const NAME_SOURCES: [(u8, &str, &str); 5] = [
    (scan::N_DNS, "DNS", "Reverse DNS lookup through this PC's DNS server."),
    (scan::N_MDNS, "mDNS", "Multicast DNS (Bonjour / Avahi): names and services that devices announce on the local network."),
    (scan::N_NETBIOS, "NetBIOS", "Windows computer names, also used by NAS boxes and printers."),
    (scan::N_UPNP, "UPnP", "Friendly names from devices that advertise themselves with UPnP / SSDP (TVs, routers, media players)."),
    (scan::N_DHCP, "DHCP listener", DHCP_HELP),
];
const PING_HELP: &str = "Sends a ping to every device found. OK means it replied, with the round-trip time. No reply usually means a firewall that ignores ping (phones, Windows PCs, some cameras), not that the device has gone. Unreachable means the network reported it can't be reached.";
const ERASE_HELP: &str = "Securely erase everything the scanner has stored about your network: labels, and all exports and snapshots. Encrypted backups and saved scans, settings, and the public vendor list are kept.";
const DATA_HELP: &str = "Save the whole scan (devices including ones not found, labels, ping and port results) to an encrypted, password-protected file, or open one. Opening a scan offers to restore its labels to this PC.";

const SHORTCUTS: &str = "F5 scan  \u{00B7}  Ctrl+F find  \u{00B7}  Esc clear";

fn devices(n: usize) -> String {
    if n == 1 { "1 device".into() } else { format!("{} devices", n) }
}

// ================================================================ themes
#[derive(Clone, Copy, PartialEq)]
enum Theme {
    Terminal,
    Amber,
}

impl Theme {
    const ALL: [Theme; 2] = [Theme::Terminal, Theme::Amber];
    fn name(self) -> &'static str {
        match self {
            Theme::Terminal => "Terminal",
            Theme::Amber => "Amber CRT",
        }
    }
    fn from_name(s: &str) -> Theme {
        Theme::ALL.into_iter().find(|t| t.name() == s).unwrap_or(Theme::Terminal)
    }
    fn pal(self) -> Pal {
        let c = |h: u32| Color32::from_rgb((h >> 16) as u8, (h >> 8) as u8, h as u8);
        match self {
            Theme::Terminal => Pal {
                dark: true, bg: c(0x0F1A13), panel: c(0x15241A), band: c(0x1D3324), stripe: c(0x13221A),
                hover: c(0x1F3B28), select: c(0x255433), line: c(0x2E5238), input: c(0x0A130D),
                primary: c(0xD8FFE4), mid: c(0x5CE68A), dim: c(0x7FA88C), accent: c(0x3DFF7A),
                warn: c(0xFFB347), bad: c(0xFF6B6B), cyan: c(0x5FE3FF),
                w_idle: c(0x1B3022), w_hover: c(0x24432D), w_active: c(0x2E5839),
            },
            Theme::Amber => Pal {
                dark: true, bg: c(0x17110A), panel: c(0x1F170D), band: c(0x2C2112), stripe: c(0x1C150C),
                hover: c(0x33260F), select: c(0x4A3513), line: c(0x4D3919), input: c(0x110C06),
                primary: c(0xFFE9B8), mid: c(0xFFB000), dim: c(0xB8935A), accent: c(0xFFC233),
                warn: c(0xFF8A3D), bad: c(0xFF5A5A), cyan: c(0xFFE07A),
                w_idle: c(0x2A1F11), w_hover: c(0x3A2B15), w_active: c(0x4D391C),
            },
        }
    }
}

#[derive(Clone, Copy)]
struct Pal {
    dark: bool,
    bg: Color32,
    panel: Color32,
    band: Color32,
    stripe: Color32,
    hover: Color32,
    select: Color32,
    line: Color32,
    input: Color32,
    primary: Color32,
    mid: Color32,
    dim: Color32,
    accent: Color32,
    warn: Color32,
    bad: Color32,
    cyan: Color32,
    w_idle: Color32,
    w_hover: Color32,
    w_active: Color32,
}

/// Clear system fonts where available: Segoe UI + Consolas on Windows, DejaVu on Linux.
/// Falls back to egui's built-in fonts if they can't be read.
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let try_font = |paths: &[&str]| paths.iter().find_map(|p| std::fs::read(p).ok());
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let ui_font = try_font(&[
        &format!("{}\\Fonts\\segoeui.ttf", windir),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]);
    let mono_font = try_font(&[
        &format!("{}\\Fonts\\consola.ttf", windir),
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]);
    if let Some(b) = ui_font {
        fonts.font_data.insert("ui".into(), egui::FontData::from_owned(b));
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "ui".into());
    }
    if let Some(b) = mono_font {
        fonts.font_data.insert("mono".into(), egui::FontData::from_owned(b));
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "mono".into());
    }
    ctx.set_fonts(fonts);
}

fn apply_theme(ctx: &egui::Context, p: &Pal) {
    let mut v = if p.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.override_text_color = Some(p.mid);
    v.panel_fill = p.bg;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.input;
    v.faint_bg_color = p.stripe;
    v.code_bg_color = p.input;
    v.hyperlink_color = p.cyan;
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.bad;
    v.window_stroke = Stroke::new(1.0_f32, p.line);
    v.selection.bg_fill = p.select;
    v.selection.stroke = Stroke::new(1.0_f32, p.primary);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.bg;
    w.noninteractive.weak_bg_fill = p.bg;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.line);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.mid);
    for (wv, bg, edge) in [(&mut w.inactive, p.w_idle, p.line), (&mut w.hovered, p.w_hover, p.mid), (&mut w.active, p.w_active, p.primary), (&mut w.open, p.w_hover, p.mid)] {
        wv.bg_fill = bg;
        wv.weak_bg_fill = bg;
        wv.bg_stroke = Stroke::new(1.0_f32, edge);
        wv.fg_stroke = Stroke::new(1.0_f32, p.primary);
    }
    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(24.0, FontFamily::Monospace)),
        (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(14.5, FontFamily::Monospace)),
        (TextStyle::Button, FontId::new(15.0, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(12.5, FontFamily::Proportional)),
    ]
    .into();
    style.spacing.tooltip_width = 420.0;
    style.interaction.selectable_labels = false;
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    style.spacing.item_spacing = egui::vec2(10.0, 7.0);
    style.spacing.interact_size.y = 26.0;
    ctx.set_style(style);
}

/// A small green radar for the window icon.
fn radar_icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let (dx, dy) = (x as f32 - 31.5, y as f32 - 31.5);
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
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

// ================================================================ data
#[derive(Clone, Copy, PartialEq)]
enum PingState {
    None,
    Pending,
    Ok,
    NoReply,
    Unreachable,
}

#[derive(Clone)]
struct Row {
    ip: Ipv4Addr,
    label: String,
    host: String,
    vendor: String,
    mac: String,
    me: bool,
    gw: bool, // this PC's default gateway (router)
    random_mac: bool,
    video: Option<Video>,
    video_desc: String,
    open_rtsp: String,     // unauthenticated rtsp:// URL, if any
    open_snapshot: String, // unauthenticated http snapshot URL, if any
    ping: String,
    ping_state: PingState,
    rt_ms: f32,                    // latest response time: discovery, then ping (drives the radar)
    ping_flash: Option<Instant>,   // manual ping result highlight (5 s)
    absent: bool,                  // a known/labelled device not found this scan (greyed, last-known IP)
    sort_ip: u32,                  // ordering only (live IP, or last-known IP for absent rows)
    names: [String; 6],            // hostname per source, in rank order (see SRC_TAGS); `host` is built from these
    last_ip: Option<Ipv4Addr>,     // absent rows: where it was last seen
}

/// Hostname sources, best first.
const SRC_TAGS: [&str; 6] = ["mDNS", "DNS", "mDNS", "NetBIOS", "UPnP", "DHCP"];
const S_MDNS_SD: usize = 0; // mDNS service discovery (friendly instance name)
const S_DNS: usize = 1;
const S_MDNS: usize = 2; // mDNS reverse lookup (host.local)
const S_NETBIOS: usize = 3;
const S_UPNP: usize = 4;
const S_DHCP: usize = 5;
const HOST_SEP: &str = "  \u{00B7}  ";

/// Absent rows have no live address; each gets a unique placeholder in 0.0.0.0/8 (never a real
/// host) so selection and row lookups keep them apart. The table shows `last_ip` instead.
fn absent_key(k: usize) -> Ipv4Addr {
    Ipv4Addr::from((k as u32 + 1) & 0x00FF_FFFF)
}
fn is_absent_key(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

/// Per-source names holding only the hostname remembered for this MAC (DHCP), if any.
fn dhcp_names_for(m: &HashMap<String, String>, mac: &str) -> [String; 6] {
    let mut n: [String; 6] = Default::default();
    n[S_DHCP] = m.get(mac).cloned().unwrap_or_default();
    n
}

fn src_of_bit(bit: u8) -> usize {
    match bit {
        scan::N_DNS => S_DNS,
        scan::N_MDNS => S_MDNS,
        _ => S_NETBIOS,
    }
}

/// Drop a trailing " [xx:xx:xx:xx:xx:xx]" - Avahi names its workstation service "host [mac]".
fn strip_mac_suffix(n: &str) -> &str {
    let t = n.trim_end();
    if let Some(i) = t.rfind(" [") {
        let inner = &t[i + 2..];
        if inner.len() == 18 && inner.ends_with(']') && inner[..17].split(':').all(|h| h.len() == 2 && h.chars().all(|c| c.is_ascii_hexdigit())) {
            return t[..i].trim_end();
        }
    }
    t
}

/// Merge the per-source names: identical names (ignoring case and any domain such as .local / .lan)
/// show once with all their sources; different ones are all shown, best-ranked first.
/// mDNS shows one name only: the friendly (service) name when there is one, else the .local name.
fn merge_names(names: &[String; 6]) -> String {
    let key = |n: &str| n.split('.').next().unwrap_or(n).trim().to_lowercase();
    let mut groups: Vec<(String, String, Vec<&str>)> = Vec::new(); // (key, shown name, tags)
    for (i, n) in names.iter().enumerate() {
        if n.trim().is_empty() || (i == S_MDNS && !names[S_MDNS_SD].trim().is_empty()) {
            continue;
        }
        let k = key(n);
        match groups.iter_mut().find(|g| g.0 == k) {
            Some(g) => {
                if !g.2.contains(&SRC_TAGS[i]) {
                    g.2.push(SRC_TAGS[i]);
                }
            }
            None => groups.push((k, n.clone(), vec![SRC_TAGS[i]])),
        }
    }
    groups.iter().map(|(_, n, t)| format!("{}  [{}]", n, t.join(", "))).collect::<Vec<_>>().join(HOST_SEP)
}

impl Row {
    /// Set one source's name and rebuild the Hostname cell. Returns true if the cell changed.
    fn set_name(&mut self, src: usize, name: &str) -> bool {
        self.names[src] = strip_mac_suffix(name.trim()).to_string();
        let h = merge_names(&self.names);
        if h != self.host {
            self.host = h;
            true
        } else {
            false
        }
    }
    /// Every name heard for this device, one per line with its source (Hostname cell tooltip).
    fn names_tooltip(&self) -> String {
        const WHAT: [&str; 6] = ["mDNS (friendly name)", "DNS", "mDNS (.local name)", "NetBIOS", "UPnP", "DHCP"];
        self.names.iter().enumerate().filter(|(_, n)| !n.is_empty()).map(|(i, n)| format!("{}: {}", WHAT[i], n)).collect::<Vec<_>>().join("\n")
    }
    fn host_text(&self) -> String {
        let tag = if self.me { Some(THIS_PC) } else if self.gw { Some(GATEWAY) } else { None };
        match (tag, self.host.is_empty()) {
            (Some(t), true) => t.into(),
            (Some(t), false) => format!("{}  ({})", self.host, t),
            _ => self.host.clone(),
        }
    }
    fn cell(&self, c: usize) -> String {
        match c {
            C_IP => match (self.absent, self.last_ip) {
                (true, Some(ip)) => ip.to_string(),
                (true, None) => String::new(),
                _ => self.ip.to_string(),
            },
            C_LABEL => self.label.clone(),
            C_HOST => match self.video {
                Some(v) => format!("[{}] {}", v.tag(), self.host_text()),
                None => self.host_text(),
            },
            C_VENDOR => self.vendor.clone(),
            C_MAC => self.mac.clone(),
            _ => self.ping.clone(),
        }
    }
}

enum Msg {
    Tick,
    AddTotal(usize),
    Phase(String),
    Found(Ipv4Addr, String, f32, Option<Echo>), // ip, mac, response time (ms), ping result from discovery
    #[cfg_attr(not(windows), allow(dead_code))]
    Mac(Ipv4Addr, String),                       // a MAC found after the device was (late lookup)
    Name(Ipv4Addr, usize, String), // ip, source (S_*), name
    Ssdp(HashMap<Ipv4Addr, String>),
    Mdns(HashMap<Ipv4Addr, String>),
    Vendors(HashMap<String, String>, String),
    Pinged(Ipv4Addr, Echo),
    Video(Ipv4Addr, Video, String),
    Stream(Ipv4Addr, scan::OpenStream),
    VideoDone,
    Port(PortRow),
    PortTick,
    PortPhase(String),
    PortDone,
    Status(String),
    Dhcp(scan::DhcpSeen),                // a hostname heard by the DHCP listener
    DhcpState(Result<(), String>),       // listener opened / couldn't open port 67
    QuietPing(Ipv4Addr, Echo),
    AbsentPinged(String, Ipv4Addr, Echo), // mac, last-known address, result           // background ping for a DHCP-added row (no status message)
    Done,
}

#[derive(Clone, Copy, PartialEq)]
enum Filter {
    None,
    Unknown,
    Absent,
    Video,
}

enum Action {
    Edit(usize),
    Forget(usize),
    Copy(usize, Option<usize>),
    PingOne(usize),
    Open(usize, bool),
    PortScan(usize, bool),
    CopyText(String),
    Vlc(usize),
}

#[derive(Clone)]
struct PortRow {
    ip: Ipv4Addr,
    port: u16,
    state: PortState,
    banner: String,
}

#[derive(Clone, Copy, PartialEq)]
enum PsTarget {
    Selected,
    Video,
    All,
}

struct PortScanUi {
    target: PsTarget,
    ports: String,
    timeout_ms: u32,
    parallel: u32,
    per_host: u32,
    phase: String,
    grab: bool,
    show_closed: bool,
    results: Vec<PortRow>,
    running: bool,
    done: usize,
    total: usize,
    error: String,
    stop: Arc<AtomicBool>,
}

enum PwMode {
    SaveScan,
    OpenScan(Vec<u8>),
}

struct PwDialog {
    mode: PwMode,
    pw1: String,
    pw2: String,
    error: String,
    focus: bool,
}

impl Drop for PwDialog {
    fn drop(&mut self) {
        self.pw1.zeroize();
        self.pw2.zeroize();
    }
}

struct EditState {
    mac: String,
    ip: Ipv4Addr,
    label: String,
    focus: bool,
}

struct App {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    theme: Theme,
    pal: Pal,
    adapters: Vec<Adapter>,
    sel: usize,
    my_ips: HashSet<Ipv4Addr>,
    subnet: String,
    names: u8, // scan::N_* bits: which name sources are enabled
    workers: u32,
    rows: Vec<Row>,
    sel_ips: HashSet<Ipv4Addr>, // rows picked in the main table (click, Ctrl+click, Shift+click)
    anchor: Option<Ipv4Addr>,
    hover_row: Option<usize>,
    sort: (usize, bool),
    oui: HashMap<String, String>,
    oui_note: String,
    devices: HashMap<String, DeviceInfo>,
    ssdp: HashMap<Ipv4Addr, String>,
    mdns: HashMap<Ipv4Addr, String>,
    stop: Arc<AtomicBool>,
    scanning: bool,
    pings_pending: usize,
    loading_vendors: bool,
    done: usize,
    total: usize,
    t0: Instant,
    net_text: String,
    phase: String,
    status: String,
    edit: Option<EditState>,
    confirm_big: Option<usize>,
    snapshot_pending: bool,
    confirm_erase: Option<(usize, Vec<std::path::PathBuf>, bool)>, // (data files, saved files, also erase saved)
    flash_until: Option<Instant>,
    snap_frames: u8,
    col_w: [f32; 6],
    pw: Option<PwDialog>,
    restore_choice: Option<HashMap<String, DeviceInfo>>,
    clip: Option<(u64, Instant)>,
    filter: String,
    focus_filter: bool,
    count_filter: Filter,
    confirm_forget: Option<(String, String)>, // (mac, display name)
    conflicts: Vec<String>,
    video_running: bool,
    ps: Option<PortScanUi>,
    win_size: egui::Vec2,
    status_flash: Option<Instant>,
    status_seen: String,
    status_at: Instant,
    ping_batch: Vec<Ipv4Addr>,
    gateways: HashSet<Ipv4Addr>,
    blips: HashMap<Ipv4Addr, Blip>,
    manual_pings: HashSet<Ipv4Addr>,
    radar_fade: f32,
    radar_angle: f32,
    radar_last: Instant,
    radar_open: bool,
    gap_centre: Option<(f32, f32, f32)>, // (centre x, button-row top, gap half-width)
    target_row_right: f32, // right edge of the Threads box, to align the Adapter row
    progress_top: f32,     // y of the progress bar top, to size the radar
    title_end_y: f32, // bottom of the title/theme row
    status_path: Option<(String, std::path::PathBuf)>, // status text + file it refers to   // where "Update vendors" is - the radar centres on it
    title_end: f32,             // right edge of the title + company name
    select_all_pending: bool,
    known_backups: Vec<std::path::PathBuf>, // saved scans written or opened outside Documents (for Erase all data)
    dhcp_names: HashMap<String, String>, // MAC -> hostname heard by the DHCP listener
    dhcp_stop: Option<Arc<AtomicBool>>,
    dhcp_state: String,                  // status-bar text while the listener is enabled
    show_vendor: bool,                   // Manufacturer column shown
    hscroll: f32,                        // table's horizontal scroll (arrow keys only)
    hscroll_at: Option<Instant>,         // last arrow-key scroll (brightens the bar briefly)
    vscroll_rows: f32,                   // Up / Down presses waiting to scroll the results (rows; + = down)
    vscroll_off: f32,                    // results' vertical scroll position, last frame
    vscroll_max: f32,                    // how far the results can scroll, last frame
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        store::migrate_old_files();
        let settings = store::load_settings();
        let theme = Theme::from_name(settings.get("theme").map(String::as_str).unwrap_or(""));
        let pal = theme.pal();
        setup_fonts(&cc.egui_ctx);
        apply_theme(&cc.egui_ctx, &pal);
        let (tx, rx) = channel();
        let mut app = App {
            tx,
            rx,
            theme,
            pal,
            adapters: Vec::new(),
            sel: 0,
            my_ips: HashSet::new(),
            subnet: String::new(),
            names: match settings.get("name_src").and_then(|v| v.parse::<u8>().ok()) {
                Some(n) => n,
                None if settings.get("names").map(|v| v == "0").unwrap_or(false) => 0, // v1.3 "Resolve names" off
                None => scan::N_DEFAULT,
            },
            workers: settings.get("threads").and_then(|v| v.parse().ok()).unwrap_or(256),
            rows: Vec::new(),
            sel_ips: HashSet::new(),
            anchor: None,
            hover_row: None,
            sort: (C_IP, false),
            oui: HashMap::new(),
            oui_note: "loading vendors".into(),
            devices: store::load_devices(),
            ssdp: HashMap::new(),
            mdns: HashMap::new(),
            stop: Arc::new(AtomicBool::new(false)),
            scanning: false,
            pings_pending: 0,
            loading_vendors: false,
            done: 0,
            total: 0,
            t0: Instant::now(),
            net_text: String::new(),
            phase: String::new(),
            status: "Ready".into(),
            edit: None,
            confirm_big: None,
            snapshot_pending: false,
            confirm_erase: None,
            flash_until: None,
            snap_frames: 0,
            col_w: [140.0, 170.0, 360.0, 300.0, 170.0, 120.0],
            pw: None,
            restore_choice: None,
            clip: None,
            filter: String::new(),
            focus_filter: false,
            count_filter: Filter::None,
            confirm_forget: None,
            conflicts: Vec::new(),
            video_running: false,
            ps: None,
            win_size: egui::vec2(1400.0, 760.0),
            status_flash: None,
            status_seen: String::new(),
            status_at: Instant::now(),
            ping_batch: Vec::new(),
            gateways: HashSet::new(),
            blips: HashMap::new(),
            manual_pings: HashSet::new(),
            radar_fade: 0.0,
            radar_angle: -std::f32::consts::FRAC_PI_2,
            radar_last: Instant::now(),
            radar_open: false,
            gap_centre: None,
            target_row_right: 620.0,
            progress_top: 190.0,
            title_end_y: 40.0,
            status_path: None,
            title_end: 520.0,
            select_all_pending: false,
            known_backups: settings.get("backups").map(|v| v.split('|').filter(|x| !x.is_empty()).map(std::path::PathBuf::from).collect()).unwrap_or_default(),
            dhcp_names: store::load_dhcp_names(),
            dhcp_stop: None,
            dhcp_state: String::new(),
            show_vendor: settings.get("show_vendor").map(|v| v != "0").unwrap_or(true),
            hscroll: 0.0,
            hscroll_at: None,
            vscroll_rows: 0.0,
            vscroll_off: 0.0,
            vscroll_max: 0.0,
        };
        app.refresh_adapters();
        app.load_vendors(false, cc.egui_ctx.clone());
        if app.names & scan::N_DHCP != 0 {
            app.set_dhcp_listener(true, &cc.egui_ctx);
        }
        #[cfg(debug_assertions)]
        if let Ok(mode) = std::env::var("MYRIA_DEMO") {
            app.demo(&mode, &cc.egui_ctx);
        }
        app
    }

    /// Debug builds only: fill the table with sample data for layout checks.
    #[cfg(debug_assertions)]
    fn demo(&mut self, mode: &str, ctx: &egui::Context) {
        let data = [
            ("192.168.1.1", "Router/Firewall", "", "TP-Link Systems Inc.", "bc:07:1d:09:31:00", None),
            ("192.168.1.50", "Hikvision NVR", "", "Hangzhou Hikvision Digital Technology Co.,Ltd.", "ec:c8:9c:97:60:63", Some(Video::Nvr)),
            ("192.168.1.51", "Street Cam 1", "IPC-T250H-MU GREY20240819AAWRFM3792057.local  [mDNS]", "Hangzhou Hikvision Digital Technology Co.,Ltd.", "5c:34:5b:b3:dd:03", Some(Video::Camera)),
            ("192.168.1.54", "", "", "Shenzhen Vatilon Electronics Co.,Ltd", "e8:b7:23:41:75:61", Some(Video::Stream)),
            ("192.168.1.66", "Workstation", "DESKTOP-AC5MDDM  [DNS]", "ASUSTek COMPUTER INC.", "38:2c:4a:64:19:27", None),
            ("192.168.1.80", "YSF-Reflector", "YSF-Reflector.local  [mDNS]", "Raspberry Pi Trading Ltd", "e4:5f:01:98:f7:ee", None),
            ("192.168.1.103", "", "Android.local  [mDNS]", "(Private / randomised)", "e6:a8:28:65:37:84", None),
            ("192.168.1.195", "", "", "LiteON", "6c:4b:90:5c:4f:e1", None),
            ("192.168.1.254", "Extreme Networks", "", "Extreme Networks, Inc.", "00:04:96:a1:70:c8", None),
        ];
        for (k, (ip, label, host, vendor, mac, video)) in data.iter().enumerate() {
            let ip: Ipv4Addr = ip.parse().unwrap();
            let (ping, ping_state) = if k == 7 { ("No reply".to_string(), PingState::NoReply) } else { (format!("OK  {} ms", k * 3), PingState::Ok) };
            self.rows.push(Row {
                ip, label: label.to_string(), host: host.to_string(), vendor: vendor.to_string(), mac: mac.to_string(),
                me: ip == Ipv4Addr::new(192, 168, 1, 66), gw: ip == Ipv4Addr::new(192, 168, 1, 1), random_mac: vendor.starts_with('('), video: *video,
                video_desc: "DS-7608NI-K2".into(), ping, ping_state, rt_ms: [0.6, 1.1, 2.2, 4.4, 0.2, 0.9, 260.0, 410.0, 1.0][k], ping_flash: None, open_rtsp: String::new(), open_snapshot: String::new(), absent: false, sort_ip: u32::from(ip), names: Default::default(), last_ip: None });
        }
        self.subnet = "192.168.1.0/24".into();
        self.net_text = "192.168.1.0/24".into();
        self.total = 488;
        self.done = 488;
        self.status = "Done - 9 devices on 192.168.1.0/24 in 18.7s".into();
        if mode == "ports" {
            self.open_port_scan(Some(3), false, ctx);
            if let Some(ps) = self.ps.as_mut() {
                ps.total = 1024;
                ps.done = 1024;
                for (port, st, b) in [(80u16, PortState::Open, "Server: webserver"), (443, PortState::Open, "TLS"), (554, PortState::Open, "RTSP/1.0 401 Unauthorized"), (23, PortState::Open, ""), (22, PortState::Closed, "")] {
                    ps.results.push(PortRow { ip: Ipv4Addr::new(192, 168, 1, 54), port, state: st, banner: b.into() });
                }
            }
        }
        if mode == "sweep" {
            self.scanning = true;
            self.radar_fade = 1.0;
        }
        if mode == "radar" {
            self.radar_open = true;
            self.scanning = true; // keep the sweep running for the screenshot
            self.radar_fade = 1.0;
        }
        if mode == "absent" {
            // pretend two labelled devices from a previous scan are missing now
            for (mac, ip) in [("aa:bb:cc:00:11:22", "192.168.1.60"), ("aa:bb:cc:00:11:23", "192.168.1.61")] {
                self.devices.insert(mac.into(), DeviceInfo { label: if ip.ends_with("60") { "Front Doorbell".into() } else { "Shed Cam".into() }, notes: String::new(), last_ip: ip.into() });
            }
            self.add_absent_rows();
            self.resort();
        }
        if mode == "insecure" {
            if let Some(r) = self.rows.iter_mut().find(|r| r.ip == Ipv4Addr::new(192, 168, 1, 54)) {
                r.video = Some(Video::Camera);
                r.open_rtsp = "rtsp://192.168.1.54:554/live".into();
                r.open_snapshot = "http://192.168.1.54/snapshot.jpg".into();
            }
        }
        if mode == "restore" {
            let mut m = HashMap::new();
            m.insert("6c:4b:90:5c:4f:e1".to_string(), DeviceInfo { label: "Printer".into(), notes: String::new(), last_ip: String::new() });
            self.restore_choice = Some(m);
        }
        if mode == "erase" {
            self.confirm_erase = Some((2, vec![std::path::PathBuf::from("a.mls"), std::path::PathBuf::from("b.mlb"), std::path::PathBuf::from("c.mlb")], false));
        }
        if mode == "pingflash" {
            let now = Instant::now();
            for r in self.rows.iter_mut().take(8) {
                r.ping_flash = Some(now + Duration::from_millis(5000)); // peaks ~5.5 s in, for screenshots
            }
        }
        if mode == "multi" {
            for ip in ["192.168.1.51", "192.168.1.54", "192.168.1.80"] {
                self.sel_ips.insert(ip.parse().unwrap());
            }
            self.open_port_scan(None, false, ctx);
        }
        if mode == "flash" {
            self.status_flash = Some(Instant::now() + Duration::from_millis(5000)); // flash starts ~5 s in, for screenshots
        }
        if mode == "pw" {
            self.pw = Some(PwDialog { mode: PwMode::SaveScan, pw1: "secret".into(), pw2: String::new(), error: "Use at least 10 characters.".into(), focus: false });
        }
    }

    fn save_settings(&self) {
        let mut s = HashMap::new();
        s.insert("theme".to_string(), self.theme.name().to_string());
        s.insert("threads".to_string(), self.workers.to_string());
        s.insert("name_src".to_string(), self.names.to_string());
        s.insert("show_vendor".to_string(), if self.show_vendor { "1" } else { "0" }.to_string());
        s.insert("backups".to_string(), self.known_backups.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().join("|"));
        s.insert("win".to_string(), format!("{:.0},{:.0}", self.win_size.x, self.win_size.y));
        store::save_settings(&s);
    }

    fn set_theme(&mut self, ctx: &egui::Context, t: Theme) {
        self.theme = t;
        self.pal = t.pal();
        apply_theme(ctx, &self.pal);
        self.save_settings();
    }

    // ------------------------------------------------------------ adapters & vendors
    fn refresh_adapters(&mut self) {
        self.adapters = scan::adapters();
        self.gateways = scan::default_gateways().into_iter().collect();
        self.my_ips = self.adapters.iter().map(|a| a.ip).collect();
        let dip = scan::default_ip();
        self.sel = self.adapters.iter().position(|a| Some(a.ip) == dip).unwrap_or(0);
        self.adapter_chosen();
        if self.adapters.is_empty() {
            self.status = "No IPv4 adapters found - enter a subnet manually".into();
        }
    }

    fn adapter_chosen(&mut self) {
        if let Some(a) = self.adapters.get(self.sel) {
            if let Some((net, p)) = scan::parse_cidr(&format!("{}/{}", a.ip, a.prefix)) {
                self.subnet = format!("{}/{}", net, p);
            }
        }
    }

    /// Offline first: a downloaded copy, else the copy built into the .exe.
    fn load_vendors(&mut self, force_download: bool, ctx: egui::Context) {
        self.loading_vendors = true;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut err = None;
            if force_download || (!store::oui_path().exists() && !store::has_builtin_oui()) {
                let _ = tx.send(Msg::Status("Downloading manufacturer list from IEEE ...".into()));
                ctx.request_repaint();
                if let Err(e) = store::download_oui() {
                    err = Some(e);
                }
            }
            let (m, src) = store::load_oui();
            let note = match src {
                store::OuiSource::Downloaded => "offline copy",
                store::OuiSource::BuiltIn => "built-in",
                store::OuiSource::None => "none",
            };
            let _ = tx.send(Msg::Vendors(m, note.to_string()));
            if let Some(e) = err {
                let _ = tx.send(Msg::Status(format!("Vendor update failed: {} - still using the saved list", e)));
            }
            ctx.request_repaint();
        });
    }

    fn vendor_of(&self, mac: &str, random_mac: bool) -> String {
        if mac.starts_with('(') {
            return String::new();
        }
        if random_mac {
            return "(Private / randomised)".into();
        }
        let key: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).take(6).collect::<String>().to_uppercase();
        self.oui.get(&key).cloned().unwrap_or_default()
    }

    // ------------------------------------------------------------ scanning
    fn start(&mut self, ctx: &egui::Context, confirmed: bool) {
        if self.scanning || self.pings_pending > 0 {
            return;
        }
        let Some((net, pfx)) = scan::parse_cidr(&self.subnet) else {
            self.status = "Enter a subnet like 192.168.1.0/24".into();
            return;
        };
        let hosts = scan::hosts(net, pfx);
        if hosts.len() > 4096 && !confirmed {
            self.confirm_big = Some(hosts.len());
            return;
        }
        self.save_settings();
        self.rows.clear();
        self.sel_ips.clear();
        self.anchor = None;
        self.ssdp.clear();
        self.mdns.clear();
        self.conflicts.clear();
        self.blips.clear();
        self.stop.store(false, Ordering::SeqCst);
        self.scanning = true;
        self.done = 0;
        self.total = hosts.len();
        self.t0 = Instant::now();
        self.net_text = format!("{}/{}", net, pfx);
        self.phase = "Scanning".into();

        let names = self.names;
        let workers = (self.workers.max(1) as usize).min(hosts.len().max(1));
        let (tx, stop, c) = (self.tx.clone(), self.stop.clone(), ctx.clone());
        // is the target our own network? (then a missing MAC means "retry", not "routed")
        let local = self.adapters.iter().any(|a| {
            scan::parse_cidr(&format!("{}/{}", a.ip, a.prefix)).map(|(an, ap)| scan::in_net(a.ip, net, pfx) || scan::in_net(net, an, ap)).unwrap_or(false)
        });
        thread::spawn(move || run_scan(hosts, names, workers, local, tx, stop, c));

        let local = self.my_ips.iter().copied().find(|ip| scan::in_net(*ip, net, pfx));
        if names & scan::N_UPNP != 0 {
            let (tx, c) = (self.tx.clone(), ctx.clone());
            thread::spawn(move || {
                let _ = tx.send(Msg::Ssdp(scan::ssdp_discover(net, pfx, local)));
                c.request_repaint();
            });
        }
        if names & scan::N_MDNS != 0 {
            let (tx2, c2) = (self.tx.clone(), ctx.clone());
            thread::spawn(move || {
                let _ = tx2.send(Msg::Mdns(scan::mdns_discover(net, pfx, local)));
                c2.request_repaint();
            });
        }
    }

    fn ping(&mut self, ctx: &egui::Context, only: Option<usize>) {
        let ips: Vec<Ipv4Addr> = match only {
            Some(i) if i < self.rows.len() => vec![self.rows[i].ip],
            Some(_) => return,
            None => self.rows.iter().filter(|r| !r.absent).map(|r| r.ip).collect(),
        };
        if ips.is_empty() {
            self.status = "Nothing to ping - scan first".into();
            return;
        }
        self.ping_batch.clear();
        for ip in ips {
            self.manual_pings.insert(ip);
            self.ping_ip(ip);
        }
        self.status = format!("Pinging {} ...", devices(self.pings_pending));
        ctx.request_repaint();
    }

    /// Label for a device: by MAC, or - if the MAC couldn't be read - by where that label was last seen.
    fn label_for(&self, mac: &str, ip: Ipv4Addr) -> String {
        if let Some(d) = self.devices.get(mac) {
            return d.label.clone();
        }
        if mac.starts_with('(') {
            let ip = ip.to_string();
            if let Some(d) = self.devices.values().find(|d| d.last_ip == ip && !d.label.is_empty()) {
                return d.label.clone();
            }
        }
        String::new()
    }

    /// After a scan: remember where each labelled device was seen (saved once, only if anything moved).
    fn note_last_ips(&mut self) {
        let mut moved = false;
        for r in &self.rows {
            if let Some(d) = self.devices.get_mut(&r.mac) {
                let ip = r.ip.to_string();
                if d.last_ip != ip {
                    d.last_ip = ip;
                    moved = true;
                }
            }
        }
        if moved {
            let _ = store::save_devices(&self.devices);
        }
    }

    /// Add greyed rows (with their last known address) for labelled devices that weren't found this scan.
    fn add_absent_rows(&mut self) {
        let present: HashSet<String> = self.rows.iter().map(|r| r.mac.clone()).collect();
        let mut added = Vec::new();
        for (k, (mac, d)) in self.devices.iter().filter(|(m, d)| !d.label.is_empty() && !present.contains(*m) && !m.starts_with('(')).enumerate() {
            let random = u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16).map(|b| b & 2 != 0).unwrap_or(false);
            let vendor = self.vendor_of(mac, random);
            let last_ip = d.last_ip.parse::<Ipv4Addr>().ok().filter(|ip| !ip.is_unspecified());
            let sort_ip = last_ip.map(u32::from).unwrap_or(u32::MAX);
            added.push(Row {
                ip: absent_key(k), label: d.label.clone(), host: String::new(), vendor, mac: mac.clone(),
                me: false, gw: false, random_mac: random, video: None, video_desc: String::new(),
                open_rtsp: String::new(), open_snapshot: String::new(), ping: String::new(), ping_state: PingState::None,
                rt_ms: 0.0, ping_flash: None, absent: true, sort_ip, names: dhcp_names_for(&self.dhcp_names, mac), last_ip });
            if let Some(r) = added.last_mut() {
                r.host = merge_names(&r.names);
            }
        }
        self.rows.extend(added);
    }

    /// Add a newly found device row (and its radar dot). Name: UPnP if already heard, else a remembered DHCP name.
    fn add_row(&mut self, ip: Ipv4Addr, mac: String, ms: f32) {
        let me = self.my_ips.contains(&ip);
        let random_mac = !me && u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16).map(|b| b & 2 != 0).unwrap_or(false);
        let mut names: [String; 6] = Default::default();
        names[S_MDNS_SD] = self.mdns.get(&ip).map(|n| strip_mac_suffix(n).to_string()).unwrap_or_default();
        names[S_UPNP] = self.ssdp.get(&ip).cloned().unwrap_or_default();
        names[S_DHCP] = self.dhcp_names.get(&mac).cloned().unwrap_or_default();
        let host = merge_names(&names);
        let vendor = self.vendor_of(&mac, random_mac);
        let label = self.label_for(&mac, ip);
        self.rows.push(Row { ip, label, host, vendor, mac, me, gw: self.gateways.contains(&ip), random_mac, video: None, video_desc: String::new(), open_rtsp: String::new(), open_snapshot: String::new(), ping: String::new(), ping_state: PingState::None, rt_ms: ms.max(0.1), ping_flash: None, absent: false, sort_ip: u32::from(ip), names, last_ip: None });
        self.blips.insert(ip, Blip { from: radar_frac(ms), at: Instant::now(), flash: Instant::now() });
    }

    /// Start or stop the passive DHCP listener.
    fn set_dhcp_listener(&mut self, on: bool, ctx: &egui::Context) {
        if let Some(s) = self.dhcp_stop.take() {
            s.store(true, Ordering::SeqCst);
        }
        self.dhcp_state.clear();
        if !on {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.dhcp_stop = Some(stop.clone());
        self.dhcp_state = "DHCP: starting".into();
        let (tx, tx2, c, c2) = (self.tx.clone(), self.tx.clone(), ctx.clone(), ctx.clone());
        thread::spawn(move || {
            scan::dhcp_listen(
                stop,
                move |r| {
                    let _ = tx.send(Msg::DhcpState(r));
                    c.request_repaint();
                },
                move |seen| {
                    let _ = tx2.send(Msg::Dhcp(seen));
                    c2.request_repaint();
                },
            )
        });
    }

    /// A hostname heard in a DHCP broadcast: remember it, fill a blank name, flash the radar dot.
    /// A device the scan missed is added (when its address is in the target range and no scan is running).
    fn dhcp_heard(&mut self, seen: scan::DhcpSeen) -> bool {
        if self.dhcp_stop.is_none() {
            return false; // switched off while the packet was in flight
        }
        if self.dhcp_names.get(&seen.mac) != Some(&seen.host) {
            self.dhcp_names.insert(seen.mac.clone(), seen.host.clone());
            let _ = store::save_dhcp_names(&self.dhcp_names);
        }
        let now = Instant::now();
        let ip = if let Some(i) = self.rows.iter().position(|r| r.mac == seen.mac && !r.absent) {
            let r = &mut self.rows[i];
            r.set_name(S_DHCP, &seen.host);
            let shown = self.blips.get(&r.ip).map(|b| b.current(eff_ms(r))).unwrap_or(radar_frac(eff_ms(r)));
            self.blips.insert(r.ip, Blip { from: shown, at: now, flash: now });
            r.ip
        } else {
            let target = scan::parse_cidr(if self.net_text.is_empty() { &self.subnet } else { &self.net_text });
            let Some(ip) = seen.ip.filter(|ip| !self.scanning && target.map(|(n, p)| scan::in_net(*ip, n, p)).unwrap_or(false) && self.row_index(*ip).is_none()) else {
                return false; // the scan will pick the name up from the cache when it finds the device
            };
            self.rows.retain(|r| !(r.absent && r.mac == seen.mac)); // a greyed "not found" row comes back to life
            self.add_row(ip, seen.mac.clone(), 1000.0);
            if let Some(r) = self.rows.last_mut() {
                r.ping = "pinging...".into();
                r.ping_state = PingState::Pending;
            }
            let tx = self.tx.clone();
            thread::spawn(move || {
                let e = scan::echo(ip);
                let _ = tx.send(Msg::QuietPing(ip, e));
            });
            ip
        };
        if !self.scanning && self.pings_pending == 0 {
            self.status = format!("DHCP: {} is {} ({})", ip, seen.host, seen.mac);
            self.status_flash = Some(Instant::now()); // same yellow flash as a ping result
        }
        true
    }

    /// Ping a "not found this scan" device at its last known address.
    fn ping_absent(&mut self, i: usize) {
        let Some(r) = self.rows.get_mut(i) else { return };
        let Some(ip) = r.last_ip else { return };
        r.ping = "pinging...".into();
        r.ping_state = PingState::Pending;
        let mac = r.mac.clone();
        self.status = format!("Pinging {} (last known address) ...", ip);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let e = scan::echo(ip);
            let _ = tx.send(Msg::AbsentPinged(mac, ip, e));
        });
    }

    fn ping_ip(&mut self, ip: Ipv4Addr) {
        let Some(i) = self.row_index(ip) else { return };
        let want_mac = self.rows[i].mac.starts_with('(') && self.is_local(ip);
        let r = &mut self.rows[i];
        if r.ping_state == PingState::Pending {
            return;
        }
        r.ping = "pinging...".into();
        r.ping_state = PingState::Pending;
        self.pings_pending += 1;
        self.ping_batch.push(ip);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let e = scan::echo(ip);
            // a device on our own network with no MAC yet: the ping just put it in Windows' cache
            #[cfg(windows)]
            if want_mac && matches!(e, Echo::Ok(_)) {
                if let Some(m) = scan::win::arp_probe(ip) {
                    let _ = tx.send(Msg::Mac(ip, m));
                }
            }
            #[cfg(not(windows))]
            let _ = want_mac;
            let _ = tx.send(Msg::Pinged(ip, e));
        });
    }

    /// Is this address on one of this PC's own networks?
    fn is_local(&self, ip: Ipv4Addr) -> bool {
        self.adapters.iter().any(|a| scan::parse_cidr(&format!("{}/{}", a.ip, a.prefix)).map(|(n, p)| scan::in_net(ip, n, p)).unwrap_or(false))
    }

    fn row_index(&self, ip: Ipv4Addr) -> Option<usize> {
        self.rows.iter().position(|r| r.ip == ip)
    }

    fn resort(&mut self) {
        let (c, rev) = self.sort;
        self.rows.sort_by(|a, b| {
            let o = if c == C_IP { a.sort_ip.cmp(&b.sort_ip) } else { a.cell(c).to_lowercase().cmp(&b.cell(c).to_lowercase()) };
            if rev {
                o.reverse()
            } else {
                o
            }
        });
    }

    fn handle_messages(&mut self) {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Tick => self.done += 1,
                Msg::AddTotal(n) => self.total += n,
                Msg::Phase(p) => self.phase = p,
                Msg::Found(ip, mac, ms, echo) => {
                    if let Some(i) = self.row_index(ip) {
                        let old = &self.rows[i].mac;
                        if old != &mac && !old.starts_with('(') && !mac.starts_with('(') {
                            self.conflicts.push(format!("{} answered from two different MAC addresses ({} and {}) - possible IP conflict or ARP spoofing", ip, old, mac));
                        }
                        continue;
                    }
                    self.add_row(ip, mac, ms);
                    if let Some(e) = echo {
                        let r = self.rows.last_mut().unwrap();
                        (r.ping, r.ping_state) = ping_text(e);
                    }
                    changed = true;
                }
                Msg::Name(ip, src, n) => {
                    if let Some(i) = self.row_index(ip) {
                        if self.rows[i].set_name(src, &n) {
                            changed = self.sort.0 == C_HOST || changed;
                        }
                    }
                }
                Msg::Mdns(map) => {
                    for r in self.rows.iter_mut().filter(|r| !r.absent) {
                        if let Some(n) = map.get(&r.ip) {
                            r.set_name(S_MDNS_SD, n);
                        }
                    }
                    self.mdns = map;
                    changed = true;
                }
                Msg::Ssdp(map) => {
                    for r in self.rows.iter_mut().filter(|r| !r.absent) {
                        if let Some(n) = map.get(&r.ip) {
                            r.set_name(S_UPNP, n);
                        }
                    }
                    self.ssdp = map;
                    changed = true;
                }
                Msg::Vendors(oui, note) => {
                    self.oui = oui;
                    self.loading_vendors = false;
                    self.oui_note = format!("{} vendors ({})", self.oui.len(), note);
                    for i in 0..self.rows.len() {
                        let v = self.vendor_of(&self.rows[i].mac, self.rows[i].random_mac);
                        self.rows[i].vendor = v;
                    }
                    if !self.scanning && self.oui.is_empty() {
                        self.status = "No vendor list - connect to the internet once and click UPDATE VENDORS".into();
                    }
                }
                Msg::Pinged(ip, e) => {
                    self.pings_pending = self.pings_pending.saturating_sub(1);
                    let manual = self.manual_pings.remove(&ip);
                    if let Some(i) = self.row_index(ip) {
                        let now = Instant::now();
                        let r = &mut self.rows[i];
                        // glide the radar dot from where it is now to its new distance
                        let shown = self.blips.get(&ip).map(|b| b.current(eff_ms(r))).unwrap_or(radar_frac(eff_ms(r)));
                        if let Echo::Ok(ms) = e {
                            r.rt_ms = (ms as f32).max(0.1);
                        }
                        self.blips.insert(ip, Blip { from: shown, at: now, flash: now });
                        if manual {
                            r.ping_flash = Some(now);
                        }
                        (r.ping, r.ping_state) = ping_text(e);
                    }
                    if self.pings_pending == 0 && !self.scanning {
                        let batch: Vec<&Row> = self.ping_batch.iter().filter_map(|ip| self.rows.iter().find(|r| r.ip == *ip)).collect();
                        self.status = if batch.len() == 1 {
                            let r = batch[0];
                            let name = if r.label.is_empty() { String::new() } else { format!(" ({})", r.label) };
                            format!("Ping {}{}: {}", r.ip, name, r.ping)
                        } else {
                            let ok = batch.iter().filter(|r| r.ping_state == PingState::Ok).count();
                            format!("Ping complete - {} of {} replied", ok, batch.len())
                        };
                        self.ping_batch.clear();
                        self.status_flash = Some(Instant::now());
                    } else {
                        self.status = format!("Pinging ... {} still waiting", self.pings_pending);
                    }
                    if self.sort.0 == C_PING {
                        changed = true;
                    }
                }
                Msg::Video(ip, v, desc) => {
                    if let Some(i) = self.row_index(ip) {
                        let r = &mut self.rows[i];
                        // ONVIF's camera/NVR verdict beats a bare RTSP answer
                        if r.video.is_none() || r.video == Some(Video::Stream) {
                            r.video = Some(v);
                        }
                        if !desc.is_empty() {
                            r.video_desc = desc;
                        }
                    }
                }
                Msg::Stream(ip, open) => {
                    if let Some(i) = self.row_index(ip) {
                        self.rows[i].open_rtsp = open.rtsp.unwrap_or_default();
                        self.rows[i].open_snapshot = open.snapshot.unwrap_or_default();
                        changed = true;
                    }
                }
                Msg::VideoDone => {
                    self.video_running = false;
                    let n = self.rows.iter().filter(|r| r.video.is_some()).count();
                    if n > 0 && !self.scanning {
                        self.status = format!("{} - {} video device(s) confirmed", self.status, n);
                    }
                }
                Msg::Port(pr) => {
                    if let Some(ps) = self.ps.as_mut() {
                        ps.results.push(pr);
                    }
                }
                Msg::PortTick => {
                    if let Some(ps) = self.ps.as_mut() {
                        ps.done += 1;
                    }
                }
                Msg::PortPhase(t) => {
                    if let Some(ps) = self.ps.as_mut() {
                        ps.phase = t;
                    }
                }
                Msg::PortDone => {
                    self.status_flash = Some(Instant::now());
                    if let Some(ps) = self.ps.as_ref() {
                        let open: Vec<&PortRow> = ps.results.iter().filter(|r| r.state == PortState::Open).collect();
                        let hosts: HashSet<Ipv4Addr> = open.iter().map(|r| r.ip).collect();
                        let risky = open.iter().filter(|r| scan::risk_note(r.port).is_some()).count();
                        self.status = format!(
                            "Port scan complete - {} open port{} on {}{}",
                            open.len(),
                            if open.len() == 1 { "" } else { "s" },
                            devices(hosts.len()),
                            if risky > 0 { format!(" ({} risky)", risky) } else { String::new() }
                        );
                    }
                    if let Some(ps) = self.ps.as_mut() {
                        ps.running = false;
                        ps.done = ps.total;
                        ps.results.sort_by_key(|r| (u32::from(r.ip), r.port));
                    }
                }
                Msg::Mac(ip, mac) => {
                    if let Some(i) = self.row_index(ip) {
                        let real = !mac.starts_with('(');
                        let random = real && u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16).map(|b| b & 2 != 0).unwrap_or(false) && !self.rows[i].me;
                        let vendor = if real { self.vendor_of(&mac, random) } else { String::new() };
                        let label = self.label_for(&mac, ip);
                        let dhcp = self.dhcp_names.get(&mac).cloned();
                        let r = &mut self.rows[i];
                        if let Some(h) = dhcp {
                            r.set_name(S_DHCP, &h);
                        }
                        r.mac = mac;
                        r.random_mac = random;
                        r.vendor = vendor;
                        if !label.is_empty() {
                            r.label = label;
                        }
                        changed = true;
                    }
                }
                Msg::Status(s) => self.status = s,
                Msg::DhcpState(r) => {
                    if self.dhcp_stop.is_some() {
                        self.dhcp_state = match r {
                            Ok(()) => "DHCP: listening".into(),
                            Err(e) => format!("DHCP: unavailable ({})", e),
                        };
                    }
                }
                Msg::Dhcp(seen) => {
                    changed |= self.dhcp_heard(seen);
                }
                Msg::AbsentPinged(mac, ip, e) => {
                    if let Some(r) = self.rows.iter_mut().find(|r| r.absent && r.mac == mac) {
                        (r.ping, r.ping_state) = ping_text(e);
                        r.ping_flash = Some(Instant::now());
                        let name = if r.label.is_empty() { String::new() } else { format!(" ({})", r.label) };
                        // that address may have been handed to something else since
                        let other = self.rows.iter().find(|x| !x.absent && x.ip == ip && x.mac != mac);
                        let note = match (e, other) {
                            (Echo::Ok(_), Some(o)) => format!(" - but that address now belongs to {}", if o.label.is_empty() { o.mac.clone() } else { o.label.clone() }),
                            _ => String::new(),
                        };
                        let r = self.rows.iter().find(|r| r.absent && r.mac == mac).unwrap();
                        self.status = format!("Ping {}{} (last known address): {}{}", ip, name, r.ping, note);
                        self.status_flash = Some(Instant::now());
                    }
                }
                Msg::QuietPing(ip, e) => {
                    if let Some(i) = self.row_index(ip) {
                        let now = Instant::now();
                        let r = &mut self.rows[i];
                        let shown = self.blips.get(&ip).map(|b| b.current(eff_ms(r))).unwrap_or(radar_frac(eff_ms(r)));
                        if let Echo::Ok(ms) = e {
                            r.rt_ms = (ms as f32).max(0.1);
                        }
                        (r.ping, r.ping_state) = ping_text(e);
                        self.blips.insert(ip, Blip { from: shown, at: now, flash: now });
                        changed |= self.sort.0 == C_PING;
                    }
                }
                Msg::Done => {
                    self.scanning = false;
                    self.note_last_ips();
                    self.status_flash = Some(Instant::now());
                    let mut by_mac: HashMap<&str, Vec<String>> = HashMap::new();
                    for r in self.rows.iter().filter(|r| !r.random_mac && !r.mac.starts_with('(')) {
                        by_mac.entry(r.mac.as_str()).or_default().push(r.ip.to_string());
                    }
                    let mut multi: Vec<String> = by_mac
                        .into_iter()
                        .filter(|(_, ips)| ips.len() > 1)
                        .map(|(m, ips)| format!("{} answers on {} - one device with several addresses, or ARP spoofing", m, ips.join(", ")))
                        .collect();
                    multi.sort();
                    self.conflicts.extend(multi);
                    self.add_absent_rows();
                    self.start_video_detection();
                    self.flash_until = Some(Instant::now() + Duration::from_millis(1000));
                    self.done = self.total;
                    self.status = format!(
                        "{} - {} on {} in {:.1}s",
                        if self.stop.load(Ordering::SeqCst) { "Stopped" } else { "Done" },
                        devices(self.rows.len()),
                        self.net_text,
                        self.t0.elapsed().as_secs_f32()
                    );
                }
            }
        }
        if changed {
            self.resort();
        }
        if self.scanning {
            self.status = format!("{} {} ... {} found", self.phase, self.net_text, self.rows.len());
        }
    }

    // ------------------------------------------------------------ actions
    fn copy(&mut self, ctx: &egui::Context, i: usize, col: Option<usize>) {
        if let Some(r) = self.rows.get(i) {
            let one = |r: &Row| match col {
                Some(c) => r.cell(c),
                None => (0..HEAD.len()).map(|c| r.cell(c)).collect::<Vec<_>>().join("\t"),
            };
            let text = if self.sel_ips.len() > 1 && self.sel_ips.contains(&r.ip) {
                self.rows.iter().filter(|x| self.sel_ips.contains(&x.ip)).map(one).collect::<Vec<_>>().join("\n")
            } else {
                one(r)
            };
            self.clip = Some((platform::text_hash(&text), Instant::now()));
            ctx.output_mut(|o| o.copied_text = text);
            self.status = format!("Copied - the clipboard clears in {} seconds", CLIP_SECS);
        }
    }

    fn save_edit(&mut self, mac: String, label: String) {
        let label = label.trim().to_string();
        let notes = self.devices.get(&mac).map(|d| d.notes.clone()).unwrap_or_default();
        if label.is_empty() && notes.is_empty() {
            self.devices.remove(&mac);
        } else {
            let last_ip = self.rows.iter().find(|r| r.mac == mac && !r.absent).map(|r| r.ip.to_string())
                .or_else(|| self.devices.get(&mac).map(|d| d.last_ip.clone()))
                .unwrap_or_default();
            self.devices.insert(mac.clone(), DeviceInfo { label: label.clone(), notes, last_ip });
        }
        for r in self.rows.iter_mut().filter(|r| r.mac == mac) {
            r.label = label.clone();
        }
        self.status = match store::save_devices(&self.devices) {
            Ok(_) => format!("Label saved to {}", store::devices_path().display()),
            Err(e) => format!("Could not save: {}", e),
        };
        if self.sort.0 == C_LABEL {
            self.resort();
        }
    }

    fn erase_everything(&mut self, also_saved: Vec<std::path::PathBuf>) {
        self.stop.store(true, Ordering::SeqCst);
        let n_saved = also_saved.len();
        let (n, errors) = store::secure_erase_all(&also_saved);
        if n_saved > 0 {
            self.known_backups.retain(|p| p.exists());
            self.save_settings();
        }
        self.wipe(); // overwrite results, labels, port results, passwords and our clipboard text in memory
        self.adapter_chosen();
        self.sel_ips.clear();
        self.anchor = None;
        self.total = 0;
        self.done = 0;
        self.status_flash = Some(Instant::now());
        self.status = if errors.is_empty() {
            format!("Securely erased {} file(s) and cleared memory. No scanner data remains on this PC.", n)
        } else {
            format!("Erased {} file(s); {} could not be erased: {}", n, errors.len(), errors.join(", "))
        };
    }

    /// ONVIF discovery + RTSP probe on every device found. Only confirmed video devices are marked.
    fn start_video_detection(&mut self) {
        let ips: Vec<Ipv4Addr> = self.rows.iter().map(|r| r.ip).collect();
        if ips.is_empty() {
            return;
        }
        self.video_running = true;
        let local = self.adapters.get(self.sel).map(|a| a.ip);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let onvif = scan::onvif_discover(local);
            for (ip, (v, desc)) in &onvif {
                let _ = tx.send(Msg::Video(*ip, *v, desc.clone()));
            }
            for ip in onvif.keys().copied().collect::<Vec<_>>() {
                let tx = tx.clone();
                thread::spawn(move || {
                    let open = scan::open_stream(ip);
                    if open.any() {
                        let _ = tx.send(Msg::Stream(ip, open));
                    }
                });
            }
            let hs: Vec<_> = ips
                .into_iter()
                .map(|ip| {
                    let tx = tx.clone();
                    thread::spawn(move || {
                        let rtsp = scan::rtsp_probe(ip);
                        if rtsp {
                            let _ = tx.send(Msg::Video(ip, Video::Stream, String::new()));
                        }
                        // only look for OPEN streams on things that are actually cameras
                        if rtsp {
                            let open = scan::open_stream(ip);
                            if open.any() {
                                let _ = tx.send(Msg::Stream(ip, open));
                            }
                        }
                    })
                })
                .collect();
            for h in hs {
                let _ = h.join();
            }
            let _ = tx.send(Msg::VideoDone);
        });
    }

    fn open_port_scan(&mut self, i: Option<usize>, quick: bool, ctx: &egui::Context) {
        // right-clicking an unselected row makes it the selection
        if let Some(ip) = i.and_then(|i| self.rows.get(i)).map(|r| r.ip) {
            if !self.sel_ips.contains(&ip) {
                self.sel_ips.clear();
                self.sel_ips.insert(ip);
                self.anchor = Some(ip);
            }
        }
        let keep = self.ps.take();
        let mut ps = PortScanUi {
            target: if self.sel_ips.is_empty() { PsTarget::All } else { PsTarget::Selected },
            ports: keep.as_ref().map(|k| k.ports.clone()).unwrap_or_else(|| scan::PRESETS[0].1.to_string()),
            timeout_ms: keep.as_ref().map(|k| k.timeout_ms).unwrap_or(400),
            parallel: keep.as_ref().map(|k| k.parallel).unwrap_or(200),
            per_host: keep.as_ref().map(|k| k.per_host).unwrap_or(12),
            phase: String::new(),
            grab: keep.as_ref().map(|k| k.grab).unwrap_or(true),
            show_closed: false,
            results: Vec::new(),
            running: false,
            done: 0,
            total: 0,
            error: String::new(),
            stop: Arc::new(AtomicBool::new(false)),
        };
        if quick {
            ps.ports = scan::PRESETS[0].1.to_string();
        }
        self.ps = Some(ps);
        if quick {
            self.run_port_scan(ctx);
        }
    }

    fn run_port_scan(&mut self, ctx: &egui::Context) {
        let targets: Vec<Ipv4Addr> = {
            let Some(ps) = self.ps.as_ref() else { return };
            match ps.target {
                PsTarget::Selected => self.rows.iter().filter(|r| self.sel_ips.contains(&r.ip)).map(|r| r.ip).collect(),
                PsTarget::Video => self.rows.iter().filter(|r| r.video.is_some()).map(|r| r.ip).collect(),
                PsTarget::All => self.rows.iter().map(|r| r.ip).collect(),
            }
        };
        let Some(ps) = self.ps.as_mut() else { return };
        let ports = match scan::parse_ports(&ps.ports) {
            Ok(p) => p,
            Err(e) => {
                ps.error = e;
                return;
            }
        };
        if targets.is_empty() {
            ps.error = if ps.target == PsTarget::Selected {
                "No devices selected - click rows in the main list (Ctrl+click for several, Shift+click for a range)".into()
            } else {
                "No target devices - scan the network first".into()
            };
            return;
        }
        ps.error.clear();
        ps.results.clear();
        ps.running = true;
        ps.done = 0;
        ps.total = targets.len() * ports.len();
        ps.stop = Arc::new(AtomicBool::new(false));
        ps.phase = "Scanning".into();
        let n_targets = targets.len();
        let n_ports = ports.len();
        let (timeout, total_par, per_host, grab) = (ps.timeout_ms as u64, ps.parallel.max(1) as usize, ps.per_host.max(1) as usize, ps.grab);
        let (tx, stop, c) = (self.tx.clone(), ps.stop.clone(), ctx.clone());
        self.status = format!("Port scanning {} on {} ...", devices(n_targets), if n_ports == 1 { "1 port".to_string() } else { format!("{} ports", n_ports) });
        thread::spawn(move || {
            run_ports(targets, ports, timeout, total_par, per_host, grab, &tx, &stop);
            let _ = tx.send(Msg::PortDone);
            c.request_repaint();
        });
    }

    /// Column widths, recomputed every frame: every column except Ping is exactly as wide as its widest
    /// content (heading included), so nothing is cropped and nothing is wider than it needs to be.
    /// Ping gets a fixed minimum (its widest possible text) and takes whatever space is left, so
    /// changing ping times never change the table's width.
    fn fit_widths(&self, ctx: &egui::Context) -> [f32; 6] {
        let body = FontId::proportional(15.0);
        let mono = FontId::monospace(14.5);
        let w = |s: &str, f: FontId| ctx.fonts(|fs| fs.layout_no_wrap(s.to_string(), f, Color32::WHITE).size().x);
        let sp = ctx.style().spacing.item_spacing.x; // gap egui puts between labels in a cell
        let btn = ctx.style().spacing.button_padding.x;
        let arrow = "  \u{25B2}";
        let mut cw = [0f32; 6];
        for (i, h) in HEAD.iter().enumerate() {
            // headings are frameless buttons (padded both sides); Ping's is a plain label after PAD
            let t = w(&format!("{}{}", h.to_uppercase(), arrow), body.clone());
            cw[i] = if i == C_PING { PAD + t } else { t + 2.0 * btn };
        }
        for r in &self.rows {
            cw[C_IP] = cw[C_IP].max(PAD + w(&r.cell(C_IP), mono.clone()));
            cw[C_LABEL] = cw[C_LABEL].max(PAD + w(if r.label.is_empty() && !r.me { "Unknown device" } else { &r.label }, body.clone()));
            // Hostname: the same pieces, in the same fonts, that the cell draws
            let mut parts: Vec<f32> = Vec::new();
            if let Some(v) = r.video {
                parts.push(w(&format!(" {} ", v.tag()), FontId::proportional(11.5)));
            }
            if !r.open_rtsp.is_empty() || !r.open_snapshot.is_empty() {
                parts.push(w(" OPEN STREAM ", FontId::proportional(11.0)));
            }
            for (k, part) in r.host.split(HOST_SEP).filter(|x| !x.is_empty()).enumerate() {
                if k > 0 {
                    parts.push(w("\u{00B7}", body.clone()));
                }
                match part.split_once("  [") {
                    Some((n, t)) => {
                        parts.push(w(n, body.clone()));
                        parts.push(w(&format!("[{}", t), FontId::proportional(12.0)));
                    }
                    None => parts.push(w(part, body.clone())),
                }
            }
            if r.me {
                parts.push(w(&format!("({})", THIS_PC), body.clone()));
            } else if r.gw {
                parts.push(w(&format!("({})", GATEWAY), body.clone()));
            }
            if !parts.is_empty() {
                cw[C_HOST] = cw[C_HOST].max(PAD + parts.iter().sum::<f32>() + sp * (parts.len() - 1) as f32);
            }
            cw[C_VENDOR] = cw[C_VENDOR].max(PAD + w(&r.vendor, body.clone()));
            cw[C_MAC] = cw[C_MAC].max(w(&r.mac, mono.clone()) + 2.0 * PAD); // centred: room both sides
        }
        // Ping: wide enough for anything it can show, whatever it shows right now
        for t in ["OK  999 ms", "pinging...", "Unreachable", "No reply", "not found this scan"] {
            cw[C_PING] = cw[C_PING].max(PAD + w(t, body.clone()));
        }
        cw.map(|v| (v + PAD).ceil()) // a little breathing room on the right of every column
    }

    fn start_save_scan(&mut self) {
        if self.rows.is_empty() {
            self.status = "Nothing to save yet - scan first".into();
            return;
        }
        self.pw = Some(PwDialog { mode: PwMode::SaveScan, pw1: String::new(), pw2: String::new(), error: String::new(), focus: true });
    }

    fn start_open_scan(&mut self) {
        let Some(path) = platform::open_dialog("Open saved scan", &store::output_dir(), "mls", "DevEcho Network Scanner saved scan") else { return };
        self.remember_file(&path);
        match std::fs::read(&path) {
            Ok(data) => self.pw = Some(PwDialog { mode: PwMode::OpenScan(data), pw1: String::new(), pw2: String::new(), error: String::new(), focus: true }),
            Err(e) => self.status = format!("Couldn't read {}: {}", path.display(), e),
        }
    }

    fn load_scan(&mut self, mut ls: LoadedScan) {
        self.stop.store(true, Ordering::SeqCst);
        let before = self.dhcp_names.len();
        for (mac, h) in ls.dhcp.drain() {
            self.dhcp_names.entry(mac).or_insert(h);
        }
        if self.dhcp_names.len() != before {
            let _ = store::save_dhcp_names(&self.dhcp_names);
        }
        self.wipe_rows();
        self.rows = ls.rows;
        self.sel_ips.clear();
        self.anchor = None;
        self.conflicts.clear();
        self.total = 0;
        self.done = 0;
        if !ls.ports.is_empty() {
            self.open_port_scan(None, false, &egui::Context::default());
            if let Some(ps) = self.ps.as_mut() {
                ps.results = ls.ports;
                ps.total = ps.results.len();
                ps.done = ps.total;
                ps.target = PsTarget::All;
            }
        }
        for r in self.rows.iter_mut().filter(|r| !r.absent) {
            r.gw = self.gateways.contains(&r.ip);
        }
        self.subnet = ls.subnet.clone();
        self.net_text = ls.subnet.clone();
        self.blips.clear();
        let now = Instant::now();
        for r in self.rows.iter().filter(|r| !r.absent) {
            self.blips.insert(r.ip, Blip { from: radar_frac(eff_ms(r)), at: now, flash: now });
        }
        self.status = format!("Viewing saved scan of {} from {} - {}", ls.subnet, ls.saved, devices(self.rows.len()));
        // offer the file's labels to this PC: its label list plus labels shown on its device rows
        let mut offer = ls.labels;
        for r in &self.rows {
            if !r.label.is_empty() && !r.mac.starts_with('(') {
                offer.entry(r.mac.clone()).or_insert(DeviceInfo { label: r.label.clone(), notes: String::new(), last_ip: r.cell(C_IP) });
            }
        }
        let differs = offer.iter().any(|(m, d)| self.devices.get(m).map(|x| x.label != d.label).unwrap_or(true));
        if differs && !offer.is_empty() {
            self.restore_choice = Some(offer);
        }
    }

    fn wipe_rows(&mut self) {
        for r in self.rows.iter_mut() {
            r.label.zeroize();
            r.host.zeroize();
            r.names.iter_mut().for_each(|n| n.zeroize());
            r.vendor.zeroize();
            r.mac.zeroize();
            r.ping.zeroize();
            r.video_desc.zeroize();
        }
        self.rows.clear();
    }

    fn remember_file(&mut self, path: &std::path::Path) {
        self.known_backups.retain(|p| p != path && p.exists());
        self.known_backups.insert(0, path.to_path_buf());
        self.known_backups.truncate(20);
        self.save_settings();
    }

    /// Returns true when the dialog can close.
    fn finish_password(&mut self) -> bool {
        let Some(d) = self.pw.as_mut() else { return true };
        match &d.mode {
            PwMode::SaveScan => {
                if d.pw1.chars().count() < MIN_PW {
                    d.error = format!("Use at least {} characters.", MIN_PW);
                    return false;
                }
                if d.pw1 != d.pw2 {
                    d.error = "The passwords don't match.".into();
                    return false;
                }
                let ports: Vec<PortRow> = self.ps.as_ref().map(|p| p.results.clone()).unwrap_or_default();
                let text = zeroize::Zeroizing::new(scan_to_text(&self.subnet, &self.rows, &ports, &self.devices, &self.dhcp_names));
                let blob = match store::encrypt_blob(store::MAGIC_SCAN, &text, &d.pw1) {
                    Ok(b) => b,
                    Err(e) => {
                        d.error = format!("Encryption failed: {}", e);
                        return false;
                    }
                };
                let name = format!("scan_{}_{}.mls", self.subnet.replace(['/', '.'], "-"), store::timestamp());
                match platform::save_dialog("Save encrypted scan", &name, &store::ensure(&store::output_dir()), "mls", "DevEcho Network Scanner saved scan") {
                    Some(path) => {
                        self.status = match std::fs::write(&path, blob) {
                            Ok(_) => {
                                self.remember_file(&path);
                                self.status_flash = Some(Instant::now());
                                let t = format!("Encrypted scan ({}, {} label(s)) saved to {}  (double-click to open)", devices(self.rows.len()), self.devices.len(), path.display());
                                self.status_path = Some((t.clone(), path.clone()));
                                t
                            }
                            Err(e) => format!("Save failed: {}", e),
                        }
                    }
                    None => self.status = "Save cancelled".into(),
                }
                true
            }
            PwMode::OpenScan(data) => match store::decrypt_blob(store::MAGIC_SCAN, data, &d.pw1).and_then(|t| scan_from_text(&t)) {
                Ok(ls) => {
                    self.load_scan(ls);
                    true
                }
                Err(e) => {
                    d.error = e;
                    d.pw1.zeroize();
                    false
                }
            },
        }
    }

    fn apply_restore(&mut self, mut map: HashMap<String, DeviceInfo>, merge: bool) {
        let n = map.len();
        if !merge {
            for (_, mut v) in self.devices.drain() {
                v.label.zeroize();
                v.notes.zeroize();
            }
        }
        for (k, v) in map.drain() {
            self.devices.insert(k, v);
        }
        for r in self.rows.iter_mut() {
            r.label = self.devices.get(&r.mac).map(|d| d.label.clone()).unwrap_or_default();
        }
        self.status = match store::save_devices(&self.devices) {
            Ok(_) => {
                self.status_flash = Some(Instant::now());
                format!("{} {} label(s)", if merge { "Merged" } else { "Restored" }, n)
            }
            Err(e) => format!("Restore failed: {}", e),
        };
    }

    /// Best-effort wipe of everything sensitive held in memory.
    fn wipe(&mut self) {
        for r in self.rows.iter_mut() {
            r.label.zeroize();
            r.host.zeroize();
            r.names.iter_mut().for_each(|n| n.zeroize());
            r.vendor.zeroize();
            r.mac.zeroize();
            r.ping.zeroize();
        }
        self.rows.clear();
        self.blips.clear();
        for (mut k, mut v) in self.devices.drain() {
            k.zeroize();
            v.label.zeroize();
            v.notes.zeroize();
        }
        for (_, mut v) in self.ssdp.drain() {
            v.zeroize();
        }
        for (mut k, mut v) in self.dhcp_names.drain() {
            k.zeroize();
            v.zeroize();
        }
        if let Some(mut m) = self.restore_choice.take() {
            for (mut k, mut v) in m.drain() {
                k.zeroize();
                v.label.zeroize();
            }
        }
        if let Some(e) = self.edit.as_mut() {
            e.label.zeroize();
            e.mac.zeroize();
        }
        if let Some(ps) = self.ps.as_mut() {
            ps.stop.store(true, Ordering::SeqCst);
            for r in ps.results.iter_mut() {
                r.banner.zeroize();
            }
            ps.results.clear();
        }
        self.filter.zeroize();
        self.pw = None; // PwDialog zeroizes on drop
        self.status.zeroize();
        self.subnet.zeroize();
        if let Some((h, _)) = self.clip.take() {
            platform::clear_clipboard_if(h);
        }
    }

    fn take_snapshot_result(&mut self, ctx: &egui::Context) {
        if !self.snapshot_pending {
            return;
        }
        let img = ctx.input(|i| {
            i.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = img {
            self.snapshot_pending = false;
            let [w, h] = img.size;
            let mut rgba = Vec::with_capacity(w * h * 4);
            for c in &img.pixels {
                let [r, g, b, _] = c.to_array();
                rgba.extend_from_slice(&[r, g, b, 255]);
            }
            let path = store::ensure(&store::output_dir()).join(format!("DevEcho_{}.png", store::timestamp()));
            self.status = match store::save_png(&path, w, h, &rgba) {
                Ok(_) => {
                    let t = format!("Snapshot saved to {}  (double-click to open)", path.display());
                    self.status_path = Some((t.clone(), path.clone()));
                    t
                }
                Err(e) => format!("Snapshot failed: {}", e),
            };
            ctx.style_mut(|s| s.interaction.tooltip_delay = 0.5);
        } else {
            ctx.request_repaint();
        }
    }
}

/// One probing pass over `list` with `workers` threads.
#[cfg_attr(not(windows), allow(dead_code))]
const MAC_PENDING: &str = "(MAC pending)";

/// Per-device DNS / mDNS / NetBIOS lookups (the enabled ones); every answer goes to the table.
fn send_names(ip: Ipv4Addr, mask: u8, tx: &Sender<Msg>) {
    for (bit, n) in scan::hostnames(ip, mask) {
        let _ = tx.send(Msg::Name(ip, src_of_bit(bit), n));
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn arp_pass(list: Vec<Ipv4Addr>, workers: usize, names: u8, local: bool, tx: &Sender<Msg>, stop: &Arc<AtomicBool>, found: &Arc<Mutex<HashSet<Ipv4Addr>>>, pending: &Arc<Mutex<HashSet<Ipv4Addr>>>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(list)));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (q, tx, stop, found, pending) = (queue.clone(), tx.clone(), stop.clone(), found.clone(), pending.clone());
        handles.push(thread::spawn(move || loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Some(ip) = q.lock().unwrap().pop_front() else { break };
            // Ping and ARP for every address: either one answering means the device is there.
            // A successful ping also puts its MAC in Windows' cache, so the ARP lookup is instant.
            let t = Instant::now();
            let echo = scan::win::icmp_echo(ip, 700);
            let t2 = Instant::now();
            let mac = scan::win::arp_probe(ip);
            let arp_ms = t2.elapsed().as_secs_f32() * 1000.0;
            let _ = t;
            let _ = tx.send(Msg::Tick);
            let mac = match (mac, echo) {
                (Some(m), _) => Some(m),
                // answered the ping but the MAC lookup failed: on our own network that's just a
                // lookup that needs retrying; only on another network is there genuinely no MAC
                (None, Echo::Ok(_)) if local => {
                    pending.lock().unwrap().insert(ip);
                    Some(MAC_PENDING.to_string())
                }
                (None, Echo::Ok(_)) => Some("(routed - no MAC)".to_string()),
                _ => None,
            };
            if let Some(mac) = mac {
                if !found.lock().unwrap().insert(ip) {
                    continue;
                }
                let ms = match echo {
                    Echo::Ok(rtt) => rtt as f32,
                    _ => arp_ms,
                };
                let _ = tx.send(Msg::Found(ip, mac, ms, Some(echo))); // row appears now ...
                if names & scan::N_PER_HOST != 0 && !stop.load(Ordering::Relaxed) {
                    send_names(ip, names, &tx); // ... names fill in afterwards
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn run_scan(hosts: Vec<Ipv4Addr>, names: u8, workers: usize, local: bool, tx: Sender<Msg>, stop: Arc<AtomicBool>, ctx: egui::Context) {
    let found: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::new(Mutex::new(HashSet::new()));
    let pending: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::new(Mutex::new(HashSet::new()));

    // Pass 0: likely infrastructure (.1, .2, last two addresses) on its own, before the burst -
    // switches and routers often rate-limit ARP on their management CPU.
    let mut infra: Vec<Ipv4Addr> = Vec::new();
    for ip in hosts.iter().take(2).chain(hosts.iter().rev().take(2)) {
        if !infra.contains(ip) {
            infra.push(*ip);
        }
    }
    let rest: Vec<Ipv4Addr> = hosts.iter().copied().filter(|ip| !infra.contains(ip)).collect();
    arp_pass(infra.clone(), infra.len().max(1), names, local, &tx, &stop, &found, &pending);

    // Pass 1: everything else at once.
    arp_pass(rest, workers, names, local, &tx, &stop, &found, &pending);

    // Pass 2: re-try the silent addresses more gently - sleepy Wi-Fi clients and
    // switches/routers whose management CPU rate-limits ARP miss a 254-request burst.
    let missed: Vec<Ipv4Addr> = {
        let f = found.lock().unwrap();
        hosts.iter().copied().filter(|ip| !f.contains(ip)).collect()
    };
    if !missed.is_empty() && !stop.load(Ordering::Relaxed) {
        let _ = tx.send(Msg::AddTotal(missed.len()));
        let _ = tx.send(Msg::Phase("Second pass".into()));
        ctx.request_repaint();
        arp_pass(missed, workers.min(128), names, local, &tx, &stop, &found, &pending);
    }

    // Devices that answered the ping but whose MAC lookup failed: ask again, slowly.
    let retry: Vec<Ipv4Addr> = pending.lock().unwrap().iter().copied().collect();
    if !retry.is_empty() && !stop.load(Ordering::Relaxed) {
        let _ = tx.send(Msg::Phase("Looking up MAC addresses".into()));
        let q = Arc::new(Mutex::new(VecDeque::from(retry)));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let (q, tx, pending) = (q.clone(), tx.clone(), pending.clone());
                thread::spawn(move || {
                    while let Some(ip) = q.lock().unwrap().pop_front() {
                        for attempt in 0..3 {
                            if let Some(m) = scan::win::arp_probe(ip) {
                                pending.lock().unwrap().remove(&ip);
                                let _ = tx.send(Msg::Mac(ip, m));
                                break;
                            }
                            if attempt < 2 {
                                thread::sleep(Duration::from_millis(250));
                            }
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            let _ = h.join();
        }
    }

    // Finally, anything Windows learned that we didn't catch directly.
    if !stop.load(Ordering::Relaxed) {
        let wanted: HashSet<Ipv4Addr> = hosts.iter().copied().collect();
        let table = scan::win::neighbours();
        for (ip, mac) in &table {
            if pending.lock().unwrap().remove(ip) {
                let _ = tx.send(Msg::Mac(*ip, mac.clone())); // the ping put it in Windows' table
            }
        }
        for ip in pending.lock().unwrap().drain() {
            let _ = tx.send(Msg::Mac(ip, "(no MAC)".into()));
        }
        let late: Vec<(Ipv4Addr, String)> = table
            .into_iter()
            .filter(|(ip, _)| wanted.contains(ip) && found.lock().unwrap().insert(*ip))
            .collect();
        let hs: Vec<_> = late
            .into_iter()
            .map(|(ip, mac)| {
                let _ = tx.send(Msg::Found(ip, mac, 800.0, None)); // answered late
                let tx = tx.clone();
                thread::spawn(move || {
                    if names & scan::N_PER_HOST != 0 {
                        send_names(ip, names, &tx);
                    }
                })
            })
            .collect();
        for h in hs {
            let _ = h.join();
        }
    }
    let _ = tx.send(Msg::Done);
    ctx.request_repaint();
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
fn run_scan(hosts: Vec<Ipv4Addr>, names: u8, workers: usize, _local: bool, tx: Sender<Msg>, stop: Arc<AtomicBool>, ctx: egui::Context) {
    for pass in 0..2 {
        let list: Vec<Ipv4Addr> = if pass == 0 {
            hosts.clone()
        } else {
            let t = scan::arp_table();
            let m: Vec<_> = hosts.iter().copied().filter(|ip| !t.contains_key(ip)).collect();
            let _ = tx.send(Msg::AddTotal(m.len()));
            let _ = tx.send(Msg::Phase("Second pass".into()));
            m
        };
        if stop.load(Ordering::Relaxed) || list.is_empty() {
            break;
        }
        let queue = Arc::new(Mutex::new(VecDeque::from(list)));
        let n = if pass == 0 { workers } else { workers.min(128) };
        let hs: Vec<_> = (0..n)
            .map(|_| {
                let (q, tx, stop) = (queue.clone(), tx.clone(), stop.clone());
                thread::spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(ip) = q.lock().unwrap().pop_front() else { break };
                    scan::ping(ip);
                    let _ = tx.send(Msg::Tick);
                })
            })
            .collect();
        for h in hs {
            let _ = h.join();
        }
    }
    if !stop.load(Ordering::Relaxed) {
        let table = scan::arp_table();
        let found: Vec<Ipv4Addr> = hosts.iter().copied().filter(|ip| table.contains_key(ip)).collect();
        for ip in &found {
            let _ = tx.send(Msg::Found(*ip, table[ip].clone(), 5.0, None));
        }
        ctx.request_repaint();
        if names & scan::N_PER_HOST != 0 {
            let hs: Vec<_> = found
                .into_iter()
                .map(|ip| {
                    let tx = tx.clone();
                    thread::spawn(move || send_names(ip, names, &tx))
                })
                .collect();
            for h in hs {
                let _ = h.join();
            }
        }
    }
    let _ = tx.send(Msg::Done);
    ctx.request_repaint();
}

fn esc_join(fields: &[String]) -> String {
    fields.iter().map(|f| store::csv_escape(f)).collect::<Vec<_>>().join(",")
}

fn ping_code(s: PingState) -> &'static str {
    match s {
        PingState::Ok => "ok",
        PingState::NoReply => "noreply",
        PingState::Unreachable => "unreach",
        _ => "",
    }
}

fn scan_to_text(subnet: &str, rows: &[Row], ports: &[PortRow], labels: &HashMap<String, DeviceInfo>, dhcp: &HashMap<String, String>) -> String {
    let mut t = format!("#myriameter-scan,1\n{}\n", esc_join(&["meta".into(), subnet.into(), store::timestamp()]));
    for r in rows {
        let mut f: Vec<String> = vec![
            "row".into(), r.cell(C_IP), r.label.clone(), r.host.clone(), r.vendor.clone(), r.mac.clone(),
            (r.me as u8).to_string(), (r.random_mac as u8).to_string(),
            r.video.map(|v| v.tag().to_string()).unwrap_or_default(), r.video_desc.clone(), r.ping.clone(), ping_code(r.ping_state).into(),
            format!("{:.1}", r.rt_ms), r.open_rtsp.clone(), r.open_snapshot.clone(),
            (r.absent as u8).to_string(),
        ];
        f.extend(r.names.iter().cloned()); // per-source names, so a reopened scan merges/ranks the same way
        t += &esc_join(&f);
        t.push('\n');
    }
    for p in ports {
        let st = match p.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "silent",
        };
        t += &esc_join(&["port".into(), p.ip.to_string(), p.port.to_string(), st.into(), p.banner.clone()]);
        t.push('\n');
    }
    for (mac, d) in labels {
        if !d.label.is_empty() {
            t += &esc_join(&["label".into(), mac.clone(), d.label.clone(), d.last_ip.clone()]);
            t.push('\n');
        }
    }
    for (mac, h) in dhcp {
        t += &esc_join(&["dhcp".into(), mac.clone(), h.clone()]); // hostnames heard by the DHCP listener
        t.push('\n');
    }
    t
}

struct LoadedScan {
    subnet: String,
    saved: String,
    rows: Vec<Row>,
    ports: Vec<PortRow>,
    labels: HashMap<String, DeviceInfo>,
    dhcp: HashMap<String, String>,
}

fn scan_from_text(t: &str) -> Result<LoadedScan, String> {
    if !t.starts_with("#myriameter-scan,") {
        return Err("Unrecognised scan file".into());
    }
    let mut ls = LoadedScan { subnet: String::new(), saved: String::new(), rows: Vec::new(), ports: Vec::new(), labels: HashMap::new(), dhcp: HashMap::new() };
    for line in t.lines().skip(1) {
        let f = store::csv_fields(line);
        let g = |i: usize| f.get(i).cloned().unwrap_or_default();
        match f.first().map(String::as_str) {
            Some("meta") => {
                ls.subnet = g(1);
                ls.saved = g(2);
            }
            Some("row") => {
                let absent = g(15) == "1";
                let last: Option<Ipv4Addr> = g(1).parse().ok();
                let ip = if absent {
                    absent_key(ls.rows.iter().filter(|r| r.absent).count())
                } else {
                    match last {
                        Some(ip) => ip,
                        None => continue,
                    }
                };
                let mut names: [String; 6] = Default::default();
                for (k, n) in names.iter_mut().enumerate() {
                    *n = g(16 + k);
                }
                let video = match g(8).as_str() {
                    "CAM" => Some(Video::Camera),
                    "NVR" => Some(Video::Nvr),
                    "RTSP" => Some(Video::Stream),
                    _ => None,
                };
                let ping_state = match g(11).as_str() {
                    "ok" => PingState::Ok,
                    "noreply" => PingState::NoReply,
                    "unreach" => PingState::Unreachable,
                    _ => PingState::None,
                };
                ls.rows.push(Row {
                    ip, label: g(2), host: g(3), vendor: g(4), mac: g(5), me: g(6) == "1", gw: false, random_mac: g(7) == "1",
                    video, video_desc: g(9), ping: g(10), ping_state, rt_ms: g(12).parse().unwrap_or(1.0), ping_flash: None, open_rtsp: g(13), open_snapshot: g(14), absent,
                    sort_ip: if absent { last.map(u32::from).unwrap_or(u32::MAX) } else { u32::from(ip) },
                    names, last_ip: if absent { last } else { None } });
            }
            Some("port") => {
                let (Ok(ip), Ok(port)) = (g(1).parse(), g(2).parse()) else { continue };
                let state = match g(3).as_str() {
                    "open" => PortState::Open,
                    "closed" => PortState::Closed,
                    _ => PortState::Filtered,
                };
                ls.ports.push(PortRow { ip, port, state, banner: g(4) });
            }
            Some("label") => {
                if !g(1).is_empty() {
                    ls.labels.insert(g(1).to_lowercase(), DeviceInfo { label: g(2), notes: String::new(), last_ip: g(3) });
                }
            }
            Some("dhcp") => {
                if !g(1).is_empty() && !g(2).is_empty() {
                    ls.dhcp.insert(g(1).to_lowercase(), g(2));
                }
            }
            _ => {}
        }
    }
    Ok(ls)
}

/// Port scan that small devices can cope with: each device gets at most `per_host` connections
/// at once (cameras and IoT kit choke and go silent under a burst), the overall `total_par` is
/// shared between devices, and ports that didn't answer are re-checked slowly before being
/// reported as "no response".
fn run_ports(targets: Vec<Ipv4Addr>, ports: Vec<u16>, timeout: u64, total_par: usize, per_host: usize, grab: bool, tx: &Sender<Msg>, stop: &Arc<AtomicBool>) {
    let per = per_host.min((total_par / targets.len().max(1)).max(1));
    let silent: Arc<Mutex<Vec<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let pass = |jobs: Vec<(Ipv4Addr, Vec<u16>)>, per: usize, timeout: u64, first: bool| {
        let mut hs = Vec::new();
        for (ip, list) in jobs {
            let q = Arc::new(Mutex::new(VecDeque::from(list)));
            for _ in 0..per {
                let (q, tx, stop, silent) = (q.clone(), tx.clone(), stop.clone(), silent.clone());
                hs.push(thread::spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(port) = q.lock().unwrap().pop_front() else { break };
                    let (state, banner) = scan::probe_port(ip, port, timeout, grab);
                    if first && state == PortState::Filtered {
                        silent.lock().unwrap().push((ip, port)); // decide after the slow re-check
                    } else {
                        let _ = tx.send(Msg::Port(PortRow { ip, port, state, banner }));
                    }
                    if first {
                        let _ = tx.send(Msg::PortTick);
                    }
                }));
            }
        }
        for h in hs {
            let _ = h.join();
        }
    };
    pass(targets.iter().map(|ip| (*ip, ports.clone())).collect(), per, timeout, true);
    let retry: Vec<(Ipv4Addr, u16)> = std::mem::take(&mut *silent.lock().unwrap());
    if !retry.is_empty() && !stop.load(Ordering::Relaxed) {
        let _ = tx.send(Msg::PortPhase(format!("Re-checking {} silent port(s) slowly", retry.len())));
        let mut by_ip: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
        for (ip, p) in retry {
            by_ip.entry(ip).or_default().push(p);
        }
        pass(by_ip.into_iter().collect(), 4, (timeout * 2).min(5000), false);
    }
}

// ================================================================ radar
/// Distance from the centre as a fraction of the radius: fast replies near the rim, slow ones
/// towards the middle, on a log scale (replies range from <1 ms to hundreds of ms).
fn ping_text(e: Echo) -> (String, PingState) {
    match e {
        Echo::Ok(0) => ("OK  <1 ms".into(), PingState::Ok),
        Echo::Ok(ms) => (format!("OK  {} ms", ms), PingState::Ok),
        Echo::NoReply => ("No reply".into(), PingState::NoReply),
        Echo::Unreachable => ("Unreachable".into(), PingState::Unreachable),
    }
}

/// Response time used for placing a dot: devices that stopped answering all sit on the timeout ring.
fn eff_ms(r: &Row) -> f32 {
    match r.ping_state {
        PingState::NoReply | PingState::Unreachable => 1000.0,
        _ => r.rt_ms,
    }
}

fn radar_frac(ms: f32) -> f32 {
    (0.95 - 0.75 * ((ms.max(0.0) + 1.0).log10() / 1001f32.log10())).clamp(0.18, 0.95)
}

#[derive(Clone, Copy)]
struct Blip {
    from: f32,     // radius fraction it is gliding from
    at: Instant,   // when the glide started
    flash: Instant, // last refresh (0.5 s flash)
}

impl Blip {
    fn current(&self, ms: f32) -> f32 {
        let k = (self.at.elapsed().as_secs_f32() / 0.4).min(1.0);
        let e = 1.0 - (1.0 - k).powi(3);
        self.from + (radar_frac(ms) - self.from) * e
    }
}

struct RadarDot {
    ip: Ipv4Addr,
    pos: egui::Pos2,
    text: String,
}

/// Draw the radar into `rect`. Each device sits at its position within the scanned range
/// (network address at 12 o'clock, clockwise) and at a distance set by its latest response time.
/// Returns the dots so the large view can show hover details.
#[allow(clippy::too_many_arguments)]
fn draw_radar(painter: &egui::Painter, rect: Rect, p: &Pal, amber: bool, rows: &[Row], blips: &HashMap<Ipv4Addr, Blip>, net: Option<(Ipv4Addr, u8)>, sweep: f32, fade: f32, big: bool) -> Vec<RadarDot> {
    let c = rect.center();
    let compact = big && rect.width() < 260.0; // header radar: markers inside the rim
    let fsz = if compact { (rect.width() * 0.075).clamp(8.5, 11.0) } else { (rect.width() * 0.035).clamp(9.5, 12.0) };
    let margin = if big && !compact { fsz + 6.0 } else { 1.5 };
    let r = rect.width().min(rect.height()) / 2.0 - margin;
    let on = 0.35 + 0.65 * fade;
    let ring = |a: f32| {
        let c = if amber { Color32::from_rgb(0xFF, 0xB0, 0x00) } else { Color32::from_rgb(0x3D, 0xFF, 0x7A) };
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (a * 255.0) as u8)
    };
    let disc = if amber { Color32::from_rgb(0x14, 0x0E, 0x06) } else if p.dark { Color32::from_rgb(0x0C, 0x1A, 0x11) } else { Color32::from_rgb(0x12, 0x2A, 0x1A) };
    let lw = if big { 1.6_f32 } else { 1.0_f32 };
    painter.circle_filled(c, r, disc);
    for k in [0.66, 0.33] {
        painter.circle_stroke(c, r * k, Stroke::new(lw, ring(0.14 + 0.2 * on)));
    }
    painter.line_segment([pos2(c.x - r, c.y), pos2(c.x + r, c.y)], Stroke::new(lw * 0.8, ring(0.07 + 0.08 * on)));
    painter.line_segment([pos2(c.x, c.y - r), pos2(c.x, c.y + r)], Stroke::new(lw * 0.8, ring(0.07 + 0.08 * on)));
    // quarter markers: enlarged view only (too cluttered on the small header radar)
    if big && !compact {
        if let Some((n, pfx)) = net {
            let size = 1u64 << (32 - pfx as u32);
            let base = u32::from(n) as u64;
            let mark = |off: u64| {
                let ip = Ipv4Addr::from((base + off) as u32).octets();
                if size > 256 { format!(".{}.{}", ip[2], ip[3]) } else { format!(".{}", ip[3]) }
            };
            let f = FontId::monospace(fsz);
            let col = ring(0.55 + 0.35 * on);
            // outside the ring on the large view; just inside it on the compact header radar
            let (gv, gh) = if compact { (-(fsz * 0.5 + 4.0), -4.0) } else { (fsz * 0.5 + 3.0, 3.0) };
            painter.text(pos2(c.x, c.y - r - gv), Align2::CENTER_CENTER, mark(if size > 2 { 1 } else { 0 }), f.clone(), col);
            painter.text(pos2(c.x + r + gh, c.y), if compact { Align2::RIGHT_CENTER } else { Align2::LEFT_CENTER }, mark(size / 4), f.clone(), col);
            painter.text(pos2(c.x, c.y + r + gv), Align2::CENTER_CENTER, mark(size / 2), f.clone(), col);
            painter.text(pos2(c.x - r - gh, c.y), if compact { Align2::LEFT_CENTER } else { Align2::RIGHT_CENTER }, mark(size * 3 / 4), f, col);
        }
    }
    // sweep with a fading trail
    if fade > 0.01 {
        // smooth trail: thin filled slices fading out behind the arm
        let steps = 40;
        let span = 0.9f32;
        for i in 0..steps {
            let a0 = sweep - span * i as f32 / steps as f32;
            let a1 = sweep - span * (i + 1) as f32 / steps as f32;
            let col = ring(0.38 * (1.0 - i as f32 / steps as f32).powf(1.6) * fade);
            painter.add(egui::Shape::convex_polygon(
                vec![c, pos2(c.x + a0.cos() * r, c.y + a0.sin() * r), pos2(c.x + a1.cos() * r, c.y + a1.sin() * r)],
                col,
                Stroke::NONE,
            ));
        }
        let arm = if amber { Color32::from_rgb(0xFF, 0xE9, 0xB8) } else { Color32::from_rgb(0xD8, 0xFF, 0xE4) };
        let arm = Color32::from_rgba_unmultiplied(arm.r(), arm.g(), arm.b(), (0.95 * fade * 255.0) as u8);
        painter.line_segment([c, pos2(c.x + sweep.cos() * r, c.y + sweep.sin() * r)], Stroke::new(lw * 1.8, arm));
    }
    // blips
    let mut dots = Vec::new();
    if let Some((n, pfx)) = net {
        let size = (1u64 << (32 - pfx as u32)) as f32;
        let base = u32::from(n);
        let dot_r = if compact { 2.5 } else if big { 5.0 } else { 1.6 };
        for row in rows {
            let off = u32::from(row.ip).wrapping_sub(base) as f32;
            if off >= size {
                continue;
            }
            let a = -std::f32::consts::FRAC_PI_2 + off / size * std::f32::consts::TAU;
            let frac = blips.get(&row.ip).map(|b| b.current(eff_ms(row))).unwrap_or(radar_frac(eff_ms(row)));
            let pos = pos2(c.x + a.cos() * r * frac, c.y + a.sin() * r * frac);
            let unknown = row.label.is_empty() && !row.me;
            let col = if amber {
                if unknown { Color32::from_rgb(0xFF, 0xE9, 0xB8) } else if row.video.is_some() { Color32::from_rgb(0xB8, 0x93, 0x5A) } else { Color32::from_rgb(0xFF, 0xB0, 0x00) }
            } else if unknown {
                p.warn
            } else if row.video.is_some() {
                p.cyan
            } else {
                Color32::from_rgb(0x3D, 0xFF, 0x7A)
            };
            if row.ping_state == PingState::NoReply || row.ping_state == PingState::Unreachable {
                painter.circle_stroke(pos, dot_r, Stroke::new(lw * 1.2, col)); // silent: hollow
            } else {
                painter.circle_filled(pos, dot_r, col);
            }
            if let Some(b) = blips.get(&row.ip) {
                let t = b.flash.elapsed().as_secs_f32() / 0.5;
                if t < 1.0 {
                    let k = (t * std::f32::consts::PI).sin();
                    let white = Color32::from_rgba_unmultiplied(255, 255, 255, (k * 200.0) as u8);
                    painter.circle_filled(pos, dot_r * (1.0 + 0.6 * k), white);
                    painter.circle_stroke(pos, dot_r * (1.4 + 2.5 * t), Stroke::new(lw, Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), ((1.0 - t) * 200.0) as u8)));
                }
            }
            let name = if !row.label.is_empty() { row.label.clone() } else { row.host.split("  [").next().unwrap_or("").to_string() };
            let reply = if row.ping_state == PingState::NoReply { "no reply".to_string() } else { format!("{:.1} ms", row.rt_ms) };
            dots.push(RadarDot { ip: row.ip, pos, text: format!("{}   {}   {}", row.ip, if name.is_empty() { "Unknown device" } else { &name }, reply) });
        }
    }
    painter.circle_stroke(c, r, Stroke::new(lw * 1.4, ring(0.5 + 0.45 * on)));
    dots
}

/// Single-line text box drawn by us so the *visible characters* sit centred vertically, whatever the
/// font (egui centres the line box, which leaves digits sitting high). `center_h` also centres
/// short text horizontally (used for the Target box).
#[allow(clippy::too_many_arguments)]
fn line_edit(ui: &mut egui::Ui, p: &Pal, id: egui::Id, text: &mut String, width: f32, mono: bool, center_h: bool, password: bool, hint: &str) -> egui::Response {
    let h = ui.spacing().interact_size.y;
    let (rect, resp) = ui.allocate_exact_size(vec2(width, h), egui::Sense::click());
    let focused = ui.memory(|m| m.has_focus(id));
    ui.painter().rect(rect, 3.0, p.input, Stroke::new(1.0_f32, if focused { p.primary } else { p.line }));
    let font = if mono { FontId::monospace(14.5) } else { FontId::proportional(15.0) };
    let shown = if text.is_empty() {
        hint.to_string()
    } else if password {
        "\u{2022}".repeat(text.chars().count())
    } else {
        text.clone()
    };
    let galley = ui.fonts(|f| f.layout_no_wrap(shown, font.clone(), Color32::WHITE));
    let (mut top, mut bot) = (f32::MAX, f32::MIN);
    for row in &galley.rows {
        for g in &row.glyphs {
            if g.uv_rect.size.y > 0.0 {
                top = top.min(g.pos.y + g.uv_rect.offset.y);
                bot = bot.max(g.pos.y + g.uv_rect.offset.y + g.uv_rect.size.y);
            }
        }
    }
    let line_h = ui.fonts(|f| f.row_height(&font));
    let mid = if top < bot { (top + bot) / 2.0 } else { line_h / 2.0 };
    let pad = 8.0;
    let tw = galley.size().x + 2.0;
    let fits = center_h && tw < width - 2.0 * pad;
    let w = if fits { tw } else { width - 2.0 * pad };
    let x = if fits { rect.center().x - w / 2.0 } else { rect.left() + pad };
    let inner = Rect::from_min_size(pos2(x, rect.center().y - mid), vec2(w, line_h));
    let mut te = egui::TextEdit::singleline(text).id(id).frame(false).font(font).text_color(p.primary).margin(vec2(0.0, 0.0)).desired_width(w).password(password);
    if !hint.is_empty() {
        te = te.hint_text(RichText::new(hint).color(p.dim).italics());
    }
    let r = ui.put(inner, te);
    if resp.clicked() {
        r.request_focus();
    }
    ui.advance_cursor_after_rect(rect);
    r
}

/// A label whose *visible characters* sit centred vertically in the cell (egui centres the line box,
/// which leaves monospace digits sitting high). `centre_x` centres it horizontally in the cell too.
/// Italics are compensated for egui's slant (it leans glyph tops right by a quarter of their height).
fn ink_label(ui: &mut egui::Ui, text: &str, font: FontId, color: Color32, italics: bool, centre_x: bool) -> egui::Response {
    let mut job = egui::text::LayoutJob::default();
    job.append(text, 0.0, egui::TextFormat { font_id: font, color, italics, ..Default::default() });
    let galley = ui.fonts(|f| f.layout_job(job));
    let (mut top, mut bot) = (f32::MAX, f32::MIN);
    for row in &galley.rows {
        for g in &row.glyphs {
            if g.uv_rect.size.y > 0.0 {
                top = top.min(g.pos.y + g.uv_rect.offset.y);
                bot = bot.max(g.pos.y + g.uv_rect.offset.y + g.uv_rect.size.y);
            }
        }
    }
    let mid = if top < bot { (top + bot) / 2.0 } else { galley.size().y / 2.0 };
    let slant = if italics && top < bot { (bot - top) * 0.125 } else { 0.0 }; // half the lean, so the slant is centred on the upright position
    let cell = ui.max_rect();
    let w = galley.size().x;
    if centre_x {
        let x = cell.center().x - w / 2.0;
        ui.add_space((x - ui.cursor().left()).max(0.0));
    }
    let (rect, resp) = ui.allocate_exact_size(vec2(w, cell.height()), egui::Sense::hover());
    ui.painter().galley(pos2(rect.left() - slant, rect.center().y - mid), galley, color);
    resp
}

/// The devices table's columns at fixed widths. The header and the rows are two tables built from
/// this, so they always line up. `resizable` only draws the column separators (exact widths can't move).
fn table_columns<'a>(ui: &'a mut egui::Ui, widths: &[f32]) -> TableBuilder<'a> {
    let mut tb = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .vscroll(false)
        .sense(egui::Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    for &w in widths {
        tb = tb.column(Column::exact(w).clip(true));
    }
    tb
}

fn panel_frame(p: &Pal) -> egui::Frame {
    egui::Frame::none().fill(p.panel).inner_margin(egui::Margin::symmetric(14.0, 10.0))
}

/// Lively progress bar: bright fill, moving stripes while busy, dual-colour text, flash on completion.
fn progress_bar(ui: &mut egui::Ui, p: &Pal, frac: f32, busy: bool, flash: f32, text: &str) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 24.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 5.0, p.input);
    let fill = Rect::from_min_size(rect.min, vec2(rect.width() * frac.clamp(0.0, 1.0), rect.height()));
    // completion flash: one smooth rise to yellow and back over 1 s (flash runs 1 -> 0)
    let base = if flash > 0.0 {
        let k = (flash.clamp(0.0, 1.0) * std::f32::consts::PI).sin(); // 0 -> 1 -> 0, eased
        let y = Color32::from_rgb(0xFF, 0xD8, 0x3D);
        let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * k) as u8;
        Color32::from_rgb(mix(p.accent.r(), y.r()), mix(p.accent.g(), y.g()), mix(p.accent.b(), y.b()))
    } else {
        p.accent
    };
    if fill.width() > 0.0 {
        painter.rect_filled(fill, 5.0, base);
        if busy {
            let fp = ui.painter_at(fill);
            let off = (ui.input(|i| i.time) as f32 * 45.0) % 18.0;
            let mut x = fill.left() - 24.0 + off;
            while x < fill.right() + 24.0 {
                fp.line_segment([pos2(x, fill.bottom()), pos2(x + 12.0, fill.top())], Stroke::new(5.0_f32, Color32::from_white_alpha(55)));
                x += 18.0;
            }
        }
    }
    painter.rect_stroke(rect, 5.0, Stroke::new(1.0_f32, p.line));
    let font = FontId::proportional(14.0);
    let on_fill = Color32::from_rgb(0x0A, 0x0A, 0x0A);
    ui.painter_at(fill).text(rect.center(), Align2::CENTER_CENTER, text, font.clone(), on_fill);
    let rest = Rect::from_min_max(pos2(fill.right(), rect.top()), rect.max);
    ui.painter_at(rest).text(rect.center(), Align2::CENTER_CENTER, text, font, p.primary);
}

impl Drop for App {
    fn drop(&mut self) {
        self.save_settings(); // window size + column widths (settings, not user data)
        self.wipe();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.snap_frames > 0 {
            // tooltips are hidden; wait a couple of frames so none is in the capture
            self.snap_frames -= 1;
            if self.snap_frames == 0 {
                self.snapshot_pending = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            }
            ctx.request_repaint();
        }
        self.take_snapshot_result(ctx);
        self.handle_messages();
        if let Some(r) = ctx.input(|i| i.viewport().inner_rect) {
            self.win_size = r.size();
        }
        let dialog_open = self.edit.is_some() || self.pw.is_some() || self.restore_choice.is_some() || self.confirm_erase.is_some() || self.confirm_big.is_some() || self.confirm_forget.is_some();
        if !dialog_open {
            if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
                self.start(ctx, false);
            }
            if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::F)) {
                self.focus_filter = true;
            }
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) && self.ps.is_none() {
                if self.filter.is_empty() {
                    self.sel_ips.clear();
                }
                self.filter.clear();
            }
            if !ctx.wants_keyboard_input() && ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::A)) {
                self.select_all_pending = true;
            }
        }
        self.col_w = self.fit_widths(ctx);
        if !ctx.wants_keyboard_input() && self.edit.is_none() && self.pw.is_none() {
            let (l, r) = ctx.input(|i| (i.key_pressed(egui::Key::ArrowLeft), i.key_pressed(egui::Key::ArrowRight)));
            let (up, down) = ctx.input(|i| (i.key_pressed(egui::Key::ArrowUp), i.key_pressed(egui::Key::ArrowDown)));
            if up || down {
                self.vscroll_rows += if down { 3.0 } else { -3.0 }; // three rows per press, like a mouse-wheel notch
            }
            if l || r {
                self.hscroll += if r { 80.0 } else { -80.0 }; // clamped when the table is laid out
                self.hscroll_at = Some(Instant::now());
            }
        }
        if self.hscroll_at.map(|t| t.elapsed() < Duration::from_millis(1000)).unwrap_or(false) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if let Some((h, t)) = self.clip {
            if t.elapsed() >= Duration::from_secs(CLIP_SECS) {
                if platform::clear_clipboard_if(h) {
                    self.status = "Clipboard cleared".into();
                    self.status_flash = Some(Instant::now());
                }
                self.clip = None;
            } else {
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }
        let flash = match self.flash_until {
            Some(t) if Instant::now() < t => (t - Instant::now()).as_secs_f32(),
            _ => {
                self.flash_until = None;
                0.0
            }
        };
        if self.scanning || self.loading_vendors || self.pings_pending > 0 || flash > 0.0 {
            ctx.request_repaint_after(Duration::from_millis(30));
        }
        let p = self.pal;
        {
            let dt = self.radar_last.elapsed().as_secs_f32().min(0.1);
            self.radar_last = Instant::now();
            let target = if self.scanning { 1.0 } else { 0.0 };
            self.radar_fade += (target - self.radar_fade) * (dt * 3.0).min(1.0);
            if self.radar_fade > 0.01 {
                self.radar_angle = (self.radar_angle + dt * std::f32::consts::PI * 1.4) % std::f32::consts::TAU;
            }
            let anim = self.radar_fade > 0.01
                || self.blips.values().any(|b| b.flash.elapsed() < Duration::from_millis(500) || b.at.elapsed() < Duration::from_millis(400))
                || self.rows.iter().any(|r| r.ping_flash.map(|t| t.elapsed() < Duration::from_secs(1) || t > Instant::now()).unwrap_or(false));
            if anim {
                ctx.request_repaint_after(Duration::from_millis(16));
            }
        }
        let radar_net = scan::parse_cidr(if self.net_text.is_empty() { &self.subnet } else { &self.net_text }).filter(|(_, pfx)| *pfx >= 22);
        let amber = self.theme == Theme::Amber;

        // ---------------- header & controls
        egui::TopBottomPanel::top("controls").frame(panel_frame(&p)).show(ctx, |ui| {
            let panel_top = ui.min_rect().top();
            let panel_right = ui.max_rect().right();
            ui.horizontal(|ui| {
                let title = ui.label(RichText::new(">_ DevEcho Network Scanner").size(24.0).strong().monospace().color(p.primary));
                ui.label(RichText::new("v1.4").size(15.0).monospace().color(p.dim));
                ui.add_space(40.0);
                // Company name in the title's font, its capitals as tall as the title's lower-case letters.
                let ink = |g: &egui::Galley, pick: &dyn Fn(char) -> bool| {
                    let (mut t, mut b) = (f32::MAX, f32::MIN);
                    for row in &g.rows {
                        for gl in &row.glyphs {
                            if pick(gl.chr) && gl.uv_rect.size.y > 0.0 {
                                t = t.min(gl.pos.y + gl.uv_rect.offset.y);
                                b = b.max(gl.pos.y + gl.uv_rect.offset.y + gl.uv_rect.size.y);
                            }
                        }
                    }
                    if t < b { (t, b) } else { (0.0, g.size().y) }
                };
                let tx = ui.fonts(|f| f.layout_no_wrap("x".into(), FontId::monospace(24.0), Color32::WHITE));
                let (xt, xb) = ink(&tx, &|c| c == 'x');
                let probe = ui.fonts(|f| f.layout_no_wrap("N".into(), FontId::monospace(24.0), Color32::WHITE));
                let (nt, nb) = ink(&probe, &|c| c == 'N');
                let size = (24.0 * (xb - xt) / (nb - nt).max(1.0)).clamp(10.0, 24.0);
                let mut job = egui::text::LayoutJob::default();
                job.append("MYRIAMETER.UK", 0.0, egui::TextFormat { font_id: FontId::monospace(size), extra_letter_spacing: size * 0.12, color: p.dim, ..Default::default() });
                let galley = ui.fonts(|f| f.layout_job(job));
                let (ct, cb) = ink(&galley, &|c| c.is_ascii_uppercase());
                let (rect, _) = ui.allocate_exact_size(galley.size(), egui::Sense::hover());
                let pos = pos2(rect.min.x, title.rect.top() + (xt + xb) / 2.0 - (ct + cb) / 2.0);
                ui.painter().galley(pos, galley, p.dim);
                // Theme selector in the top-right corner, flush to the right edge.
                let w = 130.0;
                let trect = Rect::from_min_size(pos2(panel_right - w, title.rect.top()), vec2(w, ui.spacing().interact_size.y));
                let mut chosen = self.theme;
                ui.allocate_ui_at_rect(trect, |ui| {
                    egui::ComboBox::from_id_source("theme").width(w).selected_text(self.theme.name()).show_ui(ui, |ui| {
                        for t in Theme::ALL {
                            ui.selectable_value(&mut chosen, t, t.name());
                        }
                    });
                });
                if chosen != self.theme {
                    self.set_theme(ctx, chosen);
                }
                self.title_end = rect.right();            // company-name right edge (radar stays clear of it)
                self.title_end_y = title.rect.bottom();
            });
            ui.add_space(8.0);
            egui::Grid::new("grid").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
                ui.label(RichText::new("Adapter").color(p.dim));
                ui.horizontal(|ui| {
                    let before = self.sel;
                    let text = self.adapters.get(self.sel).map(|a| format!("{}  -  {}/{}", a.name, a.ip, a.prefix)).unwrap_or_else(|| "(none)".into());
                    // width so that Refresh's right edge lines up with the Threads box below
                    let start_x = ui.cursor().left();
                    let refresh_w = ui.fonts(|f| f.layout_no_wrap("Refresh".into(), FontId::proportional(15.0), Color32::WHITE).size().x) + 2.0 * ui.spacing().button_padding.x;
                    let combo_w = (self.target_row_right - start_x - refresh_w - ui.spacing().item_spacing.x).clamp(180.0, 900.0);
                    egui::ComboBox::from_id_source("adapter").width(combo_w).selected_text(RichText::new(text).color(p.primary)).show_ui(ui, |ui| {
                        for (i, a) in self.adapters.iter().enumerate() {
                            ui.selectable_value(&mut self.sel, i, format!("{}  -  {}/{}", a.name, a.ip, a.prefix));
                        }
                    });
                    if self.sel != before {
                        self.adapter_chosen();
                    }
                    if ui.button("Refresh").on_hover_text("Re-read this PC's network adapters").clicked() {
                        self.refresh_adapters();
                    }
                });
                ui.end_row();

                ui.label(RichText::new("Target").color(p.dim));
                ui.horizontal(|ui| {
                    let tid = ui.make_persistent_id("target_edit");
                    let r = line_edit(ui, &p, tid, &mut self.subnet, 190.0, true, true, false, "");
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.start(ctx, false);
                    }
                    ui.add_space(6.0);
                    // "Names" drop-down: exactly the footprint the old "Resolve names" checkbox had,
                    // so nothing else on the row moves.
                    let sp = ui.spacing();
                    let text_w = ui.fonts(|f| f.layout_no_wrap("Resolve names".into(), FontId::proportional(15.0), Color32::WHITE).size().x);
                    let nsize = vec2(sp.icon_width + sp.icon_spacing + text_w, sp.interact_size.y);
                    let on = [scan::N_DNS, scan::N_MDNS, scan::N_NETBIOS, scan::N_UPNP, scan::N_DHCP].iter().filter(|b| self.names & **b != 0).count();
                    let caption = "Hostname";
                    let npop = ui.make_persistent_id("names_menu");
                    let nopen = ui.memory(|m| m.is_popup_open(npop));
                    // Drawn by hand (like the Target box) so it's exactly as tall as the Target box and the
                    // caption's visible letters sit centred, both vertically and in the space left of the arrow.
                    let (nrect, nb) = ui.allocate_exact_size(nsize, egui::Sense::click());
                    {
                        let vis = ui.style().interact(&nb);
                        let painter = ui.painter();
                        painter.rect(nrect, 3.0, vis.weak_bg_fill, vis.bg_stroke);
                        let arrow_w = 18.0;
                        let font = FontId::proportional(15.0);
                        let galley = ui.fonts(|f| f.layout_no_wrap(caption.to_string(), font, if on == 0 { p.dim } else { p.primary }));
                        let (mut top, mut bot) = (f32::MAX, f32::MIN);
                        for row in &galley.rows {
                            for g in &row.glyphs {
                                if g.uv_rect.size.y > 0.0 {
                                    top = top.min(g.pos.y + g.uv_rect.offset.y);
                                    bot = bot.max(g.pos.y + g.uv_rect.offset.y + g.uv_rect.size.y);
                                }
                            }
                        }
                        let mid = if top < bot { (top + bot) / 2.0 } else { galley.size().y / 2.0 };
                        let text_area = (nrect.left(), nrect.right() - arrow_w);
                        let x = (text_area.0 + text_area.1) / 2.0 - galley.size().x / 2.0 + 3.0;
                        painter.galley(pos2(x, nrect.center().y - mid), galley, if on == 0 { p.dim } else { p.primary });
                        // drop-down arrow, painted so it never depends on the font
                        let (cx, cy) = (nrect.right() - 10.0, nrect.center().y);
                        let acol = if nb.hovered() { p.primary } else { p.dim };
                        painter.add(egui::Shape::convex_polygon(vec![pos2(cx - 4.0, cy - 2.0), pos2(cx + 4.0, cy - 2.0), pos2(cx, cy + 3.0)], acol, Stroke::NONE));
                    }
                    let nb = if nopen { nb } else { nb.on_hover_text(NAMES_HELP) };
                    if nb.clicked() {
                        ui.memory_mut(|m| m.toggle_popup(npop));
                    }
                    let before = self.names;
                    egui::popup_below_widget(ui, npop, &nb, |ui| {
                        ui.set_min_width(200.0);
                        for (bit, name, help) in NAME_SOURCES {
                            let mut v = self.names & bit != 0;
                            if ui.checkbox(&mut v, name).on_hover_text(help).changed() {
                                self.names = if v { self.names | bit } else { self.names & !bit };
                            }
                            if bit == scan::N_UPNP {
                                ui.separator();
                            }
                        }
                    });
                    if self.names != before {
                        ui.memory_mut(|m| m.open_popup(npop)); // keep the list open while ticking
                        if (self.names ^ before) & scan::N_DHCP != 0 {
                            self.set_dhcp_listener(self.names & scan::N_DHCP != 0, ctx);
                        }
                        self.save_settings();
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(RichText::new("Threads").color(p.dim)).on_hover_text(THREADS_HELP);
                    let thr = ui.add(egui::DragValue::new(&mut self.workers).clamp_range(16..=1024).speed(8)).on_hover_text(THREADS_HELP);
                    if thr.changed() {
                        self.save_settings();
                    }
                    if (self.target_row_right - thr.rect.right()).abs() > 0.5 {
                        self.target_row_right = thr.rect.right();
                        ctx.request_repaint();
                    }
                });
                ui.end_row();
            });
            ui.add_space(10.0);

            // Buttons: seven equal widths across the full row.
            let busy = self.scanning || self.pings_pending > 0;
            ui.horizontal(|ui| {
                let gap = ui.spacing().item_spacing.x;
                let _ = gap;
                let pad = ui.spacing().button_padding.x;
                let w = ui.fonts(|f| f.layout_no_wrap("Update vendors".into(), FontId::proportional(15.0), Color32::WHITE).size().x) + 2.0 * pad + 28.0;
                let size = vec2(w, 30.0);
                if ui.add_enabled(!busy, egui::Button::new(RichText::new("Scan").strong()).min_size(size)).on_hover_text("Find every device on the target network").clicked() {
                    self.start(ctx, false);
                }
                if ui.add_enabled(self.scanning, egui::Button::new("Stop").min_size(size)).clicked() {
                    self.stop.store(true, Ordering::SeqCst);
                }
                if ui.add_enabled(!busy && !self.rows.is_empty(), egui::Button::new("Ping all").min_size(size)).on_hover_text(PING_HELP).clicked() {
                    self.ping(ctx, None);
                }
                let ps_btn = ui.add_enabled(!self.scanning && !self.rows.is_empty(), egui::Button::new("Port scan").min_size(size)).on_hover_text("Check which ports are open on one device, the video devices, or all devices");
                if ps_btn.clicked() {
                    self.open_port_scan(None, false, ctx);
                }
                let left_group_right = ps_btn.rect.right();
                // Right-hand group (Save/open .. Update vendors) anchored to the right edge.
                let sp = ui.spacing().item_spacing.x;
                let right_w = 3.0 * w + 2.0 * sp;
                let left_w = 4.0 * w + 3.0 * sp;
                let _ = left_w;
                let radar_d = (self.progress_top - (ui.min_rect().top() - 8.0)) * 0.9;
                ui.add_space((panel_right - ui.cursor().left() - right_w).max(radar_d * 0.5 + 20.0));
                let right_group_left = ui.cursor().left();
                // radar centres in the gap between the two groups
                self.gap_centre = Some(((left_group_right + right_group_left) / 2.0, ps_btn.rect.top(), (right_group_left - left_group_right) / 2.0));
                let pop = ui.make_persistent_id("data_menu");
                let menu_open = ui.memory(|m| m.is_popup_open(pop));
                let lb = ui.add_enabled(!busy, egui::Button::new("Save / open").min_size(size));
                let lb = if menu_open { lb } else { lb.on_hover_text(DATA_HELP) }; // no tooltip over the open menu
                if lb.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(pop));
                }
                egui::popup_below_widget(ui, pop, &lb, |ui| {
                    ui.set_min_width(300.0);
                    if ui.button("Save scan (encrypted)...").clicked() {
                        ui.memory_mut(|m| m.close_popup());
                        self.start_save_scan();
                    }
                    if ui.button("Open saved scan...").clicked() {
                        ui.memory_mut(|m| m.close_popup());
                        self.start_open_scan();
                    }
                    ui.separator();
                    if ui.button(RichText::new("Erase all data...").strong().color(p.bad)).on_hover_text(ERASE_HELP).clicked() {
                        ui.memory_mut(|m| m.close_popup());
                        let n = store::user_data_files().len();
                        let saved = store::saved_files(&self.known_backups);
                        let in_memory = !self.rows.is_empty() || !self.devices.is_empty() || self.ps.is_some() || self.clip.is_some();
                        if n == 0 && saved.is_empty() && !in_memory {
                            self.status = "Nothing to erase - no results, labels or files are stored".into();
                        } else {
                            self.confirm_erase = Some((n, saved, false));
                        }
                    }
                });
                if ui.add_enabled(self.snap_frames == 0, egui::Button::new("Snapshot").min_size(size)).on_hover_text("Save a PNG picture of this window to Documents\\DevEcho Network Scanner").clicked() {
                    ctx.style_mut(|s| s.interaction.tooltip_delay = 1.0e6);
                    self.snap_frames = 3;
                    ctx.request_repaint();
                }
                let vb = ui.add(egui::Button::new(RichText::new("Update vendors").color(if self.loading_vendors { p.dim } else { p.primary })).min_size(size))
                    .on_hover_text("Left-click: download latest IEEE manufacturer list\nRight-click: enable / disable the Manufacturer column");
                if vb.clicked() && !self.loading_vendors {
                    self.load_vendors(true, ctx.clone());
                }
                if vb.secondary_clicked() {
                    self.show_vendor = !self.show_vendor;
                    self.save_settings();
                    self.status = format!("Manufacturer column {}", if self.show_vendor { "shown" } else { "hidden" });
                }
            });
            // Radar: drawn after the button row so this frame's gap centre is known. Spans the
            // window's top edge down to the button row, centred on the gap between the two groups.
            if let Some((cx, _btn_top, _gap_half)) = self.gap_centre {
                if radar_net.is_some() || self.scanning {
                    // Diameter = 90% of the space from the window's top to the top of the progress bar.
                    // Centred horizontally in the gap between the two button groups.
                    let d = (self.progress_top - panel_top) * 0.9;
                    if d >= 64.0 {
                        let cy = panel_top + (self.progress_top - panel_top) / 2.0;
                        let r = Rect::from_center_size(pos2(cx, cy), vec2(d, d));
                        let painter = ui.ctx().layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("radar_layer")));
                        let dots = draw_radar(&painter, r, &p, amber, &self.rows, &self.blips, radar_net, self.radar_angle, self.radar_fade, true);
                        let resp = ui.interact(r, ui.make_persistent_id("hdr_radar"), egui::Sense::click());
                        let hit = resp.hover_pos().and_then(|m| dots.iter().filter(|dd| dd.pos.distance(m) < 9.0).min_by(|a, b| a.pos.distance(m).total_cmp(&b.pos.distance(m))));
                        let resp = match hit {
                            Some(dd) => resp.on_hover_text(dd.text.clone()),
                            None => resp.on_hover_text("Each dot is a device: position = its address in the range, distance from the centre = how fast it replied. Click to enlarge."),
                        };
                        if resp.clicked() {
                            self.radar_open = !self.radar_open;
                        }
                    }
                }
            }
            ui.add_space(10.0);
            let frac = if self.total > 0 { self.done as f32 / self.total as f32 } else { 0.0 };
            let text = if self.scanning {
                format!("{}  {:.0}%   ({}/{})", self.phase, frac * 100.0, self.done, self.total)
            } else if flash > 0.0 {
                format!("Complete  -  {} found", devices(self.rows.len()))
            } else if self.total > 0 {
                format!("Complete  -  100%  -  {}", devices(self.rows.len()))
            } else {
                "Ready".to_string()
            };
            let pb_top = ui.cursor().top();
            if (self.progress_top - pb_top).abs() > 0.5 {
                self.progress_top = pb_top;
                ctx.request_repaint();
            }
            progress_bar(ui, &p, if self.scanning || self.total > 0 { frac } else { 0.0 }, self.scanning, 0.0, &text);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Find").color(p.dim));
                let fid = ui.make_persistent_id("find_edit");
                let fr = line_edit(ui, &p, fid, &mut self.filter, 360.0, false, false, false, "IP, label, hostname, manufacturer or MAC");
                if self.focus_filter {
                    fr.request_focus();
                    self.focus_filter = false;
                }
                if !self.filter.is_empty() && ui.small_button("Clear").clicked() {
                    self.filter.clear();
                }
                let unknown = self.rows.iter().filter(|r| r.label.is_empty() && !r.me && !r.absent).count();
                let video = self.rows.iter().filter(|r| r.video.is_some() && !r.absent).count();
                let absent = self.rows.iter().filter(|r| r.absent).count();
                let live = self.rows.iter().filter(|r| !r.absent).count();
                let n_sel = self.sel_ips.len();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let yellow = Color32::from_rgb(0xFF, 0xD3, 0x3D);
                    let mut pill = |ui: &mut egui::Ui, text: String, col: Color32, f: Option<Filter>| {
                        let on = f.map(|f| self.count_filter == f).unwrap_or(false);
                        let r = ui.add(egui::Button::new(RichText::new(text).strong().color(col)).frame(on).fill(if on { p.w_idle } else { Color32::TRANSPARENT }).stroke(Stroke::new(1.0_f32, if on { p.mid } else { Color32::TRANSPARENT })));
                        if let Some(f) = f {
                            if r.on_hover_text("Click to filter; click again or \"devices\" to clear").clicked() {
                                self.count_filter = if on { Filter::None } else { f };
                            }
                        }
                    };
                    // laid out right-to-left -> visual order: devices, unknown, absent, video, selected
                    if n_sel > 0 {
                        pill(ui, format!("{} selected", n_sel), yellow, None);
                    }
                    if self.video_running {
                        ui.label(RichText::new("checking video...").color(p.dim));
                    } else if video > 0 {
                        pill(ui, format!("{} video", video), p.cyan, Some(Filter::Video));
                    }
                    if absent > 0 {
                        pill(ui, format!("{} absent", absent), p.dim, Some(Filter::Absent));
                    }
                    if unknown > 0 {
                        pill(ui, format!("{} unknown", unknown), p.warn, Some(Filter::Unknown));
                    }
                    if live > 0 {
                        pill(ui, devices(live), p.accent, Some(Filter::None));
                    }
                });
            });
            for c in &self.conflicts {
                ui.label(RichText::new(format!("Warning: {}", c)).color(p.warn));
            }
        });

        // Status line: smooth 1-second yellow flash when something completes.
        let k = match self.status_flash {
            Some(t) if t.elapsed() < Duration::from_millis(1000) => {
                ctx.request_repaint();
                (t.elapsed().as_secs_f32() * std::f32::consts::PI).sin() // 0 -> 1 -> 0
            }
            _ => {
                self.status_flash = None;
                0.0
            }
        };
        let yellow = Color32::from_rgb(0xFF, 0xD3, 0x3D);
        let mix = |a: Color32, b: Color32| {
            let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * k).round() as u8;
            Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
        };
        let status_bg = mix(p.panel, yellow);
        let lum = |c: Color32| {
            let l = |v: u8| {
                let v = v as f32 / 255.0;
                if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
            };
            0.2126 * l(c.r()) + 0.7152 * l(c.g()) + 0.0722 * l(c.b())
        };
        let contrast = |a: Color32, b: Color32| {
            let (x, y) = (lum(a), lum(b));
            (x.max(y) + 0.05) / (x.min(y) + 0.05)
        };
        let ink = Color32::from_rgb(0x14, 0x14, 0x14);
        if self.status != self.status_seen {
            self.status_seen = self.status.clone();
            self.status_at = Instant::now();
        }
        let age = self.status_at.elapsed().as_secs_f32();
        let busy_now = self.scanning || self.pings_pending > 0 || self.ps.as_ref().map(|p| p.running).unwrap_or(false);
        if age >= 30.0 && !busy_now && !self.status.is_empty() {
            self.status.clear();
            self.status_seen.clear();
        }
        let fade = if busy_now { 1.0 } else { ((30.0 - age) / 5.0).clamp(0.0, 1.0) };
        if fade < 1.0 && !self.status.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(100));
        } else if !self.status.is_empty() && !busy_now {
            ctx.request_repaint_after(Duration::from_secs_f32((25.0 - age).max(0.1)));
        }
        let status_fg = if contrast(p.primary, status_bg) >= contrast(ink, status_bg) { p.primary } else { ink };
        let status_fg = status_fg.gamma_multiply(fade);
        let status_dim = if status_fg == ink { Color32::from_rgb(0x3A, 0x3A, 0x3A) } else { p.dim };
        egui::TopBottomPanel::bottom("status").frame(panel_frame(&p).fill(status_bg)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                let path = self.status_path.as_ref().filter(|(t, _)| *t == self.status).map(|(_, p)| p.clone());
                let shown = if self.status.is_empty() { ">".to_string() } else { format!("> {}", self.status) };
                let sl = ui.add(egui::Label::new(RichText::new(shown).color(status_fg)).sense(egui::Sense::click()));
                if let Some(path) = path {
                    if sl.on_hover_text("Double-click to open the folder").double_clicked() {
                        platform::reveal(&path);
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&self.oui_note).color(status_dim));
                    if !self.dhcp_state.is_empty() {
                        ui.add_space(16.0);
                        // yellow while listening (dark ink on the flash so it stays readable); red if the port couldn't be opened
                        let col = if self.dhcp_state.contains("unavailable") {
                            p.bad
                        } else if contrast(yellow, status_bg) >= contrast(ink, status_bg) {
                            yellow
                        } else {
                            ink
                        };
                        ui.label(RichText::new(&self.dhcp_state).color(col)).on_hover_text(DHCP_HELP);
                    }
                    ui.add_space(16.0);
                    ui.label(RichText::new(SHORTCUTS).color(status_dim));
                });
            });
        });

        // ---------------- results table
        let mut action: Option<Action> = None;
        let mut sort_click: Option<usize> = None;
        let mut clicked: Option<usize> = None;
        let mut menu_row: Option<usize> = None;
        let mut hovered: Option<usize> = None;
        let n_sel = self.sel_ips.len();
        let q = self.filter.trim().to_lowercase();
        let pass_find = |r: &Row| {
            if q.is_empty() {
                return true;
            }
            // ".54" matches the end of the address only; a full IP matches exactly
            if let Some(suffix) = q.strip_prefix('.') {
                return r.ip.to_string().ends_with(&format!(".{}", suffix));
            }
            if q.chars().all(|c| c.is_ascii_digit() || c == '.') && q.contains('.') {
                if r.ip.to_string() == q {
                    return true;
                }
            }
            (0..HEAD.len()).any(|c| r.cell(c).to_lowercase().contains(&q)) || (q.contains("unknown") && r.label.is_empty())
        };
        let cf = self.count_filter;
        let pass_count = |r: &Row| match cf {
            Filter::None => true,
            Filter::Unknown => r.label.is_empty() && !r.me && !r.absent,
            Filter::Video => r.video.is_some() && !r.absent,
            Filter::Absent => r.absent,
        };
        let visible: Vec<usize> = (0..self.rows.len()).filter(|&i| pass_find(&self.rows[i]) && pass_count(&self.rows[i])).collect();
        egui::CentralPanel::default().frame(egui::Frame::none().fill(p.bg).inner_margin(egui::Margin::symmetric(8.0, 4.0))).show(ctx, |ui| {
            let half_gap = ui.spacing().item_spacing.x * 0.5;
            let fill_cell = |ui: &mut egui::Ui, col: Color32| {
                let rect = ui.max_rect().expand2(vec2(half_gap, 0.0));
                ui.painter().rect_filled(rect, 0.0, col);
            };
            let cw = self.col_w;
            let sp = ui.spacing().item_spacing.x;
            let vis_cols: Vec<usize> = (0..HEAD.len()).filter(|&c| c != C_VENDOR || self.show_vendor).collect();
            let full = ui.available_rect_before_wrap();
            // every column at its fitted width; Ping takes any spare room, so the table always fills the window
            let others: f32 = vis_cols.iter().filter(|&&c| c != C_PING).map(|&c| cw[c] + sp).sum();
            let ping_w = cw[C_PING].max(full.width() - others);
            let total = others + ping_w;
            let widths: Vec<f32> = vis_cols.iter().map(|&c| if c == C_PING { ping_w } else { cw[c] }).collect();
            let max_off = (total - full.width()).max(0.0).ceil();
            self.hscroll = self.hscroll.clamp(0.0, max_off);
            let off = self.hscroll;
            let bar_h = if max_off > 0.0 { 10.0 } else { 0.0 };
            ui.push_id("devices_table", |ui| {
                // header: its own table, shifted by the horizontal scroll, so it stays put when rows scroll
                let mut hu = ui.child_ui(Rect::from_min_size(full.min - vec2(off, 0.0), vec2(total, 40.0)), egui::Layout::top_down(egui::Align::Min));
                hu.set_clip_rect(Rect::from_min_size(full.min, vec2(full.width(), 40.0)).intersect(ui.clip_rect()));
                hu.push_id("hdr", |ui| {
                    table_columns(ui, &widths)
                        .header(32.0, |mut header| {
                    for &i in &vis_cols {
                        let h = &HEAD[i];
                        header.col(|ui| {
                            fill_cell(ui, p.band);
                            let arrow = if self.sort.0 == i { if self.sort.1 { "  \u{25BC}" } else { "  \u{25B2}" } } else { "" };
                            let t = RichText::new(format!("{}{}", h.to_uppercase(), arrow)).strong().color(p.primary);
                            if i == C_PING {
                                // left-aligned at the same padding as the cells, so the P sits over the O of "OK"
                                ui.add_space(PAD);
                                let b = ui.add(egui::Label::new(t).sense(egui::Sense::click())).on_hover_text(PING_HELP);
                                if b.clicked() {
                                    sort_click = Some(i);
                                }
                            } else {
                                ui.with_layout(egui::Layout::centered_and_justified(egui::Direction::LeftToRight), |ui| {
                                    if ui.add(egui::Button::new(t).frame(false)).clicked() {
                                        sort_click = Some(i);
                                    }
                                });
                            }
                        });
                    }
                        })
                        .body(|_| {});
                });
                let head_bottom = hu.min_rect().bottom();
                // rows: a vertical scroll area the width of the window (so its scroll bar is always visible),
                // holding the full-width table shifted left by the horizontal scroll
                let body_rect = Rect::from_min_max(pos2(full.left(), head_bottom), pos2(full.right(), full.bottom() - bar_h));
                let mut bu = ui.child_ui(body_rect, egui::Layout::top_down(egui::Align::Min));
                bu.set_clip_rect(body_rect.intersect(ui.clip_rect()));
                let vkeys = std::mem::take(&mut self.vscroll_rows);
                let mut sa = egui::ScrollArea::vertical().id_source("rows_scroll").auto_shrink([false, false]);
                if vkeys != 0.0 {
                    // Up / Down keys: move from where the list is now (egui keeps it within range)
                    let max = (self.vscroll_max).max(0.0);
                    sa = sa.vertical_scroll_offset((self.vscroll_off + vkeys * (ROW_H + bu.spacing().item_spacing.y)).clamp(0.0, max));
                }
                let out = sa.show(&mut bu, |su| {
                    let r = Rect::from_min_size(pos2(su.max_rect().left() - off, su.cursor().top()), vec2(total, body_rect.height()));
                    su.allocate_ui_at_rect(r, |ui| {
                        ui.push_id("body", |ui| {
                            table_columns(ui, &widths).body(|body| {
                    body.rows(ROW_H, visible.len(), |mut row| {
                        let i = visible[row.index()];
                        let r = &self.rows[i];
                        let selected = self.sel_ips.contains(&r.ip);
                        let hot = self.hover_row == Some(i) && !selected;
                        row.set_selected(selected);
                        for &c in &vis_cols {
                            row.col(|ui| {
                                if hot {
                                    fill_cell(ui, p.hover);
                                }
                                ui.add_space(PAD);
                                match c {
                                    C_IP => {
                                        let mono = ui.style().text_styles.get(&egui::TextStyle::Monospace).cloned().unwrap_or(FontId::monospace(14.0));
                                        if !r.absent {
                                            ink_label(ui, &r.ip.to_string(), mono, p.primary, false, false);
                                        } else if let Some(ip) = r.last_ip {
                                            ink_label(ui, &ip.to_string(), mono, p.dim, true, false)
                                                .on_hover_text("Last known address - not found this scan");
                                        }
                                    }
                                    C_LABEL => {
                                        if r.label.is_empty() && !r.me {
                                            ui.label(RichText::new("Unknown device").italics().color(p.warn))
                                                .on_hover_text("No label yet - double-click to name it");
                                        } else {
                                            let col = if r.absent { p.dim } else { p.primary };
                                            ui.label(RichText::new(&r.label).strong().color(col));
                                        }
                                    }
                                    C_HOST => {
                                        if let Some(v) = r.video {
                                            let hover = match v {
                                                Video::Camera => "Confirmed camera (answered ONVIF discovery)",
                                                Video::Nvr => "Confirmed recorder / NVR (answered ONVIF discovery)",
                                                Video::Stream => "Serves an RTSP video stream",
                                            };
                                            let extra = if r.video_desc.is_empty() { String::new() } else { format!("\n{}", r.video_desc) };
                                            ui.label(RichText::new(format!(" {} ", v.tag())).size(11.5).strong().color(p.bg).background_color(p.cyan))
                                                .on_hover_text(format!("{}{}", hover, extra));
                                        }
                                        if !r.open_rtsp.is_empty() || !r.open_snapshot.is_empty() {
                                            let mut t = Vec::new();
                                            if !r.open_rtsp.is_empty() { t.push(format!("RTSP stream needs no password:\n{}", r.open_rtsp)); }
                                            if !r.open_snapshot.is_empty() { t.push(format!("Snapshot image needs no password:\n{}", r.open_snapshot)); }
                                            ui.label(RichText::new(" OPEN STREAM ").size(11.0).strong().color(Color32::BLACK).background_color(p.bad))
                                                .on_hover_text(t.join("\n\n"));
                                        }
                                        let name_col = if r.absent { p.dim } else { p.mid };
                                        for (k, part) in r.host.split(HOST_SEP).filter(|x| !x.is_empty()).enumerate() {
                                            if k > 0 {
                                                ui.label(RichText::new("\u{00B7}").color(p.dim));
                                            }
                                            let tip = r.names_tooltip();
                                            let hover = |resp: egui::Response| if tip.is_empty() { resp } else { resp.on_hover_text(tip.as_str()) };
                                            if let Some((name, tag)) = part.split_once("  [") {
                                                hover(ui.label(RichText::new(name).color(name_col)));
                                                hover(ui.label(RichText::new(format!("[{}", tag)).size(12.0).color(p.dim)));
                                            } else {
                                                hover(ui.label(RichText::new(part).color(name_col)));
                                            }
                                        }
                                        if r.me {
                                            ui.label(RichText::new(format!("({})", THIS_PC)).strong().color(p.cyan));
                                        } else if r.gw {
                                            ui.label(RichText::new(format!("({})", GATEWAY)).strong().color(p.cyan))
                                                .on_hover_text("This PC's default gateway - the router traffic leaves the network through");
                                        }
                                    }
                                    C_VENDOR => {
                                        let col = if r.absent { p.dim } else if r.random_mac { p.warn } else { p.mid };
                                        ui.label(RichText::new(&r.vendor).color(col));
                                    }
                                    C_MAC => {
                                        let mono = ui.style().text_styles.get(&egui::TextStyle::Monospace).cloned().unwrap_or(FontId::monospace(14.0));
                                        ink_label(ui, &r.mac, mono, p.dim, false, true); // centred under the heading
                                    }
                                    _ if r.absent && r.ping.is_empty() => {
                                        ui.label(RichText::new("not found this scan").italics().color(p.dim));
                                    }
                                    _ => {
                                        let mut flash_ink: Option<Color32> = None;
                                        if let Some(t) = r.ping_flash {
                                            let t = t.elapsed().as_secs_f32();
                                            if t < 1.0 {
                                                let k = (t * std::f32::consts::PI).sin();
                                                let base = match r.ping_state {
                                                    PingState::Ok => p.accent,
                                                    PingState::NoReply => p.warn,
                                                    _ => p.bad,
                                                };
                                                let mixc = |a: Color32, b: Color32| {
                                                    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * k).round() as u8;
                                                    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
                                                };
                                                let bg = mixc(p.bg, base);
                                                fill_cell(ui, bg);
                                                // whichever of the normal colour or near-black reads better on this frame's fill
                                                let lum = |c: Color32| {
                                                    let l = |v: u8| {
                                                        let v = v as f32 / 255.0;
                                                        if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
                                                    };
                                                    0.2126 * l(c.r()) + 0.7152 * l(c.g()) + 0.0722 * l(c.b())
                                                };
                                                let cr = |a: Color32, b: Color32| {
                                                    let (x, y) = (lum(a), lum(b));
                                                    (x.max(y) + 0.05) / (x.min(y) + 0.05)
                                                };
                                                let ink = Color32::from_rgb(0x0A, 0x0A, 0x0A);
                                                flash_ink = Some(if cr(base, bg) >= cr(ink, bg) { base } else { ink });
                                            }
                                        }
                                        let col = match r.ping_state {
                                            PingState::Ok => p.accent,
                                            PingState::NoReply => p.warn,
                                            PingState::Unreachable => p.bad,
                                            _ => p.dim,
                                        };
                                        ui.label(RichText::new(&r.ping).strong().color(flash_ink.unwrap_or(col)));
                                    }
                                }
                            });
                        }
                        let resp = row.response();
                        if resp.hovered() {
                            hovered = Some(i);
                        }
                        if resp.clicked() {
                            clicked = Some(i);
                        }
                        if resp.double_clicked() {
                            action = Some(Action::Edit(i));
                        }
                        let absent = r.absent;
                        let has_last = r.last_ip.is_some();
                        resp.context_menu(|ui| {
                            menu_row = Some(i);
                            if ui.button("Edit label...").clicked() {
                                action = Some(Action::Edit(i));
                                ui.close_menu();
                            }
                            let ping_txt = if n_sel > 1 { "Ping selected" } else if absent { "Ping last known IP" } else { "Ping this device" };
                            if ui.add_enabled(!absent || has_last, egui::Button::new(ping_txt)).clicked() {
                                action = Some(Action::PingOne(i));
                                ui.close_menu();
                            }
                            if ui.add_enabled(!absent, egui::Button::new("Quick service check")).clicked() {
                                action = Some(Action::PortScan(i, true));
                                ui.close_menu();
                            }
                            if ui.add_enabled(!absent, egui::Button::new(if n_sel > 1 { "Port scan selected..." } else { "Port scan..." })).clicked() {
                                action = Some(Action::PortScan(i, false));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Forget this device").on_hover_text("Delete this device's label, notes and last-seen IP").clicked() {
                                action = Some(Action::Forget(i));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.add_enabled(!absent, egui::Button::new("Open web page")).clicked() {
                                action = Some(Action::Open(i, false));
                                ui.close_menu();
                            }
                            if ui.add_enabled(!absent, egui::Button::new("Open web page (HTTPS)")).clicked() {
                                action = Some(Action::Open(i, true));
                                ui.close_menu();
                            }
                            ui.separator();
                            for (txt, col) in [("Copy IP", Some(C_IP)), ("Copy MAC", Some(C_MAC)), ("Copy row", None)] {
                                let txt = if n_sel > 1 && self.sel_ips.contains(&r.ip) { format!("{} ({} rows)", txt, n_sel) } else { txt.to_string() };
                                // absent rows copy their last known address (if one was recorded)
                                let enabled = !absent || has_last || col == Some(C_MAC);
                                if ui.add_enabled(enabled, egui::Button::new(txt.as_str())).clicked() {
                                    action = Some(Action::Copy(i, col));
                                    ui.close_menu();
                                }
                            }
                            // stream actions last, for cameras with an open (passwordless) stream
                            if r.video.is_some() {
                                let has_rtsp = !r.open_rtsp.is_empty();
                                if has_rtsp {
                                    ui.separator();
                                    if ui.add_enabled(has_rtsp, egui::Button::new("Copy RTSP address")).on_hover_text(if has_rtsp { r.open_rtsp.as_str() } else { "No open RTSP stream found" }).clicked() {
                                        action = Some(Action::CopyText(r.open_rtsp.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.add_enabled(has_rtsp, egui::Button::new("Open in VLC")).on_hover_text("Play the open stream in VLC (if installed)").clicked() {
                                        action = Some(Action::Vlc(i));
                                        ui.close_menu();
                                    }
                                }
                            }
                        });
                    });
                            });
                        });
                    });
                });
                self.vscroll_off = out.state.offset.y;
                self.vscroll_max = (out.content_size.y - out.inner_rect.height()).max(0.0);
                // horizontal scroll bar: only when the table is wider than the window; moved with the arrow keys
                if max_off > 0.0 {
                    let track = Rect::from_min_max(pos2(full.left(), full.bottom() - bar_h + 3.0), pos2(full.right(), full.bottom() - 1.0));
                    let tw = (track.width() * full.width() / total).max(30.0);
                    let tx = track.left() + (track.width() - tw) * (off / max_off);
                    let active = self.hscroll_at.map(|t| t.elapsed() < Duration::from_millis(900)).unwrap_or(false);
                    ui.painter().rect_filled(track, 3.0, p.line.gamma_multiply(0.6));
                    ui.painter().rect_filled(Rect::from_min_size(pos2(tx, track.top()), vec2(tw, track.height())), 3.0, if active { p.primary } else { p.dim });
                }
            });
        });
        if self.select_all_pending {
            self.select_all_pending = false;
            for &k in &visible {
                self.sel_ips.insert(self.rows[k].ip);
            }
        }
        if hovered != self.hover_row {
            self.hover_row = hovered;
            ctx.request_repaint();
        }

        if let Some(i) = clicked {
            let ip = self.rows[i].ip;
            let m = ctx.input(|inp| inp.modifiers);
            if m.shift && self.anchor.is_some() {
                let pos = |x: Ipv4Addr| visible.iter().position(|&k| self.rows[k].ip == x);
                if let (Some(a), Some(b)) = (self.anchor.and_then(pos), pos(ip)) {
                    if !m.command {
                        self.sel_ips.clear();
                    }
                    for &k in &visible[a.min(b)..=a.max(b)] {
                        self.sel_ips.insert(self.rows[k].ip);
                    }
                }
            } else if m.command {
                if !self.sel_ips.remove(&ip) {
                    self.sel_ips.insert(ip);
                }
                self.anchor = Some(ip);
            } else if self.sel_ips.len() == 1 && self.sel_ips.contains(&ip) {
                // plain click on the only selected row clears the selection
                self.sel_ips.clear();
                self.anchor = None;
            } else {
                self.sel_ips.clear();
                self.sel_ips.insert(ip);
                self.anchor = Some(ip);
            }
        }
        if let Some(i) = menu_row {
            let ip = self.rows[i].ip;
            if !self.sel_ips.contains(&ip) {
                self.sel_ips.clear();
                self.sel_ips.insert(ip);
                self.anchor = Some(ip);
            }
        }
        if let Some(c) = sort_click {
            self.sort = if self.sort.0 == c { (c, !self.sort.1) } else { (c, false) };
            self.resort();
        }
        match action {
            Some(Action::Edit(i)) => {
                if let Some(r) = self.rows.get(i) {
                    if !r.mac.starts_with('(') {
                        self.edit = Some(EditState { mac: r.mac.clone(), ip: r.ip, label: r.label.clone(), focus: true });
                    }
                }
            }
            Some(Action::Forget(i)) => {
                if let Some(r) = self.rows.get(i) {
                    self.confirm_forget = Some((r.mac.clone(), if r.label.is_empty() { r.ip.to_string() } else { r.label.clone() }));
                }
            }
            Some(Action::Copy(i, col)) => self.copy(ctx, i, col),
            Some(Action::PingOne(i)) => {
                if self.rows[i].absent {
                    self.ping_absent(i);
                } else {
                    let ips: Vec<Ipv4Addr> = if self.sel_ips.contains(&self.rows[i].ip) { self.sel_ips.iter().copied().filter(|ip| !is_absent_key(*ip)).collect() } else { vec![self.rows[i].ip] };
                    self.ping_batch.clear();
                    for ip in ips {
                        self.manual_pings.insert(ip);
                        self.ping_ip(ip);
                    }
                    self.status = format!("Pinging {} ...", devices(self.pings_pending));
                }
            }
            Some(Action::CopyText(t)) => {
                self.clip = Some((platform::text_hash(&t), Instant::now()));
                ctx.output_mut(|o| o.copied_text = t);
                self.status = format!("Copied - the clipboard clears in {} seconds", CLIP_SECS);
            }
            Some(Action::Vlc(i)) => {
                if let Some(r) = self.rows.get(i) {
                    if !r.open_rtsp.is_empty() {
                        platform::open_in_vlc(&r.open_rtsp);
                        self.status = format!("Opening {} in VLC", r.open_rtsp);
                    }
                }
            }
            Some(Action::Open(i, https)) => {
                if let Some(r) = self.rows.get(i) {
                    let url = format!("{}://{}/", if https { "https" } else { "http" }, r.ip);
                    platform::open_url(&url);
                    self.status = format!("Opened {}", url);
                }
            }
            Some(Action::PortScan(i, quick)) => self.open_port_scan(Some(i), quick, ctx),
            None => {}
        }

        // ---------------- label dialog
        let mut close = false;
        let mut save: Option<(String, String)> = None;
        if let Some(e) = self.edit.as_mut() {
            egui::Window::new(RichText::new("Edit label").size(16.0).strong().color(p.primary))
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(RichText::new(format!("{}   {}", e.ip, e.mac)).monospace().color(p.dim));
                    ui.add_space(6.0);
                    let r = line_edit(ui, &p, egui::Id::new("label_edit"), &mut e.label, 340.0, false, false, false, "e.g. Hall camera");
                    if e.focus {
                        r.request_focus();
                        e.focus = false;
                    }
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        save = Some((e.mac.clone(), e.label.clone()));
                    }
                    ui.add_space(4.0);
                    ui.label(RichText::new("Saved by MAC address and kept between runs. Clear it to remove.").color(p.dim).size(12.5));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new("Save").min_size(vec2(90.0, 28.0))).clicked() {
                            save = Some((e.mac.clone(), e.label.clone()));
                        }
                        if ui.add(egui::Button::new("Cancel").min_size(vec2(90.0, 28.0))).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            close = true;
                        }
                    });
                });
        }
        if let Some((mac, label)) = save {
            self.save_edit(mac, label);
            close = true;
        }
        if close {
            self.edit = None;
        }

        // ---------------- erase confirmation
        if self.confirm_erase.is_some() {
            let mut go = None;
            let mut open_folder = false;
            if let Some((nfiles, saved, also)) = self.confirm_erase.as_mut() {
                egui::Window::new(RichText::new("Erase all data?").size(16.0).strong().color(p.bad))
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.set_max_width(480.0);
                        ui.label(format!(
                            "This securely overwrites and deletes {} file(s) the scanner has stored on this PC (device labels and snapshots), and clears everything held in memory: results, labels, port results and any copied text. Settings and the public vendor list are kept.",
                            nfiles
                        ));
                        if !saved.is_empty() {
                            ui.add_space(8.0);
                            ui.label(RichText::new(format!("{} encrypted saved file(s) (saved scans and label backups) remain in your save folder. They are not erased unless you tick the box below.", saved.len())).color(p.warn));
                            ui.horizontal(|ui| {
                                ui.checkbox(also, format!("Also erase the {} saved file(s)", saved.len()));
                                if ui.small_button("Open folder").clicked() {
                                    open_folder = true;
                                }
                            });
                        }
                        ui.add_space(6.0);
                        ui.label(RichText::new("This cannot be undone.").strong().color(p.bad));
                        ui.add_space(4.0);
                        ui.label(RichText::new("On SSDs, wear-levelling means no program can guarantee old copies are physically gone. Full-disk encryption (BitLocker) is the real protection.").size(12.5).color(p.dim));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let b = egui::Button::new(RichText::new("Erase everything").strong().color(Color32::WHITE)).fill(Color32::from_rgb(0xB0, 0x24, 0x24)).min_size(vec2(160.0, 30.0));
                            if ui.add(b).clicked() {
                                go = Some(true);
                            }
                            if ui.add(egui::Button::new("Cancel").min_size(vec2(100.0, 30.0))).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                go = Some(false);
                            }
                        });
                    });
            }
            if open_folder {
                platform::open_url(&store::output_dir().to_string_lossy());
            }
            if let Some(g) = go {
                if let Some((_, saved, also)) = self.confirm_erase.take() {
                    if g {
                        self.erase_everything(if also { saved } else { Vec::new() });
                    }
                }
            }
        }

        // ---------------- forget device confirmation
        if self.confirm_forget.is_some() {
            let mut go = None;
            if let Some((mac, name)) = self.confirm_forget.clone() {
                egui::Window::new(RichText::new("Forget device?").size(16.0).strong().color(p.bad))
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.set_max_width(420.0);
                        ui.label(format!("Delete all stored information for \"{}\" ({})?", name, mac));
                        ui.add_space(4.0);
                        ui.label(RichText::new("Its label, notes and last-seen address are removed. If it's online it stays in the list as unlabelled; if it's absent it disappears.").size(12.5).color(p.dim));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let b = egui::Button::new(RichText::new("Forget").strong().color(Color32::WHITE)).fill(Color32::from_rgb(0xB0, 0x24, 0x24)).min_size(vec2(110.0, 28.0));
                            if ui.add(b).clicked() {
                                go = Some(true);
                            }
                            if ui.add(egui::Button::new("Cancel").min_size(vec2(90.0, 28.0))).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                                go = Some(false);
                            }
                        });
                    });
            }
            if let Some(g) = go {
                if let Some((mac, _)) = self.confirm_forget.take() {
                    if g {
                        self.devices.remove(&mac);
                        let _ = store::save_devices(&self.devices);
                        self.rows.retain(|r| !(r.absent && r.mac == mac)); // drop the absent row
                        for r in self.rows.iter_mut().filter(|r| r.mac == mac) {
                            r.label.clear(); // a live row becomes unlabelled
                        }
                        self.status = format!("Forgotten {}", mac);
                    }
                }
            }
        }

        // ---------------- password dialog (save / open scan)
        let mut pw_done: Option<bool> = None; // Some(true)=OK pressed, Some(false)=cancel
        if let Some(d) = self.pw.as_mut() {
            let backup = matches!(d.mode, PwMode::SaveScan);
            let title = match d.mode {
                PwMode::SaveScan => "Encrypt saved scan",
                PwMode::OpenScan(_) => "Unlock saved scan",
            };
            egui::Window::new(RichText::new(title).size(16.0).strong().color(p.primary))
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_max_width(420.0);
                    ui.label(if backup {
                        "Choose a password for this file. It's encrypted with AES-256 and an Argon2id-derived key. If you lose the password, the file can't be recovered."
                    } else {
                        "Enter the password used when this file was saved."
                    });
                    ui.add_space(8.0);
                    let r1 = line_edit(ui, &p, egui::Id::new("pw1_edit"), &mut d.pw1, 380.0, false, false, true, "Password");
                    if d.focus {
                        r1.request_focus();
                        d.focus = false;
                    }
                    let mut enter = r1.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if backup {
                        let r2 = line_edit(ui, &p, egui::Id::new("pw2_edit"), &mut d.pw2, 380.0, false, false, true, "Repeat password");
                        enter = enter || (r2.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                        ui.label(RichText::new(format!("At least {} characters. A short phrase works well.", MIN_PW)).size(12.5).color(p.dim));
                    }
                    if !d.error.is_empty() {
                        ui.label(RichText::new(&d.error).color(p.bad));
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(if backup { "Encrypt and save" } else { "Unlock" }).min_size(vec2(140.0, 28.0))).clicked() || enter {
                            pw_done = Some(true);
                        }
                        if ui.add(egui::Button::new("Cancel").min_size(vec2(90.0, 28.0))).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            pw_done = Some(false);
                        }
                    });
                });
        }
        match pw_done {
            Some(true) => {
                if self.finish_password() {
                    self.pw = None;
                }
            }
            Some(false) => self.pw = None,
            None => {}
        }

        // ---------------- merge or overwrite?
        let mut choice: Option<Option<bool>> = None; // Some(Some(merge)) / Some(None)=cancel
        if let Some(map) = self.restore_choice.as_ref() {
            egui::Window::new(RichText::new("Restore labels").size(16.0).strong().color(p.primary))
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_max_width(440.0);
                    ui.label(format!("The file holds {} label(s). This PC currently has {}.", map.len(), self.devices.len()));
                    ui.add_space(4.0);
                    ui.label(RichText::new("Add these labels to this PC so future scans show them? Merge keeps this PC's labels and adds the file's (the file wins where both name the same device). Overwrite replaces all labels on this PC with the file's. View only shows them for this file but doesn't keep them.").size(12.5).color(p.dim));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new("Merge").min_size(vec2(110.0, 28.0))).clicked() {
                            choice = Some(Some(true));
                        }
                        if ui.add(egui::Button::new("Overwrite").min_size(vec2(110.0, 28.0))).clicked() {
                            choice = Some(Some(false));
                        }
                        if ui.add(egui::Button::new("View only").min_size(vec2(100.0, 28.0))).clicked() {
                            choice = Some(None);
                        }
                    });
                });
        }
        if let Some(c) = choice {
            if let Some(mut map) = self.restore_choice.take() {
                match c {
                    Some(merge) => self.apply_restore(map, merge),
                    None => {
                        for (mut k, mut v) in map.drain() {
                            k.zeroize();
                            v.label.zeroize();
                        }
                        self.status = "Viewing only - this file's labels are not saved on this PC (Save / open > Open saved scan again to merge them)".into();
                    }
                }
            }
        }

        // ---------------- snapshot window
        // ---------------- large radar
        if self.radar_open && radar_net.is_some() {
            let mut open = true;
            egui::Window::new(RichText::new("Radar").size(16.0).strong().color(p.primary))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_pos(pos2((ctx.screen_rect().right() - 470.0).max(8.0), 70.0))
                .show(ctx, |ui| {
                    let (rect, resp) = ui.allocate_exact_size(vec2(420.0, 420.0), egui::Sense::hover());
                    let dots = draw_radar(ui.painter(), rect, &p, amber, &self.rows, &self.blips, radar_net, self.radar_angle, self.radar_fade, true);
                    let hit = resp.hover_pos().and_then(|m| dots.iter().filter(|d| d.pos.distance(m) < 10.0).min_by(|a, b| a.pos.distance(m).total_cmp(&b.pos.distance(m))));
                    let line = hit.map(|d| d.text.clone()).unwrap_or_else(|| "Hover over a dot for details".into());
                    ui.label(RichText::new(line).color(if hit.is_some() { p.primary } else { p.dim }));
                    if let Some(d) = hit {
                        let _ = d.ip;
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                });
            if !open {
                self.radar_open = false;
            }
        }

        // ---------------- port scan window
        let mut ps_close = false;
        let mut ps_start = false;
        let mut ps_copy: Option<String> = None;
        let video_n = self.rows.iter().filter(|r| r.video.is_some()).count();
        let all_n = self.rows.len();
        let labels: HashMap<Ipv4Addr, String> = self.rows.iter().map(|r| (r.ip, r.label.clone())).collect();
        let sel_n = self.sel_ips.len();
        if let Some(ps) = self.ps.as_mut() {
            let mut open = true;
            egui::Window::new(RichText::new("Port scan").size(16.0).strong().color(p.primary))
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .min_width(860.0)
                .default_size(vec2(880.0, 520.0))
                // open on the right so the IP / label columns stay free for picking devices
                .default_pos(pos2((ctx.screen_rect().right() - 900.0).max(8.0), 270.0))
                .show(ctx, |ui| {
                    egui::Grid::new("ps_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                        ui.label(RichText::new("Targets").color(p.dim));
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut ps.target, PsTarget::Selected, format!("Selected devices ({})", sel_n))
                                .on_hover_text("Pick devices in the main list: click a row, Ctrl+click to add or remove, Shift+click for a range, Ctrl+A for all.");
                            ui.add_enabled_ui(video_n > 0, |ui| ui.radio_value(&mut ps.target, PsTarget::Video, format!("Video devices ({})", video_n)))
                                .response
                                .on_hover_text("Only devices confirmed by ONVIF or an RTSP stream");
                            ui.radio_value(&mut ps.target, PsTarget::All, format!("All devices ({})", all_n));
                        });
                        ui.end_row();
                        ui.label(RichText::new("Ports").color(p.dim));
                        let pw = (ui.available_width() - 4.0).max(300.0);
                        line_edit(ui, &p, egui::Id::new("ports_edit"), &mut ps.ports, pw, true, false, false, "22, 80, 443, 8000-8100")
                            .on_hover_text("Single ports, lists and ranges, e.g. 22, 80, 443, 8000-8100");
                        ui.end_row();
                        ui.label(RichText::new("Presets").color(p.dim));
                        ui.horizontal(|ui| {
                            for (name, ports) in scan::PRESETS {
                                if ui.button(name).on_hover_text(ports).clicked() {
                                    ps.ports = ports.to_string();
                                }
                            }
                        });
                        ui.end_row();
                        ui.label(RichText::new("Options").color(p.dim));
                        ui.horizontal(|ui| {
                            ui.label("Timeout");
                            ui.add(egui::DragValue::new(&mut ps.timeout_ms).clamp_range(100..=5000).speed(10).suffix(" ms"))
                                .on_hover_text("How long to wait for each port. Longer is more thorough but slower.");
                            ui.add_space(10.0);
                            ui.label("Parallel");
                            ui.add(egui::DragValue::new(&mut ps.parallel).clamp_range(16..=1000).speed(4))
                                .on_hover_text("Total connections at once, shared between all target devices.");
                            ui.add_space(10.0);
                            ui.label("Per device");
                            ui.add(egui::DragValue::new(&mut ps.per_host).clamp_range(1..=64).speed(1))
                                .on_hover_text("Most connections to any one device at once. Small devices like cameras stop answering if this is too high. 8-16 is safe.");
                            ui.add_space(10.0);
                            ui.checkbox(&mut ps.grab, "Grab banners").on_hover_text("Ask open services to identify themselves");
                            ui.checkbox(&mut ps.show_closed, "Show closed");
                        });
                        ui.end_row();
                    });
                    if !ps.error.is_empty() {
                        ui.label(RichText::new(&ps.error).color(p.bad));
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!ps.running, egui::Button::new(RichText::new("Start").strong()).min_size(vec2(110.0, 28.0))).clicked() {
                            ps_start = true;
                        }
                        if ui.add_enabled(ps.running, egui::Button::new("Stop").min_size(vec2(90.0, 28.0))).clicked() {
                            ps.stop.store(true, Ordering::SeqCst);
                        }
                        if ui.add_enabled(!ps.results.is_empty(), egui::Button::new("Copy results").min_size(vec2(120.0, 28.0))).clicked() {
                            let t: Vec<String> = ps.results.iter().filter(|r| r.state == PortState::Open).map(|r| format!("{}\t{}\t{}\t{}", r.ip, r.port, scan::service_name(r.port), r.banner)).collect();
                            ps_copy = Some(t.join("\n"));
                        }

                    });
                    ui.add_space(6.0);
                    let frac = if ps.total > 0 { ps.done as f32 / ps.total as f32 } else { 0.0 };
                    let txt = if ps.running && ps.done >= ps.total && ps.total > 0 {
                        ps.phase.clone()
                    } else if ps.running {
                        format!("{}  {:.0}%   ({}/{})", ps.phase, frac * 100.0, ps.done, ps.total)
                    } else if ps.total > 0 {
                        "Complete".to_string()
                    } else {
                        "Ready".to_string()
                    };
                    progress_bar(ui, &p, frac, ps.running, 0.0, &txt);
                    ui.add_space(6.0);
                    let count = |st: PortState| ps.results.iter().filter(|r| r.state == st).count();
                    let (open_n, closed_n, silent_n) = (count(PortState::Open), count(PortState::Closed), count(PortState::Filtered));
                    let risky = ps.results.iter().filter(|r| r.state == PortState::Open && scan::risk_note(r.port).is_some()).count();
                    ui.label(
                        RichText::new(format!(
                            "{} open  \u{00B7}  {} risky  \u{00B7}  {} closed  \u{00B7}  {} no response{}",
                            open_n,
                            risky,
                            closed_n,
                            silent_n,
                            if ps.show_closed { "" } else { "  (closed / no response hidden)" }
                        ))
                        .color(p.dim),
                    )
                    .on_hover_text("Closed = the device refused the connection. No response = nothing answered, even on a slow re-check - usually a firewall.");
                    ui.add_space(4.0);
                    let mut shown: Vec<&PortRow> = ps.results.iter().filter(|r| ps.show_closed || r.state == PortState::Open).collect();
                    shown.sort_by_key(|r| (u32::from(r.ip), r.port));
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(230.0).at_least(120.0))
                        .column(Column::initial(70.0).at_least(60.0))
                        .column(Column::initial(170.0).at_least(80.0))
                        .column(Column::initial(110.0).at_least(80.0))
                        .column(Column::remainder().at_least(150.0))
                        .header(26.0, |mut h| {
                            for t in ["DEVICE", "PORT", "SERVICE", "STATE", "BANNER / NOTE"] {
                                h.col(|ui| {
                                    ui.add_space(PAD);
                                    ui.label(RichText::new(t).strong().color(p.primary));
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(ROW_H, shown.len(), |mut row| {
                                let r = shown[row.index()];
                                let lbl = labels.get(&r.ip).filter(|l| !l.is_empty()).map(|l| format!("  {}", l)).unwrap_or_default();
                                row.col(|ui| {
                                    ui.add_space(PAD);
                                    ui.label(RichText::new(format!("{}{}", r.ip, lbl)).color(p.primary));
                                });
                                row.col(|ui| {
                                    ui.add_space(PAD);
                                    ui.label(RichText::new(r.port.to_string()).color(p.primary));
                                });
                                row.col(|ui| {
                                    ui.add_space(PAD);
                                    ui.label(RichText::new(scan::service_name(r.port)).color(p.mid));
                                });
                                let (st, col) = match r.state {
                                    PortState::Open => ("Open", p.accent),
                                    PortState::Closed => ("Closed", p.dim),
                                    PortState::Filtered => ("No response", p.dim),
                                };
                                row.col(|ui| {
                                    ui.add_space(PAD);
                                    ui.label(RichText::new(st).strong().color(col));
                                });
                                row.col(|ui| {
                                    ui.add_space(PAD);
                                    match scan::risk_note(r.port).filter(|_| r.state == PortState::Open) {
                                        Some(n) => ui.label(RichText::new(n).color(p.bad)),
                                        None => ui.label(RichText::new(&r.banner).color(p.dim)),
                                    };
                                });
                            });
                        });
                });
            if !open {
                ps.stop.store(true, Ordering::SeqCst);
                ps_close = true;
            }
        }
        if ps_start {
            self.run_port_scan(ctx);
        }
        if let Some(t) = ps_copy {
            self.clip = Some((platform::text_hash(&t), Instant::now()));
            ctx.output_mut(|o| o.copied_text = t);
            self.status = format!("Copied open ports - the clipboard clears in {} seconds", CLIP_SECS);
        }
        if ps_close {
            if let Some(mut ps) = self.ps.take() {
                for r in ps.results.iter_mut() {
                    r.banner.zeroize();
                }
            }
        }
        if self.ps.as_ref().map(|p| p.running).unwrap_or(false) || self.video_running {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        // ---------------- large-subnet confirmation
        if let Some(n) = self.confirm_big {
            let mut go = None;
            egui::Window::new(RichText::new("Large target").size(16.0).strong().color(p.warn))
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!("{} has {} addresses and may take a while.", self.subnet.trim(), n));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new("Scan anyway").min_size(vec2(120.0, 28.0))).clicked() {
                            go = Some(true);
                        }
                        if ui.add(egui::Button::new("Cancel").min_size(vec2(100.0, 28.0))).clicked() {
                            go = Some(false);
                        }
                    });
                });
            if let Some(g) = go {
                self.confirm_big = None;
                if g {
                    self.start(ctx, true);
                }
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let size = store::load_settings()
        .get("win")
        .and_then(|v| v.split_once(',').and_then(|(w, h)| Some([w.parse::<f32>().ok()?, h.parse::<f32>().ok()?])))
        .filter(|[w, h]| *w >= 900.0 && *h >= 460.0 && *w < 10000.0 && *h < 10000.0)
        .unwrap_or([1480.0, 820.0]); // default fits everything to the Ping column
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP)
            .with_inner_size(size)
            .with_maximized(true)
            .with_min_inner_size([980.0, 480.0])
            .with_icon(radar_icon()),
        ..Default::default()
    };
    eframe::run_native(APP, options, Box::new(|cc| Box::new(App::new(cc))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostname_merge() {
        let mut n: [String; 6] = Default::default();
        n[S_DHCP] = "WIFIWASHMACHINE-7584".into();
        assert_eq!(merge_names(&n), "WIFIWASHMACHINE-7584  [DHCP]"); // only the remembered one: still shown
        n[S_DNS] = "wifiwashmachine-7584.lan".into();
        n[S_NETBIOS] = "WIFIWASHMACHINE-7584".into();
        assert_eq!(merge_names(&n), "wifiwashmachine-7584.lan  [DNS, NetBIOS, DHCP]"); // same name: once
        n[S_MDNS_SD] = "Samsung Washer".into();
        assert_eq!(merge_names(&n), format!("Samsung Washer  [mDNS]{}wifiwashmachine-7584.lan  [DNS, NetBIOS, DHCP]", HOST_SEP));
        assert_eq!(merge_names(&Default::default()), "");
        // mDNS: the friendly name hides the .local name
        let mut c: [String; 6] = Default::default();
        c[S_MDNS_SD] = "HIKVISION IPC-T250H - G64687817".into();
        c[S_MDNS] = "IPC-T250H20210901AAWRG64687817.local".into();
        assert_eq!(merge_names(&c), "HIKVISION IPC-T250H - G64687817  [mDNS]");
        // Avahi's "host [mac]" service name matches the plain host name from DNS / NetBIOS
        let mut r = Row {
            ip: Ipv4Addr::new(192, 168, 1, 80), label: String::new(), host: String::new(), vendor: String::new(), mac: String::new(),
            me: false, gw: false, random_mac: false, video: None, video_desc: String::new(), ping: String::new(), ping_state: PingState::None,
            rt_ms: 1.0, ping_flash: None, open_rtsp: String::new(), open_snapshot: String::new(), absent: false, sort_ip: 0, names: Default::default(), last_ip: None };
        r.set_name(S_MDNS_SD, "YSF-Reflector [e4:5f:01:98:f7:ee]");
        r.set_name(S_DNS, "YSF-REFLECTOR");
        r.set_name(S_MDNS, "YSF-Reflector.local");
        r.set_name(S_NETBIOS, "YSF-REFLECTOR");
        assert_eq!(r.host, "YSF-Reflector  [mDNS, DNS, NetBIOS]");
        assert_eq!(strip_mac_suffix("Cam [not a mac]"), "Cam [not a mac]");
    }
    #[test]
    fn scan_roundtrip() {
        let rows = vec![Row {
            ip: Ipv4Addr::new(192, 168, 1, 51), label: "Street Cam, \"1\"".into(), host: "cam.local  [mDNS]".into(), vendor: "Hikvision".into(),
            mac: "5c:34:5b:b3:dd:03".into(), me: false, gw: false, random_mac: false, video: Some(Video::Camera), video_desc: "DS-2CD".into(),
            ping: "OK  1 ms".into(), ping_state: PingState::Ok, rt_ms: 1.0, ping_flash: None, open_rtsp: String::new(), open_snapshot: String::new(), absent: false, sort_ip: 0, names: Default::default(), last_ip: None }];
        let ports = vec![PortRow { ip: Ipv4Addr::new(192, 168, 1, 51), port: 554, state: PortState::Open, banner: "RTSP/1.0 401".into() }];
        let mut labels = HashMap::new();
        labels.insert("5c:34:5b:b3:dd:03".to_string(), DeviceInfo { label: "Street Cam, \"1\"".into(), notes: String::new(), last_ip: String::new() });
        let text = scan_to_text("192.168.1.0/24", &rows, &ports, &labels, &HashMap::new());
        let blob = store::encrypt_blob(store::MAGIC_SCAN, &text, "a long password").unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("Street Cam"));
        let ls = scan_from_text(&store::decrypt_blob(store::MAGIC_SCAN, &blob, "a long password").unwrap()).unwrap();
        assert_eq!(ls.subnet, "192.168.1.0/24");
        assert_eq!(ls.rows[0].label, "Street Cam, \"1\"");
        assert_eq!(ls.rows[0].video, Some(Video::Camera));
        assert_eq!(ls.ports[0].port, 554);
        assert_eq!(ls.labels["5c:34:5b:b3:dd:03"].label, "Street Cam, \"1\"");
    }

    #[test]
    fn saved_scan_keeps_dhcp_names() {
        let mut d = HashMap::new();
        d.insert("1c:9d:c2:cc:75:84".to_string(), "WIFIWASHMACHINE-7584".to_string());
        let ls = scan_from_text(&scan_to_text("192.168.1.0/24", &[], &[], &HashMap::new(), &d)).unwrap();
        assert_eq!(ls.dhcp["1c:9d:c2:cc:75:84"], "WIFIWASHMACHINE-7584");
    }

    #[test]
    fn saved_scan_keeps_absent_rows() {
        let mut names: [String; 6] = Default::default();
        names[S_DHCP] = "WIFIWASHMACHINE-7584".into();
        let rows = vec![Row {
            ip: absent_key(0), label: "Washing Machine".into(), host: merge_names(&names), vendor: "Espressif Inc.".into(),
            mac: "1c:9d:c2:cc:75:84".into(), me: false, gw: false, random_mac: false, video: None, video_desc: String::new(),
            ping: String::new(), ping_state: PingState::None, rt_ms: 0.0, ping_flash: None, open_rtsp: String::new(), open_snapshot: String::new(),
            absent: true, sort_ip: 0, names, last_ip: Some(Ipv4Addr::new(192, 168, 1, 116)) }];
        let ls = scan_from_text(&scan_to_text("192.168.1.0/24", &rows, &[], &HashMap::new(), &HashMap::new())).unwrap();
        let r = &ls.rows[0];
        assert!(r.absent);
        assert!(is_absent_key(r.ip));
        assert_eq!(r.last_ip, Some(Ipv4Addr::new(192, 168, 1, 116)));
        assert_eq!(r.names[S_DHCP], "WIFIWASHMACHINE-7584");
        assert_eq!(r.cell(C_IP), "192.168.1.116");
    }

    #[test]
    fn old_saved_scan_formats_open() {
        // v1.2-era scan text: no response-time column on rows, 3-field label lines
        let old = "#myriameter-scan,1\nmeta,192.168.1.0/24,20261028_220057\n\
row,192.168.1.199,Weather Monitor,,Espressif Inc.,04:b2:47:9c:c4:6c,0,0,,,OK  42 ms,ok\n\
row,192.168.1.195,Printer,,LiteON,6c:4b:90:5c:4f:e1,0,0,,,No reply,noreply\n\
label,04:b2:47:9c:c4:6c,Weather Monitor\n";
        let blob = store::encrypt_blob(store::MAGIC_SCAN, old, "a long password").unwrap();
        let ls = scan_from_text(&store::decrypt_blob(store::MAGIC_SCAN, &blob, "a long password").unwrap()).unwrap();
        assert_eq!(ls.rows.len(), 2);
        assert_eq!(ls.rows[0].rt_ms, 1.0); // missing column -> default
        assert_eq!(ls.rows[1].label, "Printer"); // label only on the row, not in the label list...
        assert!(!ls.labels.contains_key("6c:4b:90:5c:4f:e1")); // ...which is why rows must be offered too
        assert_eq!(ls.labels["04:b2:47:9c:c4:6c"].label, "Weather Monitor");
    }

    #[test]
    fn find_dot_prefix() {
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let ends = |addr: &str, q: &str| ip(addr).to_string().ends_with(&format!(".{}", q.strip_prefix('.').unwrap()));
        assert!(ends("192.168.1.1", ".1"));
        assert!(!ends("192.168.1.100", ".1"));
        assert!(!ends("192.168.1.10", ".1"));
        assert!(ends("192.168.1.100", ".100"));
    }

    #[test]
    fn open_stream_survives_save() {
        let mut rows = vec![Row {
            ip: Ipv4Addr::new(192, 168, 1, 54), label: "Cam".into(), host: String::new(), vendor: "Vatilon".into(),
            mac: "e8:b7:23:41:75:61".into(), me: false, gw: false, random_mac: false, video: Some(Video::Camera), video_desc: String::new(),
            open_rtsp: "rtsp://192.168.1.54:554/live".into(), open_snapshot: String::new(),
            ping: "OK  1 ms".into(), ping_state: PingState::Ok, rt_ms: 1.0, ping_flash: None, absent: false, sort_ip: 0, names: Default::default(), last_ip: None }];
        let text = scan_to_text("192.168.1.0/24", &rows, &[], &HashMap::new(), &HashMap::new());
        let ls = scan_from_text(&text).unwrap();
        assert_eq!(ls.rows[0].open_rtsp, "rtsp://192.168.1.54:554/live");
        rows.clear();
    }

    #[test]
    fn port_scan_gentle_on_small_devices() {
        // a listener that only accepts a few connections at a time still gets every port answered
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap().port();
        std::thread::spawn(move || for s in l.incoming().flatten() { drop(s); });
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        run_ports(vec![Ipv4Addr::LOCALHOST], vec![1, 2, 3, open], 300, 200, 12, false, &tx, &stop);
        drop(tx);
        let res: Vec<PortRow> = rx.try_iter().filter_map(|m| if let Msg::Port(p) = m { Some(p) } else { None }).collect();
        assert_eq!(res.len(), 4);
        assert!(res.iter().any(|r| r.port == open && r.state == PortState::Open));
    }
}
