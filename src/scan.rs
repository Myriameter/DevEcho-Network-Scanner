//! Network side: adapters, ARP probing, name lookups (DNS / mDNS / NetBIOS / UPnP).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Adapter {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

// ------------------------------------------------------------------ subnet maths
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let s = s.trim();
    let (ip, pfx) = match s.split_once('/') {
        Some((a, b)) => (a.trim().parse::<Ipv4Addr>().ok()?, b.trim().parse::<u8>().ok()?),
        None => (s.parse::<Ipv4Addr>().ok()?, 32),
    };
    if pfx > 32 {
        return None;
    }
    let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
    Some((Ipv4Addr::from(u32::from(ip) & mask), pfx))
}

pub fn hosts(net: Ipv4Addr, pfx: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(net);
    let size: u64 = 1u64 << (32 - pfx as u32);
    let (first, last) = if pfx >= 31 { (0, size - 1) } else { (1, size - 2) };
    (first..=last).map(|i| Ipv4Addr::from(base.wrapping_add(i as u32))).collect()
}

pub fn in_net(ip: Ipv4Addr, net: Ipv4Addr, pfx: u8) -> bool {
    let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
    u32::from(ip) & mask == u32::from(net)
}

pub fn default_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("10.255.255.255:1").ok()?; // no packet is sent
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

pub fn adapters() -> Vec<Adapter> {
    let mut out = os_adapters();
    if out.is_empty() {
        if let Some(ip) = default_ip() {
            out.push(Adapter { name: "Default route (guessed /24)".into(), ip, prefix: 24 });
        }
    }
    out
}

#[allow(dead_code)]
pub fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":")
}

// ------------------------------------------------------------------ Windows API
#[cfg(any(windows, feature = "wincheck"))]
#[allow(non_snake_case, dead_code)]
pub mod win {
    use super::{mac_str, Adapter};
    use std::ffi::c_void;
    use std::net::Ipv4Addr;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn SendARP(dest: u32, src: u32, mac: *mut u8, len: *mut u32) -> u32;
        fn GetAdaptersAddresses(family: u32, flags: u32, reserved: *mut c_void, addrs: *mut u8, size: *mut u32) -> u32;
        fn GetIpNetTable(table: *mut u8, size: *mut u32, order: i32) -> u32;
        fn GetIpForwardTable(table: *mut u8, size: *mut u32, order: i32) -> u32;
        fn IcmpCreateFile() -> isize;
        fn IcmpCloseHandle(h: isize) -> i32;
        fn IcmpSendEcho(h: isize, dest: u32, data: *const c_void, size: u16, opts: *const c_void, reply: *mut c_void, reply_size: u32, timeout: u32) -> u32;
    }

    /// ICMP echo via the Windows ICMP API (no admin rights needed).
    pub fn icmp_echo(ip: Ipv4Addr, timeout_ms: u32) -> super::Echo {
        let h = unsafe { IcmpCreateFile() };
        if h == -1 {
            return super::Echo::NoReply;
        }
        let data = [0x61u8; 32];
        let mut reply = vec![0u64; 64]; // 512 bytes: ICMP_ECHO_REPLY + payload + slack
        let n = unsafe {
            IcmpSendEcho(h, u32::from_ne_bytes(ip.octets()), data.as_ptr() as *const c_void, data.len() as u16,
                         std::ptr::null(), reply.as_mut_ptr() as *mut c_void, 512, timeout_ms)
        };
        unsafe { IcmpCloseHandle(h) };
        if n == 0 {
            return super::Echo::NoReply;
        }
        let b = unsafe { std::slice::from_raw_parts(reply.as_ptr() as *const u8, 12) };
        let status = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
        let rtt = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
        match status {
            0 => super::Echo::Ok(rtt),
            11002 | 11003 | 11004 | 11005 => super::Echo::Unreachable, // net/host/protocol/port unreachable
            _ => super::Echo::NoReply,
        }
    }

    /// Default gateways from Windows' routing table (routes to 0.0.0.0/0).
    pub fn default_gateways() -> Vec<Ipv4Addr> {
        let mut size: u32 = 0;
        unsafe { GetIpForwardTable(std::ptr::null_mut(), &mut size, 0) };
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        if unsafe { GetIpForwardTable(buf.as_mut_ptr(), &mut size, 0) } != 0 {
            return Vec::new();
        }
        let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let mut out = Vec::new();
        for i in 0..n {
            // MIB_IPFORWARDROW: dest, mask, policy, next hop, ... (14 x u32)
            let o = 4 + i * 56;
            let Some(r) = buf.get(o..o + 56) else { break };
            let (dest, mask, hop) = (&r[0..4], &r[4..8], &r[12..16]);
            if dest == [0; 4] && mask == [0; 4] && hop != [0; 4] {
                let g = Ipv4Addr::new(hop[0], hop[1], hop[2], hop[3]);
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
        out
    }

    /// Windows' own ARP/neighbour cache - catches devices that answered late.
    pub fn neighbours() -> Vec<(Ipv4Addr, String)> {
        let mut size: u32 = 0;
        unsafe { GetIpNetTable(std::ptr::null_mut(), &mut size, 0) };
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        if unsafe { GetIpNetTable(buf.as_mut_ptr(), &mut size, 0) } != 0 {
            return Vec::new();
        }
        let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let mut out = Vec::new();
        for i in 0..n {
            let o = 4 + i * 24; // MIB_IPNETROW: index, physlen, phys[8], addr, type
            let Some(r) = buf.get(o..o + 24) else { break };
            let plen = u32::from_ne_bytes([r[4], r[5], r[6], r[7]]) as usize;
            let typ = u32::from_ne_bytes([r[20], r[21], r[22], r[23]]);
            let mac = &r[8..14];
            if plen == 6 && (typ == 3 || typ == 4) && mac != [0xff; 6] && !(mac[0] == 1 && mac[1] == 0 && mac[2] == 0x5e) && mac != [0; 6] {
                out.push((Ipv4Addr::new(r[16], r[17], r[18], r[19]), mac_str(mac)));
            }
        }
        out
    }

    #[repr(C)]
    struct SockAddr {
        family: u16,
        data: [u8; 14],
    }
    #[repr(C)]
    struct SocketAddress {
        sockaddr: *const SockAddr,
        len: i32,
    }
    #[repr(C)]
    struct Unicast {
        length: u32,
        flags: u32,
        next: *const Unicast,
        address: SocketAddress,
        prefix_origin: i32,
        suffix_origin: i32,
        dad_state: i32,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        lease_lifetime: u32,
        on_link_prefix: u8,
    }
    #[repr(C)]
    struct AdapterAddresses {
        length: u32,
        if_index: u32,
        next: *const AdapterAddresses,
        adapter_name: *const u8,
        first_unicast: *const Unicast,
        first_anycast: *const c_void,
        first_multicast: *const c_void,
        first_dns: *const c_void,
        dns_suffix: *const u16,
        description: *const u16,
        friendly_name: *const u16,
        phys: [u8; 8],
        phys_len: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: i32,
    }

    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    pub fn arp_probe(ip: Ipv4Addr) -> Option<String> {
        let mut mac = [0u8; 8];
        let mut len: u32 = 6;
        let rc = unsafe { SendARP(u32::from_ne_bytes(ip.octets()), 0, mac.as_mut_ptr(), &mut len) };
        if rc == 0 && len == 6 {
            Some(mac_str(&mac[..6]))
        } else {
            None
        }
    }

    pub fn adapters() -> Vec<Adapter> {
        const AF_INET: u32 = 2;
        const FLAGS: u32 = 0x2 | 0x4 | 0x8; // skip anycast, multicast, DNS servers
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let mut ok = false;
        for _ in 0..4 {
            buf = vec![0u64; size as usize / 8 + 1];
            let rc = unsafe {
                GetAdaptersAddresses(AF_INET, FLAGS, std::ptr::null_mut(), buf.as_mut_ptr() as *mut u8, &mut size)
            };
            if rc == 0 {
                ok = true;
                break;
            }
            if rc != 111 {
                break; // anything but ERROR_BUFFER_OVERFLOW is fatal
            }
        }
        let mut out = Vec::new();
        if !ok {
            return out;
        }
        unsafe {
            let mut p = buf.as_ptr() as *const AdapterAddresses;
            while !p.is_null() {
                let a = &*p;
                if a.oper_status == 1 && a.if_type != 24 {
                    let mut name = wide(a.friendly_name);
                    if name.is_empty() {
                        name = wide(a.description);
                    }
                    let mut u = a.first_unicast;
                    while !u.is_null() {
                        let ua = &*u;
                        let sa = ua.address.sockaddr;
                        if !sa.is_null() && (*sa).family == AF_INET as u16 {
                            let d = (*sa).data;
                            let ip = Ipv4Addr::new(d[2], d[3], d[4], d[5]);
                            let o = ip.octets();
                            if o[0] != 127 && !(o[0] == 169 && o[1] == 254) {
                                out.push(Adapter { name: name.clone(), ip, prefix: ua.on_link_prefix });
                            }
                        }
                        u = ua.next;
                    }
                }
                p = a.next;
            }
        }
        out
    }
}

#[cfg(windows)]
fn os_adapters() -> Vec<Adapter> {
    win::adapters()
}

#[cfg(windows)]
pub fn default_gateways() -> Vec<Ipv4Addr> {
    win::default_gateways()
}

#[cfg(not(windows))]
pub fn default_gateways() -> Vec<Ipv4Addr> {
    // /proc/net/route: Iface Destination Gateway ... (hex, little-endian)
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 2 && f[1] == "00000000" {
                if let Ok(g) = u32::from_str_radix(f[2], 16) {
                    let ip = Ipv4Addr::from(g.to_le_bytes());
                    if !ip.is_unspecified() && !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ Linux / other
#[cfg(not(windows))]
fn os_adapters() -> Vec<Adapter> {
    // `ip -o -4 addr` : "2: eth0    inet 192.168.1.10/24 brd ..."
    let mut out = Vec::new();
    if let Ok(o) = std::process::Command::new("ip").args(["-o", "-4", "addr"]).output() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let Some(i) = f.iter().position(|x| *x == "inet") {
                if let (Some(name), Some(cidr)) = (f.get(1), f.get(i + 1)) {
                    if let Some((ip_s, p)) = cidr.split_once('/') {
                        if let (Ok(ip), Ok(prefix)) = (ip_s.parse::<Ipv4Addr>(), p.parse::<u8>()) {
                            let o = ip.octets();
                            if o[0] != 127 && !(o[0] == 169 && o[1] == 254) {
                                out.push(Adapter { name: name.to_string(), ip, prefix });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(not(windows))]
pub fn ping(ip: Ipv4Addr) {
    let _ = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &ip.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(windows))]
pub fn arp_table() -> HashMap<Ipv4Addr, String> {
    let mut t = HashMap::new();
    if let Ok(s) = std::fs::read_to_string("/proc/net/arp") {
        for line in s.lines().skip(1) {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 4 && p[3] != "00:00:00:00:00:00" {
                if let Ok(ip) = p[0].parse() {
                    t.insert(ip, p[3].to_lowercase());
                }
            }
        }
    }
    t
}

// ------------------------------------------------------------------ ping
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Echo {
    Ok(u32),
    NoReply,
    Unreachable,
}

/// Two attempts, 1 s each - a single lost packet shouldn't mark a device as silent.
pub fn echo(ip: Ipv4Addr) -> Echo {
    let first = echo_once(ip, 1000);
    if first == Echo::NoReply {
        echo_once(ip, 1000)
    } else {
        first
    }
}

#[cfg(windows)]
fn echo_once(ip: Ipv4Addr, timeout_ms: u32) -> Echo {
    win::icmp_echo(ip, timeout_ms)
}

#[cfg(not(windows))]
fn echo_once(ip: Ipv4Addr, timeout_ms: u32) -> Echo {
    let secs = (timeout_ms / 1000).max(1).to_string();
    let Ok(o) = std::process::Command::new("ping").args(["-c", "1", "-W", &secs, &ip.to_string()]).output() else {
        return Echo::NoReply;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    if o.status.success() {
        let ms = text
            .split("time=")
            .nth(1)
            .and_then(|t| t.split_whitespace().next())
            .and_then(|t| t.parse::<f32>().ok())
            .unwrap_or(0.0);
        Echo::Ok(ms.round() as u32)
    } else if text.contains("nreachable") {
        Echo::Unreachable
    } else {
        Echo::NoReply
    }
}

// ------------------------------------------------------------------ name lookups
fn dns_name(ip: Ipv4Addr) -> String {
    match dns_lookup::lookup_addr(&IpAddr::V4(ip)) {
        Ok(n) if n != ip.to_string() => n,
        _ => String::new(),
    }
}

fn dns_decode(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let l = *buf.get(off)? as usize;
        if l & 0xC0 == 0xC0 {
            if end.is_none() {
                end = Some(off + 2);
            }
            off = ((l & 0x3F) << 8) | *buf.get(off + 1)? as usize;
            hops += 1;
            if hops > 20 {
                return None;
            }
            continue;
        }
        if l == 0 {
            return Some((labels.join("."), end.unwrap_or(off + 1)));
        }
        labels.push(String::from_utf8_lossy(buf.get(off + 1..off + 1 + l)?).into_owned());
        off += 1 + l;
    }
}

fn mdns_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    let q = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let id = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) & 0xFFFF) as u16;
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for part in q.split('.') {
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.extend_from_slice(&[0, 0, 12, 0, 1]);
    let r = (|| -> Option<String> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        s.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;
        s.send_to(&pkt, (ip, 5353)).ok()?;
        let mut d = [0u8; 4096];
        let (n, _) = s.recv_from(&mut d).ok()?;
        let d = &d[..n];
        let qd = u16::from_be_bytes([*d.get(4)?, *d.get(5)?]);
        let an = u16::from_be_bytes([*d.get(6)?, *d.get(7)?]);
        let mut off = 12;
        for _ in 0..qd {
            off = dns_decode(d, off)?.1 + 4;
        }
        for _ in 0..an {
            off = dns_decode(d, off)?.1;
            let h = d.get(off..off + 10)?;
            let typ = u16::from_be_bytes([h[0], h[1]]);
            let rdl = u16::from_be_bytes([h[8], h[9]]) as usize;
            off += 10;
            if typ == 12 {
                return Some(dns_decode(d, off)?.0.trim_end_matches('.').to_string());
            }
            off += rdl;
        }
        None
    })();
    r.unwrap_or_default()
}

const NBSTAT: [u8; 50] = *b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01";

fn netbios_name(ip: Ipv4Addr) -> String {
    let r = (|| -> Option<String> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        s.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;
        s.send_to(&NBSTAT, (ip, 137)).ok()?;
        let mut d = [0u8; 4096];
        let (n, _) = s.recv_from(&mut d).ok()?;
        let d = &d[..n];
        let count = *d.get(56)? as usize;
        for i in 0..count {
            let e = d.get(57 + i * 18..75 + i * 18)?;
            let name = String::from_utf8_lossy(&e[..15]).trim().to_string();
            let flags = u16::from_be_bytes([e[16], e[17]]);
            if !name.is_empty() && e[15] == 0 && flags & 0x8000 == 0 {
                return Some(name);
            }
        }
        None
    })();
    r.unwrap_or_default()
}

// Name-source bits (the "Names" drop-down).
pub const N_DNS: u8 = 1;
pub const N_MDNS: u8 = 2;
pub const N_NETBIOS: u8 = 4;
pub const N_UPNP: u8 = 8;
pub const N_DHCP: u8 = 16;
pub const N_DEFAULT: u8 = N_DNS | N_MDNS | N_NETBIOS | N_UPNP;
/// Sources that need a per-device lookup during the scan.
pub const N_PER_HOST: u8 = N_DNS | N_MDNS | N_NETBIOS;

/// The enabled ones of DNS, mDNS and NetBIOS in parallel. Returns every non-empty answer as
/// (source bit, name); the caller ranks and merges them. Each lookup has its own timeout.
pub fn hostnames(ip: Ipv4Addr, mask: u8) -> Vec<(u8, String)> {
    let fns: [(u8, fn(Ipv4Addr) -> String); 3] = [(N_DNS, dns_name), (N_MDNS, mdns_name), (N_NETBIOS, netbios_name)];
    let (tx, rx) = mpsc::channel::<(u8, String)>();
    for (bit, f) in fns {
        if mask & bit != 0 {
            let tx = tx.clone();
            thread::spawn(move || {
                let _ = tx.send((bit, f(ip)));
            });
        }
    }
    drop(tx);
    rx.iter().filter(|(_, n)| !n.trim().is_empty()).map(|(b, n)| (b, n.trim().trim_end_matches('.').to_string())).collect()
}

// ------------------------------------------------------------------ passive DHCP listener
/// What a device said about itself in a DHCP broadcast.
#[derive(Clone, Debug, PartialEq)]
pub struct DhcpSeen {
    pub mac: String,
    pub host: String,
    pub ip: Option<Ipv4Addr>, // its current or requested address, when the packet says
}

/// Keep only a sensible printable hostname (DHCP option 12 is free text from the device).
fn clean_host(b: &[u8]) -> String {
    let s: String = b.iter().take_while(|&&c| c != 0).filter(|c| c.is_ascii_graphic()).map(|&c| c as char).take(63).collect();
    s.trim_end_matches('.').to_string()
}

/// Parse a BOOTP/DHCP client message (DISCOVER / REQUEST / INFORM). Read-only; never replies.
pub fn parse_dhcp(d: &[u8]) -> Option<DhcpSeen> {
    if d.len() < 240 || d[0] != 1 || d[1] != 1 || d[2] != 6 || d[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None; // not a client request on Ethernet/Wi-Fi with the DHCP magic cookie
    }
    let mac = mac_str(&d[28..34]);
    let ciaddr = Ipv4Addr::new(d[12], d[13], d[14], d[15]);
    let (mut kind, mut host, mut fqdn, mut req) = (0u8, String::new(), String::new(), None);
    let mut i = 240;
    while i < d.len() {
        let code = d[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        let len = *d.get(i + 1)? as usize;
        let v = d.get(i + 2..i + 2 + len)?;
        match code {
            53 if len == 1 => kind = v[0],
            12 => host = clean_host(v),
            50 if len == 4 => req = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            81 if len > 3 => {
                // client FQDN: flags, rcode1, rcode2, name (wire format when the E bit is set)
                let name = &v[3..];
                fqdn = if v[0] & 0x04 != 0 {
                    let mut out = Vec::new();
                    let mut k = 0;
                    while k < name.len() && name[k] != 0 {
                        let l = name[k] as usize;
                        if let Some(lab) = name.get(k + 1..k + 1 + l) {
                            if !out.is_empty() {
                                out.push(b'.');
                            }
                            out.extend_from_slice(lab);
                        }
                        k += 1 + l;
                    }
                    clean_host(&out)
                } else {
                    clean_host(name)
                };
            }
            _ => {}
        }
        i += 2 + len;
    }
    if !matches!(kind, 1 | 3 | 8) {
        return None; // DISCOVER, REQUEST, INFORM only
    }
    if host.is_empty() {
        host = fqdn.split('.').next().unwrap_or("").to_string();
    }
    if host.is_empty() || mac == "00:00:00:00:00:00" {
        return None;
    }
    let ip = if !ciaddr.is_unspecified() { Some(ciaddr) } else { req };
    Some(DhcpSeen { mac, host, ip })
}

/// Listen on UDP 67 for DHCP broadcasts until `stop` is set. `on_state` gets Ok(()) once listening,
/// or Err(reason) if the port can't be opened; `on_seen` gets every hostname heard.
pub fn dhcp_listen(stop: std::sync::Arc<std::sync::atomic::AtomicBool>, on_state: impl Fn(Result<(), String>), on_seen: impl Fn(DhcpSeen)) {
    use std::sync::atomic::Ordering;
    // a previous listener may still be letting go of the port: retry briefly
    let mut sock = None;
    let mut err = String::new();
    for _ in 0..8 {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match UdpSocket::bind("0.0.0.0:67") {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => {
                err = match e.kind() {
                    std::io::ErrorKind::AddrInUse => "port 67 in use".into(),
                    std::io::ErrorKind::PermissionDenied => "no permission for port 67".into(),
                    _ => e.to_string(),
                };
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    let Some(s) = sock else {
        on_state(Err(err));
        return;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    on_state(Ok(()));
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::Relaxed) {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            if let Some(seen) = parse_dhcp(&buf[..n]) {
                on_seen(seen);
            }
        }
    }
}

// ------------------------------------------------------------------ UPnP / SSDP
fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&#39;", "'").replace("&amp;", "&")
}

fn http_get(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr: SocketAddr = if hostport.contains(':') { hostport.parse().ok()? } else { format!("{}:80", hostport).parse().ok()? };
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(s, "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", path, hostport).ok()?;
    let mut body = Vec::new();
    let _ = s.take(65536).read_to_end(&mut body);
    Some(String::from_utf8_lossy(&body).into_owned())
}

fn friendly_name(xml: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let a = lower.find("<friendlyname>")? + "<friendlyname>".len();
    let b = a + lower[a..].find("</friendlyname>")?;
    let n = html_unescape(xml[a..b].trim());
    if n.is_empty() {
        None
    } else {
        Some(n)
    }
}

pub fn ssdp_discover(net: Ipv4Addr, pfx: u8, local: Option<Ipv4Addr>) -> HashMap<Ipv4Addr, String> {
    let msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let mut locs: HashMap<Ipv4Addr, String> = HashMap::new();
    let bind = (local.unwrap_or(Ipv4Addr::UNSPECIFIED), 0);
    if let Ok(s) = UdpSocket::bind(bind) {
        let _ = s.set_multicast_ttl_v4(2);
        let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
        for _ in 0..2 {
            let _ = s.send_to(msg, ("239.255.255.250", 1900));
        }
        let end = Instant::now() + Duration::from_secs(3);
        let mut buf = [0u8; 8192];
        while Instant::now() < end {
            if let Ok((n, SocketAddr::V4(from))) = s.recv_from(&mut buf) {
                let ip = *from.ip();
                if locs.contains_key(&ip) || !in_net(ip, net, pfx) {
                    continue;
                }
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("location") {
                            locs.insert(ip, v.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
    let handles: Vec<_> = locs
        .into_iter()
        .map(|(ip, url)| thread::spawn(move || (ip, http_get(&url).and_then(|x| friendly_name(&x)))))
        .collect();
    handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .filter_map(|(ip, n)| n.map(|n| (ip, n)))
        .collect()
}

/// One-shot mDNS service discovery (like the Ubiquiti controller): multicast-ask who's announcing
/// services, follow PTR -> SRV/A to map each device's friendly instance name to its IP. Read-only.
pub fn mdns_discover(net: Ipv4Addr, pfx: u8, local: Option<Ipv4Addr>) -> HashMap<Ipv4Addr, String> {
    let mut names: HashMap<Ipv4Addr, String> = HashMap::new();
    let bind = (local.unwrap_or(Ipv4Addr::UNSPECIFIED), 0);
    let Ok(s) = UdpSocket::bind(bind) else { return names };
    let _ = s.set_multicast_ttl_v4(2);
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));

    // Query the service enumerator plus a batch of common service types directly, so we get
    // instance names in one pass without waiting for a second round of queries.
    let types = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
        "_ipp._tcp.local", "_printer._tcp.local", "_spotify-connect._tcp.local", "_hap._tcp.local",
        "_miio._udp.local", "_ewelink._tcp.local", "_smartthings._tcp.local", "_matter._tcp.local",
        "_homekit._tcp.local", "_workstation._tcp.local", "_device-info._tcp.local", "_sonos._tcp.local",
    ];
    for t in types {
        let _ = s.send_to(&mdns_query(t, 12), ("224.0.0.251", 5353));
    }

    // instance name -> friendly label, instance -> target host, host/A -> ip
    let mut instance_label: HashMap<String, String> = HashMap::new();
    let mut instance_host: HashMap<String, String> = HashMap::new();
    let mut host_ip: HashMap<String, Ipv4Addr> = HashMap::new();
    let mut ptr_seen: Vec<String> = Vec::new();

    let end = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 8192];
    while Instant::now() < end {
        let (n, from) = match s.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(f))) => (n, f),
            _ => continue,
        };
        let src = *from.ip();
        parse_mdns_records(&buf[..n], &mut instance_label, &mut instance_host, &mut host_ip, &mut ptr_seen);
        // many devices put their A record in the same packet; if the sender is in-range and named, keep it
        let _ = src;
    }

    // Resolve: for each instance we have a host for, map its friendly label to the host's IP.
    for (inst, host) in &instance_host {
        if let Some(ip) = host_ip.get(host) {
            if in_net(*ip, net, pfx) {
                let label = instance_label.get(inst).cloned().unwrap_or_else(|| first_label(inst));
                names.entry(*ip).or_insert(label);
            }
        }
    }
    names
}

/// Build an mDNS query packet for one name and record type.
fn mdns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // id 0, 1 question
    for part in name.split('.') {
        if part.is_empty() {
            continue;
        }
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // class IN
    pkt
}

/// The human-friendly first label of a service instance, e.g. "Samsung Washer._http._tcp.local" -> "Samsung Washer".
fn first_label(name: &str) -> String {
    // decode DNS escaping of the first label
    let mut out = String::new();
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '.' {
            break;
        }
        if c == '\\' {
            if let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    let digits: String = (0..3).filter_map(|_| chars.next()).collect();
                    if let Ok(b) = digits.parse::<u8>() {
                        out.push(b as char);
                        continue;
                    }
                } else {
                    out.push(d);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

fn parse_mdns_records(
    d: &[u8],
    instance_label: &mut HashMap<String, String>,
    instance_host: &mut HashMap<String, String>,
    host_ip: &mut HashMap<String, Ipv4Addr>,
    ptr_seen: &mut Vec<String>,
) {
    let _ = ptr_seen;
    let run = (|| -> Option<()> {
        let qd = u16::from_be_bytes([*d.get(4)?, *d.get(5)?]);
        let an = u16::from_be_bytes([*d.get(6)?, *d.get(7)?]);
        let ns = u16::from_be_bytes([*d.get(8)?, *d.get(9)?]);
        let ar = u16::from_be_bytes([*d.get(10)?, *d.get(11)?]);
        let mut off = 12;
        for _ in 0..qd {
            off = dns_decode(d, off)?.1 + 4;
        }
        for _ in 0..(an as usize + ns as usize + ar as usize) {
            let (name, no) = dns_decode(d, off)?;
            off = no;
            let h = d.get(off..off + 10)?;
            let typ = u16::from_be_bytes([h[0], h[1]]);
            let rdl = u16::from_be_bytes([h[8], h[9]]) as usize;
            off += 10;
            let rd_start = off;
            match typ {
                12 => {} // PTR enumerations are followed up by the direct type queries
                33 => {
                    // SRV: name is the instance; target host is at rd_start+6
                    if let Some((host, _)) = dns_decode(d, rd_start + 6) {
                        instance_host.insert(name.clone(), host);
                    }
                }
                1 => {
                    // A: name is the host, rdata is 4 bytes
                    if rdl == 4 {
                        if let Some(b) = d.get(rd_start..rd_start + 4) {
                            host_ip.insert(name.clone(), Ipv4Addr::new(b[0], b[1], b[2], b[3]));
                        }
                    }
                }
                16 => {
                    // TXT: sometimes carries a friendly 'fn=' / 'md=' label; keep the instance's own label
                    instance_label.entry(name.clone()).or_insert_with(|| first_label(&name));
                }
                _ => {}
            }
            off = rd_start + rdl;
        }
        Some(())
    })();
    let _ = run;
    // ensure every instance we saw via SRV has at least its first-label name
    let insts: Vec<String> = instance_host.keys().cloned().collect();
    for inst in insts {
        instance_label.entry(inst.clone()).or_insert_with(|| first_label(&inst));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dhcp_request() {
        let mut d = vec![0u8; 240];
        d[0] = 1;
        d[1] = 1;
        d[2] = 6;
        d[28..34].copy_from_slice(&[0x1c, 0x9d, 0xc2, 0xcc, 0x75, 0x84]);
        d[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        d.extend_from_slice(&[53, 1, 3, 50, 4, 192, 168, 1, 116]);
        d.push(12);
        d.push(20);
        d.extend_from_slice(b"WIFIWASHMACHINE-7584");
        d.push(255);
        let s = parse_dhcp(&d).unwrap();
        assert_eq!(s.mac, "1c:9d:c2:cc:75:84");
        assert_eq!(s.host, "WIFIWASHMACHINE-7584");
        assert_eq!(s.ip, Some(Ipv4Addr::new(192, 168, 1, 116)));
        // a server reply (op 2) or an OFFER is ignored
        let mut r = d.clone();
        r[0] = 2;
        assert!(parse_dhcp(&r).is_none());
        let mut o = d.clone();
        o[242] = 2;
        assert!(parse_dhcp(&o).is_none());
        // FQDN fallback (option 81, wire format)
        let mut f = d[..240].to_vec();
        f.extend_from_slice(&[53, 1, 1, 81, 3 + 8, 0x04, 0, 0, 3, b'e', b's', b'p', 2, b'h', b'q', 0, 255]);
        assert_eq!(parse_dhcp(&f).unwrap().host, "esp");
    }

    #[test]
    fn cidr() {
        assert_eq!(parse_cidr("192.168.1.66/24"), Some((Ipv4Addr::new(192, 168, 1, 0), 24)));
        assert_eq!(hosts(Ipv4Addr::new(192, 168, 1, 0), 24).len(), 254);
        assert_eq!(hosts(Ipv4Addr::new(10, 0, 0, 5), 32).len(), 1);
        assert!(in_net(Ipv4Addr::new(192, 168, 1, 9), Ipv4Addr::new(192, 168, 1, 0), 24));
    }
    #[test]
    fn mdns_service_name() {
        assert_eq!(first_label("Samsung Washer 1234._http._tcp.local"), "Samsung Washer 1234");
        assert_eq!(first_label("Office\\032Printer._ipp._tcp.local"), "Office Printer");
        // SRV + A in one packet -> instance label mapped to IP
        let mut il = std::collections::HashMap::new();
        let mut ih = std::collections::HashMap::new();
        let mut hi = std::collections::HashMap::new();
        let mut ps = Vec::new();
        // build a tiny response: 0 questions, 2 answers (SRV for instance -> host, A for host)
        let mut d = vec![0u8,0, 0x84,0, 0,0, 0,2, 0,0, 0,0];
        // SRV: name "Cam._rtsp._tcp.local", type 33, data: prio/weight/port(6) + target "cam.local"
        let srv_name = b"\x03Cam\x05_rtsp\x04_tcp\x05local\x00";
        d.extend_from_slice(srv_name);
        d.extend_from_slice(&[0,33, 0,1, 0,0,0,120]); // type SRV, class, ttl
        let target = b"\x03cam\x05local\x00";
        let rdl = (6 + target.len()) as u16;
        d.extend_from_slice(&rdl.to_be_bytes());
        d.extend_from_slice(&[0,0, 0,0, 0x01,0xBB]); // prio, weight, port 443
        d.extend_from_slice(target);
        // A: name "cam.local", type 1, 4 bytes 192.168.1.9
        d.extend_from_slice(b"\x03cam\x05local\x00");
        d.extend_from_slice(&[0,1, 0,1, 0,0,0,120, 0,4, 192,168,1,9]);
        parse_mdns_records(&d, &mut il, &mut ih, &mut hi, &mut ps);
        let host = ih.get("Cam._rtsp._tcp.local").expect("instance->host");
        assert_eq!(hi.get(host.as_str()), Some(&Ipv4Addr::new(192,168,1,9)));
        assert_eq!(il.get("Cam._rtsp._tcp.local").map(|s| s.as_str()), Some("Cam"));
    }

    #[test]
    fn mdns_decode() {
        let mut r = vec![0u8, 1, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        let q = b"\x011\x011\x03168\x03192\x07in-addr\x04arpa\x00";
        r.extend_from_slice(q);
        r.extend_from_slice(&[0, 12, 0, 1, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 120, 0, 13]);
        r.extend_from_slice(b"\x06nas-pi\x05local\x00");
        let (n, off) = dns_decode(&r, 12).unwrap();
        assert_eq!(n, "1.1.168.192.in-addr.arpa");
        let off = off + 4;
        let (_, off) = dns_decode(&r, off).unwrap();
        assert_eq!(dns_decode(&r, off + 10).unwrap().0, "nas-pi.local");
    }
    #[test]
    fn upnp_name() {
        let x = "<root><device><friendlyName>Bedroom TV &amp; more</friendlyName></device></root>";
        assert_eq!(friendly_name(x).unwrap(), "Bedroom TV & more");
    }
}

// ================================================================== port scanning
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

pub const PRESETS: [(&str, &str); 6] = [
    ("Common", "21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080"),
    ("Web", "80, 443, 8000, 8008, 8080, 8443, 8888"),
    ("Remote access", "22, 23, 3389, 5900, 5938, 5985, 5986"),
    ("Cameras / NVR", "80, 443, 554, 1935, 8000, 8554, 8899, 34567, 37777"),
    ("1-1024", "1-1024"),
    ("All", "1-65535"),
];

/// "22, 80, 8000-8100" -> sorted, de-duplicated ports. Err explains what's wrong.
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut v = Vec::new();
    for part in s.split([',', ' ', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let a: u16 = a.parse().map_err(|_| format!("'{}' isn't a port number", part))?;
        let b: u16 = b.parse().map_err(|_| format!("'{}' isn't a port range", part))?;
        if a == 0 || b == 0 || a > b {
            return Err(format!("'{}' isn't a valid range (1-65535)", part));
        }
        v.extend(a..=b);
    }
    v.sort_unstable();
    v.dedup();
    if v.is_empty() {
        return Err("Enter at least one port".into());
    }
    Ok(v)
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "MS-RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        554 => "RTSP",
        993 => "IMAPS",
        995 => "POP3S",
        1723 => "PPTP",
        1883 => "MQTT",
        1935 => "RTMP",
        3306 => "MySQL",
        3389 => "RDP",
        5900 => "VNC",
        5938 => "TeamViewer",
        5985 => "WinRM",
        5986 => "WinRM (TLS)",
        8000 => "Hikvision SDK / HTTP",
        8008 | 8080 | 8888 => "HTTP (alt)",
        8443 => "HTTPS (alt)",
        8554 => "RTSP (alt)",
        8899 => "ONVIF (alt)",
        34567 => "XMeye DVR",
        37777 => "Dahua",
        _ => "",
    }
}

/// Plain-English warning for ports that are risky to leave open on a LAN.
pub fn risk_note(port: u16) -> Option<&'static str> {
    match port {
        23 => Some("Risky: Telnet sends logins unencrypted - disable it if you can"),
        21 => Some("Risky: FTP sends logins unencrypted"),
        139 | 445 => Some("File sharing (SMB) - make sure it's meant to be shared"),
        3389 => Some("Remote Desktop - keep it off the internet"),
        5900 => Some("VNC remote control - often weakly protected"),
        34567 => Some("XMeye cloud/DVR port - known for weak security"),
        _ => None,
    }
}

fn read_some(s: &mut TcpStream, ms: u64) -> String {
    let _ = s.set_read_timeout(Some(Duration::from_millis(ms)));
    let mut buf = [0u8; 512];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).into_owned(),
        _ => String::new(),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().chars().filter(|c| !c.is_control()).take(80).collect()
}

/// What an open port says about itself (best effort, short timeouts).
fn banner(ip: Ipv4Addr, port: u16, s: &mut TcpStream) -> String {
    match port {
        443 | 8443 | 993 | 995 | 5986 => "TLS".into(),
        554 | 8554 => {
            let _ = write!(s, "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port);
            first_line(&read_some(s, 700))
        }
        80 | 8000 | 8008 | 8080 | 8888 | 8899 => {
            let _ = write!(s, "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
            let r = read_some(s, 700);
            r.lines()
                .find(|l| l.to_ascii_lowercase().starts_with("server:"))
                .map(|l| l.trim().chars().take(80).collect())
                .unwrap_or_else(|| first_line(&r))
        }
        _ => first_line(&read_some(s, 500)), // SSH / FTP / SMTP / Telnet greet first
    }
}

pub fn probe_port(ip: Ipv4Addr, port: u16, timeout_ms: u64, grab: bool) -> (PortState, String) {
    let addr = SocketAddr::from((ip, port));
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(mut s) => {
            let b = if grab { banner(ip, port, &mut s) } else { String::new() };
            (PortState::Open, b)
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => (PortState::Closed, String::new()),
        Err(_) => (PortState::Filtered, String::new()),
    }
}

// ================================================================== video devices
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Video {
    Camera,
    Nvr,
    Stream,
}

impl Video {
    pub fn tag(self) -> &'static str {
        match self {
            Video::Camera => "CAM",
            Video::Nvr => "NVR",
            Video::Stream => "RTSP",
        }
    }
}

fn xml_values<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    // matches <anyprefix:Tag>value</anyprefix:Tag>
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&format!(":{}>", tag)).or_else(|| rest.find(&format!("<{}>", tag))) {
        let start = rest[i..].find('>').map(|j| i + j + 1).unwrap_or(rest.len());
        let end = rest[start..].find('<').map(|j| start + j).unwrap_or(rest.len());
        out.push(rest[start..end].trim());
        rest = &rest[end..];
    }
    out
}

/// Classify an ONVIF ProbeMatch from its Types and Scopes.
pub fn classify_onvif(xml: &str) -> Option<(Video, String)> {
    let types = xml_values(xml, "Types").join(" ");
    let scopes = xml_values(xml, "Scopes").join(" ");
    if !types.contains("NetworkVideoTransmitter") && !types.contains("Device") && !scopes.contains("onvif://") {
        return None;
    }
    let scope = |key: &str| {
        scopes.split_whitespace().find_map(|s| s.strip_prefix(&format!("onvif://www.onvif.org/{}/", key))).map(|v| v.replace("%20", " "))
    };
    let model = scope("hardware").unwrap_or_default();
    let name = scope("name").unwrap_or_default();
    let low = format!("{} {} {}", scopes, model, types).to_lowercase();
    let nvr = low.contains("type/nvr") || low.contains("networkvideorecorder") || low.contains("recorder")
        || model.starts_with("DS-7") || model.starts_with("DS-9") || model.starts_with("NVR");
    let desc = [name, model].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" / ");
    Some((if nvr { Video::Nvr } else { Video::Camera }, desc))
}

/// WS-Discovery probe for ONVIF devices; listens ~2.5 s.
pub fn onvif_discover(local: Option<Ipv4Addr>) -> HashMap<Ipv4Addr, (Video, String)> {
    let id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let msg = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><e:Header><w:MessageID>uuid:{:032x}</w:MessageID>\
<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>\
<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>\
<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>",
        id
    );
    let mut out = HashMap::new();
    let Ok(s) = UdpSocket::bind((local.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)) else { return out };
    let _ = s.set_multicast_ttl_v4(2);
    let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
    for _ in 0..2 {
        let _ = s.send_to(msg.as_bytes(), ("239.255.255.250", 3702));
    }
    let end = Instant::now() + Duration::from_millis(2500);
    let mut buf = vec![0u8; 16384];
    while Instant::now() < end {
        if let Ok((n, SocketAddr::V4(from))) = s.recv_from(&mut buf) {
            if let Some(c) = classify_onvif(&String::from_utf8_lossy(&buf[..n])) {
                out.insert(*from.ip(), c);
            }
        }
    }
    out
}

/// True if the device answers as an RTSP (video streaming) server on 554 or 8554.
pub fn rtsp_probe(ip: Ipv4Addr) -> bool {
    [554u16, 8554].iter().any(|&port| {
        if let Ok(mut s) = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_millis(400)) {
            let _ = write!(s, "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port);
            read_some(&mut s, 800).starts_with("RTSP/")
        } else {
            false
        }
    })
}

/// What a video device exposes WITHOUT any login (all passive, read-only).
#[derive(Clone, Default)]
pub struct OpenStream {
    pub rtsp: Option<String>,
    pub snapshot: Option<String>,
}

impl OpenStream {
    pub fn any(&self) -> bool {
        self.rtsp.is_some() || self.snapshot.is_some()
    }
}

const RTSP_PATHS: [&str; 10] = [
    "/", "/Streaming/Channels/101", "/Streaming/Channels/1", "/live", "/live/ch0",
    "/cam/realmonitor?channel=1&subtype=0", "/11", "/h264", "/stream1", "/video1",
];
const SNAP_PATHS: [&str; 8] = [
    "/onvif-http/snapshot", "/snapshot.jpg", "/snap.jpg", "/image/jpeg.cgi",
    "/cgi-bin/snapshot.cgi", "/axis-cgi/jpg/image.cgi", "/tmpfs/auto.jpg", "/jpg/image.jpg",
];

fn rtsp_status(ip: Ipv4Addr, port: u16, verb: &str, path: &str) -> Option<u16> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_millis(400)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
    let _ = write!(s, "{} rtsp://{}:{}{} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n", verb, ip, port, path);
    let r = read_some(&mut s, 900);
    if !r.starts_with("RTSP/") {
        return None;
    }
    r.split_whitespace().nth(1).and_then(|c| c.parse().ok())
}

/// GET the path; Some(true) if it answered 200 with image content and no auth challenge.
fn http_image(ip: Ipv4Addr, port: u16, path: &str) -> Option<bool> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_millis(350)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(700)));
    let _ = write!(s, "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", path, ip);
    let mut buf = [0u8; 400];
    let n = s.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
    let first = head.lines().next().unwrap_or("");
    if !first.contains("200") || head.contains("www-authenticate") {
        return Some(false);
    }
    Some(head.contains("content-type: image") || head.contains("content-type: multipart"))
}

/// Passively find an open RTSP stream and/or an open snapshot image. No credentials are ever sent.
pub fn open_stream(ip: Ipv4Addr) -> OpenStream {
    let mut out = OpenStream::default();
    'rtsp: for &port in &[554u16, 8554] {
        if rtsp_status(ip, port, "OPTIONS", "/").is_none() {
            continue; // not an RTSP port
        }
        for path in RTSP_PATHS {
            if rtsp_status(ip, port, "DESCRIBE", path) == Some(200) {
                out.rtsp = Some(format!("rtsp://{}:{}{}", ip, port, path));
                break 'rtsp;
            }
        }
    }
    for &port in &[80u16, 8080] {
        for path in SNAP_PATHS {
            if http_image(ip, port, path) == Some(true) {
                out.snapshot = Some(format!("http://{}:{}{}", ip, port, path));
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests2 {
    use super::*;
    #[test]
    fn ports() {
        assert_eq!(parse_ports("22, 80,8000-8002 80").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("http").is_err());
        assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
    }
    #[test]
    fn onvif() {
        let x = "<d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types><d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/DS-2CD2143G2-I onvif://www.onvif.org/name/HIKVISION%20DS-2CD</d:Scopes></d:ProbeMatch>";
        let (v, d) = classify_onvif(x).unwrap();
        assert_eq!(v, Video::Camera);
        assert!(d.contains("DS-2CD2143G2-I"));
        let n = x.replace("DS-2CD2143G2-I", "DS-7608NI-K2");
        assert_eq!(classify_onvif(&n).unwrap().0, Video::Nvr);
    }
}
#[cfg(test)]
mod tests3 {
    use super::*;
    #[test]
    fn probe_live() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let (st, b) = probe_port(Ipv4Addr::LOCALHOST, port, 500, true);
        assert_eq!(st, PortState::Open);
        assert!(b.starts_with("SSH-2.0"));
        let (st2, _) = probe_port(Ipv4Addr::LOCALHOST, 1, 500, false);
        assert_eq!(st2, PortState::Closed);
    }
}
