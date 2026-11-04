# DevEcho Network Scanner v1.4

Fast LAN discovery with a GUI, written in Rust. It finds every device on your network, works out what each one is, flags cameras and recorders that stream video without a password, and lets you label devices so you recognise them next time. Your labels are encrypted on disk.

For use on networks you own or are authorised to test.

## What's new in v1.4

- **Passive DHCP listener.** Picks up the hostname a device announces when it joins the network, so ESP32 gadgets and other devices that ignore DNS, mDNS and NetBIOS finally get a name. It never sends anything.
- **Ping + ARP together.** Every address is pinged and ARP-requested in one pass; a device counts as found if either answers.
- **Every hostname, ranked and merged.** Each device keeps the name from every source. Matching names show once with all their sources (`washer [DNS, DHCP]`); different names are all listed, best first. Hover to see every name heard.
- **Hostname source picker.** Turn DNS, mDNS, NetBIOS, UPnP and DHCP on or off from the **Hostname** drop-down.
- **Known devices stay visible.** A labelled device that isn't found in a scan still shows, greyed, with its last known IP, so you can ping it or copy the IP. **Forget this device** removes it.
- **Clickable header counts** filter the list: devices / unknown / absent / video / selected.
- **OPEN STREAM badge** in red on any camera whose stream or snapshot can be viewed with no password (hover for the URL).
- **Saved scans are now the backup.** A `.mls` file holds every row, every hostname with its source, all labels and every DHCP-learned name. Opening one can merge or overwrite this PC's labels. Separate label backups (`.mlb`) are gone; any old ones are still removed by **Erase all data**.
- **Interface:** opens maximised, columns size themselves to their contents, arrow-key scrolling (sideways too, with a position bar), and the Manufacturer column can be hidden by right-clicking **Update vendors**.

Labels and settings from earlier versions are picked up automatically on first run.

## Download

Get `devecho-network-scanner.exe` from this repository (Windows 10/11, 64-bit). It's a single portable file, with no installer and no admin rights needed. Just run it.

### VirusTotal scan

[![VirusTotal: 1/70](https://img.shields.io/badge/VirusTotal-1%2F70-yellowgreen?logo=virustotal)](https://www.virustotal.com/gui/file/f208698b7e5c72f475cc0b682865ed778dc1b248ce54acb90714817f69e916db/detection)

**1 / 70** security vendors flagged `devecho-network-scanner.exe` (scanned 4 November 2026). The one detection is a generic name from Bkav Pro (`W32.Malware.9E9D6E2A`); the other 69 report it as clean. Unsigned tools that ping and probe the network are a common source of heuristic false positives. [View the full report](https://www.virustotal.com/gui/file/f208698b7e5c72f475cc0b682865ed778dc1b248ce54acb90714817f69e916db/detection), or build it yourself from source (below).

SHA-256: `f208698b7e5c72f475cc0b682865ed778dc1b248ce54acb90714817f69e916db`

To check that your download is the same file, run this in PowerShell and compare the hash:

```powershell
Get-FileHash .\devecho-network-scanner.exe -Algorithm SHA256
```

## Features

### Discovery
- **Automatic adapter detection.** Lists this PC's active IPv4 adapters and their subnets. You can also type any subnet, e.g. `192.168.1.0/24`.
- **Ping + ARP sweep.** Each address gets an ICMP ping and an ARP request at the same time (the native Windows `SendARP` API on Windows; parallel ping plus the kernel ARP table on Linux). A device is found if either answers, and a read of the OS neighbour cache catches late replies.
- **Passive DHCP listener** (off by default). Listens on UDP port 67 for the broadcasts devices send when they join the network. It runs the whole time the app is open, not just during a scan. A detection fills in the hostname, flashes the radar dot, and brings back a "not found" device or adds one the scan missed. The status line shows `DHCP: listening` or `DHCP: unavailable (...)`, for example when another copy of the scanner already has the port. Windows may ask you to allow it through the firewall.
- **Adjustable threads.** 256 covers a /24 in about 3 seconds. Raise it for bigger networks, or lower it to be gentler on the network.
- **Large-target guard.** Asks for confirmation before scanning more than 4,096 addresses.
- **This PC and the gateway** are marked in the results.

### Identification
- **Hostnames from five sources:** DNS, mDNS, NetBIOS and UPnP/SSDP (on by default) and the DHCP listener, chosen from the **Hostname** drop-down.
  - Names are ranked: mDNS friendly name, DNS, mDNS `.local` name, NetBIOS, UPnP, DHCP. mDNS shows one name (the friendly name if there is one), and the MAC address that Linux machines tack onto their mDNS name (`host [xx:xx:...]`) is removed.
  - Names that agree (ignoring case and `.local` / `.lan`) show once with all their sources; names that differ are all shown, separated by `·`.
  - DHCP names are remembered per MAC (encrypted), so they show on later scans.
- **Manufacturer lookup** from the MAC address, using the IEEE OUI list. A copy is built into the .exe, so this works offline. **Update vendors** downloads the latest list from IEEE; right-click it to show or hide the Manufacturer column.
- **Video device detection.** ONVIF WS-Discovery confirms cameras and NVRs (with model and name where they report it), and RTSP probing finds video streams. Devices get CAM / NVR / RTSP badges.
- **Unprotected video check.** A red **OPEN STREAM** badge marks RTSP streams and HTTP snapshot URLs that answer without a password (hover for the URL). This check is passive: no credentials are ever sent.

### Ping
- **Ping all / ping selected.** Uses the Windows ICMP API (no admin needed), with two attempts per device. Results show OK + round-trip time, No reply or Unreachable.

### Port scanning
- **Targets:** selected devices, video devices only, or all devices.
- **Ports:** single ports, lists and ranges (`22, 80, 443, 8000-8100`), or presets: Common, Web, Remote access, Cameras / NVR, 1-1024, All.
- **Tunable:** timeout, total parallel connections, and a per-device limit so small devices like cameras don't stop answering.
- **Banner grabbing:** SSH/FTP/SMTP greetings, HTTP `Server:` headers and RTSP responses.
- **Open / Closed / No response states.** Silent ports are re-checked slowly before being reported.
- **Plain-English risk notes** for Telnet, FTP, SMB, RDP, VNC and the XMeye DVR port.
- **Quick service check** from a device's right-click menu.

### Working with results
- **Live radar view** in the centre. Position = address in range, distance from centre = response time. Dots flash when a device replies or is heard by the DHCP listener. Click to enlarge, hover for details.
- **Clickable header counts:** devices / unknown / absent / video / selected, each one a filter.
- **Search** by IP, label, hostname, manufacturer or MAC (Ctrl+F; Esc clears).
- **Known devices.** Labelled devices persist. One that isn't found in a scan still appears, greyed, with its last known IP in grey italics, "not found this scan" in the Ping column, and any remembered hostname. Right-click to ping or copy that IP; **Forget this device** deletes its label, notes and last-seen IP (after confirmation).
- **Selection:** click, Ctrl+click, Shift+click, Ctrl+A. Clicking the only selected row deselects it.
- **Keyboard:** Up / Down scroll the results; Left / Right scroll sideways when the table is wider than the window, with a thin position bar above the status line.
- **Right-click actions:** edit label, ping, port scan, open the web page (HTTP/HTTPS), copy IP / MAC / row, copy the RTSP address, open in VLC.
- **Labels and notes** are saved by MAC address and kept between runs. Double-click a row to label it.
- **Self-sizing columns.** Columns fit their contents and Ping takes the remaining width. The window opens maximised.
- **Snapshot:** saves a PNG of the window.
- **Themes:** Terminal (green) and Amber CRT.
- **Shortcuts:** F5 scan · Ctrl+F find · Esc clear.

### Saving and restoring
- **Save scan (encrypted):** one password-protected `.mls` file holds every row (including devices not found that scan), every hostname with its source, all labels, every DHCP-learned name, and ping and port results. Double-click it to open.
- **A saved scan is also your backup.** Opening one offers to merge into or overwrite this PC's labels, and adds any DHCP names this PC doesn't know yet.

## Security and privacy

### Encryption
- **Labels and DHCP names at rest (Windows):** stored as `devices.dat` and `dhcp_names.dat`, encrypted with Windows DPAPI so only your Windows user account on this PC can read them.
- **Saved scans:** AES-256-GCM, with the key derived from your password by **Argon2id** (64 MiB of memory, 3 passes, a random 16-byte salt per file, a random nonce).
- **Tamper detection:** the whole file header is authenticated, so a wrong password, a damaged file or any altered byte is rejected.
- **Malicious-file safety:** encryption settings in a file are only accepted within fixed limits, so a crafted file can't demand gigabytes of memory or offer weaker settings.
- **Password rules:** at least 10 characters, entered twice. There is no recovery, so a lost password means the file can't be opened.

### Memory and clipboard hygiene
- **Zeroised secrets:** passwords, decrypted data, results and labels are wiped from memory when they're no longer needed (using `zeroize`), including on Erase all.
- **Self-clearing clipboard:** copied text is cleared after 30 seconds, but only if the clipboard still holds what the scanner put there.

### Secure erase
- **Erase all data** overwrites every stored file (labels, DHCP names, snapshots, saved scans and any old `.mlb` label backups) with random data and then zeros, flushing each pass to disk. It then truncates the file, renames it to a random name and deletes it, and clears everything held in memory.
- Settings and the public vendor list are kept.
- Note: on SSDs, wear-levelling means no program can guarantee old copies are physically gone. Full-disk encryption (BitLocker) is the real protection.

### Passive by design
- The scanner never tries passwords or logs in to anything. Video checks only look for streams and snapshots that are already open.
- The DHCP listener only listens. It never sends a packet.
- **No telemetry.** The only internet request is the optional **Update vendors** download from `standards-oui.ieee.org`, made with the system's `curl`.

## Where data is stored

| What | Windows | Linux |
|---|---|---|
| Labels (DPAPI-encrypted on Windows) | `%APPDATA%\DevEcho Network Scanner\devices.dat` | `~/.config/devecho-network-scanner/` |
| DHCP names (DPAPI-encrypted on Windows) | `%APPDATA%\DevEcho Network Scanner\dhcp_names.dat` | `~/.config/devecho-network-scanner/` |
| Settings, vendor list | `%APPDATA%\DevEcho Network Scanner\` | `~/.config/devecho-network-scanner/` |
| Saved scans, snapshots | `Documents\DevEcho Network Scanner\` | `~/Documents/DevEcho Network Scanner/` |

On Linux there's no DPAPI, so local data is not encrypted.

## Building from source

Requires a recent stable [Rust](https://rustup.rs/) toolchain.

```bash
cargo build --release
```

The binary is written to `target/release/`. To build the manufacturer list into the .exe, put IEEE's [`oui.csv`](https://standards-oui.ieee.org/oui/oui.csv) next to `Cargo.toml` before building. It's git-ignored.

Run the tests with:

```bash
cargo test
```

## License

Copyright (C) 2026 Myriameter

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY. See [LICENSE](LICENSE) for the full text.
