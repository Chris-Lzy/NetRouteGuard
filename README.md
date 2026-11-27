# NetRouteGuard

A lightweight, native Windows desktop utility written in Rust (`eframe`/`egui`) to **monitor network routes, manage proxy environment variables & Windows system proxy bypasses, auto-route by Mainland China IP geo-lookup, and launch apps in isolated Direct or Proxy mode**.

> 中文详细使用说明请查看：[使用说明.md](./使用说明.md)

## Features

- **Link Diagnostics & Live TCP Monitor**
  - Diagnose any domain/URL: DNS resolution, Windows `ProxyOverride` match, `NO_PROXY` match, direct TCP latency, and proxy port health.
  - Real-time TCP connection monitor mapped to process names and PIDs, highlighting **Direct** vs **Proxy** connections.
- **Auto-Rule (Ping + Mainland China IP Lookup)**
  - Embedded offline APNIC Mainland China IPv4 CIDR table (`src/cn_cidrs.rs`) for instant `< 1 ms` geo-classification.
  - Automatically routes **LAN / Mainland China IPs → Direct**, and **Non-Mainland IPs → Proxy**, syncing directly to `NO_PROXY` and `ProxyOverride`.
- **Environment Variables & Windows System Proxy**
  - Edit `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` with automatic `WM_SETTINGCHANGE` broadcast.
  - Toggle and configure Windows WinINET (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`) with instant `InternetSetOptionW` refresh.
  - Automatic JSON snapshots in `backups/` before changes.
- **Local App Scanner & Per-App Direct/Proxy Launcher**
  - Scan running processes, Start Menu/Desktop shortcuts, and installed programs.
  - Configure individual apps as **Direct** or **Proxy**, restart them in an isolated environment, or generate Desktop shortcuts (`Direct` / `Proxy` editions).

## Build from Source (Windows)

Requirements:
- Rust toolchain (`x86_64-pc-windows-msvc` or `x86_64-pc-windows-gnu` with `windres`)

```powershell
cargo build --release
```

The compiled executable will be at `target/release/net_route_guard.exe`.

## License

[MIT](./LICENSE)
