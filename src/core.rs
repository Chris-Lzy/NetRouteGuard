use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};
use winreg::enums::*;
use winreg::RegKey;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const USER_ENV_KEY: &str = "Environment";

pub const PROXY_ENV_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    pub pattern: String,
    pub mode: String, // "direct" or "proxy"
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEntry {
    pub name: String,
    pub path: String,
    #[serde(default = "default_app_mode")]
    pub mode: String, // "direct" or "proxy"
    #[serde(default = "default_extra_args")]
    pub extra_args: String,
}

fn default_app_mode() -> String {
    "direct".to_string()
}

#[derive(Debug, Clone)]
pub struct ScannedApp {
    pub name: String,
    pub path: String,
    pub source: String,
    pub running: bool,
}

fn default_extra_args() -> String {
    "--no-proxy-server".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub rules: Vec<DomainRule>,
    pub apps: Vec<AppEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WinInetProxy {
    pub proxy_enable: bool,
    pub proxy_server: String,
    pub proxy_override: String,
    pub auto_config_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub timestamp: u64,
    pub user_env: HashMap<String, String>,
    pub wininet: WinInetProxy,
}

#[derive(Debug, Clone)]
pub struct DiagResult {
    pub host: String,
    pub port: u16,
    pub ips: Vec<String>,
    pub dns_error: String,
    pub wininet_path: String,
    pub env_path: String,
    pub proxy_server: String,
    pub proxy_port_alive: bool,
    pub proxy_port_ms: Option<f64>,
    pub direct_ok: bool,
    pub direct_ms: Option<f64>,
    pub direct_msg: String,
    pub ping_ok: bool,
    pub ping_ms: Option<u32>,
    pub region_label: String,
    pub recommended_mode: String,
}

#[derive(Debug, Clone)]
pub struct AutoGeoResult {
    pub host: String,
    pub resolved_ip: String,
    pub ping_ok: bool,
    pub ping_ms: Option<u32>,
    pub region_label: String,
    pub recommended_mode: String, // "direct" | "proxy"
}

#[derive(Debug, Clone)]
pub struct TcpConnInfo {
    pub process: String,
    pub pid: u32,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub route: String, // "走代理" | "直连" | "本地回环"
}

pub fn base_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_file() -> PathBuf {
    base_dir().join("rules.json")
}

pub fn backup_dir() -> PathBuf {
    base_dir().join("backups")
}

pub fn launcher_dir() -> PathBuf {
    base_dir().join("launchers")
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

pub fn broadcast_setting_change() {
    let env_w: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            env_w.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            3000,
            &mut result,
        );
    }
}

pub fn refresh_wininet_settings() {
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
    }
}

pub fn get_env_vars() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for k in PROXY_ENV_KEYS {
        map.insert(k.to_string(), String::new());
    }
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(USER_ENV_KEY, KEY_READ) {
        for (name, val) in key.enum_values().flatten() {
            let upper = name.to_uppercase();
            if PROXY_ENV_KEYS.contains(&upper.as_str()) || upper.contains("PROXY") {
                map.insert(name, val.to_string());
            }
        }
    }
    map
}

pub fn set_env_vars(values: &HashMap<String, String>) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(USER_ENV_KEY, KEY_SET_VALUE | KEY_READ)
        .map_err(|e| format!("打开注册表 Environment 失败: {e}"))?;

    for (name, val) in values {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            let _ = key.delete_value(name);
        } else {
            key.set_value(name, &trimmed)
                .map_err(|e| format!("写入环境变量 {name} 失败: {e}"))?;
        }
    }
    broadcast_setting_change();
    Ok(())
}

pub fn get_wininet_proxy() -> WinInetProxy {
    let mut info = WinInetProxy::default();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_READ) {
        let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        info.proxy_enable = enable != 0;
        info.proxy_server = key.get_value("ProxyServer").unwrap_or_default();
        info.proxy_override = key.get_value("ProxyOverride").unwrap_or_default();
        info.auto_config_url = key.get_value("AutoConfigURL").unwrap_or_default();
    }
    info
}

pub fn set_wininet_proxy(info: &WinInetProxy, update_pac: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_SET_VALUE | KEY_READ)
        .map_err(|e| format!("打开 Internet Settings 失败: {e}"))?;

    let enable_val: u32 = if info.proxy_enable { 1 } else { 0 };
    key.set_value("ProxyEnable", &enable_val)
        .map_err(|e| format!("设置 ProxyEnable 失败: {e}"))?;
    key.set_value("ProxyServer", &info.proxy_server.trim())
        .map_err(|e| format!("设置 ProxyServer 失败: {e}"))?;
    key.set_value("ProxyOverride", &info.proxy_override.trim())
        .map_err(|e| format!("设置 ProxyOverride 失败: {e}"))?;

    if update_pac {
        let pac = info.auto_config_url.trim();
        if pac.is_empty() {
            let _ = key.delete_value("AutoConfigURL");
        } else {
            key.set_value("AutoConfigURL", &pac)
                .map_err(|e| format!("设置 AutoConfigURL 失败: {e}"))?;
        }
    }

    refresh_wininet_settings();
    Ok(())
}

pub fn load_config() -> AppConfig {
    let path = config_file();
    if let Ok(text) = fs::read_to_string(&path) {
        if let Ok(cfg) = serde_json::from_str::<AppConfig>(&text) {
            return cfg;
        }
    }
    let default_cfg = AppConfig {
        rules: vec![DomainRule {
            pattern: "nas.example.com".to_string(),
            mode: "direct".to_string(),
            note: "示例：内网/NAS 直连".to_string(),
        }],
        apps: vec![],
    };
    let _ = save_config(&default_cfg);
    default_cfg
}

pub fn save_config(cfg: &AppConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(config_file(), json).map_err(|e| format!("保存配置失败: {e}"))
}

pub fn create_backup(label: &str) -> Result<PathBuf, String> {
    let dir = backup_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("backup_{ts}_{label}.json"));
    let snap = BackupSnapshot {
        timestamp: ts,
        user_env: get_env_vars(),
        wininet: get_wininet_proxy(),
    };
    let json = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn restore_backup(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let snap: BackupSnapshot = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    set_env_vars(&snap.user_env)?;
    set_wininet_proxy(&snap.wininet, true)?;
    Ok(())
}

pub fn extract_host_port(target: &str) -> (String, u16) {
    let mut s = target.trim().to_string();
    if s.is_empty() {
        return (String::new(), 0);
    }
    let mut default_port = 443u16;
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx].to_lowercase();
        if scheme == "http" {
            default_port = 80;
        }
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find('/') {
        s = s[..idx].to_string();
    }
    if let Some(idx) = s.rfind('@') {
        s = s[idx + 1..].to_string();
    }
    if let Some(idx) = s.rfind(':') {
        if let Ok(p) = s[idx + 1..].parse::<u16>() {
            return (s[..idx].to_string(), p);
        }
    }
    (s, default_port)
}

pub fn parse_proxy_host_port(proxy_str: &str) -> (String, u16) {
    let mut s = proxy_str.trim().to_string();
    if s.is_empty() {
        return ("127.0.0.1".to_string(), 7897);
    }
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if s.contains('=') {
        if let Some(first) = s.split(';').next() {
            if let Some((_, rhs)) = first.split_once('=') {
                s = rhs.to_string();
            }
        }
    }
    if let Some(idx) = s.find('/') {
        s = s[..idx].to_string();
    }
    if let Some(idx) = s.rfind(':') {
        if let Ok(p) = s[idx + 1..].parse::<u16>() {
            return (s[..idx].to_string(), p);
        }
    }
    (s, 7897)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star_p, mut star_t) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn match_pattern(host: &str, pattern: &str) -> bool {
    let h = host.trim().to_lowercase();
    let p = pattern.trim().to_lowercase();
    if h.is_empty() || p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if p == "<local>" {
        return !h.contains('.');
    }
    if p.contains('*') {
        return wildcard_match(&p, &h);
    }
    if let Some(stripped) = p.strip_prefix('.') {
        return h == stripped || h.ends_with(&p);
    }
    h == p || h.ends_with(&format!(".{p}"))
}

pub fn matches_bypass_list(host: &str, list_str: &str, sep: char) -> Option<String> {
    for token in list_str.split(sep) {
        let t = token.trim();
        if !t.is_empty() && match_pattern(host, t) {
            return Some(t.to_string());
        }
    }
    None
}

pub fn sync_rules_to_system(rules: &[DomainRule]) -> Result<(String, String), String> {
    let _ = create_backup("auto_before_sync");
    let mut env = get_env_vars();
    let mut wininet = get_wininet_proxy();

    let mut no_proxy_items: Vec<String> = env
        .get("NO_PROXY")
        .cloned()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut override_items: Vec<String> = wininet
        .proxy_override
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let proxy_set: HashSet<String> = rules
        .iter()
        .filter(|r| r.mode == "proxy")
        .map(|r| r.pattern.trim().to_lowercase())
        .collect();

    no_proxy_items.retain(|x| !proxy_set.contains(&x.to_lowercase()));
    override_items.retain(|x| !proxy_set.contains(&x.to_lowercase()));

    let mut no_proxy_lower: HashSet<String> = no_proxy_items.iter().map(|s| s.to_lowercase()).collect();
    let mut override_lower: HashSet<String> = override_items.iter().map(|s| s.to_lowercase()).collect();

    for rule in rules.iter().filter(|r| r.mode == "direct") {
        let pat = rule.pattern.trim();
        if pat.is_empty() {
            continue;
        }
        let lower = pat.to_lowercase();
        if !no_proxy_lower.contains(&lower) {
            no_proxy_items.push(pat.to_string());
            no_proxy_lower.insert(lower.clone());
        }
        if !override_lower.contains(&lower) {
            if let Some(pos) = override_items.iter().position(|v| v.eq_ignore_ascii_case("<local>")) {
                override_items.insert(pos, pat.to_string());
            } else {
                override_items.push(pat.to_string());
            }
            override_lower.insert(lower);
        }
    }

    let new_no_proxy = no_proxy_items.join(",");
    let new_override = override_items.join(";");

    env.insert("NO_PROXY".to_string(), new_no_proxy.clone());
    set_env_vars(&env)?;

    wininet.proxy_override = new_override.clone();
    set_wininet_proxy(&wininet, false)?;

    Ok((new_no_proxy, new_override))
}

pub fn tcp_probe(host: &str, port: u16, timeout_ms: u64) -> (bool, Option<f64>, String) {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => return (false, None, format!("地址解析失败: {e}")),
    };
    let Some(first) = addrs.first() else {
        return (false, None, "无可用 IP".to_string());
    };
    let t0 = Instant::now();
    match TcpStream::connect_timeout(first, Duration::from_millis(timeout_ms)) {
        Ok(_) => {
            let ms = (t0.elapsed().as_secs_f64() * 10000.0).round() / 10.0;
            (true, Some(ms), "连接成功".to_string())
        }
        Err(e) => (false, None, e.to_string()),
    }
}

pub fn is_private_or_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

pub fn is_china_mainland_ip(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let val = u32::from(v4);
    let ranges = crate::cn_cidrs::CN_IPV4_RANGES;
    let idx = ranges.partition_point(|&(start, _)| start <= val);
    if idx == 0 {
        return false;
    }
    let (start, end) = ranges[idx - 1];
    val >= start && val <= end
}

pub fn ping_host(target: &str) -> (bool, Option<u32>) {
    let out = Command::new("ping")
        .args(["-n", "1", "-w", "1000", target])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(o) = out else {
        return (false, None);
    };
    let ok = o.status.success();
    let text = String::from_utf8_lossy(&o.stdout);
    let mut ms = None;
    for token in text.split_whitespace() {
        let lower = token.to_lowercase();
        if lower.contains("ms") {
            let digits: String = lower
                .trim_start_matches("time=")
                .trim_start_matches("time<")
                .trim_start_matches("时间=")
                .trim_start_matches("时间<")
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(v) = digits.parse::<u32>() {
                ms = Some(v);
                break;
            }
        }
    }
    (ok, ms)
}

pub fn classify_ip_region(ip_str: &str) -> (String, String) {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_private_or_loopback_ip(ip) {
            return ("内网/本地 IP".to_string(), "direct".to_string());
        }
        if is_china_mainland_ip(ip) {
            return ("中国大陆 IP".to_string(), "direct".to_string());
        }
        return ("非中国大陆 IP (海外)".to_string(), "proxy".to_string());
    }
    ("未知归属".to_string(), "proxy".to_string())
}

pub fn auto_check_ip_region(target: &str) -> AutoGeoResult {
    let (host, port) = extract_host_port(target);
    let mut resolved_ip = String::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        resolved_ip = ip.to_string();
    } else if let Ok(mut iter) = format!("{host}:{port}").to_socket_addrs() {
        if let Some(sa) = iter.find(|s| s.is_ipv4()).or_else(|| iter.next()) {
            resolved_ip = sa.ip().to_string();
        }
    }

    let ping_target = if resolved_ip.is_empty() { host.as_str() } else { resolved_ip.as_str() };
    let (ping_ok, ping_ms) = ping_host(ping_target);
    let (region_label, recommended_mode) = if resolved_ip.is_empty() {
        ("DNS 解析失败 (默认建议走代理)".to_string(), "proxy".to_string())
    } else {
        classify_ip_region(&resolved_ip)
    };

    AutoGeoResult {
        host,
        resolved_ip,
        ping_ok,
        ping_ms,
        region_label,
        recommended_mode,
    }
}

pub fn diagnose_target(target: &str) -> DiagResult {
    let (host, port) = extract_host_port(target);
    let env = get_env_vars();
    let wininet = get_wininet_proxy();

    let mut ips = Vec::new();
    let mut dns_error = String::new();
    match format!("{host}:{port}").to_socket_addrs() {
        Ok(iter) => {
            let mut seen = HashSet::new();
            for sa in iter {
                let ip = sa.ip().to_string();
                if seen.insert(ip.clone()) {
                    ips.push(ip);
                }
            }
        }
        Err(e) => dns_error = e.to_string(),
    }

    let no_proxy_match = matches_bypass_list(&host, env.get("NO_PROXY").map(|s| s.as_str()).unwrap_or(""), ',');
    let override_match = matches_bypass_list(&host, &wininet.proxy_override, ';');

    let proxy_server = if !wininet.proxy_server.is_empty() {
        wininet.proxy_server.clone()
    } else {
        env.get("HTTPS_PROXY")
            .filter(|s| !s.is_empty())
            .or_else(|| env.get("HTTP_PROXY").filter(|s| !s.is_empty()))
            .cloned()
            .unwrap_or_default()
    };
    let (proxy_host, proxy_port) = parse_proxy_host_port(&proxy_server);

    let wininet_path = if !wininet.proxy_enable {
        "直连 (系统代理未开启)".to_string()
    } else if let Some(ref m) = override_match {
        format!("直连 (命中 ProxyOverride: {m})")
    } else {
        format!("走代理 ({proxy_server})")
    };

    let env_proxy_val = env
        .get("HTTPS_PROXY")
        .filter(|s| !s.is_empty())
        .or_else(|| env.get("HTTP_PROXY").filter(|s| !s.is_empty()))
        .or_else(|| env.get("ALL_PROXY").filter(|s| !s.is_empty()))
        .cloned();

    let env_path = match env_proxy_val {
        None => "直连 (未设置代理环境变量)".to_string(),
        Some(val) => {
            if let Some(ref m) = no_proxy_match {
                format!("直连 (命中 NO_PROXY: {m})")
            } else {
                format!("走代理 ({val})")
            }
        }
    };

    let (direct_ok, direct_ms, direct_msg) = tcp_probe(&host, port, 2000);
    let (proxy_port_alive, proxy_port_ms, _) = tcp_probe(&proxy_host, proxy_port, 1000);
    let ping_target = ips.first().map(|s| s.as_str()).unwrap_or(host.as_str());
    let (ping_ok, ping_ms) = ping_host(ping_target);
    let (region_label, recommended_mode) = if let Some(first_ip) = ips.first() {
        classify_ip_region(first_ip)
    } else {
        ("DNS 解析失败 (建议走代理)".to_string(), "proxy".to_string())
    };

    DiagResult {
        host,
        port,
        ips,
        dns_error,
        wininet_path,
        env_path,
        proxy_server,
        proxy_port_alive,
        proxy_port_ms,
        direct_ok,
        direct_ms,
        direct_msg,
        ping_ok,
        ping_ms,
        region_label,
        recommended_mode,
    }
}

fn get_process_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let out = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split("\",\"").collect();
            if parts.len() >= 2 {
                let name = parts[0].trim_start_matches('"').to_string();
                if let Ok(pid) = parts[1].trim_end_matches('"').parse::<u32>() {
                    map.insert(pid, name);
                }
            }
        }
    }
    map
}

pub fn get_active_connections(proxy_port: u16) -> Vec<TcpConnInfo> {
    let proc_map = get_process_map();
    let mut conns = Vec::new();
    let out = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(o) = out else {
        return conns;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || parts[0] != "TCP" {
            continue;
        }
        let (local_addr, remote_addr, state, pid_str) = (parts[1], parts[2], parts[3], parts[4]);
        if !matches!(state, "ESTABLISHED" | "SYN_SENT" | "CLOSE_WAIT") {
            continue;
        }
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let proc_name = proc_map.get(&pid).cloned().unwrap_or_else(|| format!("PID:{pid}"));

        let (r_host, r_port) = match remote_addr.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().unwrap_or(0)),
            None => (remote_addr, 0),
        };

        let is_loopback = matches!(r_host, "127.0.0.1" | "[::1]" | "0.0.0.0" | "[::]")
            || r_host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);

        let route = if r_port == proxy_port && is_loopback {
            "走代理"
        } else if is_loopback {
            "本地回环"
        } else {
            "直连"
        };

        conns.push(TcpConnInfo {
            process: proc_name,
            pid,
            local: local_addr.to_string(),
            remote: remote_addr.to_string(),
            state: state.to_string(),
            route: route.to_string(),
        });
    }
    conns
}

pub fn launch_app_with_mode(
    exe_path: &str,
    mode: &str,
    extra_args: &str,
    proxy_server: &str,
    kill_existing: bool,
) -> Result<String, String> {
    let p = Path::new(exe_path);
    if !p.exists() {
        return Err(format!("找不到程序: {exe_path}"));
    }
    let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("app.exe");

    if kill_existing {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", file_name])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        std::thread::sleep(Duration::from_millis(600));
    }

    let mut cmd = Command::new(p);
    if let Some(parent) = p.parent() {
        cmd.current_dir(parent);
    }

    if mode == "proxy" {
        let srv = if proxy_server.trim().is_empty() {
            "127.0.0.1:7897"
        } else {
            proxy_server.trim()
        };
        let proxy_url = if srv.contains("://") {
            srv.to_string()
        } else {
            format!("http://{srv}")
        };
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("ALL_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        cmd.env("all_proxy", &proxy_url);
        cmd.env("NO_PROXY", "127.0.0.1,localhost,::1");
        cmd.arg(format!("--proxy-server={srv}"));
    } else {
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            cmd.env_remove(k);
        }
        cmd.env("NO_PROXY", "*");
        cmd.env("no_proxy", "*");
        for arg in extra_args.split_whitespace() {
            cmd.arg(arg);
        }
    }

    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    let mode_label = if mode == "proxy" { "代理模式" } else { "直连模式" };

    cmd.spawn()
        .map(|_| format!("已以{mode_label}启动 {file_name}"))
        .map_err(|e| format!("启动失败: {e}"))
}

pub fn create_mode_shortcut(
    name: &str,
    exe_path: &str,
    mode: &str,
    extra_args: &str,
    proxy_server: &str,
) -> Result<PathBuf, String> {
    let dir = launcher_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let is_proxy = mode == "proxy";
    let tag = if is_proxy { "代理版" } else { "直连版" };
    let bat_path = dir.join(format!("{name}_{tag}.bat"));

    let bat = if is_proxy {
        let srv = if proxy_server.trim().is_empty() {
            "127.0.0.1:7897"
        } else {
            proxy_server.trim()
        };
        let proxy_url = if srv.contains("://") {
            srv.to_string()
        } else {
            format!("http://{srv}")
        };
        format!(
            "@echo off\r\n\
             set HTTP_PROXY={proxy_url}\r\n\
             set HTTPS_PROXY={proxy_url}\r\n\
             set ALL_PROXY={proxy_url}\r\n\
             set NO_PROXY=127.0.0.1,localhost,::1\r\n\
             start \"\" \"{exe_path}\" --proxy-server={srv}\r\n"
        )
    } else {
        format!(
            "@echo off\r\n\
             set HTTP_PROXY=\r\n\
             set HTTPS_PROXY=\r\n\
             set ALL_PROXY=\r\n\
             set http_proxy=\r\n\
             set https_proxy=\r\n\
             set all_proxy=\r\n\
             set NO_PROXY=*\r\n\
             start \"\" \"{exe_path}\" {extra_args}\r\n"
        )
    };
    fs::write(&bat_path, bat).map_err(|e| e.to_string())?;

    let desktop = std::env::var("USERPROFILE")
        .map(|u| PathBuf::from(u).join("Desktop"))
        .unwrap_or_else(|_| dir.clone());
    let lnk_path = desktop.join(format!("{name} ({tag}).lnk"));

    let ps = format!(
        "$W = New-Object -ComObject WScript.Shell; \
         $S = $W.CreateShortcut('{}'); \
         $S.TargetPath = '{}'; \
         $S.IconLocation = '{},0'; \
         $S.WindowStyle = 7; \
         $S.Save()",
        lnk_path.display(),
        bat_path.display(),
        exe_path
    );
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("创建快捷方式失败: {e}"))?;

    Ok(lnk_path)
}

pub fn scan_local_apps() -> Vec<ScannedApp> {
    let ps_script = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$seen = @{}
$runningSet = @{}
function Add-App($name, $path, $src, $run) {
    if (-not $path) { return }
    $p = $path.Trim().Trim('"')
    if ($p -match '^(.+?\.exe)\b') { $p = $matches[1] } else { return }
    if ($p -like 'C:\Windows\*') { return }
    $leaf = [System.IO.Path]::GetFileName($p).ToLower()
    if ($leaf -match '^(unins|uninstall|setup|update|updater|crashreporter).*\.exe$') { return }
    if (-not (Test-Path $p)) { return }
    $key = $p.ToLower()
    if ($seen.ContainsKey($key)) {
        if ($run) { $seen[$key].Running = $true }
        return
    }
    $n = if ($name) { $name.Trim() } else { [System.IO.Path]::GetFileNameWithoutExtension($p) }
    $seen[$key] = [PSCustomObject]@{ Name=$n; Path=$p; Source=$src; Running=$run }
}

Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $runningSet[$_.Path.ToLower()] = $true
    Add-App $_.ProcessName $_.Path '运行中' $true
}

$sh = New-Object -ComObject WScript.Shell
$lnkDirs = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:USERPROFILE\Desktop"
)
foreach ($d in $lnkDirs) {
    if (Test-Path $d) {
        Get-ChildItem $d -Filter '*.lnk' -Recurse | ForEach-Object {
            $sc = $sh.CreateShortcut($_.FullName)
            if ($sc.TargetPath -like '*.exe') {
                $isRun = $runningSet.ContainsKey($sc.TargetPath.ToLower())
                Add-App $_.BaseName $sc.TargetPath '开始菜单/桌面' $isRun
            }
        }
    }
}

$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $regPaths | ForEach-Object {
    if ($_.DisplayName -and $_.DisplayIcon) {
        $isRun = $false
        Add-App $_.DisplayName $_.DisplayIcon '已安装程序' $isRun
    }
}

$seen.Values | Sort-Object @{Expression='Running';Descending=$true}, Name | ForEach-Object {
    "$($_.Name)`t$($_.Path)`t$($_.Source)`t$($_.Running)"
}
"#;

    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let mut list = Vec::new();
    let Ok(o) = out else {
        return list;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            list.push(ScannedApp {
                name: parts[0].trim().to_string(),
                path: parts[1].trim().to_string(),
                source: parts[2].trim().to_string(),
                running: parts[3].trim().eq_ignore_ascii_case("true"),
            });
        }
    }
    list
}
