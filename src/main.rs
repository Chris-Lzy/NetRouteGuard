#![windows_subsystem = "windows"]

mod cn_cidrs;
mod core;

use eframe::egui;
use std::collections::HashMap;
use std::fs;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Monitor,
    Rules,
    EnvAndSys,
    Apps,
}

#[derive(PartialEq, Clone, Copy)]
enum ConnFilter {
    All,
    ProxyOnly,
    DirectOnly,
}

struct NetRouteGuardApp {
    tab: Tab,
    cfg: core::AppConfig,

    // Cached system state
    wininet: core::WinInetProxy,
    env_vars: HashMap<String, String>,
    proxy_port_alive: bool,
    proxy_port_ms: Option<f64>,
    proxy_host_port: String,

    // Tab 1: Monitor & Diagnose
    diag_input: String,
    diag_result: Option<core::DiagResult>,
    diag_rx: Option<Receiver<core::DiagResult>>,

    conns: Vec<core::TcpConnInfo>,
    conn_rx: Option<Receiver<Vec<core::TcpConnInfo>>>,
    conn_filter: ConnFilter,
    conn_keyword: String,
    auto_refresh: bool,
    last_conn_refresh: Instant,

    // Tab 2: Domain Rules
    new_rule_pattern: String,
    new_rule_mode: String,
    new_rule_note: String,
    auto_geo_rx: Option<Receiver<core::AutoGeoResult>>,
    batch_geo_rx: Option<Receiver<Vec<core::AutoGeoResult>>>,

    // Tab 3: Env & System Proxy
    env_http: String,
    env_https: String,
    env_all: String,
    env_no: String,
    sys_enable: bool,
    sys_server: String,
    sys_override: String,
    sys_pac: String,

    // Tab 4: Apps
    new_app_name: String,
    new_app_path: String,
    new_app_mode: String,
    new_app_args: String,
    scanned_apps: Vec<core::ScannedApp>,
    scan_rx: Option<Receiver<Vec<core::ScannedApp>>>,
    scan_keyword: String,
    scan_running_only: bool,

    status_msg: String,
}

impl NetRouteGuardApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_chinese_font(&cc.egui_ctx);
        let cfg = core::load_config();
        let mut app = Self {
            tab: Tab::Monitor,
            cfg,
            wininet: core::WinInetProxy::default(),
            env_vars: HashMap::new(),
            proxy_port_alive: false,
            proxy_port_ms: None,
            proxy_host_port: "127.0.0.1:7897".to_string(),
            diag_input: "example.com".to_string(),
            diag_result: None,
            diag_rx: None,
            conns: Vec::new(),
            conn_rx: None,
            conn_filter: ConnFilter::All,
            conn_keyword: String::new(),
            auto_refresh: true,
            last_conn_refresh: Instant::now() - Duration::from_secs(10),
            new_rule_pattern: String::new(),
            new_rule_mode: "direct".to_string(),
            new_rule_note: String::new(),
            auto_geo_rx: None,
            batch_geo_rx: None,
            env_http: String::new(),
            env_https: String::new(),
            env_all: String::new(),
            env_no: String::new(),
            sys_enable: false,
            sys_server: String::new(),
            sys_override: String::new(),
            sys_pac: String::new(),
            new_app_name: String::new(),
            new_app_path: String::new(),
            new_app_mode: "direct".to_string(),
            new_app_args: "--no-proxy-server".to_string(),
            scanned_apps: Vec::new(),
            scan_rx: None,
            scan_keyword: String::new(),
            scan_running_only: false,
            status_msg: "就绪".to_string(),
        };
        app.refresh_system_state();
        app.trigger_conn_refresh();
        app
    }

    fn refresh_system_state(&mut self) {
        self.wininet = core::get_wininet_proxy();
        self.env_vars = core::get_env_vars();

        self.env_http = self.env_vars.get("HTTP_PROXY").cloned().unwrap_or_default();
        self.env_https = self.env_vars.get("HTTPS_PROXY").cloned().unwrap_or_default();
        self.env_all = self.env_vars.get("ALL_PROXY").cloned().unwrap_or_default();
        self.env_no = self.env_vars.get("NO_PROXY").cloned().unwrap_or_default();

        self.sys_enable = self.wininet.proxy_enable;
        self.sys_server = self.wininet.proxy_server.clone();
        self.sys_override = self.wininet.proxy_override.clone();
        self.sys_pac = self.wininet.auto_config_url.clone();

        let srv = if !self.wininet.proxy_server.is_empty() {
            self.wininet.proxy_server.clone()
        } else if !self.env_https.is_empty() {
            self.env_https.clone()
        } else {
            self.env_http.clone()
        };
        let (h, p) = core::parse_proxy_host_port(&srv);
        self.proxy_host_port = format!("{h}:{p}");
        let (alive, ms, _) = core::tcp_probe(&h, p, 400);
        self.proxy_port_alive = alive;
        self.proxy_port_ms = ms;
    }

    fn trigger_diagnose(&mut self) {
        let target = self.diag_input.trim().to_string();
        if target.is_empty() {
            return;
        }
        self.status_msg = format!("正在诊断 {target} ...");
        let (tx, rx): (Sender<core::DiagResult>, Receiver<core::DiagResult>) = mpsc::channel();
        self.diag_rx = Some(rx);
        thread::spawn(move || {
            let res = core::diagnose_target(&target);
            let _ = tx.send(res);
        });
    }

    fn trigger_conn_refresh(&mut self) {
        let (_, port) = core::parse_proxy_host_port(&self.proxy_host_port);
        let (tx, rx) = mpsc::channel();
        self.conn_rx = Some(rx);
        self.last_conn_refresh = Instant::now();
        thread::spawn(move || {
            let list = core::get_active_connections(port);
            let _ = tx.send(list);
        });
    }

    fn sync_rules(&mut self) {
        match core::sync_rules_to_system(&self.cfg.rules) {
            Ok(_) => {
                self.refresh_system_state();
                self.status_msg = "分流规则已同步到 NO_PROXY 与系统代理例外".to_string();
            }
            Err(e) => self.status_msg = format!("同步失败: {e}"),
        }
    }
}

impl eframe::App for NetRouteGuardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.diag_rx {
            if let Ok(res) = rx.try_recv() {
                self.diag_result = Some(res);
                self.diag_rx = None;
                self.status_msg = "诊断完成".to_string();
            }
        }
        if let Some(rx) = &self.conn_rx {
            if let Ok(list) = rx.try_recv() {
                self.conns = list;
                self.conn_rx = None;
            }
        }
        if let Some(rx) = &self.scan_rx {
            if let Ok(list) = rx.try_recv() {
                self.status_msg = format!("扫描完成，共发现 {} 个本机应用", list.len());
                self.scanned_apps = list;
                self.scan_rx = None;
            }
        }
        if let Some(rx) = &self.auto_geo_rx {
            if let Ok(geo) = rx.try_recv() {
                self.auto_geo_rx = None;
                if !geo.host.is_empty() {
                    let ping_txt = match (geo.ping_ok, geo.ping_ms) {
                        (true, Some(ms)) => format!("Ping {ms}ms"),
                        (true, None) => "Ping 通".to_string(),
                        _ => "Ping 超时".to_string(),
                    };
                    let note = format!("{} | {} | {}", geo.resolved_ip, ping_txt, geo.region_label);
                    if let Some(r) = self.cfg.rules.iter_mut().find(|r| r.pattern.eq_ignore_ascii_case(&geo.host)) {
                        r.mode = geo.recommended_mode.clone();
                        r.note = note;
                    } else {
                        self.cfg.rules.push(core::DomainRule {
                            pattern: geo.host.clone(),
                            mode: geo.recommended_mode.clone(),
                            note,
                        });
                    }
                    let _ = core::save_config(&self.cfg);
                    self.sync_rules();
                    let m_lbl = if geo.recommended_mode == "direct" { "直连" } else { "走代理" };
                    self.status_msg = format!("自动分流完成: {} ({}) -> {}", geo.host, geo.region_label, m_lbl);
                    self.trigger_diagnose();
                }
            }
        }
        if let Some(rx) = &self.batch_geo_rx {
            if let Ok(results) = rx.try_recv() {
                self.batch_geo_rx = None;
                for geo in &results {
                    if let Some(r) = self.cfg.rules.iter_mut().find(|r| r.pattern.eq_ignore_ascii_case(&geo.host)) {
                        r.mode = geo.recommended_mode.clone();
                        let p_txt = geo.ping_ms.map(|m| format!("{m}ms")).unwrap_or_else(|| if geo.ping_ok { "通".into() } else { "超时".into() });
                        r.note = format!("{} | Ping {} | {}", geo.resolved_ip, p_txt, geo.region_label);
                    }
                }
                let _ = core::save_config(&self.cfg);
                self.sync_rules();
                self.status_msg = format!("已完成 {} 条规则的 Ping 与大陆 IP 自动重判并同步", results.len());
            }
        }
        if self.auto_refresh && self.conn_rx.is_none() && self.last_conn_refresh.elapsed() >= Duration::from_secs(3) {
            self.trigger_conn_refresh();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        // Top Header
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.heading("NetRouteGuard");
                ui.separator();

                let sys_txt = if self.wininet.proxy_enable {
                    format!("系统代理: 开启 ({})", self.wininet.proxy_server)
                } else {
                    "系统代理: 关闭".to_string()
                };
                let sys_col = if self.wininet.proxy_enable {
                    egui::Color32::from_rgb(37, 99, 235)
                } else {
                    egui::Color32::from_rgb(21, 128, 61)
                };
                ui.colored_label(sys_col, sys_txt);
                ui.separator();

                let env_srv = if !self.env_https.is_empty() {
                    &self.env_https
                } else {
                    &self.env_http
                };
                let env_txt = if env_srv.is_empty() {
                    "环境变量代理: 未设置".to_string()
                } else {
                    format!("环境变量代理: {env_srv}")
                };
                ui.colored_label(
                    if env_srv.is_empty() {
                        egui::Color32::from_rgb(21, 128, 61)
                    } else {
                        egui::Color32::from_rgb(37, 99, 235)
                    },
                    env_txt,
                );
                ui.separator();

                let port_txt = if self.proxy_port_alive {
                    format!("代理端口 {}: 在线 ({:.1}ms)", self.proxy_host_port, self.proxy_port_ms.unwrap_or(0.0))
                } else {
                    format!("代理端口 {}: 未监听", self.proxy_host_port)
                };
                ui.colored_label(
                    if self.proxy_port_alive {
                        egui::Color32::from_rgb(21, 128, 61)
                    } else {
                        egui::Color32::from_rgb(185, 28, 28)
                    },
                    port_txt,
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("刷新状态").clicked() {
                        self.refresh_system_state();
                        self.trigger_conn_refresh();
                        self.status_msg = "已刷新全部状态".to_string();
                    }
                    if ui.button("一键同步分流规则").clicked() {
                        self.sync_rules();
                    }
                    if ui.button("备份当前配置").clicked() {
                        match core::create_backup("manual") {
                            Ok(p) => self.status_msg = format!("已备份: {}", p.display()),
                            Err(e) => self.status_msg = format!("备份失败: {e}"),
                        }
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Monitor, " 链路诊断与实时监控 ");
                ui.selectable_value(&mut self.tab, Tab::Rules, " 域名分流规则 (直连/代理) ");
                ui.selectable_value(&mut self.tab, Tab::EnvAndSys, " 环境变量与系统代理 ");
                ui.selectable_value(&mut self.tab, Tab::Apps, " 应用直连/代理管理 ");
            });
            ui.add_space(2.0);
        });

        // Bottom Status Bar
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_msg);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let admin = if core::is_admin() { "管理员权限: 是" } else { "管理员权限: 否 (当前用户设置无需管理员)" };
                    ui.label(admin);
                });
            });
        });

        // Central Body
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Monitor => self.ui_monitor_tab(ui),
            Tab::Rules => self.ui_rules_tab(ui),
            Tab::EnvAndSys => self.ui_env_tab(ui),
            Tab::Apps => self.ui_apps_tab(ui),
        });
    }
}

impl NetRouteGuardApp {
    fn ui_monitor_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("指定链接 / 域名路径诊断").strong());
            ui.horizontal(|ui| {
                ui.label("目标域名或链接:");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.diag_input).desired_width(320.0));
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.trigger_diagnose();
                }
                if ui.button("诊断路径").clicked() {
                    self.trigger_diagnose();
                }
                if ui.add_enabled(self.auto_geo_rx.is_none(), egui::Button::new("Ping 并自动分流 (非大陆走代理)")).clicked() {
                    let target = self.diag_input.trim().to_string();
                    if !target.is_empty() {
                        self.status_msg = format!("正在 Ping {target} 并判定归属...");
                        let (tx, rx) = mpsc::channel();
                        self.auto_geo_rx = Some(rx);
                        thread::spawn(move || {
                            let _ = tx.send(core::auto_check_ip_region(&target));
                        });
                    }
                }
                if ui.button("设为直连并应用").clicked() {
                    let (host, _) = core::extract_host_port(&self.diag_input);
                    if !host.is_empty() {
                        if let Some(r) = self.cfg.rules.iter_mut().find(|r| r.pattern.eq_ignore_ascii_case(&host)) {
                            r.mode = "direct".to_string();
                        } else {
                            self.cfg.rules.push(core::DomainRule {
                                pattern: host,
                                mode: "direct".to_string(),
                                note: "快速添加".to_string(),
                            });
                        }
                        let _ = core::save_config(&self.cfg);
                        self.sync_rules();
                        self.trigger_diagnose();
                    }
                }
                if ui.button("设为走代理并应用").clicked() {
                    let (host, _) = core::extract_host_port(&self.diag_input);
                    if !host.is_empty() {
                        if let Some(r) = self.cfg.rules.iter_mut().find(|r| r.pattern.eq_ignore_ascii_case(&host)) {
                            r.mode = "proxy".to_string();
                        } else {
                            self.cfg.rules.push(core::DomainRule {
                                pattern: host,
                                mode: "proxy".to_string(),
                                note: "快速添加".to_string(),
                            });
                        }
                        let _ = core::save_config(&self.cfg);
                        self.sync_rules();
                        self.trigger_diagnose();
                    }
                }
            });

            if let Some(res) = &self.diag_result {
                ui.separator();
                let ips = if res.ips.is_empty() {
                    format!("解析失败 ({})", res.dns_error)
                } else {
                    res.ips.join(", ")
                };
                ui.label(format!("目标主机: {}:{}   |   DNS 解析 IP: {}", res.host, res.port, ips));
                ui.label(format!("系统代理路径 (浏览器/WinINET): {}", res.wininet_path));
                ui.label(format!("环境变量路径 (CLI/脚本/部分应用): {}", res.env_path));
                let d_txt = if res.direct_ok {
                    format!("成功 ({:.1} ms)", res.direct_ms.unwrap_or(0.0))
                } else {
                    format!("失败 ({})", res.direct_msg)
                };
                let p_txt = if res.proxy_port_alive {
                    format!("在线 ({:.1} ms)", res.proxy_port_ms.unwrap_or(0.0))
                } else {
                    "不可达".to_string()
                };
                let ping_txt = match (res.ping_ok, res.ping_ms) {
                    (true, Some(ms)) => format!("通 ({ms} ms)"),
                    (true, None) => "通".to_string(),
                    _ => "超时/不可达".to_string(),
                };
                let rec_lbl = if res.recommended_mode == "direct" { "建议直连" } else { "建议走代理" };
                ui.label(format!("直连 TCP 探测: {d_txt}   |   代理端口 ({}) 状态: {p_txt}", res.proxy_server));
                ui.colored_label(
                    if res.recommended_mode == "direct" { egui::Color32::from_rgb(21, 128, 61) } else { egui::Color32::from_rgb(185, 28, 28) },
                    format!("Ping 测速: {ping_txt}   |   IP 归属: {}   |   自动判定: {rec_lbl}", res.region_label),
                );
            }
        });

        ui.add_space(6.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("本机实时 TCP 连接与进程路由监控").strong());
                ui.separator();
                ui.selectable_value(&mut self.conn_filter, ConnFilter::All, "全部");
                ui.selectable_value(&mut self.conn_filter, ConnFilter::ProxyOnly, "仅看走代理");
                ui.selectable_value(&mut self.conn_filter, ConnFilter::DirectOnly, "仅看直连");
                ui.separator();
                ui.label("关键字:");
                ui.add(egui::TextEdit::singleline(&mut self.conn_keyword).desired_width(140.0));
                ui.checkbox(&mut self.auto_refresh, "3秒自动刷新");
                if ui.button("立即刷新").clicked() {
                    self.trigger_conn_refresh();
                }
            });

            ui.separator();
            let kw = self.conn_keyword.trim().to_lowercase();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("conn_grid").striped(true).num_columns(6).spacing([14.0, 4.0]).show(ui, |ui| {
                    ui.strong("进程名");
                    ui.strong("PID");
                    ui.strong("本地地址");
                    ui.strong("远端地址");
                    ui.strong("状态");
                    ui.strong("路径判定");
                    ui.end_row();

                    for c in &self.conns {
                        match self.conn_filter {
                            ConnFilter::ProxyOnly if c.route != "走代理" => continue,
                            ConnFilter::DirectOnly if c.route != "直连" => continue,
                            _ => {}
                        }
                        if !kw.is_empty()
                            && !c.process.to_lowercase().contains(&kw)
                            && !c.remote.to_lowercase().contains(&kw)
                        {
                            continue;
                        }
                        ui.label(&c.process);
                        ui.label(c.pid.to_string());
                        ui.label(&c.local);
                        ui.label(&c.remote);
                        ui.label(&c.state);
                        let col = match c.route.as_str() {
                            "走代理" => egui::Color32::from_rgb(185, 28, 28),
                            "直连" => egui::Color32::from_rgb(21, 128, 61),
                            _ => egui::Color32::GRAY,
                        };
                        ui.colored_label(col, &c.route);
                        ui.end_row();
                    }
                });
            });
        });
    }

    fn ui_rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.label("说明：设为「直连 (DIRECT)」的域名会自动写入用户环境变量 NO_PROXY 和 Windows 系统代理例外 (ProxyOverride)；设为「走代理 (PROXY)」会从例外列表移除。");
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("自动规则：Ping 并检测 IP 是否在中国大陆（大陆/内网 -> 直连，非大陆 -> 一律走代理）").strong());
            let busy = self.batch_geo_rx.is_some();
            if ui.add_enabled(!busy, egui::Button::new(if busy { "正在 Ping 检测..." } else { "全部规则 Ping 并自动分流" })).clicked() {
                let targets: Vec<String> = self.cfg.rules.iter().map(|r| r.pattern.clone()).collect();
                self.status_msg = "正在批量 Ping 并检测各域名 IP 归属...".to_string();
                let (tx, rx) = mpsc::channel();
                self.batch_geo_rx = Some(rx);
                thread::spawn(move || {
                    let res: Vec<core::AutoGeoResult> = targets.iter().map(|t| core::auto_check_ip_region(t)).collect();
                    let _ = tx.send(res);
                });
            }
        });
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("域名/通配符:");
            ui.add(egui::TextEdit::singleline(&mut self.new_rule_pattern).desired_width(220.0));
            ui.label("策略:");
            egui::ComboBox::from_id_salt("rule_mode_cb")
                .selected_text(if self.new_rule_mode == "direct" { "直连 (direct)" } else { "走代理 (proxy)" })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.new_rule_mode, "direct".to_string(), "直连 (direct)");
                    ui.selectable_value(&mut self.new_rule_mode, "proxy".to_string(), "走代理 (proxy)");
                });
            ui.label("备注:");
            ui.add(egui::TextEdit::singleline(&mut self.new_rule_note).desired_width(160.0));
            if ui.button("添加规则").clicked() {
                let raw = self.new_rule_pattern.trim().to_string();
                if !raw.is_empty() {
                    let pat = if raw.contains("://") {
                        core::extract_host_port(&raw).0
                    } else {
                        raw
                    };
                    self.cfg.rules.push(core::DomainRule {
                        pattern: pat,
                        mode: self.new_rule_mode.clone(),
                        note: self.new_rule_note.trim().to_string(),
                    });
                    let _ = core::save_config(&self.cfg);
                    self.new_rule_pattern.clear();
                    self.new_rule_note.clear();
                }
            }
            if ui.button("保存并同步到系统").clicked() {
                let _ = core::save_config(&self.cfg);
                self.sync_rules();
            }
        });

        ui.separator();
        let mut toggle_idx = None;
        let mut delete_idx = None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("rules_grid").striped(true).num_columns(4).spacing([18.0, 6.0]).show(ui, |ui| {
                ui.strong("域名 / 通配符");
                ui.strong("路由策略");
                ui.strong("备注");
                ui.strong("操作");
                ui.end_row();

                for (idx, r) in self.cfg.rules.iter().enumerate() {
                    ui.label(&r.pattern);
                    let (label, col) = if r.mode == "direct" {
                        ("直连 (DIRECT)", egui::Color32::from_rgb(21, 128, 61))
                    } else {
                        ("走代理 (PROXY)", egui::Color32::from_rgb(185, 28, 28))
                    };
                    ui.colored_label(col, label);
                    ui.label(&r.note);
                    ui.horizontal(|ui| {
                        if ui.button("切换").clicked() {
                            toggle_idx = Some(idx);
                        }
                        if ui.button("删除").clicked() {
                            delete_idx = Some(idx);
                        }
                    });
                    ui.end_row();
                }
            });
        });

        if let Some(i) = toggle_idx {
            let r = &mut self.cfg.rules[i];
            r.mode = if r.mode == "direct" { "proxy".to_string() } else { "direct".to_string() };
            let _ = core::save_config(&self.cfg);
        }
        if let Some(i) = delete_idx {
            self.cfg.rules.remove(i);
            let _ = core::save_config(&self.cfg);
        }
    }

    fn ui_env_tab(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("用户环境变量 (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY)").strong());
            egui::Grid::new("env_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("HTTP_PROXY:");
                ui.add(egui::TextEdit::singleline(&mut self.env_http).desired_width(680.0));
                ui.end_row();

                ui.label("HTTPS_PROXY:");
                ui.add(egui::TextEdit::singleline(&mut self.env_https).desired_width(680.0));
                ui.end_row();

                ui.label("ALL_PROXY:");
                ui.add(egui::TextEdit::singleline(&mut self.env_all).desired_width(680.0));
                ui.end_row();

                ui.label("NO_PROXY:");
                ui.add(egui::TextEdit::singleline(&mut self.env_no).desired_width(680.0));
                ui.end_row();
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("保存环境变量并广播生效").clicked() {
                    let _ = core::create_backup("before_env_save");
                    let mut map = HashMap::new();
                    map.insert("HTTP_PROXY".to_string(), self.env_http.clone());
                    map.insert("HTTPS_PROXY".to_string(), self.env_https.clone());
                    map.insert("ALL_PROXY".to_string(), self.env_all.clone());
                    map.insert("NO_PROXY".to_string(), self.env_no.clone());
                    match core::set_env_vars(&map) {
                        Ok(_) => {
                            self.refresh_system_state();
                            self.status_msg = "环境变量已保存并广播 WM_SETTINGCHANGE".to_string();
                        }
                        Err(e) => self.status_msg = e,
                    }
                }
                if ui.button("清空代理环境变量 (保留 NO_PROXY)").clicked() {
                    let _ = core::create_backup("before_clear_env");
                    self.env_http.clear();
                    self.env_https.clear();
                    self.env_all.clear();
                    let mut map = HashMap::new();
                    map.insert("HTTP_PROXY".to_string(), String::new());
                    map.insert("HTTPS_PROXY".to_string(), String::new());
                    map.insert("ALL_PROXY".to_string(), String::new());
                    map.insert("NO_PROXY".to_string(), self.env_no.clone());
                    let _ = core::set_env_vars(&map);
                    self.refresh_system_state();
                    self.status_msg = "已清空代理环境变量".to_string();
                }
            });
        });

        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Windows 系统代理 (WinINET / 浏览器与 Electron 默认读取)").strong());
            ui.checkbox(&mut self.sys_enable, "启用系统代理 (ProxyEnable)");
            egui::Grid::new("sys_grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("代理服务器:");
                ui.add(egui::TextEdit::singleline(&mut self.sys_server).desired_width(680.0));
                ui.end_row();

                ui.label("直连例外 (分号):");
                ui.add(egui::TextEdit::singleline(&mut self.sys_override).desired_width(680.0));
                ui.end_row();

                ui.label("PAC 脚本地址:");
                ui.add(egui::TextEdit::singleline(&mut self.sys_pac).desired_width(680.0));
                ui.end_row();
            });
            ui.add_space(4.0);
            if ui.button("应用系统代理设置 (立即刷新)").clicked() {
                let _ = core::create_backup("before_sysproxy_save");
                let info = core::WinInetProxy {
                    proxy_enable: self.sys_enable,
                    proxy_server: self.sys_server.clone(),
                    proxy_override: self.sys_override.clone(),
                    auto_config_url: self.sys_pac.clone(),
                };
                match core::set_wininet_proxy(&info, true) {
                    Ok(_) => {
                        self.refresh_system_state();
                        self.status_msg = "Windows 系统代理已更新并立即生效".to_string();
                    }
                    Err(e) => self.status_msg = e,
                }
            }
        });
    }

    fn ui_apps_tab(&mut self, ui: &mut egui::Ui) {
        ui.label("说明：可扫描本机已安装/运行中的应用，分别设定为「直连」或「走代理」。点击「按策略重启」将在独立环境中按所选策略启动该应用（不影响其他软件）。");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("名称:");
            ui.add(egui::TextEdit::singleline(&mut self.new_app_name).desired_width(100.0));
            ui.label("EXE 路径:");
            ui.add(egui::TextEdit::singleline(&mut self.new_app_path).desired_width(240.0));
            egui::ComboBox::from_id_salt("app_mode_cb")
                .selected_text(if self.new_app_mode == "proxy" { "走代理" } else { "直连" })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.new_app_mode, "direct".to_string(), "直连");
                    ui.selectable_value(&mut self.new_app_mode, "proxy".to_string(), "走代理");
                });
            ui.label("参数:");
            ui.add(egui::TextEdit::singleline(&mut self.new_app_args).desired_width(130.0));
            if ui.button("添加应用").clicked() && !self.new_app_path.trim().is_empty() {
                let name = if self.new_app_name.trim().is_empty() {
                    "CustomApp".to_string()
                } else {
                    self.new_app_name.trim().to_string()
                };
                self.cfg.apps.push(core::AppEntry {
                    name,
                    path: self.new_app_path.trim().to_string(),
                    mode: self.new_app_mode.clone(),
                    extra_args: self.new_app_args.trim().to_string(),
                });
                let _ = core::save_config(&self.cfg);
                self.new_app_name.clear();
                self.new_app_path.clear();
            }
        });

        ui.separator();
        let mut del_idx = None;
        let mut toggle_idx = None;
        let mut launch_idx = None;
        let mut shortcut_idx = None;

        ui.label(egui::RichText::new("已配置的应用策略").strong());
        egui::ScrollArea::vertical().id_salt("configured_apps_scroll").max_height(210.0).show(ui, |ui| {
            egui::Grid::new("apps_grid").striped(true).num_columns(5).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.strong("应用名称");
                ui.strong("策略");
                ui.strong("程序路径");
                ui.strong("附加参数");
                ui.strong("操作");
                ui.end_row();

                for (idx, app) in self.cfg.apps.iter().enumerate() {
                    ui.label(&app.name);
                    let (m_lbl, m_col) = if app.mode == "proxy" {
                        ("走代理", egui::Color32::from_rgb(185, 28, 28))
                    } else {
                        ("直连", egui::Color32::from_rgb(21, 128, 61))
                    };
                    ui.colored_label(m_col, m_lbl);
                    ui.label(&app.path);
                    ui.label(&app.extra_args);
                    ui.horizontal(|ui| {
                        if ui.button("切换直连/代理").clicked() {
                            toggle_idx = Some(idx);
                        }
                        if ui.button("按策略重启").clicked() {
                            launch_idx = Some(idx);
                        }
                        if ui.button("桌面快捷方式").clicked() {
                            shortcut_idx = Some(idx);
                        }
                        if ui.button("删除").clicked() {
                            del_idx = Some(idx);
                        }
                    });
                    ui.end_row();
                }
            });
        });

        if let Some(i) = toggle_idx {
            let a = &mut self.cfg.apps[i];
            a.mode = if a.mode == "proxy" { "direct".to_string() } else { "proxy".to_string() };
            let _ = core::save_config(&self.cfg);
        }
        if let Some(i) = launch_idx {
            let a = &self.cfg.apps[i];
            match core::launch_app_with_mode(&a.path, &a.mode, &a.extra_args, &self.proxy_host_port, true) {
                Ok(msg) => {
                    self.status_msg = msg;
                    self.trigger_conn_refresh();
                }
                Err(e) => self.status_msg = e,
            }
        }
        if let Some(i) = shortcut_idx {
            let a = &self.cfg.apps[i];
            match core::create_mode_shortcut(&a.name, &a.path, &a.mode, &a.extra_args, &self.proxy_host_port) {
                Ok(p) => self.status_msg = format!("已创建桌面快捷方式: {}", p.display()),
                Err(e) => self.status_msg = e,
            }
        }
        if let Some(i) = del_idx {
            self.cfg.apps.remove(i);
            let _ = core::save_config(&self.cfg);
        }

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("本机应用扫描 (运行中 / 开始菜单 / 已安装程序)").strong());
            let scanning = self.scan_rx.is_some();
            if ui.add_enabled(!scanning, egui::Button::new(if scanning { "正在扫描..." } else { "扫描本机所有应用" })).clicked() {
                self.status_msg = "正在扫描本机应用，请稍候...".to_string();
                let (tx, rx) = mpsc::channel();
                self.scan_rx = Some(rx);
                thread::spawn(move || {
                    let list = core::scan_local_apps();
                    let _ = tx.send(list);
                });
            }
            ui.label("搜索:");
            ui.add(egui::TextEdit::singleline(&mut self.scan_keyword).desired_width(160.0));
            ui.checkbox(&mut self.scan_running_only, "仅看运行中");
            ui.label(format!("共 {} 个", self.scanned_apps.len()));
        });

        let kw = self.scan_keyword.trim().to_lowercase();
        let mut set_app_mode: Option<(usize, String)> = None;

        egui::ScrollArea::vertical().id_salt("scanned_apps_scroll").auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("scanned_grid").striped(true).num_columns(4).spacing([12.0, 4.0]).show(ui, |ui| {
                ui.strong("应用名称");
                ui.strong("来源/状态");
                ui.strong("程序路径");
                ui.strong("配置策略");
                ui.end_row();

                for (idx, sa) in self.scanned_apps.iter().enumerate() {
                    if self.scan_running_only && !sa.running {
                        continue;
                    }
                    if !kw.is_empty()
                        && !sa.name.to_lowercase().contains(&kw)
                        && !sa.path.to_lowercase().contains(&kw)
                    {
                        continue;
                    }
                    ui.label(&sa.name);
                    if sa.running {
                        ui.colored_label(egui::Color32::from_rgb(21, 128, 61), format!("{} (运行中)", sa.source));
                    } else {
                        ui.label(&sa.source);
                    }
                    ui.label(&sa.path);
                    ui.horizontal(|ui| {
                        if ui.button("设为直连").clicked() {
                            set_app_mode = Some((idx, "direct".to_string()));
                        }
                        if ui.button("设为代理").clicked() {
                            set_app_mode = Some((idx, "proxy".to_string()));
                        }
                    });
                    ui.end_row();
                }
            });
        });

        if let Some((idx, mode)) = set_app_mode {
            let sa = &self.scanned_apps[idx];
            if let Some(existing) = self.cfg.apps.iter_mut().find(|a| a.path.eq_ignore_ascii_case(&sa.path)) {
                existing.mode = mode.clone();
            } else {
                self.cfg.apps.push(core::AppEntry {
                    name: sa.name.clone(),
                    path: sa.path.clone(),
                    mode: mode.clone(),
                    extra_args: "--no-proxy-server".to_string(),
                });
            }
            let _ = core::save_config(&self.cfg);
            let m_txt = if mode == "proxy" { "走代理" } else { "直连" };
            self.status_msg = format!("已将 {} 设为「{}」", sa.name, m_txt);
        }
    }
}

fn setup_chinese_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = fs::read(path) {
            fonts.font_data.insert(
                "msyh".to_string(),
                egui::FontData::from_owned(bytes).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "msyh".to_string());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("msyh".to_string());
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn main() -> eframe::Result<()> {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1120.0, 740.0])
        .with_min_inner_size([920.0, 600.0]);
    if let Some(ic) = icon {
        viewport = viewport.with_icon(std::sync::Arc::new(ic));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "NetRouteGuard - 本机网络路径监控与代理分流工具",
        options,
        Box::new(|cc| Ok(Box::new(NetRouteGuardApp::new(cc)))),
    )
}
