#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
use eframe::{App, egui};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use trust_dns_resolver::{
    Resolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
};

const API_URL: &str =
    "https://api.umavpn.top/api/server/?sites=uma&sites=dmm&take=20&orderBy=timestamp";

const DOMAINS: &[&str] = &[
    "api-umamusume.cygames.jp",
    "prd-storage-app-umamusume.akamaized.net",
    "prd-storage-game-umamusume.akamaized.net",
    "prd-info-umamusume.akamaized.net",
    "apidgp-gameplayer.games.dmm.com",
    "accounts.dmm.com",
    "webdgp-gameplayer.games.dmm.com",
];

static CIPHER_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?m)^cipher\\s+.*").expect("cipher regex compiles"));

#[derive(Debug, Deserialize)]
struct ApiEnvelope {
    success: bool,
    data: Vec<ServerInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct ServerInfo {
    ip: String,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedEntry {
    domain: String,
    ip: String,
}

enum AppMessage {
    ServerListLoaded(Vec<ServerInfo>),
    Patched {
        path: PathBuf,
        resolved: Vec<ResolvedEntry>,
        routes: Vec<String>,
    },
    HostsPatched(String),
    Error(String),
    Log(String),
}

struct UmaGuiApp {
    sender: Sender<AppMessage>,
    receiver: Receiver<AppMessage>,
    server_list: Vec<ServerInfo>,
    selected_index: usize,
    dns_server: String,
    resolved_entries: Vec<ResolvedEntry>,
    route_lines: Vec<String>,
    log_messages: Vec<String>,
    last_saved_path: Option<PathBuf>,
    is_fetching: bool,
    is_processing: bool,
    hosts_busy: bool,
    last_error: Option<String>,
}

impl UmaGuiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let mut app = Self {
            sender,
            receiver,
            dns_server: "1.1.1.1".to_string(),
            server_list: Vec::new(),
            selected_index: 0,
            resolved_entries: Vec::new(),
            route_lines: Vec::new(),
            log_messages: Vec::new(),
            last_saved_path: None,
            is_fetching: false,
            is_processing: false,
            hosts_busy: false,
            last_error: None,
        };
        app.request_fetch_servers();
        app
    }

    fn request_fetch_servers(&mut self) {
        if self.is_fetching {
            return;
        }
        self.is_fetching = true;
        self.push_log("Fetching UMA VPN server list...");
        let sender = self.sender.clone();
        thread::spawn(move || {
            let result = fetch_server_list();
            match result {
                Ok(list) => {
                    let _ = sender.send(AppMessage::ServerListLoaded(list));
                }
                Err(err) => {
                    let _ = sender.send(AppMessage::Error(format!(
                        "Failed to fetch server list: {err:#}"
                    )));
                }
            }
        });
    }

    fn request_patch(&mut self, output_path: PathBuf) {
        if self.is_processing {
            self.push_log("Another operation is already running.");
            return;
        }
        let Some(server) = self.server_list.get(self.selected_index).cloned() else {
            self.last_error = Some("Server list is empty. Refresh and try again.".to_string());
            return;
        };

        let dns_server = self.dns_server.trim().to_string();
        if dns_server.is_empty() {
            self.last_error = Some("DNS server cannot be empty.".to_string());
            return;
        }

        self.is_processing = true;
        self.last_error = None;
        self.push_log(format!(
            "Starting OVPN download for server {}...",
            server.ip
        ));

        let sender = self.sender.clone();
        thread::spawn(move || {
            let result =
                download_and_patch_task(server, dns_server, output_path.clone(), sender.clone());
            if let Err(err) = result {
                let _ = sender.send(AppMessage::Error(format!(
                    "OVPN processing failed: {err:#}"
                )));
            }
        });
    }

    fn request_hosts_patch(&mut self) {
        if self.hosts_busy {
            self.push_log("Hosts modification already in progress.");
            return;
        }
        if self.resolved_entries.is_empty() {
            self.last_error = Some(
                "Patch an OVPN first to gather resolved IPs before updating hosts.".to_string(),
            );
            return;
        }

        self.hosts_busy = true;
        self.last_error = None;
        self.push_log("Attempting to update hosts file...");

        let entries = self.resolved_entries.clone();
        let sender = self.sender.clone();
        thread::spawn(move || match patch_hosts_file(&entries) {
            Ok(added) => {
                let message = if added == 0 {
                    "Hosts file already contains all UMA VPN entries.".to_string()
                } else {
                    format!("Added {added} UMA VPN entrie(s) to hosts file.")
                };
                let _ = sender.send(AppMessage::HostsPatched(message.clone()));
                let _ = sender.send(AppMessage::Log(message));
            }
            Err(err) => {
                let _ = sender.send(AppMessage::Error(format!(
                    "Failed to update hosts file: {err:#}"
                )));
            }
        });
    }

    fn push_log<S: Into<String>>(&mut self, message: S) {
        self.log_messages.push(message.into());
        if self.log_messages.len() > 500 {
            let overflow = self.log_messages.len() - 500;
            self.log_messages.drain(..overflow);
        }
    }

    fn handle_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::ServerListLoaded(list) => {
                self.server_list = list;
                self.is_fetching = false;
                if self.selected_index >= self.server_list.len() {
                    self.selected_index = 0;
                }
                self.push_log(format!(
                    "Loaded {} server(s) from UMA VPN.",
                    self.server_list.len()
                ));
            }
            AppMessage::Patched {
                path,
                resolved,
                routes,
            } => {
                self.is_processing = false;
                self.resolved_entries = resolved.clone();
                self.route_lines = routes.clone();
                self.last_saved_path = Some(path.clone());
                self.push_log(format!("Patched OVPN saved to {}.", path.display()));
                self.push_log(format!(
                    "Resolved {} domain(s) with {} unique IP route(s).",
                    self.resolved_entries.len(),
                    self.route_lines.len()
                ));
            }
            AppMessage::HostsPatched(message) => {
                self.hosts_busy = false;
                self.push_log(message);
            }
            AppMessage::Error(error) => {
                self.is_fetching = false;
                self.is_processing = false;
                self.hosts_busy = false;
                self.last_error = Some(error.clone());
                self.push_log(error);
            }
            AppMessage::Log(message) => {
                self.push_log(message);
            }
        }
    }

    fn server_display(&self, index: usize) -> String {
        self.server_list
            .get(index)
            .map(|server| {
                let country = server.country.as_deref().unwrap_or("-").to_string();
                let ts = server
                    .timestamp
                    .as_ref()
                    .map(|s| s.replace('T', " ").replace('Z', ""))
                    .unwrap_or_else(|| "-".to_string());
                format!("#{index} - {} - {} - {}", server.ip, country, ts)
            })
            .unwrap_or_else(|| "No server selected".to_string())
    }
}

impl App for UmaGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(message) = self.receiver.try_recv() {
            self.handle_message(message);
        }

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Refresh servers").clicked() {
                    self.request_fetch_servers();
                }
                if self.is_fetching {
                    ui.spinner();
                    ui.label("Fetching...");
                }
            });

            ui.separator();

            if self.server_list.is_empty() && !self.is_fetching {
                ui.label("Server list is empty. Refresh to try again.");
            } else if !self.server_list.is_empty() {
                egui::ComboBox::from_label("Server")
                    .selected_text(self.server_display(self.selected_index))
                    .show_ui(ui, |ui| {
                        for (idx, server) in self.server_list.iter().enumerate() {
                            let label = format!(
                                "#{idx} - {} - {}",
                                server.ip,
                                server.country.as_deref().unwrap_or("-")
                            );
                            ui.selectable_value(&mut self.selected_index, idx, label);
                        }
                    });
            }

            ui.horizontal(|ui| {
                ui.label("DNS server");
                ui.text_edit_singleline(&mut self.dns_server);
            });

            ui.horizontal(|ui| {
                if ui.button("Save patched OVPN...").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("OpenVPN config", &["ovpn"])
                        .set_file_name("uma_patched.ovpn")
                        .save_file()
                    {
                        self.request_patch(path);
                    }
                }
                if self.is_processing {
                    ui.spinner();
                    ui.label("Processing...");
                }
            });

            if let Some(path) = &self.last_saved_path {
                ui.label(format!("Last saved: {}", path.display()));
            }

            if !self.resolved_entries.is_empty() {
                ui.separator();
                ui.label("Resolved domains:");
                for entry in &self.resolved_entries {
                    ui.monospace(format!("{:<15} {}", entry.ip, entry.domain));
                }
            }

            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Patch hosts file").clicked() {
                    self.request_hosts_patch();
                }
                if self.hosts_busy {
                    ui.spinner();
                    ui.label("Updating hosts...");
                }
            });

            if let Some(error) = &self.last_error {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Logs");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for message in &self.log_messages {
                        ui.label(message);
                    }
                });
        });

        if self.is_fetching || self.is_processing || self.hosts_busy {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
    }
}

fn fetch_server_list() -> Result<Vec<ServerInfo>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("Unable to create HTTP client")?;

    let response = client
        .get(API_URL)
        .send()
        .context("Failed to contact UMA VPN API")?
        .error_for_status()
        .context("UMA VPN API returned an error status")?;

    let envelope: ApiEnvelope = response
        .json()
        .context("Failed to parse UMA VPN response payload")?;

    if !envelope.success {
        return Err(anyhow!("UMA VPN API reported success=false"));
    }
    if envelope.data.is_empty() {
        return Err(anyhow!("UMA VPN API returned an empty server list"));
    }

    Ok(envelope.data)
}

fn download_and_patch_task(
    server: ServerInfo,
    dns_server: String,
    output_path: PathBuf,
    sender: Sender<AppMessage>,
) -> Result<()> {
    let (resolved, routes) = download_and_patch(&server, &dns_server, &output_path, &sender)?;

    let _ = sender.send(AppMessage::Patched {
        path: output_path,
        resolved,
        routes,
    });

    Ok(())
}

fn download_and_patch(
    server: &ServerInfo,
    dns_server: &str,
    output_path: &Path,
    sender: &Sender<AppMessage>,
) -> Result<(Vec<ResolvedEntry>, Vec<String>)> {
    let _ = sender.send(AppMessage::Log(format!(
        "Resolving domains via DNS {}...",
        dns_server
    )));
    let resolved_entries = resolve_domains(dns_server, sender)?;

    if resolved_entries.is_empty() {
        return Err(anyhow!("No domains were resolved; aborting patch."));
    }

    let mut unique_ips = BTreeSet::new();
    for entry in &resolved_entries {
        unique_ips.insert(entry.ip.clone());
    }
    let route_lines: Vec<String> = unique_ips
        .iter()
        .map(|ip| format!("route {ip} 255.255.255.255 vpn_gateway"))
        .collect();

    if route_lines.is_empty() {
        return Err(anyhow!("No unique IPs found to build route lines."));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("Unable to create HTTP client for OVPN download")?;

    let download_url = format!(
        "https://api.umavpn.top/api/server/{}/config?variant=current",
        server.ip
    );
    let _ = sender.send(AppMessage::Log(format!(
        "Downloading OVPN from {download_url}"
    )));

    let response = client
        .get(&download_url)
        .send()
        .with_context(|| format!("Failed to download OVPN from {download_url}"))?
        .error_for_status()
        .context("OVPN download returned an error response")?;

    let config_text = response
        .text()
        .context("Failed to read OVPN response body as text")?;

    let patched = patch_ovpn(&config_text, &route_lines);

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent folders for {}",
                    output_path.display()
                )
            })?;
        }
    }

    fs::write(output_path, patched.as_bytes())
        .with_context(|| format!("Failed to write patched OVPN to {}", output_path.display()))?;

    Ok((resolved_entries, route_lines))
}

fn resolve_domains(dns_server: &str, sender: &Sender<AppMessage>) -> Result<Vec<ResolvedEntry>> {
    let ip: IpAddr = dns_server
        .parse()
        .context("DNS server must be a valid IPv4/IPv6 address")?;

    let name_server = NameServerConfig {
        socket_addr: SocketAddr::new(ip, 53),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };

    let mut config = ResolverConfig::new();
    config.add_name_server(name_server);

    let resolver = Resolver::new(config, ResolverOpts::default())
        .context("Failed to construct DNS resolver")?;

    let mut resolved = Vec::new();
    for domain in DOMAINS {
        match resolver.lookup_ip(*domain) {
            Ok(lookup) => {
                let mut chosen: Option<IpAddr> = None;
                for ip_addr in lookup.iter() {
                    if chosen.is_none() {
                        chosen = Some(ip_addr);
                    }
                    if ip_addr.is_ipv4() {
                        chosen = Some(ip_addr);
                        break;
                    }
                }

                if let Some(ip_addr) = chosen {
                    let entry = ResolvedEntry {
                        domain: domain.to_string(),
                        ip: ip_addr.to_string(),
                    };
                    let _ = sender.send(AppMessage::Log(format!(
                        "Resolved {} -> {}",
                        entry.domain, entry.ip
                    )));
                    resolved.push(entry);
                } else {
                    let _ = sender.send(AppMessage::Log(format!(
                        "No A/AAAA records found for {domain}"
                    )));
                }
            }
            Err(err) => {
                let _ = sender.send(AppMessage::Log(format!(
                    "Failed to resolve {domain}: {err}"
                )));
            }
        }
    }

    if resolved.is_empty() {
        return Err(anyhow!(
            "DNS resolution returned no results. Check connectivity and DNS server."
        ));
    }

    Ok(resolved)
}

fn patch_ovpn(original: &str, route_lines: &[String]) -> String {
    let mut block = String::new();
    block.push_str("allow-pull-fqdn\r\n");
    for route in route_lines {
        block.push_str(route);
        block.push_str("\r\n");
    }
    block.push_str("route-nopull\r\n");

    if let Some(mat) = CIPHER_REGEX.find(original) {
        let mut output = String::with_capacity(original.len() + block.len() + 2);
        output.push_str(&original[..mat.start()]);
        output.push_str(&block);
        if !block.ends_with("\r\n") {
            output.push_str("\r\n");
        }
        output.push_str(&original[mat.start()..]);
        output
    } else {
        format!("{}\r\n{}", block, original)
    }
}

fn patch_hosts_file(entries: &[ResolvedEntry]) -> Result<usize> {
    let hosts_path = hosts_file_path();
    let existing = fs::read_to_string(&hosts_path).unwrap_or_default();

    let mut modified_content = String::new();
    let mut updated_domains = std::collections::HashSet::new();
    let mut changed_count = 0;

    // First pass: update existing entries or keep them as-is
    for line in existing.lines() {
        let trimmed = line.trim_start();
        
        // Keep comments and empty lines as-is
        if trimmed.starts_with('#') || trimmed.is_empty() {
            modified_content.push_str(line);
            modified_content.push('\n');
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        if let Some(ip_part) = parts.next() {
            let domains_in_line: Vec<&str> = parts.collect();
            
            // Check if any of our target domains are in this line
            let mut found_target = false;
            for entry in entries {
                if domains_in_line.iter().any(|d| d.eq_ignore_ascii_case(&entry.domain)) {
                    found_target = true;
                    updated_domains.insert(entry.domain.clone());
                    
                    // If IP differs, update it; otherwise keep as-is
                    if ip_part != entry.ip {
                        modified_content.push_str(&format!("{:<15}\t{}\n", entry.ip, entry.domain));
                        changed_count += 1;
                    } else {
                        modified_content.push_str(line);
                        modified_content.push('\n');
                    }
                    break;
                }
            }
            
            // Keep non-target lines as-is
            if !found_target {
                modified_content.push_str(line);
                modified_content.push('\n');
            }
        } else {
            modified_content.push_str(line);
            modified_content.push('\n');
        }
    }

    // Second pass: append new entries that weren't in the file
    let mut to_append = Vec::new();
    for entry in entries {
        if !updated_domains.contains(&entry.domain) {
            to_append.push(format!("{:<15}\t{}", entry.ip, entry.domain));
            changed_count += 1;
        }
    }

    if !to_append.is_empty() {
        if !modified_content.ends_with('\n') {
            modified_content.push('\n');
        }
        modified_content.push_str("\n# UMA VPN pinned entries\n");
        for line in &to_append {
            modified_content.push_str(line);
            modified_content.push('\n');
        }
    }

    // Write the modified content back if there were changes
    if changed_count > 0 {
        fs::write(&hosts_path, modified_content.as_bytes())
            .with_context(|| {
                format!(
                    "Unable to write to hosts file at {}. Try running the app as Administrator.",
                    hosts_path.display()
                )
            })?;
    }

    Ok(changed_count)
}

fn hosts_contains_entry(existing: &str, entry: &ResolvedEntry) -> bool {
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        if let Some(ip_part) = parts.next() {
            if ip_part == entry.ip && parts.any(|token| token.eq_ignore_ascii_case(&entry.domain)) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn hosts_file_path() -> PathBuf {
    std::env::var("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows"))
        .join("System32\\drivers\\etc\\hosts")
}

#[cfg(not(windows))]
fn hosts_file_path() -> PathBuf {
    PathBuf::from("/etc/hosts")
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "UMA VPN Helper",
        options,
        Box::new(|cc| Box::new(UmaGuiApp::new(cc))),
    )
}
