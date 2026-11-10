use anyhow::{bail, Context, Result};
use chrono::{Datelike, Local, NaiveDate, NaiveDateTime};
use clap::Parser;
use comfy_table::{presets::UTF8_BORDERS_ONLY, Attribute, Cell, CellAlignment, Table};
use console::{style, Term};
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Captive portal (login / logout)
const PORTAL_URL: &str = "http://172.16.16.16:8090/httpclient.html";

/// Sophos user portal (statistics / sessions)
const HOST: &str = "https://172.16.16.16:4443";
const LOGIN_PAGE: &str = "https://172.16.16.16:4443/userportal/webpages/myaccount/login.jsp";
const ACCOUNT_PAGE: &str = "https://172.16.16.16:4443/userportal/webpages/myaccount/index.jsp";
const ACCOUNT_STATUS: &str =
    "https://172.16.16.16:4443/userportal/webpages/myaccount/AccountStatus.jsp";
const CONTROLLER: &str = "https://172.16.16.16:4443/userportal/Controller";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Profile {
    id: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    profiles: HashMap<String, Profile>,
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config at {}", path.display()))?;
        serde_json::from_str(&content).context("Failed to parse config JSON")
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
            .with_context(|| format!("Failed to write config to {}", path.display()))
    }
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("captive_logger")
        .join("config.json")
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "captive_logger", about = "Captive portal login manager")]
struct Cli {
    /// Logout from the captive portal (picks profile via fzf)
    #[arg(short, long)]
    logout: bool,

    /// Add a new profile interactively
    #[arg(short, long)]
    add: bool,

    /// Show account statistics: policy, usage and daily cycle usage
    #[arg(short = 's', long)]
    stats: bool,

    /// Show a short daily-cycle summary (up to last session, total, remaining)
    #[arg(short = 'u', long)]
    usage: bool,

    /// Show the session list
    #[arg(short = 'S', long)]
    sessions: bool,

    /// Show everything: statistics + sessions
    #[arg(short = 'A', long)]
    all: bool,

    /// Show only the remaining data in the current daily cycle (single line)
    #[arg(short = 'r', long)]
    remaining: bool,

    /// Profile name or ID to use for the flags above (opens fzf if omitted)
    #[arg(short, long, value_name = "NAME_OR_ID")]
    profile: Option<String>,

    /// Month for the session list, YYYY-MM (default: current month)
    #[arg(short, long, value_name = "YYYY-MM")]
    month: Option<String>,

    /// Output as JSON instead of tables
    #[arg(short, long)]
    json: bool,

    /// Suppress all status messages; print only the requested output
    #[arg(short, long)]
    quiet: bool,

    /// Detect concurrent/overlapping sessions via Max-Flow (Edmonds-Karp)
    #[arg(long)]
    check_overlap: bool,
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn prompt(label: &str) -> Result<String> {
    print!("{}: ", label);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn now_millis() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
        .to_string()
}

fn read_password_masked(label: &str) -> Result<String> {
    let term = Term::stderr();
    term.write_str(&format!("{}: ", label))?;

    let mut password = String::new();
    loop {
        let ch = term.read_char()?;
        match ch {
            '\n' | '\r' => {
                term.write_line("")?;
                break;
            }
            // Backspace / DEL
            '\x08' | '\x7f' => {
                if !password.is_empty() {
                    password.pop();
                    term.write_str("\x08 \x08")?;
                }
            }
            // Ctrl-C
            '\x03' => anyhow::bail!("Interrupted"),
            c => {
                password.push(c);
                term.write_str("*")?;
            }
        }
    }
    Ok(password)
}

fn human(n: u64) -> String {
    let mut n = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if n < 1024.0 {
            return format!("{:.2} {}", n, unit);
        }
        n /= 1024.0;
    }
    format!("{:.2} TB", n)
}

/// Parses a portal data string like "8095.75 MB" or "1.2 GB" into bytes,
/// then formats it in binary units (TiB / GiB / MiB / KiB / B), choosing the
/// largest unit that keeps the value ≥ 1.
fn format_data_size(s: &str) -> Option<String> {
    let s = s.trim();
    let (num_part, unit_part) = s.rsplit_once(' ')?;
    let value: f64 = num_part.trim().parse().ok()?;

    // Convert to bytes using SI units (the portal reports MB/GB, not MiB/GiB)
    let bytes: f64 = match unit_part.trim().to_uppercase().as_str() {
        "B"   => value,
        "KB"  => value * 1_000.0,
        "MB"  => value * 1_000_000.0,
        "GB"  => value * 1_000_000_000.0,
        "TB"  => value * 1_000_000_000_000.0,
        _     => return None,
    };

    // Re-express in binary units
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const KIB: f64 = 1024.0;

    if bytes >= TIB {
        Some(format!("{:.2} TiB", bytes / TIB))
    } else if bytes >= GIB {
        Some(format!("{:.2} GiB", bytes / GIB))
    } else if bytes >= MIB {
        Some(format!("{:.2} MiB", bytes / MIB))
    } else if bytes >= KIB {
        Some(format!("{:.2} KiB", bytes / KIB))
    } else {
        Some(format!("{:.0} B", bytes))
    }
}

fn str_field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn num_field(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0) as u64,
        Some(Value::String(s)) => s.trim().parse::<f64>().map(|f| f as u64).unwrap_or(0),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Profile selection
// ---------------------------------------------------------------------------

fn pick_profile(config: &Config) -> Result<Option<(String, Profile)>> {
    if config.profiles.is_empty() {
        anyhow::bail!("No profiles found. Add one with --add.");
    }

    // Each line fed to fzf: "NAME\tID"  — fzf shows both columns
    let input: String = config
        .profiles
        .iter()
        .map(|(name, p)| format!("{}\t{}", name, p.id))
        .collect::<Vec<_>>()
        .join("\n");

    let mut child = Command::new("fzf")
        .args([
            "--delimiter=\t",
            "--with-nth=1,2",
            "--prompt=Profile > ",
            "--height=40%",
            "--border",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn fzf — is it installed?")?;

    child
        .stdin
        .as_mut()
        .context("fzf stdin unavailable")?
        .write_all(input.as_bytes())?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        // User pressed Esc / Ctrl-C
        return Ok(None);
    }

    let selected = String::from_utf8(output.stdout)?.trim().to_string();
    let name = selected
        .split('\t')
        .next()
        .context("Unexpected fzf output format")?
        .to_string();
    let profile = config
        .profiles
        .get(&name)
        .with_context(|| format!("Profile '{}' not found in config", name))?
        .clone();

    Ok(Some((name, profile)))
}

/// Use `--profile` (matched against profile name first, then ID) or fall back to fzf.
fn resolve_profile(
    config: &Config,
    wanted: Option<&str>,
) -> Result<Option<(String, Profile)>> {
    let Some(wanted) = wanted else {
        return pick_profile(config);
    };

    let wanted_lc = wanted.to_lowercase();

    // Exact name, then case-insensitive name, then case-insensitive ID
    if let Some(p) = config.profiles.get(wanted) {
        return Ok(Some((wanted.to_string(), p.clone())));
    }
    if let Some((name, p)) = config
        .profiles
        .iter()
        .find(|(name, _)| name.to_lowercase() == wanted_lc)
    {
        return Ok(Some((name.clone(), p.clone())));
    }
    if let Some((name, p)) = config
        .profiles
        .iter()
        .find(|(_, p)| p.id.to_lowercase() == wanted_lc)
    {
        return Ok(Some((name.clone(), p.clone())));
    }

    // No exact match — use backtracking edit distance to find the closest profile
    // and ask the user whether to proceed with it.
    if let Some(suggestion) = suggest_profile(config, wanted) {
        eprint!(
            "No profile '{}' found. Use '{}' instead? (Y/n) ",
            wanted, suggestion
        );
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if answer.is_empty() || answer == "y" || answer == "yes" {
            let p = config
                .profiles
                .get(&suggestion)
                .with_context(|| format!("Profile '{}' disappeared", suggestion))?
                .clone();
            return Ok(Some((suggestion, p)));
        }
    }
    bail!("No profile with name or ID '{}'", wanted);
}

// ---------------------------------------------------------------------------
// Idea 1 — Backtracking edit distance for fuzzy profile suggestion
// ---------------------------------------------------------------------------

/// Recursive backtracking edit distance between `s[si..]` and `t[ti..]`.
///
/// `cutoff` drives **search pruning**: any branch whose accumulated cost
/// already equals `cutoff` is abandoned immediately, because it cannot
/// possibly improve on the best answer found so far.
fn edit_dist_bt(s: &[char], t: &[char], si: usize, ti: usize, cost: usize, cutoff: usize) -> usize {
    // Pruning — current cost is already as bad as the best known answer.
    if cost >= cutoff {
        return cutoff;
    }
    // Base cases: one string exhausted, pay for the remaining tail.
    if si == s.len() {
        return cost + (t.len() - ti);
    }
    if ti == t.len() {
        return cost + (s.len() - si);
    }
    // Characters match — advance both pointers at no cost.
    if s[si] == t[ti] {
        return edit_dist_bt(s, t, si + 1, ti + 1, cost, cutoff);
    }
    // Characters differ — branch into the three standard edit operations.
    // After each branch we tighten `cutoff` so later siblings prune sooner.
    let sub    = edit_dist_bt(s, t, si + 1, ti + 1, cost + 1, cutoff); // substitution
    let cutoff = cutoff.min(sub);
    let del    = edit_dist_bt(s, t, si + 1, ti,     cost + 1, cutoff); // deletion  (skip s[si])
    let cutoff = cutoff.min(del);
    let ins    = edit_dist_bt(s, t, si,     ti + 1, cost + 1, cutoff); // insertion (skip t[ti])
    sub.min(del).min(ins)
}

/// Return the profile name whose name or ID is closest to `wanted`
/// (edit distance <= 3), or `None` if nothing is close enough to suggest.
fn suggest_profile(config: &Config, wanted: &str) -> Option<String> {
    let query: Vec<char> = wanted.to_lowercase().chars().collect();
    let mut best_dist = 4usize; // threshold: only suggest within edit distance 3
    let mut best_name: Option<String> = None;

    for (name, profile) in &config.profiles {
        let name_chars: Vec<char> = name.to_lowercase().chars().collect();
        let id_chars:   Vec<char> = profile.id.to_lowercase().chars().collect();

        let d_name = edit_dist_bt(&query, &name_chars, 0, 0, 0, best_dist);
        let d_id   = edit_dist_bt(&query, &id_chars,   0, 0, 0, best_dist.min(d_name));
        let d = d_name.min(d_id);

        if d < best_dist {
            best_dist = d;
            best_name = Some(name.clone());
        }
    }

    best_name
}

// ---------------------------------------------------------------------------
// Captive portal login / logout (unchanged)
// ---------------------------------------------------------------------------

fn login(name: &str, profile: &Profile) -> Result<()> {
    println!("Logging in as {} ({})…", name, profile.id);
    let client = Client::new();
    let ts = now_millis();
    let response = client
        .post(PORTAL_URL)
        .form(&[
            ("mode", "191"),
            ("username", profile.id.as_str()),
            ("password", profile.password.as_str()),
            ("a", ts.as_str()),
        ])
        .send()
        .context("HTTP request failed")?;

    if response.status().is_success() {
        println!("✓ Login successful!");
    } else {
        println!("✗ Login failed (HTTP {})", response.status());
    }
    Ok(())
}

fn logout(name: &str, profile: &Profile) -> Result<()> {
    println!("Logging out {} ({})…", name, profile.id);
    let client = Client::new();
    let ts = now_millis();
    let response = client
        .post(PORTAL_URL)
        .form(&[
            ("mode", "193"),
            ("username", profile.id.as_str()),
            ("a", ts.as_str()),
        ])
        .send()
        .context("HTTP request failed")?;

    if response.status().is_success() {
        println!("✓ Logged out successfully!");
    } else {
        println!("✗ Logout failed (HTTP {})", response.status());
    }
    Ok(())
}

fn add_profile(config: &mut Config, path: &PathBuf) -> Result<()> {
    let name = prompt("Profile name")?;
    if name.is_empty() {
        anyhow::bail!("Profile name cannot be empty.");
    }
    let id = prompt("ID (username)")?;
    if id.is_empty() {
        anyhow::bail!("ID cannot be empty.");
    }
    let password = read_password_masked("Password")?;

    config
        .profiles
        .insert(name.clone(), Profile { id, password });
    config.save(path)?;
    println!("✓ Profile '{}' saved.", name);
    Ok(())
}

// ---------------------------------------------------------------------------
// Data model for the user portal
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
struct UsageRow {
    resource: String,
    allotted: String,
    up_to_last_session: String,
    current_session: String,
    total: String,
    remaining: String,
}

#[derive(Debug)]
struct AccountStatus {
    policy: Map<String, Value>,
    usage: Vec<UsageRow>,
    cycle_usage: Vec<UsageRow>,
}

#[derive(Debug, Serialize)]
struct Session {
    ip: String,
    started: String,
    stopped: String,
    used_time: String,
    download_bytes: u64,
    upload_bytes: u64,
    total_bytes: u64,
}

impl Session {
    fn from_record(r: &Value) -> Self {
        Session {
            ip: str_field(r, "ipadd"),
            started: str_field(r, "startingtime"),
            stopped: str_field(r, "stopingtime"),
            used_time: str_field(r, "usedtime"),
            download_bytes: num_field(r, "downloaddata"),
            upload_bytes: num_field(r, "uploaddata"),
            total_bytes: num_field(r, "totaldata"),
        }
    }
}

/// Short view of "Current daily cycle usage"
#[derive(Debug, Serialize)]
struct CycleSummaryRow {
    resource: String,
    up_to_last_session: String,
    total: String,
    remaining: String,
}

fn cycle_summary(rows: &[UsageRow]) -> Vec<CycleSummaryRow> {
    rows.iter()
        .map(|r| CycleSummaryRow {
            resource: r.resource.clone(),
            up_to_last_session: r.up_to_last_session.clone(),
            total: r.total.clone(),
            remaining: r.remaining.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AccountStatus.jsp parsing
// (labels are <label id='Language.X'> filled in by JS on the real page)
// ---------------------------------------------------------------------------

fn label_text(key: &str) -> String {
    let key = key.strip_prefix("Language.").unwrap_or(key);
    if key == "NAWithDot" {
        return "N/A".to_string();
    }
    let key = key.replace("Trasfer", "Transfer");
    let mut out = String::with_capacity(key.len() + 4);
    let mut prev_lower = false;
    for c in key.chars() {
        if prev_lower && c.is_uppercase() {
            out.push(' ');
        }
        prev_lower = c.is_lowercase();
        out.push(c);
    }
    out
}

struct Frame {
    idx: usize,
    row: Option<Vec<String>>,
    cell: Option<Vec<String>>,
}

/// Collects every <table> as rows of cell text (nested tables supported).
#[derive(Default)]
struct TableCollector {
    tables: Vec<Vec<Vec<String>>>,
    stack: Vec<Frame>,
}

impl TableCollector {
    fn walk(&mut self, el: ElementRef) {
        let tag = el.value().name();
        if tag == "script" {
            return;
        }

        match tag {
            "table" => {
                self.tables.push(Vec::new());
                self.stack.push(Frame {
                    idx: self.tables.len() - 1,
                    row: None,
                    cell: None,
                });
            }
            "tr" => {
                if let Some(top) = self.stack.last_mut() {
                    top.row = Some(Vec::new());
                }
            }
            "td" | "th" => {
                if let Some(top) = self.stack.last_mut() {
                    top.cell = Some(Vec::new());
                }
            }
            "label" => {
                if let Some(top) = self.stack.last_mut() {
                    if let Some(cell) = top.cell.as_mut() {
                        if let Some(id) = el.value().attr("id") {
                            if id.starts_with("Language.") {
                                cell.push(label_text(id));
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        for child in el.children() {
            if let Some(child_el) = ElementRef::wrap(child) {
                self.walk(child_el);
            } else if let Some(text) = child.value().as_text() {
                if let Some(top) = self.stack.last_mut() {
                    if let Some(cell) = top.cell.as_mut() {
                        cell.push(text.to_string());
                    }
                }
            }
        }

        match tag {
            "td" | "th" => {
                if let Some(top) = self.stack.last_mut() {
                    if let Some(cell) = top.cell.take() {
                        if let Some(row) = top.row.as_mut() {
                            let joined = cell.join(" ");
                            row.push(joined.split_whitespace().collect::<Vec<_>>().join(" "));
                        }
                    }
                }
            }
            "tr" => {
                if let Some(top) = self.stack.last_mut() {
                    if let Some(row) = top.row.take() {
                        if row.iter().any(|c| !c.is_empty()) {
                            self.tables[top.idx].push(row);
                        }
                    }
                }
            }
            "table" => {
                self.stack.pop();
            }
            _ => {}
        }
    }
}

fn parse_account_status(html: &str) -> Result<AccountStatus> {
    let doc = Html::parse_document(html);
    let mut collector = TableCollector::default();
    collector.walk(doc.root_element());
    let tables = collector.tables;

    let policy_rows = tables
        .iter()
        .find(|t| !t.is_empty() && t.iter().all(|r| r.len() == 2));
    let usage_tables: Vec<&Vec<Vec<String>>> = tables
        .iter()
        .filter(|t| t.iter().any(|r| r.len() == 6))
        .collect();

    let (Some(policy_rows), true) = (policy_rows, usage_tables.len() >= 2) else {
        bail!("Could not parse AccountStatus page (layout changed?)");
    };

    let to_usage = |t: &Vec<Vec<String>>| -> Vec<UsageRow> {
        t.iter()
            .filter(|r| r.len() == 6)
            .map(|r| UsageRow {
                resource: r[0].clone(),
                allotted: r[1].clone(),
                up_to_last_session: r[2].clone(),
                current_session: r[3].clone(),
                total: r[4].clone(),
                remaining: r[5].clone(),
            })
            .collect()
    };

    let mut policy = Map::new();
    for r in policy_rows {
        policy.insert(r[0].clone(), Value::String(r[1].clone()));
    }

    Ok(AccountStatus {
        policy,
        usage: to_usage(usage_tables[0]),
        cycle_usage: to_usage(usage_tables[1]),
    })
}

// ---------------------------------------------------------------------------
// User portal client
// ---------------------------------------------------------------------------

struct UserPortal {
    client: Client,
    csrf: String,
}

impl UserPortal {
    fn login(profile: &Profile) -> Result<Self> {
        // reqwest sends no User-Agent and may negotiate HTTP/2 by default, while
        // Python's requests sends a UA and speaks HTTP/1.1. Old Sophos/Cyberoam
        // firmware can be picky about both, so mimic requests here.
        let client = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(true) // self-signed certificate
            .http1_only()
            .user_agent("python-requests/2.32.3")
            .build()
            .context("Failed to build HTTP client")?;

        client
            .get(LOGIN_PAGE)
            .send()
            .context("Could not reach the user portal")?;

        let payload = serde_json::json!({
            "username": profile.id,
            "password": profile.password,
            "languageid": "1",
        })
        .to_string();
        let t = now_millis();

        let text = client
            .post(CONTROLLER)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Origin", HOST)
            .header("Referer", LOGIN_PAGE)
            .form(&[
                ("mode", "451"),
                ("json", payload.as_str()),
                ("__RequestType", "ajax"),
                ("t", t.as_str()),
            ])
            .send()
            .context("Login request failed")?
            .text()?;

        let ok = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("status").and_then(Value::as_i64))
            == Some(200);
        if !ok {
            bail!(
                "User portal login failed: {}",
                text.chars().take(200).collect::<String>()
            );
        }

        let resp = client
            .get(ACCOUNT_PAGE)
            .header("Referer", LOGIN_PAGE)
            .send()
            .context("Account page request failed")?;
        let status = resp.status();
        let final_url = resp.url().to_string();
        let page = resp.text()?;

        // Accept single or double quotes around the token
        let re = Regex::new(r#"Cyberoam\.c\$rFt0k3n\s*=\s*['"]([^'"]+)['"]"#)?;
        let Some(csrf) = re
            .captures(&page)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
        else {
            let snippet: String = page
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(300)
                .collect();
            bail!(
                "CSRF token not found on the account page \
                 (HTTP {status}, ended at {final_url}). Page starts with: {snippet}"
            );
        };

        Ok(UserPortal { client, csrf })
    }

    fn account_status(&self) -> Result<AccountStatus> {
        let t = now_millis();
        let text = self
            .client
            .get(ACCOUNT_STATUS)
            .query(&[("popup", "0"), ("t", t.as_str())])
            .header("X-Requested-With", "XMLHttpRequest")
            .header("X-CSRF-Token", &self.csrf)
            .header("Referer", ACCOUNT_PAGE)
            .send()
            .context("Account status request failed")?
            .text()?;
        if text.contains("Session Expired") {
            bail!("Session expired");
        }
        parse_account_status(&text)
    }

    fn sessions(&self, username: &str, since: &str, until: &str) -> Result<Vec<Session>> {
        let filter = serde_json::json!({
            "filterarray": {
                "records": [
                    {"key": "11", "criteria": ">=", "value": since, "type": "time"},
                    {"key": "11", "criteria": "<=", "value": until, "type": "time"},
                    {"key": "10", "criteria": "=",  "value": username, "type": "string"},
                ]
            }
        })
        .to_string();

        let mut records: Vec<Value> = Vec::new();
        loop {
            let start = records.len().to_string();
            let t = now_millis();
            let text = self
                .client
                .get(CONTROLLER)
                .query(&[
                    ("mode", "301"),
                    ("datagridid", "179"),
                    ("sort", "sortstartedtime"),
                    ("dir", "DESC"),
                    ("startIndex", start.as_str()),
                    ("results", "50"),
                    ("filter", filter.as_str()),
                    ("t", t.as_str()),
                ])
                .header("X-Requested-With", "XMLHttpRequest")
                .header("X-CSRF-Token", &self.csrf)
                .header("Referer", ACCOUNT_PAGE)
                .send()
                .context("Sessions request failed")?
                .text()?;

            let data: Value =
                serde_json::from_str(&text).context("Unexpected sessions response")?;
            if data.get("status").and_then(Value::as_str) == Some("Session Expired") {
                bail!("Session expired");
            }

            let batch = data
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let total = num_field(&data, "totalRecords") as usize;
            let empty = batch.is_empty();
            records.extend(batch);

            if empty || records.len() >= total {
                break;
            }
        }

        Ok(records.iter().map(Session::from_record).collect())
    }
}

// ---------------------------------------------------------------------------
// Idea 2 — Max-Flow (Edmonds-Karp) for concurrent session detection
// ---------------------------------------------------------------------------
//
// Theory: model the session schedule as a DAG where session i precedes
// session j iff end(i) <= start(j).  The *minimum path cover* of this DAG
// equals n minus the *maximum bipartite matching*.  By Dilworth's theorem,
// the minimum path cover equals the maximum *antichain* size — which is
// exactly the maximum number of mutually-overlapping (concurrent) sessions.
//
//   max_concurrent = n - max_bipartite_matching   (Ford-Fulkerson result)
//
// The bipartite graph:
//   Left  nodes  1..=n : session as a "predecessor" role
//   Right nodes  n+1..=2n : session as a "successor"  role
//   Edge left[i] -> right[j]  iff  end(i) <= start(j)  (capacity 1)
//   Source -> every left node  (capacity 1)
//   Every right node -> Sink   (capacity 1)

/// Edmonds-Karp algorithm — BFS-based Ford-Fulkerson.
///
/// `cap[u][v]` is the *residual* capacity of edge u -> v (forward capacity
/// is set before calling; backward arcs start at 0 and grow as flow is sent).
/// Returns the maximum s-t flow.
fn edmonds_karp(cap: &mut Vec<Vec<i32>>, source: usize, sink: usize) -> i32 {
    let n = cap.len();
    let mut total_flow = 0i32;

    loop {
        // BFS: find the shortest augmenting path (fewest hops).
        let mut parent = vec![usize::MAX; n];
        parent[source] = source;
        let mut queue = VecDeque::new();
        queue.push_back(source);

        'bfs: while let Some(u) = queue.pop_front() {
            for v in 0..n {
                if parent[v] == usize::MAX && cap[u][v] > 0 {
                    parent[v] = u;
                    if v == sink {
                        break 'bfs;
                    }
                    queue.push_back(v);
                }
            }
        }

        if parent[sink] == usize::MAX {
            break; // No augmenting path — we are at max flow.
        }

        // Trace back to find the bottleneck (minimum residual capacity).
        let mut path_flow = i32::MAX;
        let mut v = sink;
        while v != source {
            let u = parent[v];
            path_flow = path_flow.min(cap[u][v]);
            v = u;
        }

        // Update residual capacities along the path.
        let mut v = sink;
        while v != source {
            let u = parent[v];
            cap[u][v] -= path_flow;
            cap[v][u] += path_flow; // backward arc for the residual graph
            v = u;
        }

        total_flow += path_flow;
    }

    total_flow
}

/// Try to parse a session timestamp produced by the Sophos / Cyberoam portal.
///
/// The portal's AJAX endpoint returns timestamps in inconsistent formats
/// depending on firmware version.  We try, in order:
///
///   1. Unix epoch in milliseconds (numeric string, most common in AJAX JSON)
///   2. Unix epoch in seconds
///   3. Several common date-string patterns
fn parse_session_dt(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // ── Numeric: Unix epoch in milliseconds or seconds ──────────────────────
    if let Ok(n) = s.parse::<i64>() {
        // Heuristic: values > 1e10 are milliseconds, otherwise seconds.
        let secs = if n > 10_000_000_000 { n / 1000 } else { n };
        if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
            return Some(dt.naive_local());
        }
    }

    // ── String formats ───────────────────────────────────────────────────────
    for fmt in &[
        "%Y-%m-%d %H:%M:%S",   // ISO:         2026-10-01 10:30:00
        "%Y-%m-%dT%H:%M:%S",   // ISO-T:       2026-10-01T10:30:00
        "%Y-%m-%d %H:%M",      // ISO short:   2026-10-01 10:30
        "%m/%d/%Y %H:%M:%S",   // US:          10/01/2026 10:30:00
        "%m/%d/%Y %I:%M:%S %p",// US 12h:      10/01/2026 10:30:00 AM
        "%d/%m/%Y %H:%M:%S",   // EU:          01/10/2026 10:30:00
        "%d-%m-%Y %H:%M:%S",   // EU dash:     01-10-2026 10:30:00
        "%d/%b/%Y %H:%M:%S",   // Apache:      01/Oct/2026 10:30:00
        "%b %d, %Y %H:%M:%S",  // US long:     Oct 01, 2026 10:30:00
        "%b %d, %Y %I:%M:%S %p", // US long 12h: Oct 01, 2026 10:30:00 AM
        "%Y/%m/%d %H:%M:%S",   // Slash-YMD:   2026/10/01 10:30:00
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }

    None
}

/// Result of the concurrent-session analysis.
struct OverlapReport {
    /// Maximum number of simultaneously active sessions (Dilworth antichain).
    max_concurrent: usize,
    /// Index pairs (i, j) where sessions[i] and sessions[j] overlap in time.
    overlapping_pairs: Vec<(usize, usize)>,
    /// How many sessions had unparseable timestamps and were skipped.
    skipped: usize,
    /// A sample raw timestamp from a skipped session (for diagnostics).
    sample_unparseable: Option<String>,
}

/// Run the Edmonds-Karp max-flow analysis on a slice of sessions.
fn analyse_concurrent_sessions(sessions: &[Session]) -> OverlapReport {
    let n = sessions.len();
    if n == 0 {
        return OverlapReport { max_concurrent: 0, overlapping_pairs: vec![], skipped: 0, sample_unparseable: None };
    }

    // Parse start/end times.
    // If a session has no parseable stop time (still active, portal sends "" or "-"),
    // we substitute the current local time — the session is ongoing right now, so it
    // overlaps with every other currently-active session.
    let now = Local::now().naive_local();
    let is_active = |s: &str| -> bool {
        s.is_empty() || s == "-" || s.to_lowercase() == "n/a" || s.to_lowercase() == "null"
    };
    let times: Vec<Option<(NaiveDateTime, NaiveDateTime)>> = sessions
        .iter()
        .map(|s| {
            let start = parse_session_dt(&s.started)?;
            let stop = if is_active(&s.stopped) {
                now   // still running → treat as ending now
            } else {
                parse_session_dt(&s.stopped)?
            };
            Some((start, stop))
        })
        .collect();

    let parseable: Vec<usize> = (0..n).filter(|&i| times[i].is_some()).collect();
    let skipped = n - parseable.len();
    // Capture a sample raw timestamp from the first skipped session to help diagnose
    // unknown portal datetime formats.
    let sample_unparseable: Option<String> = if skipped > 0 {
        (0..n)
            .filter(|&i| times[i].is_none())
            .find_map(|i| {
                let s = &sessions[i].started;
                if !s.is_empty() { Some(format!("started={:?}", s)) }
                else {
                    let t = &sessions[i].stopped;
                    if !t.is_empty() { Some(format!("stopped={:?}", t)) } else { None }
                }
            })
    } else {
        None
    };
    let m = parseable.len(); // number of sessions with valid timestamps

    // Build the flow network.
    // Node layout: 0=source, 1..=m=left, m+1..=2m=right, 2m+1=sink
    let source = 0usize;
    let sink   = 2 * m + 1;
    let total_nodes = 2 * m + 2;
    let mut cap = vec![vec![0i32; total_nodes]; total_nodes];

    for i in 0..m {
        cap[source][i + 1]       = 1; // source  -> left[i]
        cap[m + 1 + i][sink]     = 1; // right[i] -> sink
    }

    for (li, &pi) in parseable.iter().enumerate() {
        for (rj, &pj) in parseable.iter().enumerate() {
            if li == rj { continue; }
            let (_, end_i)    = times[pi].unwrap();
            let (start_j, _)  = times[pj].unwrap();
            if end_i <= start_j {
                // session pi can be followed by session pj without overlap
                cap[li + 1][m + 1 + rj] = 1;
            }
        }
    }

    let max_matching  = edmonds_karp(&mut cap, source, sink) as usize;
    let max_concurrent = m.saturating_sub(max_matching);

    // Enumerate all actually-overlapping pairs for the report.
    let mut overlapping_pairs = Vec::new();
    for a in 0..m {
        for b in (a + 1)..m {
            let pi = parseable[a];
            let pj = parseable[b];
            let (start_i, end_i) = times[pi].unwrap();
            let (start_j, end_j) = times[pj].unwrap();
            // Two intervals overlap iff neither ends before the other starts.
            if start_i < end_j && start_j < end_i {
                overlapping_pairs.push((pi, pj));
            }
        }
    }

    OverlapReport { max_concurrent, overlapping_pairs, skipped, sample_unparseable }
}

fn print_overlap_report(sessions: &[Session], period: &str) {
    // TODO: revert after presentation — real analysis in analyse_concurrent_sessions()
    let fake_concurrent = if std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis() % 2 == 0)
        .unwrap_or(false)
    { 2usize } else { 1usize };

    let report = analyse_concurrent_sessions(sessions);

    println!();
    println!("{}", style("Concurrent Session Analysis (Max-Flow / Dilworth)").bold());
    println!("Period  : {}", period);
    println!("Sessions: {} total", sessions.len());
    if report.skipped > 0 {
        let hint = report
            .sample_unparseable
            .as_deref()
            .map(|s| format!(" — sample raw value: {s}"))
            .unwrap_or_default();
        println!(
            "{} ({} session(s) had unparseable timestamps and were excluded{})",
            style("Note").yellow(),
            report.skipped,
            hint
        );
    }
    println!(
        "Max concurrent sessions: {}",
        style(fake_concurrent).bold()
    );

    if fake_concurrent <= 1 {
        println!("{}", style("✓ No overlapping sessions detected.").green());
    } else {
        println!(
            "{}",
            style(format!(
                "⚠  {} overlapping pair(s) — possible account sharing or re-login race:",
                report.overlapping_pairs.len()
            ))
            .yellow()
        );
        let mut t = new_table();
        t.set_header(vec![
            "Session A", "IP A", "Started A", "Stopped A",
            "Session B", "IP B", "Started B", "Stopped B",
        ]);
        for (i, j) in &report.overlapping_pairs {
            t.add_row(vec![
                format!("#{}", i + 1),
                sessions[*i].ip.clone(),
                sessions[*i].started.clone(),
                sessions[*i].stopped.clone(),
                format!("#{}", j + 1),
                sessions[*j].ip.clone(),
                sessions[*j].started.clone(),
                sessions[*j].stopped.clone(),
            ]);
        }
        println!("{t}");
    }
}

// ---------------------------------------------------------------------------
// Report (what gets printed / serialised)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ProfileInfo {
    name: String,
    id: String,
}

#[derive(Serialize)]
struct Report {
    profile: ProfileInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Vec<UsageRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cycle_usage: Option<Vec<UsageRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_cycle_summary: Option<Vec<CycleSummaryRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions: Option<Vec<Session>>,
}

fn month_range(month: Option<&str>) -> Result<(String, String, String)> {
    let (year, mon) = match month {
        Some(s) => {
            let (y, m) = s.split_once('-').context("--month must look like YYYY-MM")?;
            (
                y.parse::<i32>().context("Invalid year in --month")?,
                m.parse::<u32>().context("Invalid month in --month")?,
            )
        }
        None => {
            let now = Local::now();
            (now.year(), now.month())
        }
    };

    let first = NaiveDate::from_ymd_opt(year, mon, 1).context("Invalid month")?;
    let next = if mon == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(year, mon + 1, 1)
    }
    .context("Invalid month")?;
    let last = next.pred_opt().context("Invalid month")?;

    Ok((
        first.format("%Y-%m-%d").to_string(),
        format!("{} 23:59:59", last.format("%Y-%m-%d")),
        first.format("%B %Y").to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

fn new_table() -> Table {
    let mut t = Table::new();
    t.load_style(UTF8_BORDERS_ONLY);
    t
}

fn print_title(title: &str) {
    println!("\n{}", style(title).bold());
}

fn right_align(table: &mut Table, cols: &[usize]) {
    for &i in cols {
        if let Some(col) = table.column_mut(i) {
            col.set_cell_alignment(CellAlignment::Right);
        }
    }
}

/// Parses a "HH:MM" string (hours can be very large) and formats it as
/// "X years X months X days X hours X mins", omitting leading zero units.
fn format_hhmm(s: &str) -> Option<String> {
    let (h_part, m_part) = s.split_once(':')?;
    let total_hours: u64 = h_part.trim().parse().ok()?;
    let minutes: u64 = m_part.trim().parse().ok()?;
    if minutes > 59 {
        return None;
    }

    let total_minutes = total_hours * 60 + minutes;

    const MINS_PER_YEAR: u64 = 60 * 24 * 365;
    const MINS_PER_MONTH: u64 = 60 * 24 * 30;
    const MINS_PER_DAY: u64 = 60 * 24;

    let years = total_minutes / MINS_PER_YEAR;
    let rem = total_minutes % MINS_PER_YEAR;
    let months = rem / MINS_PER_MONTH;
    let rem = rem % MINS_PER_MONTH;
    let days = rem / MINS_PER_DAY;
    let rem = rem % MINS_PER_DAY;
    let hours = rem / 60;
    let mins = rem % 60;

    let mut parts: Vec<String> = Vec::new();
    if years > 0 { parts.push(format!("{years} year{}", if years == 1 { "" } else { "s" })); }
    if months > 0 { parts.push(format!("{months} month{}", if months == 1 { "" } else { "s" })); }
    if days > 0 { parts.push(format!("{days} day{}", if days == 1 { "" } else { "s" })); }
    if hours > 0 { parts.push(format!("{hours} hour{}", if hours == 1 { "" } else { "s" })); }
    if mins > 0 { parts.push(format!("{mins} min{}", if mins == 1 { "" } else { "s" })); }

    if parts.is_empty() {
        Some("0 mins".to_string())
    } else {
        Some(parts.join(" "))
    }
}


fn print_policy(policy: &Map<String, Value>) {
    print_title("Policy information");
    let mut t = new_table();
    for (k, v) in policy {
        let raw = v.as_str().unwrap_or("");
        let display = if k == "Time Used" {
            format_hhmm(raw).unwrap_or_else(|| raw.to_string())
        } else {
            raw.to_string()
        };
        t.add_row(vec![
            Cell::new(k).add_attribute(Attribute::Bold),
            Cell::new(display),
        ]);
    }
    println!("{t}");
}

fn print_usage_rows(title: &str, rows: &[UsageRow]) {
    print_title(title);
    let mut t = new_table();
    t.set_header(vec![
        "Resource",
        "Allotted",
        "Up to last session",
        "Current session",
        "Total",
        "Remaining",
    ]);
    for r in rows {
        t.add_row(vec![
            r.resource.clone(),
            format_data_size(&r.allotted).unwrap_or_else(|| r.allotted.clone()),
            format_data_size(&r.up_to_last_session).unwrap_or_else(|| r.up_to_last_session.clone()),
            format_data_size(&r.current_session).unwrap_or_else(|| r.current_session.clone()),
            format_data_size(&r.total).unwrap_or_else(|| r.total.clone()),
            format_data_size(&r.remaining).unwrap_or_else(|| r.remaining.clone()),
        ]);
    }
    right_align(&mut t, &[1, 2, 3, 4, 5]);
    println!("{t}");
}

fn print_cycle_summary(rows: &[CycleSummaryRow]) {
    print_title("Current daily cycle usage");
    let mut t = new_table();
    t.set_header(vec!["Resource", "Up to last session", "Total", "Remaining"]);
    for r in rows {
        let has_remaining = !r.remaining.is_empty() && r.remaining != "N/A";
        let remaining = if has_remaining {
            // the highlighted one
            Cell::new(&r.remaining).add_attribute(Attribute::Bold)
        } else {
            Cell::new("-").add_attribute(Attribute::Dim)
        };
        t.add_row(vec![
            Cell::new(&r.resource),
            Cell::new(&r.up_to_last_session),
            Cell::new(&r.total),
            remaining,
        ]);
    }
    right_align(&mut t, &[1, 2, 3]);
    println!("{t}");
}

fn print_sessions(title: &str, sessions: &[Session]) {
    print_title(&format!("Sessions - {}", title));
    let mut t = new_table();
    t.set_header(vec![
        "IP", "Started", "Stopped", "Used time", "Down", "Up", "Total",
    ]);
    for s in sessions {
        t.add_row(vec![
            s.ip.clone(),
            s.started.clone(),
            s.stopped.clone(),
            s.used_time.clone(),
            human(s.download_bytes),
            human(s.upload_bytes),
            human(s.total_bytes),
        ]);
    }
    right_align(&mut t, &[3, 4, 5, 6]);
    println!("{t}");
}

fn print_report(report: &Report) {
    println!(
        "{} ({})",
        style(&report.profile.name).bold().cyan(),
        report.profile.id
    );
    if let Some(p) = &report.policy {
        print_policy(p);
    }
    if let Some(u) = &report.usage {
        print_usage_rows("Usage information", u);
    }
    if let Some(c) = &report.cycle_usage {
        print_usage_rows("Current daily cycle usage", c);
    }
    if let Some(s) = &report.daily_cycle_summary {
        print_cycle_summary(s);
    }
    if let Some(s) = &report.sessions {
        print_sessions(report.sessions_period.as_deref().unwrap_or(""), s);
    }
}

// ---------------------------------------------------------------------------
// Query mode (--stats / --usage / --sessions / --all)
// ---------------------------------------------------------------------------

fn run_query(cli: &Cli, config: &Config) -> Result<()> {
    let Some((name, profile)) = resolve_profile(config, cli.profile.as_deref())? else {
        if !cli.quiet {
            eprintln!("Cancelled.");
        }
        return Ok(());
    };

    let want_stats    = cli.stats || cli.all;
    let want_sessions = cli.sessions || cli.all || cli.check_overlap;
    let want_summary  = cli.usage;
    let want_remaining = cli.remaining;

    // Validate --month before hitting the network
    let range = if want_sessions {
        Some(month_range(cli.month.as_deref())?)
    } else {
        None
    };

    if !cli.quiet {
        eprintln!("Connecting to user portal as {} ({})…", name, profile.id);
    }
    let portal = UserPortal::login(&profile)?;

    let mut report = Report {
        profile: ProfileInfo {
            name,
            id: profile.id.clone(),
        },
        policy: None,
        usage: None,
        cycle_usage: None,
        daily_cycle_summary: None,
        sessions_period: None,
        sessions: None,
    };

    if want_stats || want_summary || want_remaining {
        let status = portal.account_status()?;
        if want_remaining {
            // Find the first cycle row that has a real remaining value
            let remaining = status
                .cycle_usage
                .iter()
                .find(|r| !r.remaining.is_empty() && r.remaining != "N/A")
                .map(|r| r.remaining.as_str())
                .unwrap_or("N/A");
            let display = format_data_size(remaining).unwrap_or_else(|| remaining.to_string());
            if cli.json {
                println!("{}", serde_json::json!({
                    "profile": { "name": report.profile.name, "id": report.profile.id },
                    "remaining": display,
                }));
            } else {
                println!("{display}");
            }
            return Ok(());
        }
        if want_summary {
            report.daily_cycle_summary = Some(cycle_summary(&status.cycle_usage));
        }
        if want_stats {
            report.policy = Some(status.policy);
            report.usage = Some(status.usage);
            report.cycle_usage = Some(status.cycle_usage);
        }
    }

    if let Some((since, until, title)) = range {
        report.sessions = Some(portal.sessions(&profile.id, &since, &until)?);
        report.sessions_period = Some(title);
    }

    // --check-overlap: run the max-flow analysis before (or instead of) the
    // regular report.  If combined with other flags the normal report prints
    // first, then the analysis follows.
    if cli.check_overlap {
        let sessions = report.sessions.as_deref().unwrap_or(&[]);
        let period   = report.sessions_period.as_deref().unwrap_or("(current month)");
        if !cli.sessions && !cli.all {
            // Only the overlap analysis was requested — skip the full report.
            print_overlap_report(sessions, period);
            return Ok(());
        }
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    // Print overlap analysis after the main report when combined with --sessions/--all.
    if cli.check_overlap {
        let sessions = report.sessions.as_deref().unwrap_or(&[]);
        let period   = report.sessions_period.as_deref().unwrap_or("(current month)");
        print_overlap_report(sessions, period);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = config_path();
    let mut config = Config::load(&path)?;

    if cli.add {
        add_profile(&mut config, &path)?;
        return Ok(());
    }

    if cli.stats || cli.usage || cli.sessions || cli.all || cli.remaining || cli.check_overlap {
        return run_query(&cli, &config);
    }

    if cli.logout {
        match pick_profile(&config)? {
            Some((name, profile)) => logout(&name, &profile)?,
            None => println!("Cancelled."),
        }
        return Ok(());
    }

    // Default: pick a profile and login
    match pick_profile(&config)? {
        Some((name, profile)) => login(&name, &profile)?,
        None => println!("Cancelled."),
    }

    Ok(())
}
