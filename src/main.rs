use anyhow::{bail, Context, Result};
use chrono::{Datelike, Local, NaiveDate};
use clap::Parser;
use comfy_table::{presets::UTF8_BORDERS_ONLY, Attribute, Cell, CellAlignment, Table};
use console::{style, Term};
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
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

    /// Profile name or ID to use for the flags above (opens fzf if omitted)
    #[arg(short, long, value_name = "NAME_OR_ID")]
    profile: Option<String>,

    /// Month for the session list, YYYY-MM (default: current month)
    #[arg(short, long, value_name = "YYYY-MM")]
    month: Option<String>,

    /// Output as JSON instead of tables
    #[arg(short, long)]
    json: bool,
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
    bail!("No profile with name or ID '{}'", wanted);
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

fn print_policy(policy: &Map<String, Value>) {
    print_title("Policy information");
    let mut t = new_table();
    for (k, v) in policy {
        t.add_row(vec![
            Cell::new(k).add_attribute(Attribute::Bold),
            Cell::new(v.as_str().unwrap_or("")),
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
            r.resource.as_str(),
            r.allotted.as_str(),
            r.up_to_last_session.as_str(),
            r.current_session.as_str(),
            r.total.as_str(),
            r.remaining.as_str(),
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
        eprintln!("Cancelled.");
        return Ok(());
    };

    let want_stats = cli.stats || cli.all;
    let want_sessions = cli.sessions || cli.all;
    let want_summary = cli.usage;

    // Validate --month before hitting the network
    let range = if want_sessions {
        Some(month_range(cli.month.as_deref())?)
    } else {
        None
    };

    eprintln!("Connecting to user portal as {} ({})…", name, profile.id);
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

    if want_stats || want_summary {
        let status = portal.account_status()?;
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

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
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

    if cli.stats || cli.usage || cli.sessions || cli.all {
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
