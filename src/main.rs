use anyhow::{Context, Result};
use clap::Parser;
use console::Term;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PORTAL_URL: &str = "http://172.16.16.16:8090/httpclient.html";

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

#[derive(Parser)]
#[command(name = "captive_logger", about = "Captive portal login manager")]
struct Cli {
    /// Logout from the captive portal (picks profile via fzf)
    #[arg(short, long)]
    logout: bool,

    /// Add a new profile interactively
    #[arg(short, long)]
    add: bool,
}

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
                    // Move back one, overwrite with space, move back again
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = config_path();
    let mut config = Config::load(&path)?;

    if cli.add {
        add_profile(&mut config, &path)?;
        return Ok(());
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
