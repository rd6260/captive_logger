# captive_logger

A CLI tool to manage and automate logins/logouts on captive portals (of IIIT Dharwad), and to check your account's data usage and session history from the college Sophos user portal.

Built with Rust. Binary: `autologger`.

## Features

- Multiple saved profiles, picked interactively with `fzf` or directly by name/ID
- One-command login and logout on the captive portal
- Account statistics: policy, usage and daily cycle usage
- A compact daily-cycle summary with the remaining quota
- Session history for any month
- `--json` output for every statistics command, so it is easy to script

## Install

```sh
git clone https://github.com/rd6260/captive_logger.git
cd captive_logger
cargo install --path .
```

The `autologger` binary will be available in your `$PATH` (via `~/.cargo/bin`).

> [!NOTE]
> Uses `fzf` for interactive profile selection. Make sure it is installed.

## Quick start

```sh
autologger --add          # save a profile once
autologger                # login (pick the profile with fzf)
autologger --usage        # how much quota is left today?
autologger --logout       # logout when done
```

## Usage

```
autologger [OPTIONS]
```

### Login and logout

| Command | Description |
|---|---|
| `autologger` | Pick a profile with `fzf` and log in |
| `autologger -l`, `--logout` | Pick a profile with `fzf` and log out |
| `autologger -a`, `--add` | Add a new profile interactively (prompts for name, ID and a masked password) |

### Statistics

These flags log in to the Sophos user portal with the chosen profile and fetch data from it. They do not log you in or out of the captive portal.

| Flag | Description |
|---|---|
| `-s`, `--stats` | Policy information, usage information and current daily cycle usage |
| `-u`, `--usage` | Short daily-cycle summary: **Resource**, **Up to last session**, **Total** and **Remaining** (in bold) |
| `-S`, `--sessions` | Session list (IP, start, stop, used time, download, upload, total) |
| `-A`, `--all` | Everything: `--stats` plus `--sessions` |

Flags can be combined, for example `autologger -s -u`.

### Modifiers

| Flag | Description |
|---|---|
| `-p`, `--profile <NAME_OR_ID>` | Use this profile instead of opening `fzf`. Matches the profile name or the ID, **case-insensitively** |
| `-m`, `--month <YYYY-MM>` | Month for the session list. Defaults to the current month. Only affects `--sessions` and `--all` |
| `-j`, `--json` | Print JSON instead of tables |

### Examples

```sh
# Pick the profile with fzf, show everything
autologger --all

# Daily quota summary for a specific profile (name or ID, any case)
autologger --usage --profile 24bds051
autologger -u -p MyProfile

# Sessions for September 2026
autologger --sessions --month 2026-09

# Full statistics as JSON, piped into jq
autologger --all --json | jq '.cycle_usage'

# Session download totals for the current month
autologger -S -j -p 24bds051 | jq '[.sessions[].download_bytes] | add'
```

### What each statistics flag shows

**`--stats`** prints three tables:

1. **Policy information**: your account's policy details as shown on the portal
2. **Usage information**: overall usage for the account
3. **Current daily cycle usage**: usage for the current daily cycle, with columns Resource, Allotted, Up to last session, Current session, Total and Remaining

**`--usage`** prints only the *Current daily cycle usage* table, trimmed to Resource, Up to last session, Total and Remaining. The Remaining column is bold. Rows with no remaining value show a dim `-`.

**`--sessions`** prints one row per session in the selected month, newest first. Download, upload and total are shown in human-readable units (B, KB, MB, GB, TB).

**`--all`** prints the policy, usage, daily cycle usage and sessions tables together.

### JSON output

With `--json`, only JSON is written to stdout. Status messages go to stderr, so piping into other tools is safe. Keys are only present when the matching flag was used. Your password is never included.

```jsonc
{
  "profile": { "name": "MyProfile", "id": "24bds051" },

  // --stats / --all
  "policy": { "<label>": "<value>" },
  "usage": [
    {
      "resource": "...",
      "allotted": "...",
      "up_to_last_session": "...",
      "current_session": "...",
      "total": "...",
      "remaining": "..."
    }
  ],
  "cycle_usage": [ /* same shape as "usage" */ ],

  // --usage
  "daily_cycle_summary": [
    { "resource": "...", "up_to_last_session": "...", "total": "...", "remaining": "..." }
  ],

  // --sessions / --all
  "sessions_period": "September 2026",
  "sessions": [
    {
      "ip": "...",
      "started": "...",
      "stopped": "...",
      "used_time": "...",
      "download_bytes": 0,
      "upload_bytes": 0,
      "total_bytes": 0
    }
  ]
}
```

The `usage`, `cycle_usage`, `daily_cycle_summary` values are strings exactly as the portal displays them (for example with units). Session sizes in JSON are raw bytes.

### Flag precedence

If several modes are given, the first match in this order wins:

1. `--add`
2. Any statistics flag (`--stats`, `--usage`, `--sessions`, `--all`)
3. `--logout`
4. Otherwise: login

## Config

Profiles are stored at `~/.config/captive_logger/config.json`.

Each profile holds a name, username (ID), and password.

```json
{
  "profiles": {
    "MyProfile": {
      "id": "24bds051",
      "password": "your-password"
    }
  }
}
```

> [!WARNING]
> Passwords are stored in plain text. Keep the file private, for example with `chmod 600 ~/.config/captive_logger/config.json`.

## Build

```sh
cargo build --release
# binary at: target/release/autologger
```

## Portals

| Purpose | Address | Constant in `src/main.rs` |
|---|---|---|
| Login / logout | `http://172.16.16.16:8090/httpclient.html` | `PORTAL_URL` |
| Statistics / sessions | `https://172.16.16.16:4443/userportal/...` | `HOST`, `LOGIN_PAGE`, `ACCOUNT_PAGE`, `ACCOUNT_STATUS`, `CONTROLLER` |

Change these constants if your network uses different addresses.

The user portal uses a self-signed certificate, so certificate verification is disabled for requests to it only.

## Troubleshooting

| Message | Likely cause |
|---|---|
| `Failed to spawn fzf — is it installed?` | `fzf` is missing. Install it, or pass `--profile` to skip it |
| `No profiles found. Add one with --add.` | No profiles saved yet |
| `No profile with name or ID '...'` | Typo in `--profile`. Matching is case-insensitive but must otherwise be exact |
| `--month must look like YYYY-MM` | Wrong month format, use for example `2026-09` |
| `User portal login failed: ...` | Wrong credentials, or the portal rejected the login |
| `CSRF token not found on the account page ...` | The portal did not return the account page. The message includes the HTTP status and the start of the page to help diagnose it |
| `Session expired` | The portal dropped the session mid-request. Run the command again |
| `Could not parse AccountStatus page (layout changed?)` | The portal's page layout differs from what the parser expects |
