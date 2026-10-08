# captive_logger

A CLI tool to manage and automate logins/logouts on captive portals (of IIIT Dharwad).

Built with Rust. Binary: `autologger`.

## Install

```sh
git clone https://github.com/rd6260/captive_logger.git
cd captive_logger
cargo install --path .
```

The `autologger` binary will be available in your `$PATH` (via `~/.cargo/bin`).

## Usage

```sh
autologger             # pick a profile and login
autologger --logout    # pick a profile and logout
autologger --add       # add a new profile
```

> [!NOTE]
> Uses `fzf` for interactive profile selection — make sure it's installed.

## Config

Profiles are stored at `~/.config/captive_logger/config.json`.

Each profile holds a name, username (ID), and password.

## Build

```sh
cargo build --release
# binary at: target/release/autologger
```

## Portal

Hardcoded to `http://172.16.16.16:8090/httpclient.html`. Change `PORTAL_URL` in `src/main.rs` if needed.
