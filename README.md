# Plugdeck

Plugdeck is a small private Rust web app for personal self-hosted tools. It is
intended to sit behind a private network such as a tailnet and provide one
daily-use site for small built-in modules.

Current modules:

- Notes with channels, messages, and optional image attachments.
- YouTube downloads through `yt-dlp`.
- Links to larger external services.

Plugdeck is not a public internet gateway. Keep it private, use an app password,
and do not commit local config, databases, downloads, or logs.

## Run

```sh
cargo run -- hash-password --stdin
PLUGDECK_PASSWORD_HASH='$argon2id$...' cargo run -- serve
```

Local config can be supplied with environment variables:

```sh
PLUGDECK_BIND=127.0.0.1:8789
PLUGDECK_DB=data/plugdeck.sqlite
PLUGDECK_DOWNLOAD_DIR=data/downloads
PLUGDECK_LINKS_FILE=plugdeck.local.toml
PLUGDECK_PASSWORD_HASH=$argon2id$...
PLUGDECK_COOKIE_SECRET=<random hex>
PLUGDECK_YTDLP=yt-dlp
PLUGDECK_MAX_ACTIVE=1
```

Example links file:

```toml
[[link]]
name = "Forgejo"
url = "http://127.0.0.1:3000"
category = "Code"
description = "Private Git forge."
```

## Import Motehold

```sh
cargo run -- import-motehold /path/to/messages.db
```
