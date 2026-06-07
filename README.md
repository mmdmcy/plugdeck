# Plugdeck

Plugdeck is a private-first Rust web app for small self-hosted tools. It is
meant to be the one place where you build and use lightweight modules instead
of scattering each tiny tool across a separate repository, service, and port.

It is not a replacement for large apps such as Git forges, password managers,
or media servers. Those should stay as separate services and can be linked from
Plugdeck.

Current modules:

- Notes with channels, messages, and optional image attachments.
- YTP Downloader for YouTube downloads through `yt-dlp`.
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
PLUGDECK_PASSWORD_HASH='$argon2id$...'
PLUGDECK_COOKIE_SECRET=<random hex>
PLUGDECK_YTDLP=yt-dlp
PLUGDECK_MAX_ACTIVE=1
```

Keep those values in an ignored `.env`, `plugdeck.local.toml`, or
`*.local.json` file on your host. Public examples should use placeholders only.

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

## Publishing Safely

Before pushing public changes:

```sh
cargo fmt --check
cargo test
cargo run -- audit-public
```

For local protection, install the Git hooks:

```sh
cargo run -- audit-public --install-hook
```

For host-specific names, domains, or other literal terms that should never be
published, add one term per line to an ignored denylist:

```text
docs/private/audit-denylist.txt
.plugdeck/audit-denylist.txt
```
