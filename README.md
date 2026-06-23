# Plugdeck

Plugdeck is a private-first Rust web app for small self-hosted tools. It is
meant to be the one place where you build and use lightweight modules instead
of scattering each tiny tool across a separate repository, service, and port.

It is not a replacement for large apps such as Git forges, password managers,
or media servers. Those should stay as separate services and can be linked from
Plugdeck.

Current modules:

- Notes with channels, messages, and optional image attachments.
- Agents with saved Codex conversation browsing, usage status, resets, and file/photo uploads.
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
PLUGDECK_AGENT_DEFAULT_WORKDIR=~
PLUGDECK_AGENT_UPLOAD_DIR=data/agent-uploads
PLUGDECK_AGENT_SLOTS=codex
PLUGDECK_AGENT_CODEX_BIN=codex
PLUGDECK_AGENT_CODEX_ARGS=
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

## Adding Modules

Plugdeck modules are small Rust web apps that share auth, styling, SQLite state,
and the home menu. Add new module wiring in `src/modules.rs`:

- add a `PlugdeckModule` entry with a name, path, stats function, and route
  registration function
- keep module state in generic SQLite tables created from `open_db`
- keep local paths, secrets, service names, and machine-specific settings in
  ignored config files, not tracked source

The existing Notes, Agents, and YTP Downloader modules are the reference
patterns for forms, uploads, background jobs, and home menu stats.

## Publishing Safely

Before pushing public changes:

```sh
cargo fmt --check
cargo test
cargo run -- audit-public
```

For production use, build a release binary and run the service from a versioned
artifact path such as `/var/lib/plugroot/releases/plugdeck/current/plugdeck`
instead of directly from `target/release` inside the Git checkout. Keep the
checkout as source, and let Plugroot's `release-check`/`doctor --strict` catch
dirty trees before restarts.

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
