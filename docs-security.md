# Security Notes

- Bind Plugdeck to a private interface, not `0.0.0.0`.
- Keep `.env`, local TOML, databases, downloads, and logs out of Git.
- Use a password hash in configuration, not a plaintext password.
- Keep large services as links in v1. Do not proxy password managers or Git
  forges through Plugdeck unless that is reviewed separately.
- Downloads run `yt-dlp` directly without a shell and only accept YouTube URLs.
