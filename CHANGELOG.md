# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-19

First release.

### Discovery and collection
- Automatic discovery of systemd units, Docker containers, Docker Compose projects
  (grouped by project) and well-known log files (Squid, ClamAV, nginx, auth.log...).
- Collectors for journald (`journalctl -o json`), Docker (SDK, CLI fallback; container
  lifecycle events merged into each container's stream) and files (inotify, rotation,
  truncation). Resume cursors: no gaps or duplicates across restarts.
- Bounded pipeline with backpressure, multiline assembly, per-source ring buffers.

### Parsing and explanations
- Parsers for Squid, ClamAV (incl. 1.4 format), nginx, sshd, dockerd, JSON lines,
  logfmt, RFC 3164/5424 syslog and ISO text; UTC timestamps; severity inference.
- Explanation engine with YAML rule packs: 224 rules in 8 packs, each with examples and
  counter-examples run in CI. Sandboxed templates; suggested commands are shell-quoted.
- Per-service insights: rates, error spikes, top values, restarts, health; overview cards
  defined by the packs.

### Desktop app
- Source tree, tabs, live follow, severity/time filters, full-text and regex search,
  smooth with millions of rows; light and dark themes.
- Explain panel, inline explanations, service Overview with timeline, Compose dashboard,
  desktop notifications, rule editor ("Create rule from this line"), export (text, JSON,
  CSV) and incident reports.
- First-run guide: what LogLens can read and how to fix what it cannot, what to monitor,
  demos.

### Security and privacy
- Secrets (URL passwords, Authorization headers, AWS/GitHub/Stripe/Slack tokens, JWTs,
  private keys, cookies, session ids, `password=` values, Luhn-valid cards, high-entropy
  tokens, custom patterns) removed before storage and again on export; optional local
  reveal vault.
- Hostile-text handling everywhere text is rendered; ReDoS timeouts for untrusted
  regexes; template whitelist; owner-only database; optional SQLCipher; Clear all data;
  memory and disk budgets with a banner.
- Never runs as root; exact fixes for missing access; optional `loglens-helper`
  read-only, socket-activated, polkit-authorized service.
- Threat model, fuzz tests, bandit and pip-audit in CI.

### Packaging
- Self-contained `.deb` for Debian 12+, Ubuntu 22.04+, Kali, Parrot (bundled Python 3.12
  and Qt), AppImage, Flatpak manifest draft, AppStream metadata and icon.
