# Roadmap

What comes after 0.1.0, roughly in order. Plans change with feedback; open an issue to
discuss any of these.

## Next (0.2)

- **Dashboard** (Phase 10): a machine-wide "what is happening now" view across all
  services. It shows health, error spikes, restarts and detections at a glance, with
  drill-down into overviews and logs.
- **Optional AI explainer** (the planned Phase 8, not in 0.1.0): explain lines no rule
  covers. It stays off by default, is opt-in per request, gets only redacted text, and
  works with a local model.
- **Format detection by content**: today a container gets the nginx/Squid/ClamAV parser
  by its image or service name.

## Later

- **Plugin API**: a stable, documented interface for third-party collectors, parsers and
  rule packs, with versioning and a manifest. Today these extension points are internal
  (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- **Remote hosts over SSH**: watch servers without installing anything on them. Stream
  `journalctl`, `docker logs` and files over SSH; per-host source trees; the same
  redaction before anything is stored locally.
- **Kubernetes pod logs**: discover namespaces, deployments and pods from the current
  kubeconfig context; group pods like Compose projects; follow restarts and OOM kills.
- **Windows and WSL**: WSL distributions first (journald and Docker inside WSL), then the
  Windows Event Log as a source.
- **More rule packs**: PostgreSQL, MySQL/MariaDB, Apache, Postfix, fail2ban, UFW,
  Kubernetes components, Traefik/Caddy.
- **Native journal reading** without `journalctl`, which would also let a sandboxed
  (Flatpak) build read the journal.
- **Helper**: Docker access through the helper with an allowlist (no `docker` group
  needed), and packages for Fedora/Arch.
