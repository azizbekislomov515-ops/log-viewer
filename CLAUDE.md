You are a senior Linux systems engineer and desktop-application architect. We are building "LogLens": a Linux desktop application that discovers every log source on the machine (systemd services, Docker containers, Docker Compose projects, and plain log files such as Squid, ClamAV, Nginx), separates them per service, and explains in plain human language what is happening in each one.

## Product goals
- Discover automatically: systemd units (journald), Docker containers, Docker Compose projects (grouped by the `com.docker.compose.project` label), and well-known file logs (/var/log/squid, /var/log/clamav, /var/log/nginx, /var/log/auth.log, etc.).
- Show each service's logs in isolation, live-tailing, filterable, searchable.
- Translate raw log lines into plain-language explanations ("Squid denied a request from 10.0.0.5 to facebook.com because of ACL 'blocked_sites'"), with severity, probable cause and suggested next step.
- Per-service "What is happening now" summary: rate of events, error spikes, top clients/domains, last restart, health state.
- Works offline and privately. No log data leaves the machine unless the user explicitly enables the optional AI explainer.
- Never requires running the GUI as root.

## Tech decisions (do not deviate without asking me)
- Language: Python 3.12+
- GUI: PySide6 (Qt 6), model/view architecture with virtualized views (must stay smooth with 1M+ lines)
- Async/IO: asyncio for collectors, bridged to Qt through a thread-safe queue / signals
- Storage: SQLite (WAL mode) with FTS5 for search, plus an in-memory ring buffer for live view
- Docker: official `docker` Python SDK (talk to the Docker socket), fall back to `docker` CLI only if the SDK fails
- journald: `journalctl -o json --follow` subprocess (primary) with optional `systemd.journal` bindings if available
- Explanation engine: declarative YAML rule packs (regex + field extraction + templated explanation) — deterministic, testable, no LLM required
- Tooling: uv or pip + pyproject.toml, ruff, mypy (strict on core), pytest, pytest-qt, pre-commit
- Layout: src/loglens/{core,collectors,parsers,explain,storage,gui,security}/ , rules/ , tests/ , docs/

## Your task right now (Phase 0 only)
1. Do NOT write application code yet.
2. Create `CLAUDE.md` at the repo root containing: product goals, tech decisions, directory layout, coding standards (type hints everywhere, small modules, no global state, docstrings on public APIs, structured logging for the app itself), testing rules, security rules (least privilege, never shell=True with untrusted input, redact secrets, no network by default), the git workflow (one commit per logical step, conventional commits), and the phase roadmap below.
3. Create `docs/ARCHITECTURE.md` with: component diagram in Mermaid, data flow (collector -> normalizer -> parser -> explainer -> storage -> GUI), the core data model (LogSource, LogEntry, Severity, Explanation, ServiceGroup) and the plugin/extension points.
4. Initialize git, pyproject.toml, ruff/mypy/pytest config, .gitignore, pre-commit config, and a minimal `src/loglens/__init__.py` plus one passing smoke test.
5. Finish with a short report: what you created, any decision you want me to confirm, and the exact command to run tests.

## Roadmap (record this in CLAUDE.md)
Phase 1 Core domain model + source discovery
Phase 2 Collectors (journald, Docker, files) + storage
Phase 3 Normalization + parser framework
Phase 4 Explanation engine + rule packs (Squid, ClamAV, Docker/Compose, sshd, Nginx, systemd, kernel)
Phase 5 GUI shell: source tree, live log view, filters, search
Phase 6 GUI insights: explanation panel, summaries, timeline, statistics
Phase 7 Privilege model, secret redaction, hardening
Phase 8 Optional opt-in AI explainer
Phase 9 Packaging, docs, CI, release

Ask me clarifying questions only if something blocks Phase 0. Otherwise proceed.s
