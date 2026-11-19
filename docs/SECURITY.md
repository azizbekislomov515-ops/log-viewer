# Security and privileges

LogLens never needs root, and the GUI refuses to run as root. Read
[THREAT_MODEL.md](THREAT_MODEL.md) for what is protected and how.

## Giving your user read access

The **Issues** panel (status bar, or ⋯ > Discovery issues) lists every source you cannot
read with the exact command to fix it. In short:

| To read | Do | Notes |
|---|---|---|
| System journal (all services) | `sudo usermod -aG systemd-journal $USER`, then log out and back in | Read-only. On Debian/Ubuntu `adm` also works; on some distros `wheel`. |
| A file in /var/log | `sudo setfacl -m u:$USER:r FILE` and `sudo setfacl -m u:$USER:rx DIR && sudo setfacl -d -m u:$USER:r DIR` | The default ACL on the directory keeps access after log rotation. Or join the file's group (e.g. `adm`). |
| Docker containers | `sudo usermod -aG docker $USER` | **Root-equivalent:** anyone in `docker` can start a privileged container. Prefer rootless Docker (`dockerd-rootless-setuptool.sh install`, then `export DOCKER_HOST=unix:///run/user/$UID/docker.sock`). |

## The optional helper (`loglens-helper`)

When you cannot (or do not want to) add your user to those groups, an administrator can
install the helper: a small read-only daemon that streams **only the sources listed in
`/etc/loglens/helper.toml`** to authorized users over a Unix socket. LogLens uses it
automatically for journal and file sources you cannot read directly when
`/run/loglens-helper.sock` exists.

* Runs as its own `loglens-helper` user (in `systemd-journal` and `adm`), never root,
  with no capabilities, no network and a syscall filter.
* Started on demand by systemd (socket activation).
* Authorizes every connection by the kernel-reported peer uid/pid: root, members of
  `allow_groups`, or polkit (`org.loglens.helper.read-logs`, an administrator password
  remembered for a while).
* Never follows symlinks; only regular files matching the configured patterns.
* Protocol: newline-delimited JSON, version 1, 64 KiB per message (see
  `src/loglens/helper/protocol.py`).

Install (as root, from a checkout; packages will do this for you):

```sh
install -m 0644 packaging/helper/loglens-helper.sysusers.conf /usr/lib/sysusers.d/loglens-helper.conf
systemd-sysusers
install -d -m 0755 /etc/loglens
install -m 0644 -o root -g root packaging/helper/helper.toml /etc/loglens/helper.toml   # edit it
install -m 0644 packaging/helper/org.loglens.helper.policy /usr/share/polkit-1/actions/
install -m 0644 packaging/helper/loglens-helper.{socket,service} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now loglens-helper.socket
```

`loglens-helper` must be on `/usr/bin` (`pip install` into a system location or a
distro package). If a file is readable only by its service's group (Squid logs are
often `proxy:proxy 0640`), add an ACL for `loglens-helper` or a sysusers `m` line for
that group.

## Secrets in logs

Before anything is stored, LogLens replaces secrets with `[REDACTED:kind]`: passwords in
URLs, `Authorization`/Bearer/Basic credentials, AWS, GitHub, Stripe and Slack tokens,
JWTs, private key blocks, cookies and session ids, `password=` / `token=` / `api_key=`
values, Luhn-valid card numbers and long random-looking tokens. Exports and incident
reports are redacted again.

Settings > Secrets:

* **Remove … before storing**: on by default. Turning it off stores logs as they are.
* **Keep originals on this computer so I can reveal them**: off by default. When on,
  the originals are kept in `~/.local/share/loglens/vault/` (owner-only) and the markers
  become `[REDACTED:kind:token]`. Exports and reports never include originals.
* **Also remove matches of**: your own regexes (one per line, checked when saving, run
  with a 5 ms timeout per line).

## Stored data

* Database: `~/.local/share/loglens/loglens.db` (plus `-wal`/`-shm`), owner-only
  (0600, directory 0700).
* **Encryption at rest (optional):** install `sqlcipher3` (and libsqlcipher), then set
  `LOGLENS_DB_KEY` in the environment LogLens starts from. Without the package LogLens
  refuses to start with that variable set rather than silently storing plaintext. An
  existing plaintext database is not converted: clear it first. Otherwise rely on
  full-disk encryption.
* **⋯ > Clear all data…** deletes every stored entry (deleted pages zeroed, file rebuilt,
  WAL truncated) and the reveal vault. Settings and rules are kept.
* Retention (Settings): entries older than N days, at most N per source, and a disk
  budget that deletes the oldest entries first.

## Resource limits

Settings > Memory budget / Disk budget / Follow at most. When a limit is hit LogLens
keeps working and says what it dropped in a banner above the logs:

* **Memory:** caches are cleared and each view keeps only its newest 50 000 loaded rows
  (everything is still in the database).
* **Disk:** the oldest entries (all sources) are deleted until the data fits.
* **Collectors:** sources beyond the limit are not followed.

## Checks

```sh
uv run pytest                                # includes fuzz and acceptance tests
uv run bandit -c pyproject.toml -r src       # security lint (also in pre-commit)
uv run pip-audit                             # known-vulnerable dependencies (network)
```
