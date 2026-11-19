# Troubleshooting LogLens

Problems are grouped by what you see. Each section gives the cause and the commands that
fix it. Most messages quoted here appear in the **Discovery issues** panel (the issues
button in the status bar, or **⋯ > Discovery issues**) and in the output of
`loglens-cli sources`, which runs discovery once and prints every issue with its fix:

```sh
loglens-cli sources
```

After you change a group membership, log out of your desktop session and log back in.
Group changes do not reach programs that are already running. Then check with `id` and
use **⋯ > Look for new sources now** in LogLens.

Contents:

- [No system services, or only my own journal](#no-system-services-or-only-my-own-journal)
- [Docker: "permission denied"](#docker-permission-denied)
- [Docker: "Cannot connect to the Docker daemon"](#docker-cannot-connect-to-the-docker-daemon)
- [Other discovery messages](#other-discovery-messages)
- [A log file "exists but is not readable"](#a-log-file-exists-but-is-not-readable)
- [The helper is not used or reports errors](#the-helper-is-not-used-or-reports-errors)
- [LogLens does not start](#loglens-does-not-start)
- [`LOGLENS_DB_KEY` errors](#loglens_db_key-errors)
- [Database errors: locked, disk full, WAL, schema](#database-errors-locked-disk-full-wal-schema)
- [Banners above the logs](#banners-above-the-logs)
- [A line has no explanation](#a-line-has-no-explanation)
- [Notifications do not appear](#notifications-do-not-appear)
- [High CPU use](#high-cpu-use)
- [Resetting LogLens](#resetting-loglens)
- [Collecting information for a bug report](#collecting-information-for-a-bug-report)

## No system services, or only my own journal

**You see:** *You can see only your own user's journal; system service logs are hidden.*
System services are listed, but their tabs stay empty.

**Cause:** Only members of certain groups may read the system journal. LogLens accepts
`systemd-journal`, `adm` or `wheel`. Without one of them, `journalctl` shows you only
your own user's entries.

**Fix:** Add yourself to `systemd-journal` (read-only access to the journal; on
Debian and Ubuntu `adm` also works):

```sh
sudo usermod -aG systemd-journal $USER
```

Log out and back in, then check that the group is active and that the journal is
readable without `sudo`:

```sh
id -nG | tr ' ' '\n' | grep -xE 'systemd-journal|adm|wheel'
journalctl -u ssh.service -n 5 --no-pager
```

If `id` still does not list the group after logging back in, reboot. LogLens checks your
groups when it starts, so restart it afterwards.

If you cannot change your groups, an administrator can enable the read-only helper
instead (see [the helper section](#the-helper-is-not-used-or-reports-errors)).

## Docker: "permission denied"

**You see:** *Docker socket not accessible: permission denied.*

**Cause:** Your user may not open the Docker socket (`/var/run/docker.sock`, owned by
`root:docker`).

**Fix, option 1: the `docker` group.**

```sh
sudo usermod -aG docker $USER
```

Log out and back in, then check with `id -nG` and `docker ps`. Be aware that membership
in `docker` is **equivalent to root**: anyone in it can start a privileged container and
take over the machine. Use it only for accounts that are trusted with root anyway.

**Fix, option 2: rootless Docker.** Docker runs as your user and LogLens talks to your
own socket. Set it up as your user (the setup tool comes with Docker's
`docker-ce-rootless-extras` package; Docker's documentation on rootless mode has the
details):

```sh
dockerd-rootless-setuptool.sh install
export DOCKER_HOST=unix:///run/user/$UID/docker.sock
```

LogLens reads `DOCKER_HOST` from the environment it was started from. Put the `export`
line in `~/.profile` and log out and back in, so that LogLens started from the menu sees
it too.

**The helper does not help here.** `loglens-helper` serves only journal and file sources;
it never proxies Docker.

## Docker: "Cannot connect to the Docker daemon"

**You see:** *Cannot connect to the Docker daemon.*

**Cause:** Docker is not running, or `DOCKER_HOST` points to a socket where nothing
listens.

**Fix:**

```sh
systemctl status docker            # system Docker
sudo systemctl enable --now docker
systemctl --user status docker     # rootless Docker
systemctl --user enable --now docker
echo "$DOCKER_HOST"                # empty means the default /var/run/docker.sock
```

If `docker ps` works in a terminal but LogLens cannot connect, your `docker` command may
use a Docker context with a different socket. Show it and set `DOCKER_HOST` to that
value (in `~/.profile`, then log out and back in):

```sh
docker context inspect --format '{{.Endpoints.docker.Host}}'
```

## Other discovery messages

| Message | Meaning and fix |
|---|---|
| *Docker does not appear to be installed.* | Neither the Docker API nor the `docker` command is available. Nothing to fix if you do not use Docker. |
| *docker inspect failed: …* | Containers were listed with the `docker` command but inspecting them failed. Run `docker inspect $(docker ps -aq)` to see the error. |
| *systemctl was not found; systemd services cannot be listed.* | The machine does not use systemd (or `systemctl` is not on the `PATH`). File and Docker sources still work. |
| *systemctl failed: …* | `systemctl list-units` returned an error. Run `systemctl list-units --type=service --all` to see it. |
| *Reading SOURCE stopped: …* | A source that was being read failed. LogLens keeps retrying. Check that the unit, container or file still exists and is readable. Helper errors also appear this way (see below). |
| An error about `file_sources.yaml` | The built-in list of log files is damaged. Reinstall the package: `sudo apt install --reinstall ./loglens_0.1.0_amd64.deb`. |

## A log file "exists but is not readable"

**You see:** *PATH exists but is not readable by your user.* The file is listed under
*Log files*, but its tab stays empty.

**Cause:** Files in `/var/log` are usually readable only by root and a group such as
`adm` or the service's own group (Squid logs are often `proxy:proxy`, mode 0640).

**Fix, option 1: join the file's group.** The issue's "How to fix" line names the group.
For example, for `adm`:

```sh
ls -l /var/log/auth.log            # shows owner and group
sudo usermod -aG adm $USER         # then log out and back in
```

**Fix, option 2: an ACL for just this log.** Give your user read access to the file,
access to its folder, and a *default* ACL on the folder so that files created by log
rotation get the same access:

```sh
sudo apt install acl               # provides setfacl/getfacl
sudo setfacl -m u:$USER:r /var/log/squid/access.log
sudo setfacl -m u:$USER:rx /var/log/squid
sudo setfacl -d -m u:$USER:r /var/log/squid
getfacl /var/log/squid/access.log  # check; check again after the next rotation
```

ACL changes take effect at once, without logging out. Use **⋯ > Look for new sources
now**, then open the file again.

## The helper is not used or reports errors

`loglens-helper` is an optional read-only service that streams the units and files listed
in `/etc/loglens/helper.toml` to authorized users. LogLens uses it automatically, but only
when both are true:

- the socket `/run/loglens-helper.sock` exists, and
- your account cannot read the source itself (for system services: you are not in
  `systemd-journal`, `adm` or `wheel`; for files: the file is not readable by you).

It never handles Docker. More background: [SECURITY.md](SECURITY.md#the-optional-helper-loglens-helper).

### Is it running?

The package installs the helper but leaves it disabled. Check and enable it:

```sh
systemctl status loglens-helper.socket
ls -l /run/loglens-helper.sock
sudo systemctl enable --now loglens-helper.socket
```

The service itself starts the first time LogLens connects. Its own log:

```sh
sudo journalctl -u loglens-helper.service -n 50 --no-pager
```

The helper reads its configuration only when it starts. After editing
`/etc/loglens/helper.toml`, restart it:

```sh
sudo systemctl restart loglens-helper.service
```

### It refuses to start

The helper exits with an error in its journal when the configuration is unsafe or
invalid:

| Error | Fix |
|---|---|
| *… must be owned by root and not group/world-writable* | `sudo chown root:root /etc/loglens/helper.toml && sudo chmod 644 /etc/loglens/helper.toml` |
| *… unknown keys […]* | Only `units`, `files`, `allow_groups`, `polkit` and `max_clients` are allowed. |
| *… 'units' (or 'files', 'allow_groups') must be a list of strings* | Write them as `["a", "b"]`. |
| *… 'files' patterns must be absolute paths* | Start each pattern with `/`, e.g. `"/var/log/squid/*.log"`. |
| *… 'polkit' must be a boolean, 'max_clients' 1..1024* | `polkit = true` or `false`; `max_clients` between 1 and 1024. |
| *refusing to run as root* | Do not run `loglens-helper` by hand as root. Use the systemd units, which run it as the `loglens-helper` user. |

### Who is allowed

Each connection is allowed when the user is root, is a member of a group listed in
`allow_groups`, or, when `polkit = true`, passes a polkit check (an administrator password
prompt; the answer is remembered for a while).

The default `allow_groups = ["loglens"]` names a group the package creates. To let a
user in without a password prompt:

```sh
sudo usermod -aG loglens $USER     # then log out and back in
```

The polkit prompt needs a polkit authentication agent in your desktop session (all
major desktops have one) and `pkcheck` (package `polkitd`, or `policykit-1` on older
releases). Without either, or when the prompt is cancelled or not answered within two
minutes, the connection is refused as `unauthorized`.

### Error codes

Helper errors appear in the Discovery issues panel as
*Reading SOURCE stopped: helper refused (CODE): MESSAGE*.

| Code | Meaning | Fix |
|---|---|---|
| `unauthorized` | *uid N may not read logs*: not root, not in `allow_groups`, and polkit said no (or no prompt could be shown). | Join an allowed group, or answer the polkit prompt. |
| `not_allowed` | *this source is not in the helper's allowlist*: the unit is not in `units`, or the file does not match a `files` pattern, is not a regular file, or is reached through a symlink. *unsupported source kind*: something other than a unit or file was requested. | Add the unit or the real file path to `/etc/loglens/helper.toml` and restart the helper. If you are not in `systemd-journal`, every system service goes through the helper, so services missing from `units` fail this way. |
| `busy` | *too many clients*: more streams at once than `max_clients` (default 16). Every source read through the helper uses one connection. | Raise `max_clients`, or follow fewer sources (unpin, close tabs). |
| `bad_request` | The request was malformed, or none arrived within 10 seconds. | Should not happen with matching versions. Check that `/usr/bin/loglens` and `/usr/bin/loglens-helper` come from the same package. |
| `too_large` | A message was bigger than 64 KiB. | As for `bad_request`. |
| `unsupported_version` | The client and helper speak different protocol versions. | Make sure both come from the same LogLens version. |
| `failed` | An internal error in the helper. | See `sudo journalctl -u loglens-helper.service`. |

Other helper messages: *helper closed the connection*, *helper sent an oversized
message*, *helper protocol error: …* (check the helper's journal), and *helper: …*, which
is the helper reporting that its own reading of the source failed; it keeps retrying.

## LogLens does not start

### "refusing to run the GUI as root"

```text
loglens: refusing to run the GUI as root: it parses hostile log text and needs only
read access. ...
```

LogLens exits with status 2 when started as root (for example with `sudo loglens`).
This is deliberate. Start it as your normal user and give that user read access as
described above.

### Qt platform plugin errors

You see something like:

```text
qt.qpa.plugin: From 6.5.0, xcb-cursor0 or libxcb-cursor0 is needed to load the Qt xcb platform plugin.
qt.qpa.plugin: Could not load the Qt platform plugin "xcb" in "" even though it was found.
This application failed to start because no Qt platform plugin could be initialized.
```

**Cause:** A system library that Qt needs is missing. This happens when the package was
installed with `dpkg -i`, which does not install dependencies.

**Fix:** Let apt install the missing dependencies, or install the usual ones directly:

```sh
sudo apt -f install
sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 \
  libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xfixes0 \
  libxcb-xkb1 libegl1 libgl1 libfontconfig1 libdbus-1-3
```

To see exactly which library is missing:

```sh
ldd /opt/loglens/python/lib/python3.12/site-packages/PySide6/Qt/plugins/platforms/libqxcb.so | grep 'not found'
QT_DEBUG_PLUGINS=1 loglens 2>&1 | grep -iE 'cannot load|not found'
```

### Wayland or X11

The package contains both the X11 (`xcb`) and the Wayland platform plugins. Qt picks one
for your session (`echo $XDG_SESSION_TYPE` shows which session you have). If the window
fails to appear, flickers, or looks wrong, try the other one:

```sh
QT_QPA_PLATFORM=xcb loglens        # X11 (under Wayland this uses XWayland)
QT_QPA_PLATFORM=wayland loglens
```

To make it permanent for the menu entry, copy the desktop file and change its `Exec`
line:

```sh
cp /usr/share/applications/org.loglens.LogLens.desktop ~/.local/share/applications/
sed -i 's|^Exec=loglens|Exec=env QT_QPA_PLATFORM=xcb loglens|' \
  ~/.local/share/applications/org.loglens.LogLens.desktop
```

### The window opens but stays empty

If the status bar shows *Background service stopped: …*, the part of LogLens that
discovers and reads logs failed to start, usually because the database could not be
opened. The text after the colon says why; see the next two sections.

## `LOGLENS_DB_KEY` errors

`LOGLENS_DB_KEY` asks LogLens to encrypt its database with SQLCipher. The `.deb` does not
include the `sqlcipher3` module, so with the package this variable must not be set.

| Message | Cause and fix |
|---|---|
| *LOGLENS_DB_KEY is set but SQLCipher is not installed: install the 'sqlcipher3' package (and libsqlcipher), or unset it to store logs unencrypted* | The variable is set, but encryption is not available. LogLens refuses to continue rather than store logs unencrypted. Unset the variable (see below). For encryption at rest with the package, use full-disk encryption. |
| *cannot open the encrypted database (wrong key?): …* | The key is wrong, or the existing database was created without encryption (an unencrypted database is never converted). Use the right key, or move the old database aside. |
| *file is not a database* | Usually an encrypted database opened without the key (or a damaged file). Set the right key, or move the database aside. |

Find where the variable is set and remove it, then log out and back in:

```sh
env | grep LOGLENS_DB_KEY
grep -rs LOGLENS_DB_KEY ~/.profile ~/.bashrc ~/.zshrc ~/.config/environment.d/ /etc/environment
```

To move the database aside (LogLens creates a new, empty one):

```sh
mv ~/.local/share/loglens/loglens.db ~/.local/share/loglens/loglens.db.old
rm -f ~/.local/share/loglens/loglens.db-wal ~/.local/share/loglens/loglens.db-shm
```

In the GUI these messages appear in the status bar as *Background service stopped: …*.
`loglens-cli` prints `loglens-cli: error: …` and exits with status 2.

## Database errors: locked, disk full, WAL, schema

### "database is locked"

Another process kept the database busy for more than 5 seconds. This happens when two
programs write the same database, for example a second LogLens window or
`loglens-cli collect` running next to the app. See what is running:

```sh
pgrep -af loglens
```

Close the extra copy, or give `loglens-cli collect` its own database with `--db`.

### Disk full

When the disk is full, new entries still appear in open tabs, but they are not stored:
the *stored* count in the status bar stops growing, and they are gone after a restart.
Started with `loglens -v`, LogLens prints *storage write failed; delivering batch live
only*. Check and free space:

```sh
df -h ~/.local/share/loglens
du -sh ~/.local/share/loglens
```

To make LogLens use less space, lower *Disk budget*, *Keep logs for* or *Keep at most
(per source)* in Settings (they apply after a restart), or use **⋯ > Clear all data…**.

### "cannot enable WAL mode on PATH"

SQLite cannot use its write-ahead log on the filesystem that holds the database, which
can happen on network filesystems. Keep the database on a local disk:

```sh
loglens --db /path/on/local/disk/loglens.db
```

(or set `XDG_DATA_HOME` to a local directory).

### "database schema vN is newer than this LogLens (vM)"

The database was written by a newer LogLens, and you are now running an older one.
Install the newer version again, or move the database aside as shown above.

## Banners above the logs

A banner across the top of the log area means a resource limit was reached. LogLens keeps
working. The limits are the *Memory budget*, *Disk budget* and *Follow at most* fields at
the bottom of Settings (the banners name the field: "Settings: Disk budget", "Settings: Follow at most"). Changes to them apply
after a restart.

| Banner | What happened | What to do |
|---|---|---|
| *Disk budget reached: the oldest N entries were deleted to stay under M MB* | Stored entries exceeded the disk budget, so the oldest, across all sources, were deleted. | Raise *Disk budget*, or keep less: lower *Keep logs for*, hide noisy sources (*Hide sources matching*), unpin sources you do not need. |
| *Memory budget reached (X of Y MB): caches cleared and the oldest N loaded rows unloaded…* | LogLens used more memory than the budget. Each tab kept its newest 50,000 loaded rows. Nothing was deleted from the database. | Reopen the tab or search to see older rows. Close tabs you do not need, or raise *Memory budget*. |
| *Collector limit reached: N source(s) are not followed (limit M…)* | More sources should be read than *Follow at most* allows; the extra ones are not read. | Unpin sources or close tabs, or raise *Follow at most*. |

A banner saying *Paused. N new entries are waiting.* belongs to one tab: press **Ctrl+P**
to resume. *Loading stored entries…* goes away by itself.

## A line has no explanation

LogLens explains a line only when a rule in a rule pack recognises it; it never guesses.
The Explain panel then says that no rule explains the line. Common reasons:

- **No rule exists for it yet.** Use **Create rule from this line…** in the Explain
  panel, or write one by hand: [WRITING_RULES.md](WRITING_RULES.md).
- **The container's format was not recognised.** LogLens picks the nginx, Squid or ClamAV
  parser for a container by its image or service name. A container with an unrelated
  name is read as generic text, and the specific rules may not match.
- **A rule only sees the first 4,096 characters** of a very long line.
- **Your rule has the same ID as an earlier one.** When two packs use the same rule ID,
  the first loaded wins and the later one is skipped. Built-in packs load first, then
  `~/.config/loglens/rules`, then the extra folders from Settings.
- **Your pack has an error.** A bad rule is skipped, and a bad pack header skips the
  whole pack. Check your packs:

```sh
loglens-cli rules lint --rules ~/.config/loglens/rules
loglens-cli rules test --rules ~/.config/loglens/rules
```

To test lines outside the app, save them to a file and run:

```sh
loglens-cli explain --file sample.log --source squid       # a pack name, or a source ID
```

Started with `loglens -v`, LogLens also prints *rule pack problem: …* for each problem it
found while loading rules.

## Notifications do not appear

- The status bar says *Desktop notifications need notify-send (package libnotify-bin).*
  Install it: `sudo apt install libnotify-bin`.
- Only followed sources notify: open a tab for the source, or pin it (right-click >
  **Pin (follow in background)**).
- Check the conditions under *Desktop notifications for* in Settings, and that the source
  is not muted (right-click shows **Unmute notifications** when it is; Settings lists
  muted IDs under *Never notify for*).
- Rate limits hold some back: one per source and condition per minute, five per minute
  in total. The next notification counts the ones held back.
- Test your desktop's notifications: `notify-send test "hello"`.

## High CPU use

LogLens does work for every line it reads, so CPU use follows the number of lines per
second in the status bar.

- Press **Ctrl+Alt+D** for the debug overlay: frame time, rows per second, pages per
  second, drain time and backlog.
- Read fewer sources: close tabs, unpin sources you do not need (pinned sources are read
  even without a tab), hide noisy ones with *Hide sources matching*, or lower *Follow at
  most*.
- A regular-expression search (**.\***) over a very large tab uses CPU until it finishes;
  it stops by itself after 10 seconds.
- Discovery runs `systemctl` and asks Docker for containers every 30 seconds. On a busy
  machine, raise *Look for new sources every* in Settings.

If CPU stays high with nothing followed, collect the information below and report it.

## Resetting LogLens

Quit LogLens first. Then delete what you want to reset:

| To reset | Delete |
|---|---|
| Open tabs and their filters | `~/.local/state/loglens/session.json` |
| All settings (the first-run guide shows again) | `~/.config/loglens/config.toml` |
| All stored logs and the reveal vault | `~/.local/share/loglens/` (or use **⋯ > Clear all data…** while running) |
| Rules you wrote | `~/.config/loglens/rules/` (back it up first) |

Everything at once, keeping a copy of your rules:

```sh
cp -r ~/.config/loglens/rules ~/loglens-rules-backup 2>/dev/null
rm -rf ~/.config/loglens ~/.local/share/loglens ~/.local/state/loglens
```

To see the first-run guide again without resetting anything, use **⋯ > Getting
started…**.

## Collecting information for a bug report

Run LogLens from a terminal with diagnostics on, reproduce the problem, then quit:

```sh
loglens -v 2>&1 | tee ~/loglens-debug.log
```

Collect versions and what discovery sees:

```sh
dpkg-query -W loglens
/opt/loglens/python/bin/python3 -I -c 'import sys, PySide6; print(sys.version); print("PySide6", PySide6.__version__)'
cat /etc/os-release
echo "session: $XDG_SESSION_TYPE"
id
systemctl --version | head -1
docker version 2>&1 | head -20
loglens-cli -v sources > ~/loglens-sources.txt 2>&1
```

Include the steps to reproduce, what you expected, what happened, and screenshots if the
problem is visual. Before you share `loglens-debug.log` and `loglens-sources.txt`, read
them: they can contain host names, user names, IP addresses and service names. Do not
attach your database or the vault folder.
