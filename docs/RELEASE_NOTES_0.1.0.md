# LogLens 0.1.0

The first release of LogLens: a desktop app that finds every log on your Linux machine,
shows each service's logs live, and explains in plain language what is happening.

## Highlights

- **Finds everything automatically:** systemd services, Docker containers, Docker Compose
  projects and well-known log files such as Squid, ClamAV, nginx and `auth.log`.
- **Explains lines:** 224 tested rules for Squid, ClamAV, Docker, Compose, sshd, nginx,
  systemd and the kernel. Each explanation gives the severity, the probable cause and the
  next step. No AI and no network. Create your own rule from any line in the app.
- **What is happening now:** an overview per service (error spikes, top clients and
  domains, restarts, health) and a dashboard per Compose project.
- **Private by design:** nothing leaves your computer. Passwords, tokens, keys and card
  numbers are removed before anything is stored. It never needs root.
- **First-run guide:** shows what LogLens can read and gives the exact command to fix
  anything it cannot.

## Install

| System | Download | Install |
|---|---|---|
| Debian 12+, Ubuntu 22.04+, Kali, Parrot, Mint (x86-64) | `loglens_0.1.0_amd64.deb` | `sudo apt install ./loglens_0.1.0_amd64.deb` |
| Any x86-64 Linux | `LogLens-0.1.0-x86_64.AppImage` | `chmod +x` it and run it |
| Python 3.12+ | `loglens-0.1.0-py3-none-any.whl` | `pipx install loglens-0.1.0-py3-none-any.whl` |

Verify downloads with `sha256sum -c SHA256SUMS`.

The `.deb` includes its own Python 3.12 and Qt (under `/opt/loglens`). It works whatever
Python your distribution ships. It also installs the optional `loglens-helper` service;
the service stays disabled until an administrator enables it (see docs/SECURITY.md).

## Known limitations

- x86-64 only for the `.deb` and AppImage.
- Reading the system journal needs the `systemd-journal` group (or the helper), and
  Docker needs Docker socket access. The app explains both.
- A container gets the Squid, ClamAV or nginx parser by its image or service name, not by
  recognising the format.
- The helper does not give access to Docker; it streams journal units and files only.
- Encryption at rest needs the optional `sqlcipher3` package, which the bundles don't
  include.
- The Flatpak manifest is a draft. Sandboxing limits journal and Docker access (see
  `packaging/flatpak/README.md`).
- The optional AI explainer is not in this release.

The full list of changes is in CHANGELOG.md; what comes next is in docs/ROADMAP.md.
