# Flatpak (draft)

`org.loglens.LogLens.yml` is a starting point, not a published package. The `.deb` is the
supported way to install LogLens on Debian-family systems; the AppImage runs anywhere.

## What the sandbox changes

| Source | `.deb` | Flatpak |
|---|---|---|
| systemd journal | `journalctl` as your user (needs `systemd-journal` group) | **No `journalctl` in the sandbox.** Use the helper (below). Reading `/var/log/journal` files directly would need native journal bindings, which LogLens does not ship yet. |
| Files in /var/log | Read directly (group/ACL permissions) | Read through `--filesystem=/var/log:ro`; host permissions still apply |
| Docker | Docker socket (root-equivalent; group or rootless Docker) | **Not granted** by default: socket access would let the app escape the sandbox. Opt in with `flatpak override --filesystem=/run/docker.sock` (or the rootless socket under `/run/user/$UID/`), knowing what it means |
| Helper | Optional | **Recommended**: the sandbox reaches `/run/loglens-helper.sock` and gets journal and file logs the admin allowed, read-only, without group changes |

## The helper-based solution

Install `loglens-helper` on the host (it is a system service, so it cannot live inside a
Flatpak): from the `.deb`, or the files in `packaging/helper/` (see docs/SECURITY.md).
Enable it with `sudo systemctl enable --now loglens-helper.socket` and list the units and
files to share in `/etc/loglens/helper.toml`. The sandboxed app finds the socket and uses
it for every journal or file source it cannot read itself.

## Building (once dependencies are generated)

```sh
flatpak-builder --user --install --force-clean build-flatpak packaging/flatpak/org.loglens.LogLens.yml
flatpak run org.loglens.LogLens
```
