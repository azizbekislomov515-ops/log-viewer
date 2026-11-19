#!/usr/bin/env bash
# QA checklist for the .deb on a fresh system. Run in a clean container:
#   docker run --rm -v "$PWD/dist:/dist" -v "$PWD/packaging/qa:/qa:ro" ubuntu:24.04 bash /qa/qa-deb.sh
# Checks: install with dependency resolution, desktop/AppStream metadata, discovery as an
# unprivileged user, explanations, live collection with redaction, the GUI (onboarding,
# window, explanations, clean exit, SIGTERM), and removal.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
step() { printf '\n==> %s\n' "$*"; }
fail() { echo "QA FAIL: $*"; exit 1; }

step "install the package (apt resolves its dependencies)"
apt-get update -qq
apt-get install -y -qq /dist/loglens_*_amd64.deb appstream desktop-file-utils >/dev/null
dpkg -s loglens | grep -E '^(Version|Installed-Size):'

step "files, launchers and metadata"
for f in /usr/bin/loglens /usr/bin/loglens-cli /usr/bin/loglens-helper \
         /usr/share/applications/org.loglens.LogLens.desktop \
         /usr/share/metainfo/org.loglens.LogLens.metainfo.xml \
         /usr/share/icons/hicolor/scalable/apps/org.loglens.LogLens.svg \
         /usr/share/icons/hicolor/256x256/apps/org.loglens.LogLens.png \
         /usr/lib/systemd/system/loglens-helper.socket /etc/loglens/helper.toml; do
    test -e "$f" || fail "missing $f"
done
desktop-file-validate /usr/share/applications/org.loglens.LogLens.desktop
# Errors fail; warnings are listed (a homepage URL is added once the project is public).
appstreamcli validate --no-net /usr/share/metainfo/org.loglens.LogLens.metainfo.xml > /tmp/as.txt 2>&1 || true
cat /tmp/as.txt
! grep -q '^E:' /tmp/as.txt || fail "AppStream metadata has errors"
getent passwd loglens-helper >/dev/null || fail "helper user not created"
test ! -w /opt/loglens/python/lib || [ "$(stat -c %U /opt/loglens)" = root ] || fail "/opt/loglens not root-owned"

step "an unprivileged user and some logs"
useradd -m qa
mkdir -p /var/log/nginx /var/log/squid
cat > /var/log/nginx/access.log <<'LOG'
10.0.0.5 - - [19/Nov/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.5"
10.0.0.5 - - [19/Nov/2026:10:00:01 +0000] "GET /missing HTTP/1.1" 404 153 "-" "curl/8.5"
LOG
echo '1795076810.563      0 172.18.0.6 TCP_DENIED/403 3431 CONNECT www.facebook.com:443 - HIER_NONE/- text/html' > /var/log/squid/access.log
echo 'secret squid internals' > /var/log/squid/cache.log
chmod 644 /var/log/nginx/access.log /var/log/squid/access.log
chmod 600 /var/log/squid/cache.log
as_qa() { su qa -s /bin/bash -c "$*"; }

step "discovery (readable files found, unreadable one explained, no root needed)"
as_qa "loglens-cli sources --json" > /tmp/sources.json
grep -q '"file:/var/log/nginx/access.log"' /tmp/sources.json || fail "nginx log not discovered"
as_qa "loglens-cli sources" | tee /tmp/sources.txt | tail -12
grep -q "setfacl" /tmp/sources.txt || fail "no fix shown for the unreadable file"

step "explanations"
as_qa "loglens-cli explain --file /var/log/squid/access.log --source squid" | tee /tmp/explain.txt
grep -qi "facebook" /tmp/explain.txt || fail "squid line not explained"

step "live collection with redaction"
as_qa "printf 'start\n' > ~/app.log"
as_qa "loglens-cli collect file:/home/qa/app.log > ~/collect.out 2>&1" & collector=$!
sleep 3
as_qa "printf 'login password=Hunter2Secret ok\nAuthorization: Bearer abcdef1234567890abcdef\n' >> ~/app.log"
sleep 4
kill -TERM "$collector"; wait "$collector" || true
grep -q "REDACTED" /home/qa/collect.out || fail "collected lines were not shown redacted"
if cat /home/qa/.local/share/loglens/loglens.db* | grep -aq -e Hunter2Secret -e abcdef1234567890abcdef; then
    fail "a secret reached the database"
fi
as_qa "loglens-cli search login" | tee /tmp/search.txt
grep -q "REDACTED" /tmp/search.txt || fail "search did not find the redacted entry"
stat -c '%a %n' /home/qa/.local/share/loglens/loglens.db | grep -q '^600 ' || fail "database not 0600"

step "GUI: first-run guide, window, explanations, clean exit"
mkdir -p /tmp/qa-out && chmod 777 /tmp/qa-out
as_qa "QT_QPA_PLATFORM=offscreen /opt/loglens/python/bin/python3.12 -I -B /qa/gui_check.py /tmp/qa-out file:/var/log/nginx/access.log" | tee /tmp/gui.txt
grep -q "exit=0" /tmp/gui.txt || fail "GUI check failed"
cp /tmp/qa-out/*.png /dist/ 2>/dev/null || true

step "GUI launcher and SIGTERM"
as_qa "QT_QPA_PLATFORM=offscreen loglens --demo >/tmp/gui-demo.log 2>&1 & echo \$! > /tmp/gui.pid; wait \$(cat /tmp/gui.pid); echo \$? > /tmp/gui.rc" & runner=$!
sleep 6
kill -TERM "$(cat /tmp/gui.pid)"
wait "$runner"
[ "$(cat /tmp/gui.rc)" = 0 ] || { cat /tmp/gui-demo.log; fail "loglens did not exit cleanly on SIGTERM"; }
su qa -s /bin/bash -c "id -u" >/dev/null
if loglens --help >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    QT_QPA_PLATFORM=offscreen loglens >/dev/null 2>&1 && fail "the GUI ran as root" || true
fi

step "remove"
apt-get remove -y -qq loglens >/dev/null
test ! -e /opt/loglens && test ! -e /usr/bin/loglens || fail "files left after removal"
echo
echo "QA PASSED"
