#!/bin/sh
# clamd cannot log to /dev/stdout here, so it logs to a file that this script follows.
# freshclam (fails: unreachable mirror) runs every 2 minutes.
mkdir -p /var/log/clamav && touch /var/log/clamav/clamd.log
chown -R clamav:clamav /var/log/clamav
clamd --config-file=/etc/clamav/clamd.conf &
( while true; do freshclam --config-file=/etc/clamav/freshclam.conf --stdout || true; sleep 120; done ) &
exec tail -n +1 -F /var/log/clamav/clamd.log
