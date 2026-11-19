#!/bin/sh
# Squid's user cannot open the container's stdout, so it logs to files we follow.
mkdir -p /var/log/squid && touch /var/log/squid/access.log /var/log/squid/cache.log
chown -R squid:squid /var/log/squid
squid -N -f /etc/squid/squid.conf &
tail -n +1 -F /var/log/squid/cache.log &
exec tail -n +1 -F /var/log/squid/access.log
