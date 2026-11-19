#!/bin/sh
# Browse through the proxy: normal pages, a 404, blocked sites, a host that does not exist.
get() { curl -s -o /dev/null -m 8 "$@" || true; }
sleep 3
while true; do
    get http://web/
    get http://web/index.html
    get http://web/missing-page
    get http://web/slow
    get https://www.facebook.com/
    get http://ads.doubleclick.net/pixel.gif
    get http://www.tiktok.com/
    get http://no-such-host.invalid/
    sleep "$(( (RANDOM % 4) + 2 ))"
done
