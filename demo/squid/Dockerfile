FROM alpine:latest
RUN apk add --no-cache squid
COPY squid.conf /etc/squid/squid.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN squid -z -N -f /etc/squid/squid.conf 2>/dev/null || true
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
