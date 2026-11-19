FROM alpine:latest
RUN apk add --no-cache clamav-daemon clamav-clamdscan freshclam
# A single custom signature for the harmless EICAR test string: ClamAV starts in seconds
# and works offline (the real signature database is ~300 MB).
COPY eicar.ndb /var/lib/clamav/eicar.ndb
COPY clamd.conf /etc/clamav/clamd.conf
COPY freshclam.conf /etc/clamav/freshclam.conf
COPY entrypoint.sh scan-loop.sh /usr/local/bin/
RUN mkdir -p /run/clamav /scan && chown -R clamav:clamav /run/clamav /var/lib/clamav /scan
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
