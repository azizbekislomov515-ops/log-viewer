#!/bin/sh
# Drop a clean file and the EICAR test file into /scan, then ask clamd to scan it.
printf 'TCPSocket 3310\nTCPAddr clamav\n' > /tmp/clamd-client.conf
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
n=0
while true; do
    n=$((n + 1))
    echo "quarterly report $n" > /scan/report-$n.txt
    printf '%s' "$EICAR" > /scan/invoice-$n.com
    clamdscan --config-file=/tmp/clamd-client.conf --stream /scan/report-$n.txt /scan/invoice-$n.com || true
    rm -f /scan/report-$n.txt /scan/invoice-$n.com
    sleep 30
done
