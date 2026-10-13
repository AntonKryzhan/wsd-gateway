#!/bin/sh
# STAGING ONLY: deliberately does NOT start/stop/enable any service.
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" != "0" ]; then echo "Run as root on FreeBSD" >&2; exit 1; fi
if [ ! -f bin/wsd-gateway-freebsd-amd64 ]; then
    echo "Missing bin/wsd-gateway-freebsd-amd64 (unpack a release or build on another machine)" >&2
    exit 1
fi
install -m 0755 bin/wsd-gateway-freebsd-amd64 /usr/local/sbin/wsd-gateway
install -m 0755 etc/rc.d/wsd_gateway /usr/local/etc/rc.d/wsd_gateway
if [ ! -f /usr/local/etc/wsd-gateway.json ]; then
    install -m 0600 configs/config.example.json /usr/local/etc/wsd-gateway.json
    echo "EDIT /usr/local/etc/wsd-gateway.json to match your interfaces."
fi
echo "STAGED. No existing service was changed."
echo "NEXT: /usr/local/sbin/wsd-gateway -config /usr/local/etc/wsd-gateway.json check"
echo "NEXT: /usr/local/sbin/wsd-gateway -config /usr/local/etc/wsd-gateway.json scan -scan-duration 20s"
