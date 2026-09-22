#!/bin/bash
# One-shot runner: starts a packet capture of DoH traffic to the configured resolver,
# runs the block generator through the OS resolver, stops the capture.
# Run as:  sudo bash run_experiment.sh [blocks] [block_seconds] [gap_seconds]
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$HERE/../../../.venv/bin/python3"
BLOCKS="${1:-8}"; BSEC="${2:-150}"; GAP="${3:-80}"
IFACE=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')
STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$HERE/captures/osdoh_${STAMP}.pcap"
echo "interface=$IFACE  out=$OUT"
if ! scutil --dns | grep -qi https; then echo "DoH profile not active (scutil --dns shows no https). Install DoH-Cloudflare.mobileconfig first."; exit 1; fi
dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true
# capture only traffic to/from the DoH resolver addresses set in the profile
tcpdump -i "$IFACE" -s 0 -w "$OUT" 'tcp port 443 and (host 1.1.1.1 or host 1.0.0.1)' &
TCPD=$!
sleep 2
# run the generator as the invoking (non-root) user so lookups go through the normal resolver path
sudo -u "${SUDO_USER:-$USER}" "$PY" "$HERE/os_doh_experiment.py" --blocks "$BLOCKS" --block-seconds "$BSEC" --gap-seconds "$GAP" --out "$HERE/captures"
sleep 70   # let the last flow idle out
kill -INT $TCPD; wait $TCPD 2>/dev/null || true
chown "${SUDO_USER:-$USER}" "$OUT" "$HERE"/captures/*.json 2>/dev/null || true
echo "capture: $(ls -la "$OUT")"
