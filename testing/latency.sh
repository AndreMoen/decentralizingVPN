#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <peer>"
    exit 1
fi

TARGET="$1"
CSV_FILE="/home/results/latencyTailscale.csv"
HOSTNAME="$(hostname -s)"

declare -A DVPN_PEERS=(
    [peerb]="fd3f:c8b:13f1:c225:2d61:d265:fb33:96b9"
    [peera]="fd3f:c8b:13f1:b0cc:b059:8ce:87c7:b07f"
    [server]="fd3f:c8b:13f1:6c81:8f6:9e56:eb06:c761"
    [desktop]="fd3f:c8b:13f1:a633:559d:9c89:10fb:5f97"
    [peerc]="fd3f:c8b:13f1:99bc:7b92:9c54:507f:7ec1"
    [laptop]="fd3f:c8b:13f1:d864:d021:920a:81e:d23f"
)

declare -A TAILSCALE_PEERS=(
    [peerbt]="100.92.124.52"
    [peerat]="100.122.50.122"
    [servert]="100.93.9.122"
    [desktopt]="100.85.77.120"
    [peerct]="100.104.215.41"
    [laptopt]="100.107.48.103"
)

if [[ -n "${DVPN_PEERS[$TARGET]:-}" ]]; then
    PEER_NAME="$TARGET"
    PEER_IP="${DVPN_PEERS[$TARGET]}"
    PATH_TYPE="dvpn"
elif [[ -n "${TAILSCALE_PEERS[$TARGET]:-}" ]]; then
    PEER_NAME="${TARGET%t}"
    PEER_IP="${TAILSCALE_PEERS[$TARGET]}"
    PATH_TYPE="tailscale"
else
    echo "Unknown peer: $TARGET"
    exit 1
fi

PING_OUT="$(ping -c 50 -i 0.2 "$PEER_IP")"

echo "$PING_OUT"

LOSS=$(echo "$PING_OUT" | awk -F',' '/packet loss/ {gsub("%","",$3); print $3}' | awk '{print $1}')
RTT=$(echo "$PING_OUT" | awk -F'=' '/rtt|round-trip/ {print $2}' | awk '{print $1}')
MDEV=$(echo "$RTT" | cut -d'/' -f4)

TMP_RTT_FILE="$(mktemp)"
trap 'rm -f "$TMP_RTT_FILE"' EXIT

echo "$PING_OUT" \
    | awk '
        /time=/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^time=/) {
                    gsub("time=", "", $i)
                    gsub("ms", "", $i)
                    print $i
                }
            }
        }
    ' \
    | LC_ALL=C sort -n > "$TMP_RTT_FILE"

COUNT=$(wc -l < "$TMP_RTT_FILE" | tr -d ' ')

if [ "$COUNT" -eq 0 ]; then
    echo "No RTT samples found"
    exit 1
fi

MIN=$(awk 'NR==1 {print $1}' "$TMP_RTT_FILE")
MAX=$(awk -v n="$COUNT" 'NR==n {print $1}' "$TMP_RTT_FILE")
AVG=$(awk '{s+=$1} END {printf "%.3f", s/NR}' "$TMP_RTT_FILE")

MEDIAN=$(awk -v n="$COUNT" '
    {
        a[NR]=$1
    }
    END {
        if (n % 2 == 1) {
            printf "%.3f", a[(n + 1) / 2]
        } else {
            printf "%.3f", (a[n / 2] + a[n / 2 + 1]) / 2
        }
    }
' "$TMP_RTT_FILE")

P95_INDEX=$(awk -v n="$COUNT" 'BEGIN { printf "%d", (n * 95 + 99) / 100 }')
P99_INDEX=$(awk -v n="$COUNT" 'BEGIN { printf "%d", (n * 99 + 99) / 100 }')

P95=$(awk -v idx="$P95_INDEX" 'NR==idx {printf "%.3f", $1}' "$TMP_RTT_FILE")
P99=$(awk -v idx="$P99_INDEX" 'NR==idx {printf "%.3f", $1}' "$TMP_RTT_FILE")

if [ ! -f "$CSV_FILE" ]; then
    echo "timestamp,sender_hostname,receiver_peer,path_type,min_ms,avg_ms,median_ms,max_ms,p95_ms,p99_ms,jitter_ms,packet_loss_pct" > "$CSV_FILE"
fi

echo "$(date -Iseconds),$HOSTNAME,$PEER_NAME,$PATH_TYPE,$MIN,$AVG,$MEDIAN,$MAX,$P95,$P99,$MDEV,$LOSS" >> "$CSV_FILE"
