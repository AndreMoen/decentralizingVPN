#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <peer_name_or_ip>"
    exit 1
fi

TARGET="$1"
CSV_FILE="/home/results/timing.csv"
HOSTNAME="$(hostname -s)"
TMP_JSON="$(mktemp)"

cleanup() {
    rm -f "$TMP_JSON"
}
trap cleanup EXIT

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

iperf3 -c "$PEER_IP" -t 15 -J > "$TMP_JSON"

python3 - "$TMP_JSON" "$CSV_FILE" "$HOSTNAME" "$PEER_NAME" "$PATH_TYPE" <<'PY'
import csv
import json
import os
import sys
from datetime import datetime

json_file, csv_file, hostname, peer_name, path_type = sys.argv[1:6]

with open(json_file, "r", encoding="utf-8") as f:
    data = json.load(f)

end = data["end"]
sent_bps = end["sum_sent"]["bits_per_second"]
recv_bps = end["sum_received"]["bits_per_second"]

row = {
    "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
    "sender_hostname": hostname,
    "receiver_peer": peer_name,
    "path_type": path_type,
    "sender_Mbps": round(sent_bps / 1_000_000, 3),
    "receiver_Mbps": round(recv_bps / 1_000_000, 3),
}

file_exists = os.path.exists(csv_file)

with open(csv_file, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "timestamp",
            "sender_hostname",
            "receiver_peer",
            "path_type",
            "sender_Mbps",
            "receiver_Mbps",
        ],
    )
    if not file_exists or os.path.getsize(csv_file) == 0:
        writer.writeheader()
    writer.writerow(row)

print(row)
PY
