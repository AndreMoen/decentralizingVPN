#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

PEERS = {
    "desktop": {
        "ip": "fd3f:c8b:13f1:a633:559d:9c89:10fb:5f97",
        "pubkey": "3v/Hx5UiEvMbX5DKPm4UMue9gVxVsdfj2I/7OIwqZxA=",
    },
    "server": {
        "ip": "fd3f:c8b:13f1:6c81:8f6:9e56:eb06:c761",
        "pubkey": "xoCyN5gh/M4njclJ1HX3DAhn9S942hG3n9JDRiYX61s=",
    },
    "peerb": {
        "ip": "fd3f:c8b:13f1:c225:2d61:d265:fb33:96b9",
        "pubkey": "YwtbeG9oTBu8RUHxDxRWnzkpwRdh4i2lUoxNVMFOKh8=",
    },
    "peerc": {
        "ip": "fd3f:c8b:13f1:99bc:7b92:9c54:507f:7ec1",
        "pubkey": "+CBJDh+e40qjmyZOd2ZGBluVucbjsOczHXTDgstbc0g=",
    },
    "peera": {
        "ip": "fd3f:c8b:13f1:b0cc:b059:8ce:87c7:b07f",
        "pubkey": "b8GP7ec6meXcfPXMn/W5SRRfmcU+xK/uuQLyWyyzvlQ=",
    },
}

BASE_ROOM = "secret-meeting-room-123"
T0_MARKER = "UDP bound"
MAX_WAIT = 240
STARTUP_WAIT = 30
POLL_INTERVAL = 0.2
LOCAL_ID_WAIT = 10.0
RUN_INTERVAL_SECONDS = 300


def normalize_ipv6(addr: str | None) -> str | None:
    if not addr:
        return None
    try:
        return str(ipaddress.IPv6Address(addr))
    except ValueError:
        return None


def wait_for_next_slot(interval_seconds: int):
    now = time.time()
    next_slot = ((int(now) // interval_seconds) + 1) * interval_seconds
    sleep_for = next_slot - now
    next_slot_str = datetime.fromtimestamp(next_slot).strftime("%H:%M:%S")
    print(f"[bench] Waiting {sleep_for:.3f}s for next run slot at {next_slot_str}")
    time.sleep(max(0.0, sleep_for))


def kill_existing(iface: str):
    subprocess.run(
        ["pkill", "-f", "torpunch"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["pkill", "-f", "go-build.*torpunch"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ip", "link", "del", iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)


def build_binary(src_dir: str, out_bin: str):
    print(f"[build] Building binary from {src_dir} -> {out_bin}")
    r = subprocess.run(["go", "build", "-o", out_bin, "."], cwd=src_dir)
    if r.returncode != 0:
        print("[build] FAILED")
        sys.exit(1)
    print("[build] OK")


def get_local_pubkey(iface: str):
    r = subprocess.run(["wg", "show", iface], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("public key:"):
            return line.split("public key:", 1)[1].strip()
    return None


def get_local_ipv6(iface: str):
    r = subprocess.run(
        ["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None

    for line in r.stdout.splitlines():
        parts = line.split()
        if "inet6" not in parts:
            continue
        idx = parts.index("inet6")
        if idx + 1 >= len(parts):
            continue
        cidr = parts[idx + 1]
        addr = cidr.split("/", 1)[0]
        norm = normalize_ipv6(addr)
        if norm:
            return norm
    return None


def get_latest_handshakes(iface: str):
    r = subprocess.run(
        ["wg", "show", iface, "latest-handshakes"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return {}

    result = {}
    for line in r.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        pubkey, ts_str = parts
        try:
            result[pubkey] = int(ts_str)
        except ValueError:
            continue
    return result


def find_local_peer_name(local_pubkey: str | None, local_ip: str | None):
    if local_pubkey:
        for name, info in PEERS.items():
            if info["pubkey"] == local_pubkey:
                return name

    norm_local_ip = normalize_ipv6(local_ip)
    if norm_local_ip:
        for name, info in PEERS.items():
            if normalize_ipv6(info["ip"]) == norm_local_ip:
                return name

    return None


def wait_for_local_identity(iface: str, timeout: float):
    deadline = time.monotonic() + timeout
    last_pubkey = None
    last_ip = None

    while time.monotonic() < deadline:
        last_pubkey = get_local_pubkey(iface)
        last_ip = get_local_ipv6(iface)
        local_name = find_local_peer_name(last_pubkey, last_ip)
        if local_name:
            return local_name, last_pubkey, last_ip
        time.sleep(0.2)

    return None, last_pubkey, last_ip


def monitor_peer(peer_name, pubkey, iface, t0_mono, t0_unix, max_wait, results, connected, lock, stop_event):
    deadline = t0_mono + max_wait
    while time.monotonic() < deadline and not stop_event.is_set():
        handshakes = get_latest_handshakes(iface)
        ts = handshakes.get(pubkey, 0)

        if ts > 0 and ts >= int(t0_unix):
            elapsed = round(time.monotonic() - t0_mono, 3)
            with lock:
                if not connected[peer_name]:
                    connected[peer_name] = True
                    results[peer_name] = elapsed
                    print(f"  [bench] ✓ {peer_name} handshake at {elapsed:.3f}s")
            return

        time.sleep(POLL_INTERVAL)

    with lock:
        if not connected[peer_name]:
            results[peer_name] = None


def terminate_process(proc: subprocess.Popen):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def run_benchmark(binary, run_id, iface, room, max_wait):
    print(f"\n{'=' * 60}")
    print(f"Run {run_id} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - room={room}")
    print(f"{'=' * 60}")

    kill_existing(iface)

    env = {**os.environ, "ROOM": room}

    proc = subprocess.Popen(
        [binary],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    t0_mono = None
    t0_unix = None
    t0_event = threading.Event()
    stop_event = threading.Event()

    def watch_stdout():
        nonlocal t0_mono, t0_unix
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                print(f"  [vpn] {line}")
                if T0_MARKER in line and t0_mono is None:
                    t0_mono = time.monotonic()
                    t0_unix = time.time()
                    print("  [bench] t0 set")
                    t0_event.set()
        finally:
            stop_event.set()

    threading.Thread(target=watch_stdout, daemon=True).start()

    if not t0_event.wait(timeout=STARTUP_WAIT):
        print("  [bench] startup timeout")
        terminate_process(proc)
        kill_existing(iface)
        return {}

    local_name, local_pubkey, local_ip = wait_for_local_identity(iface, LOCAL_ID_WAIT)
    print(f"  [bench] Local pubkey: {local_pubkey}")
    print(f"  [bench] Local IPv6: {local_ip}")

    if not local_name:
        print("  [bench] Could not determine local peer identity from pubkey or IPv6")
        terminate_process(proc)
        kill_existing(iface)
        return {}

    print(f"  [bench] Local peer detected as: {local_name}")

    monitored_peers = {
        name: info for name, info in PEERS.items()
        if name != local_name
    }
    print(f"  [bench] Monitoring {len(monitored_peers)} peers")

    results = {name: None for name in monitored_peers}
    connected = {name: False for name in monitored_peers}
    lock = threading.Lock()
    threads = []

    for peer_name, info in monitored_peers.items():
        t = threading.Thread(
            target=monitor_peer,
            args=(
                peer_name,
                info["pubkey"],
                iface,
                t0_mono,
                t0_unix,
                max_wait,
                results,
                connected,
                lock,
                stop_event,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)

    deadline = t0_mono + max_wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            print("  [bench] VPN process exited early")
            break
        time.sleep(0.1)

    stop_event.set()

    for t in threads:
        t.join(timeout=1)

    terminate_process(proc)
    kill_existing(iface)

    return results


def append_rows_to_csv(path: str, rows: list[dict]):
    if not rows:
        print("[bench] No rows to write for this run")
        return

    out_dir = os.path.dirname(path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    file_exists = os.path.isfile(path)

    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["timestamp", "nr", "room", "run", "peer", "elapsed", "timeout"],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)
        f.flush()
        os.fsync(f.fileno())


def print_summary(all_results):
    print(f"\n{'Peer':<12} {'Min(s)':>8} {'Max(s)':>8} {'Avg(s)':>8} {'Timeouts':>9}")
    print("-" * 50)
    peer_names = sorted(set(r["peer"] for r in all_results))
    for name in peer_names:
        times = [r["elapsed"] for r in all_results if r["peer"] == name and r["elapsed"] != ""]
        timeouts = sum(1 for r in all_results if r["peer"] == name and r["timeout"])
        if times:
            avg = sum(times) / len(times)
            print(f"{name:<12} {min(times):>8.3f} {max(times):>8.3f} {avg:>8.3f} {timeouts:>9}")
        else:
            print(f"{name:<12} {'-':>8} {'-':>8} {'-':>8} {timeouts:>9}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=1, help="Number of runs")
    parser.add_argument(
        "--nr",
        type=int,
        default=0,
        help="Base number appended to room identifier. Each run also appends its run id.",
    )
    parser.add_argument("--src", type=str, default=".", help="Source directory for go build")
    parser.add_argument("--binary", type=str, default="./torpunch", help="Path to compiled binary")
    parser.add_argument("--out", type=str, default="/home/results/handshake_resultsNostr3.csv", help="Output CSV file")
    parser.add_argument("--iface", type=str, default="wg0", help="WireGuard interface name")
    parser.add_argument("--no-build", action="store_true", help="Skip build step")
    parser.add_argument("--max-wait", type=int, default=MAX_WAIT, help="Maximum time to wait per run")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=RUN_INTERVAL_SECONDS,
        help="Run interval in seconds. Default is 300 for every 5 minutes.",
    )
    args = parser.parse_args()

    if not args.no_build:
        build_binary(args.src, args.binary)

    print(
        f"[bench] Synchronized mode enabled. "
        f"Runs will start every {args.interval_seconds} seconds."
    )

    all_results = []

    for run_id in range(1, args.runs + 1):
        wait_for_next_slot(args.interval_seconds)

        room = f"{BASE_ROOM}-{args.nr}-run{run_id}"
        print(f"[bench] Using room: {room}")

        timestamp = datetime.now().isoformat()
        results = run_benchmark(args.binary, run_id, args.iface, room, args.max_wait)

        rows = []
        for peer, elapsed in results.items():
            row = {
                "timestamp": timestamp,
                "nr": args.nr,
                "room": room,
                "run": run_id,
                "peer": peer,
                "elapsed": elapsed if elapsed is not None else "",
                "timeout": elapsed is None,
            }
            rows.append(row)
            all_results.append(row)

        append_rows_to_csv(args.out, rows)
        print(f"[bench] run {run_id} written to CSV")

    print(f"\n[bench] Results written to {args.out}")
    if all_results:
        print_summary(all_results)


if __name__ == "__main__":
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    main()
