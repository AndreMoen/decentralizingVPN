#!/usr/bin/env python3

import argparse
import csv
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

PEERS = {
    "desktop": {
        "ip": "fd3f:c8b:13f1:a633:559d:9c89:10fb:5f97",
        "pubkey": "3v/Hx5UiEvMbX5DKPm4UMue9gVxVsdfj2I/7OIwqZxA=",
    },
    "laptop": {
        "ip": "fd3f:c8b:13f1:d864:d021:920a:81e:d23f",
        "pubkey": "JtJjhgWE4HwF9gSkg/1z7YuPwQNfcqHeJlL7AvxjVDQ=",
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
TOR_READY_MARKER = "[tor] registered"
MAX_WAIT = 240
STARTUP_WAIT = 180
POLL_INTERVAL = 0.2
RUN_INTERVAL_SECONDS = 300

CSV_FIELDS = [
    "timestamp",
    "slot_start_unix",
    "slot_start_iso",
    "nr",
    "room",
    "run",
    "local_peer",
    "peer",
    "row_type",
    "process_start_unix",
    "process_start_iso",
    "ready_unix",
    "ready_iso",
    "startup_s",
    "handshake_wg_unix",
    "handshake_wg_iso",
    "handshake_detected_unix",
    "handshake_detected_iso",
    "elapsed_from_local_ready_s",
    "elapsed_from_slot_s",
    "timeout",
    "note",
]


def iso_utc(ts: float | int | None) -> str:
    if ts is None or ts == "":
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def build_binary(src_dir: str, out_bin: str):
    print(f"[build] Building binary from {src_dir} -> {out_bin}")
    r = subprocess.run(["go", "build", "-o", out_bin, "."], cwd=src_dir)
    if r.returncode != 0:
        print("[build] FAILED")
        sys.exit(1)
    print("[build] OK")


def kill_existing(iface: str):
    subprocess.run(["pkill", "-f", "torpunch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "go-build.*torpunch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "del", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)


def next_slot_start(now: float, interval_seconds: int) -> int:
    return ((int(now) // interval_seconds) + 1) * interval_seconds


def wait_until(target_ts: float):
    while True:
        remaining = target_ts - time.time()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1.0))


def room_for_run(base_room: str, nr: int, run_id: int) -> str:
    return f"{base_room}-{nr}-run{run_id}"


def get_local_pubkey(iface: str) -> str | None:
    r = subprocess.run(["wg", "show", iface], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("public key:"):
            return line.split("public key:", 1)[1].strip()
    return None


def get_latest_handshakes(iface: str) -> dict[str, int]:
    r = subprocess.run(["wg", "show", iface, "latest-handshakes"], capture_output=True, text=True)
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


def find_local_peer_name(local_pubkey: str | None) -> str | None:
    if not local_pubkey:
        return None
    for name, info in PEERS.items():
        if info["pubkey"] == local_pubkey:
            return name
    return None


def terminate_process(proc: subprocess.Popen | None):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def monitor_peer(
    peer_name: str,
    pubkey: str,
    iface: str,
    t_ready_mono: float,
    t_ready_unix: float,
    slot_start_unix: int,
    max_wait: int,
    results: dict,
    connected: dict,
    lock: threading.Lock,
    stop_event: threading.Event,
):
    deadline = t_ready_mono + max_wait
    while time.monotonic() < deadline and not stop_event.is_set():
        handshakes = get_latest_handshakes(iface)
        wg_ts = handshakes.get(pubkey, 0)

        # Only count handshakes that are not older than local readiness.
        # wg latest-handshakes has one second precision, so this is kept as a guard,
        # while the detected timestamp below gives fractional local timing.
        if wg_ts > 0 and wg_ts >= int(t_ready_unix):
            detected_mono = time.monotonic()
            detected_unix = time.time()
            elapsed_ready = round(detected_mono - t_ready_mono, 3)
            elapsed_slot = round(detected_unix - slot_start_unix, 3)
            with lock:
                if not connected[peer_name]:
                    connected[peer_name] = True
                    results[peer_name] = {
                        "handshake_wg_unix": wg_ts,
                        "handshake_detected_unix": detected_unix,
                        "elapsed_from_local_ready_s": elapsed_ready,
                        "elapsed_from_slot_s": elapsed_slot,
                        "timeout": False,
                        "note": "handshake observed",
                    }
                    print(
                        f"  [bench] ✓ {peer_name} handshake at "
                        f"+{elapsed_ready:.3f}s from local ready"
                    )
            return
        time.sleep(POLL_INTERVAL)

    with lock:
        if not connected[peer_name]:
            results[peer_name] = {
                "handshake_wg_unix": "",
                "handshake_detected_unix": "",
                "elapsed_from_local_ready_s": "",
                "elapsed_from_slot_s": "",
                "timeout": True,
                "note": f"no handshake within {max_wait}s of local ready",
            }


def run_benchmark(
    binary: str,
    run_id: int,
    iface: str,
    room: str,
    slot_start_unix: int,
    max_wait: int,
    onion_host_name: str | None,
    test_peer_names: set[str] | None,
) -> dict:
    print(f"\n{'=' * 60}")
    print(f"Run {run_id} room={room}")
    print(f"Slot start UTC {iso_utc(slot_start_unix)}")
    print(f"{'=' * 60}")

    kill_existing(iface)

    env = {**os.environ, "ROOM": room}
    process_start_unix = time.time()
    t_start_mono = time.monotonic()
    proc = subprocess.Popen(
        [binary],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    t_ready_mono = None
    t_ready_unix = None
    ready_event = threading.Event()
    stop_event = threading.Event()

    def watch_stdout():
        nonlocal t_ready_mono, t_ready_unix
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                print(f"  [vpn] {line}")
                if TOR_READY_MARKER in line and t_ready_mono is None:
                    t_ready_mono = time.monotonic()
                    t_ready_unix = time.time()
                    print(f"  [bench] local ready at {iso_utc(t_ready_unix)}")
                    ready_event.set()
        finally:
            stop_event.set()

    threading.Thread(target=watch_stdout, daemon=True).start()

    if not ready_event.wait(timeout=STARTUP_WAIT):
        print("  [bench] Timed out waiting for Tor ready marker")
        terminate_process(proc)
        kill_existing(iface)
        return {
            "process_start_unix": process_start_unix,
            "ready_unix": "",
            "startup_s": "",
            "local_peer": "",
            "results": {},
            "startup_timeout": True,
            "note": "timeout waiting for local ready marker",
        }

    assert t_ready_mono is not None
    assert t_ready_unix is not None
    startup_s = round(t_ready_mono - t_start_mono, 3)
    print(f"  [bench] Local ready in {startup_s:.3f}s from process start")

    local_pubkey = None
    for _ in range(20):
        local_pubkey = get_local_pubkey(iface)
        if local_pubkey:
            break
        time.sleep(0.2)

    local_name = find_local_peer_name(local_pubkey)
    if local_name:
        print(f"  [bench] Running as: {local_name}")
    else:
        print("  [bench] Could not determine known local peer name")

    monitored_peers = {
        name: info for name, info in PEERS.items()
        if info["pubkey"] != local_pubkey
        and name != onion_host_name
        and (test_peer_names is None or name in test_peer_names)
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
                t_ready_mono,
                t_ready_unix,
                slot_start_unix,
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

    deadline = t_ready_mono + max_wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            print("  [bench] VPN process exited early")
            break
        if all(connected.values()):
            print("  [bench] All monitored peers connected")
            break
        time.sleep(0.1)

    stop_event.set()
    for t in threads:
        t.join(timeout=1)

    for name, val in results.items():
        if val is None:
            results[name] = {
                "handshake_wg_unix": "",
                "handshake_detected_unix": "",
                "elapsed_from_local_ready_s": "",
                "elapsed_from_slot_s": "",
                "timeout": True,
                "note": f"no handshake within {max_wait}s of local ready",
            }
            print(f"  [bench] ✗ {name} no handshake within {max_wait}s of local ready")

    terminate_process(proc)
    kill_existing(iface)

    return {
        "process_start_unix": process_start_unix,
        "ready_unix": t_ready_unix,
        "startup_s": startup_s,
        "local_peer": local_name or "unknown",
        "results": results,
        "startup_timeout": False,
        "note": "",
    }


def append_rows_to_csv(path: str, rows: list[dict]):
    if not rows:
        print("[bench] No rows to write for this run")
        return

    out_dir = os.path.dirname(path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    file_exists = os.path.isfile(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)
        f.flush()
        os.fsync(f.fileno())


def make_rows(timestamp: str, nr: int, room: str, run_id: int, slot_start_unix: int, bench: dict) -> list[dict]:
    process_start_unix = bench["process_start_unix"]
    ready_unix = bench["ready_unix"]
    local_peer = bench["local_peer"]
    rows = [
        {
            "timestamp": timestamp,
            "slot_start_unix": slot_start_unix,
            "slot_start_iso": iso_utc(slot_start_unix),
            "nr": nr,
            "room": room,
            "run": run_id,
            "local_peer": local_peer,
            "peer": "_startup_",
            "row_type": "startup",
            "process_start_unix": process_start_unix,
            "process_start_iso": iso_utc(process_start_unix),
            "ready_unix": ready_unix,
            "ready_iso": iso_utc(ready_unix),
            "startup_s": bench["startup_s"],
            "handshake_wg_unix": "",
            "handshake_wg_iso": "",
            "handshake_detected_unix": "",
            "handshake_detected_iso": "",
            "elapsed_from_local_ready_s": "",
            "elapsed_from_slot_s": "",
            "timeout": bench["startup_timeout"],
            "note": bench["note"],
        }
    ]

    for peer, res in bench["results"].items():
        wg_ts = res["handshake_wg_unix"]
        detected_ts = res["handshake_detected_unix"]
        rows.append(
            {
                "timestamp": timestamp,
                "slot_start_unix": slot_start_unix,
                "slot_start_iso": iso_utc(slot_start_unix),
                "nr": nr,
                "room": room,
                "run": run_id,
                "local_peer": local_peer,
                "peer": peer,
                "row_type": "handshake",
                "process_start_unix": process_start_unix,
                "process_start_iso": iso_utc(process_start_unix),
                "ready_unix": ready_unix,
                "ready_iso": iso_utc(ready_unix),
                "startup_s": bench["startup_s"],
                "handshake_wg_unix": wg_ts,
                "handshake_wg_iso": iso_utc(wg_ts),
                "handshake_detected_unix": detected_ts,
                "handshake_detected_iso": iso_utc(detected_ts),
                "elapsed_from_local_ready_s": res["elapsed_from_local_ready_s"],
                "elapsed_from_slot_s": res["elapsed_from_slot_s"],
                "timeout": res["timeout"],
                "note": res["note"],
            }
        )
    return rows


def print_summary(all_rows: list[dict]):
    startups = [
        float(r["startup_s"]) for r in all_rows
        if r["row_type"] == "startup" and r["startup_s"] not in ("", None)
    ]
    if startups:
        print("\nStartup time, process start to local ready:")
        print(f"  min={min(startups):.3f}s max={max(startups):.3f}s avg={sum(startups)/len(startups):.3f}s")

    print("\nObserved time, local ready to first handshake detection:")
    peers = sorted(set(r["peer"] for r in all_rows if r["row_type"] == "handshake"))
    for peer in peers:
        values = [
            float(r["elapsed_from_local_ready_s"]) for r in all_rows
            if r["peer"] == peer and r["elapsed_from_local_ready_s"] not in ("", None)
        ]
        timeouts = sum(1 for r in all_rows if r["peer"] == peer and str(r["timeout"]).lower() == "true")
        if values:
            print(f"  {peer:<10} min={min(values):.3f}s max={max(values):.3f}s avg={sum(values)/len(values):.3f}s timeouts={timeouts}")
        else:
            print(f"  {peer:<10} no successful handshakes timeouts={timeouts}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=1, help="Number of runs")
    parser.add_argument("--nr", type=int, default=0, help="Base number appended to room identifier")
    parser.add_argument("--src", type=str, default=".", help="Source directory for go build")
    parser.add_argument("--binary", type=str, default="./torpunch", help="Path to compiled binary")
    parser.add_argument("--out", type=str, default="/home/results/handshake_resultsTor.csv", help="Output CSV file")
    parser.add_argument("--iface", type=str, default="wg0", help="WireGuard interface name")
    parser.add_argument("--no-build", action="store_true", help="Skip build step")
    parser.add_argument("--max-wait", type=int, default=MAX_WAIT, help="Maximum time to wait per run after local ready")
    parser.add_argument("--interval-seconds", type=int, default=RUN_INTERVAL_SECONDS, help="Run interval in seconds")
    parser.add_argument("--onion-host-name", type=str, default=None, help="Peer name of dedicated onion host to exclude from timing")
    parser.add_argument("--test-peers", type=str, default="", help="Comma separated peer names to monitor. Example: desktop,server,peera,peerb,peerc")
    args = parser.parse_args()

    if not args.no_build:
        build_binary(args.src, args.binary)

    test_peer_names = None
    if args.test_peers.strip():
        test_peer_names = {x.strip() for x in args.test_peers.split(",") if x.strip()}
        unknown = sorted(test_peer_names - set(PEERS))
        if unknown:
            print(f"[bench] Unknown peer names in --test-peers: {unknown}")
            sys.exit(1)

    print(f"[bench] Synchronized mode enabled. Runs start every {args.interval_seconds} seconds.")
    if args.onion_host_name:
        print(f"[bench] Excluding dedicated onion host from timing: {args.onion_host_name}")

    first_slot = next_slot_start(time.time(), args.interval_seconds)
    all_rows = []

    for run_id in range(1, args.runs + 1):
        slot_start_unix = first_slot + (run_id - 1) * args.interval_seconds
        print(f"[bench] Waiting for run {run_id} slot at {iso_utc(slot_start_unix)}")
        wait_until(slot_start_unix)

        room = room_for_run(BASE_ROOM, args.nr, run_id)
        print(f"[bench] Using room: {room}")

        timestamp = datetime.now(tz=timezone.utc).isoformat()
        bench = run_benchmark(args.binary, run_id, args.iface, room, slot_start_unix, args.max_wait, args.onion_host_name, test_peer_names)
        rows = make_rows(timestamp, args.nr, room, run_id, slot_start_unix, bench)
        append_rows_to_csv(args.out, rows)
        all_rows.extend(rows)
        print(f"[bench] run {run_id} written to CSV")

    print(f"\n[bench] Results written to {args.out}")
    if all_rows:
        print_summary(all_rows)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Re-running with sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    main()
