#!/usr/bin/env python3
import csv
import datetime as dt
import signal
import subprocess
import sys
import threading
import time
import argparse

PEERS = {
    "desktop": {"ip": "100.85.77.120"},
    "server": {"ip": "100.93.9.122"},
    "peera": {"ip": "100.122.50.122"},
    "peerb": {"ip": "100.92.124.52"},
    "peerc": {"ip": "100.104.215.41"},
}

CSV_FILE = "/home/results/tailscale_minute_runs.csv"
PING_INTERVAL = 0.5
REACHABILITY_TIMEOUT = 55
TAILSCALE_UP_TIMEOUT = 20


def run(cmd, check=True, capture_output=False):
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def ensure_tailscaled_running():
    result = run(
        ["systemctl", "is-active", "--quiet", "tailscaled"],
        check=False,
    )
    if result.returncode != 0:
        print("tailscaled is not running, starting it")
        run(["sudo", "systemctl", "start", "tailscaled"])


def tailscale_down():
    print(f"[{timestamp_now()}] sudo tailscale down")
    run(["sudo", "tailscale", "down"], check=False)


def tailscale_up():
    print(f"[{timestamp_now()}] sudo tailscale up")
    run(["sudo", "tailscale", "up"], check=True)


def timestamp_now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def seconds_until_target(second):
    now = dt.datetime.now()
    target = now.replace(second=second, microsecond=0)
    if now >= target:
        target += dt.timedelta(minutes=1)
    return (target - now).total_seconds(), target


def wait_until(target_dt):
    while True:
        now = dt.datetime.now()
        remaining = (target_dt - now).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.2))


def probe_peer(peer_name, peer_ip, start_monotonic, results, lock):
    deadline = start_monotonic + REACHABILITY_TIMEOUT

    while time.monotonic() < deadline:
        result = run(
            ["tailscale", "ping", "-c", "1", peer_ip],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            elapsed = time.monotonic() - start_monotonic
            with lock:
                results[peer_name] = {
                    "ip": peer_ip,
                    "success": True,
                    "time_seconds": round(elapsed, 3),
                }
            print(f"[{timestamp_now()}] {peer_name} reachable in {elapsed:.3f}s")
            return
        time.sleep(PING_INTERVAL)

    with lock:
        results[peer_name] = {
            "ip": peer_ip,
            "success": False,
            "time_seconds": None,
        }
    print(f"[{timestamp_now()}] {peer_name} timeout")


def write_results(run_id, up_wallclock, results):
    file_exists = False
    try:
        with open(CSV_FILE, "r", newline=""):
            file_exists = True
    except FileNotFoundError:
        pass

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "run_id",
                "up_wallclock",
                "peer",
                "ip",
                "success",
                "time_seconds",
            ],
        )
        if not file_exists:
            writer.writeheader()

        for peer_name in PEERS:
            row = results.get(
                peer_name,
                {
                    "ip": PEERS[peer_name]["ip"],
                    "success": False,
                    "time_seconds": None,
                },
            )
            writer.writerow(
                {
                    "run_id": run_id,
                    "up_wallclock": up_wallclock,
                    "peer": peer_name,
                    "ip": row["ip"],
                    "success": row["success"],
                    "time_seconds": row["time_seconds"],
                }
            )


def cleanup_and_exit(signum=None, frame=None):
    print(f"\n[{timestamp_now()}] stopping")
    try:
        tailscale_down()
    finally:
        sys.exit(0)


def run_one_cycle(run_id):
    wait_down_seconds, down_target = seconds_until_target(50)
    print(
        f"[{timestamp_now()}] run {run_id}: waiting {wait_down_seconds:.3f}s "
        f"for shutdown at {down_target.strftime('%H:%M:%S')}"
    )
    wait_until(down_target)

    tailscale_down()

    up_target = down_target + dt.timedelta(seconds=10)
    print(
        f"[{timestamp_now()}] run {run_id}: waiting for startup at "
        f"{up_target.strftime('%H:%M:%S')}"
    )
    wait_until(up_target)

    up_wallclock = timestamp_now()
    start_monotonic = time.monotonic()
    tailscale_up()

    threads = []
    results = {}
    lock = threading.Lock()

    for peer_name, peer_data in PEERS.items():
        t = threading.Thread(
            target=probe_peer,
            args=(peer_name, peer_data["ip"], start_monotonic, results, lock),
            daemon=True,
        )
        t.start()
        threads.append(t)

    join_deadline = start_monotonic + REACHABILITY_TIMEOUT + TAILSCALE_UP_TIMEOUT
    for t in threads:
        remaining = join_deadline - time.monotonic()
        if remaining > 0:
            t.join(timeout=remaining)

    print(f"[{timestamp_now()}] run {run_id} summary")
    for peer_name in PEERS:
        row = results.get(peer_name)
        if row is None:
            print(f"  {peer_name}: no result")
        elif row["success"]:
            print(f"  {peer_name}: {row['time_seconds']}s")
        else:
            print(f"  {peer_name}: timeout")

    write_results(run_id, up_wallclock, results)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    ensure_tailscaled_running()

    for run_id in range(1, args.runs + 1):
        run_one_cycle(run_id)

    print(f"\nCompleted {args.runs} runs")
    ensure_tailscaled_running()


if __name__ == "__main__":
    main()
