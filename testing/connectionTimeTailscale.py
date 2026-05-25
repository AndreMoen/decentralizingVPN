#!/usr/bin/env python3

import argparse
import csv
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

PEERS = {
    "desktop": {"ip": "100.85.77.120"},
    "laptop": {"ip": "100.107.48.103"},
    "server": {"ip": "100.93.9.122"},
    "peera": {"ip": "100.122.50.122"},
    "peerb": {"ip": "100.92.124.52"},
    "peerc": {"ip": "100.104.215.41"},
}

DEFAULT_MAX_WAIT = 120
POLL_INTERVAL = 0.2
TCP_TIMEOUT = 1.0
DEFAULT_PORT = 34999
DEFAULT_DOWN_WAIT = 10


def run_cmd(cmd, check=False, capture_output=True, text=True):
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
    )


def tailscale_down():
    return run_cmd(["tailscale", "down"])


def tailscale_up(extra_args=None):
    if extra_args is None:
        extra_args = []
    cmd = ["tailscale", "up"] + extra_args
    return run_cmd(cmd)


def get_self_tailscale_ip():
    r = run_cmd(["tailscale", "ip", "-4"])
    if r.returncode != 0:
        return None
    lines = [x.strip() for x in r.stdout.splitlines() if x.strip()]
    return lines[0] if lines else None


def wait_until_local_ip(timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ip = get_self_tailscale_ip()
        if ip:
            return ip
        time.sleep(0.2)
    return None


def tcp_connect(ip, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_until_epoch(target_ts):
    while True:
        remaining = target_ts - time.time()
        if remaining <= 0:
            return
        if remaining > 1:
            time.sleep(remaining - 0.5)
        else:
            time.sleep(min(0.01, remaining))


class BenchmarkTCPServer:
    def __init__(self, port):
        self.port = port
        self.stop_event = threading.Event()
        self.thread = None
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen()
        self.sock.settimeout(0.5)

        def run():
            while not self.stop_event.is_set():
                try:
                    conn, _addr = self.sock.accept()
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=1)


def monitor_peer(
    peer_name,
    peer_ip,
    port,
    t0_mono,
    max_wait,
    results,
    connected,
    lock,
    stop_event,
):
    deadline = t0_mono + max_wait
    while time.monotonic() < deadline and not stop_event.is_set():
        if tcp_connect(peer_ip, port):
            elapsed = round(time.monotonic() - t0_mono, 3)
            with lock:
                if not connected[peer_name]:
                    connected[peer_name] = True
                    results[peer_name] = elapsed
                    print(f"  [bench] ✓ {peer_name} tcp/{port} reachable at {elapsed:.3f}s")
            return
        time.sleep(POLL_INTERVAL)

    with lock:
        if not connected[peer_name]:
            results[peer_name] = None


def run_measurement_cycle(run_id, up_args, max_wait, port, down_wait):
    print(f"\n{'=' * 60}")
    print(f"Run {run_id} - {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'=' * 60}")

    print("  [tailscale] Bringing interface down")
    down_res = tailscale_down()
    if down_res.stdout.strip():
        print("  [tailscale down][stdout]")
        for line in down_res.stdout.splitlines():
            print(f"    {line}")
    if down_res.stderr.strip():
        print("  [tailscale down][stderr]")
        for line in down_res.stderr.splitlines():
            print(f"    {line}")

    print(f"  [tailscale] Waiting {down_wait}s with tailscale down")
    time.sleep(down_wait)

    t0_mono = time.monotonic()
    print("  [tailscale] Running: tailscale up")
    up_res = tailscale_up(up_args)

    if up_res.stdout.strip():
        print("  [tailscale up][stdout]")
        for line in up_res.stdout.splitlines():
            print(f"    {line}")
    if up_res.stderr.strip():
        print("  [tailscale up][stderr]")
        for line in up_res.stderr.splitlines():
            print(f"    {line}")

    if up_res.returncode != 0:
        print(f"  [bench] tailscale up failed with code {up_res.returncode}")
        return {}

    local_ip = wait_until_local_ip(timeout=30)
    if not local_ip:
        print("  [bench] Could not determine local Tailscale IPv4")
        return {}

    print(f"  [bench] Local Tailscale IP: {local_ip}")

    monitored_peers = {
        name: info for name, info in PEERS.items()
        if info["ip"] != local_ip
    }
    print(f"  [bench] Monitoring {len(monitored_peers)} peers on tcp/{port}")

    results = {name: None for name in monitored_peers}
    connected = {name: False for name in monitored_peers}
    lock = threading.Lock()
    stop_event = threading.Event()
    threads = []

    for peer_name, info in monitored_peers.items():
        t = threading.Thread(
            target=monitor_peer,
            args=(
                peer_name,
                info["ip"],
                port,
                t0_mono,
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
        if all(connected.values()):
            print("  [bench] All monitored peers reachable")
            break
        time.sleep(0.1)

    stop_event.set()
    for t in threads:
        t.join(timeout=1)

    for name, val in results.items():
        if val is None:
            print(f"  [bench] ✗ {name} not reachable on tcp/{port} within {max_wait}s")

    return results


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
        "--out",
        type=str,
        default="/home/results/tailscale_results.csv",
        help="Output CSV file",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_MAX_WAIT,
        help="Max wait per run in seconds",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP port used by the benchmark listener",
    )
    parser.add_argument(
        "--down-wait",
        type=int,
        default=DEFAULT_DOWN_WAIT,
        help="Seconds to wait after tailscale down before tailscale up",
    )
    parser.add_argument(
        "--start-at",
        type=int,
        default=0,
        help="Unix timestamp to start all machines at the same time",
    )
    parser.add_argument(
        "--up-arg",
        action="append",
        default=[],
        help="Extra argument to pass to tailscale up, can be repeated",
    )
    args = parser.parse_args()

    all_results = []
    local_hostname = socket.gethostname()

    if args.start_at > 0:
        now = time.time()
        if args.start_at > now:
            wait_s = args.start_at - now
            print(f"[bench] Waiting {wait_s:.3f}s until start-at {args.start_at}")
            wait_until_epoch(args.start_at)
        else:
            print(f"[bench] start-at {args.start_at} is in the past, starting immediately")

    server = BenchmarkTCPServer(args.port)
    try:
        server.start()
    except OSError as e:
        print(f"[bench] Failed to start local benchmark server on tcp/{args.port}: {e}")
        sys.exit(1)

    print(f"[bench] Local benchmark listener started on tcp/{args.port}")
    print(f"[bench] Hostname: {local_hostname}")

    try:
        for run_id in range(1, args.runs + 1):
            run_timestamp = datetime.now().isoformat()
            res = run_measurement_cycle(
                run_id=run_id,
                up_args=args.up_arg,
                max_wait=args.timeout,
                port=args.port,
                down_wait=args.down_wait,
            )

            for peer, elapsed in res.items():
                all_results.append({
                    "timestamp": run_timestamp,
                    "host": local_hostname,
                    "run": run_id,
                    "peer": peer,
                    "port": args.port,
                    "elapsed": elapsed if elapsed is not None else "",
                    "timeout": elapsed is None,
                })

        out_dir = os.path.dirname(args.out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        file_exists = os.path.isfile(args.out)
        with open(args.out, "a", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["timestamp", "host", "run", "peer", "port", "elapsed", "timeout"],
            )
            if not file_exists:
                writer.writeheader()
            writer.writerows(all_results)

        print(f"\n[bench] Results written to {args.out}")
        if all_results:
            print_summary(all_results)

    finally:
        print("\n[bench] Bringing tailscale down at end")
        tailscale_down()
        server.stop()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Re-running with sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    main()
