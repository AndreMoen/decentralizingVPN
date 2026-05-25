#!/usr/bin/env python3

import argparse
import csv
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

BASE_ROOM = "secret-meeting-room-123"
RUN_INTERVAL_SECONDS = 300
PREP_BEFORE_SECONDS = 90

CSV_FIELDS = [
    "timestamp",
    "run",
    "nr",
    "room",
    "slot_start_unix",
    "slot_start_iso",
    "process_start_unix",
    "process_start_iso",
    "ready_unix",
    "ready_iso",
    "startup_s",
    "ready_before_slot_s",
    "timeout",
    "note",
]


def iso_utc(ts: float | int | None) -> str:
    if ts is None or ts == "":
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def kill_existing(iface: str):
    subprocess.run(["pkill", "-f", "torpunch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "go-build.*torpunch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "del", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)


def build_binary(src_dir: str, out_bin: str):
    print(f"[build] Building binary from {src_dir} -> {out_bin}")
    r = subprocess.run(["go", "build", "-o", out_bin, "."], cwd=src_dir)
    if r.returncode != 0:
        print("[build] FAILED")
        sys.exit(1)
    print("[build] OK")


def next_slot_start(now: float, interval: int) -> int:
    return ((int(now) // interval) + 1) * interval


def wait_until(target_ts: float):
    while True:
        remaining = target_ts - time.time()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1.0))


def terminate_process(proc):
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


def append_host_row(path: str, row: dict):
    if not path:
        return
    out_dir = os.path.dirname(path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    file_exists = os.path.isfile(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
        f.flush()
        os.fsync(f.fileno())


def run_host(binary: str, room: str):
    env = {**os.environ, "ROOM": room}
    process_start_unix = time.time()
    process_start_mono = time.monotonic()
    proc = subprocess.Popen(
        [binary],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    ready_event = threading.Event()
    state = {
        "process_start_unix": process_start_unix,
        "process_start_mono": process_start_mono,
        "ready_unix": "",
        "ready_mono": None,
    }

    def watch_stdout():
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip()
            print(f"  [host-vpn] {line}")
            lower = line.lower()
            if ("registered" in lower or "bootstrapped 100%" in lower) and state["ready_mono"] is None:
                state["ready_mono"] = time.monotonic()
                state["ready_unix"] = time.time()
                print(f"  [host] onion ready at {iso_utc(state['ready_unix'])}")
                ready_event.set()

    threading.Thread(target=watch_stdout, daemon=True).start()
    return proc, ready_event, state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--nr", type=int, default=0)
    parser.add_argument("--src", type=str, default=".")
    parser.add_argument("--binary", type=str, default="./torpunch")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=RUN_INTERVAL_SECONDS)
    parser.add_argument("--prep-seconds", type=int, default=PREP_BEFORE_SECONDS)
    parser.add_argument("--iface", type=str, default="wg0")
    parser.add_argument("--out", type=str, default="/home/results/onion_host_resultsTor.csv")
    args = parser.parse_args()

    if not args.no_build:
        build_binary(args.src, args.binary)

    current_proc = None

    def shutdown(sig, frame):
        print("\n[host] shutting down")
        terminate_process(current_proc)
        kill_existing(args.iface)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    first_slot = next_slot_start(time.time(), args.interval_seconds)

    for run_id in range(1, args.runs + 1):
        slot_start = first_slot + (run_id - 1) * args.interval_seconds
        prep_time = slot_start - args.prep_seconds
        teardown_time = slot_start + args.interval_seconds - args.prep_seconds
        room = f"{BASE_ROOM}-{args.nr}-run{run_id}"

        print("\n" + "=" * 60)
        print(f"[host] Run {run_id}")
        print(f"[host] Room: {room}")
        print(f"[host] Start at UTC: {iso_utc(prep_time)}")
        print(f"[host] Slot UTC: {iso_utc(slot_start)} to {iso_utc(slot_start + args.interval_seconds)}")
        print(f"[host] Tear down at UTC: {iso_utc(teardown_time)}")
        print("=" * 60)

        if time.time() < prep_time:
            wait_until(prep_time)
        else:
            print("[host] Starting immediately")

        terminate_process(current_proc)
        current_proc = None
        kill_existing(args.iface)

        current_proc, ready_event, state = run_host(args.binary, room)

        ready_deadline = slot_start
        while time.time() < ready_deadline:
            if ready_event.is_set():
                print("[host] Onion ready before peer slot")
                break
            if current_proc.poll() is not None:
                print("[host] Process exited early")
                break
            time.sleep(0.2)

        ready_unix = state["ready_unix"]
        startup_s = ""
        ready_before_slot_s = ""
        timeout = not bool(ready_unix)
        note = ""
        if ready_unix:
            startup_s = round(float(ready_unix) - float(state["process_start_unix"]), 3)
            ready_before_slot_s = round(slot_start - float(ready_unix), 3)
            if ready_before_slot_s < 0:
                note = "host became ready after peer slot started"
        else:
            note = "host did not become ready before peer slot"

        append_host_row(
            args.out,
            {
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "run": run_id,
                "nr": args.nr,
                "room": room,
                "slot_start_unix": slot_start,
                "slot_start_iso": iso_utc(slot_start),
                "process_start_unix": state["process_start_unix"],
                "process_start_iso": iso_utc(state["process_start_unix"]),
                "ready_unix": ready_unix,
                "ready_iso": iso_utc(ready_unix),
                "startup_s": startup_s,
                "ready_before_slot_s": ready_before_slot_s,
                "timeout": timeout,
                "note": note,
            },
        )

        if time.time() < teardown_time:
            print(f"[host] Holding until UTC {iso_utc(teardown_time)}")
            wait_until(teardown_time)

        print(f"[host] Stopping at UTC {iso_utc(teardown_time)}")
        terminate_process(current_proc)
        current_proc = None
        kill_existing(args.iface)

    terminate_process(current_proc)
    kill_existing(args.iface)
    print("[host] Done")


if __name__ == "__main__":
    main()
