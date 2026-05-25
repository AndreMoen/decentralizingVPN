#!/usr/bin/env python3

import argparse
import csv
import itertools
import os
from collections import defaultdict


def fnum(x):
    if x in (None, ""):
        return None
    try:
        return float(x)
    except ValueError:
        return None


def read_rows(paths):
    rows = []
    for path in paths:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                row["source_file"] = os.path.basename(path)
                rows.append(row)
    return rows


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvs", nargs="+", help="CSV files from tor_peer_timer_accurate.py")
    ap.add_argument("--out-directional", default="tor_directional_pair_corrected.csv")
    ap.add_argument("--out-pairs", default="tor_pair_summary.csv")
    args = ap.parse_args()

    rows = read_rows(args.csvs)

    ready = {}
    for r in rows:
        if r.get("row_type") == "startup" and r.get("local_peer") and r.get("ready_unix"):
            key = (r.get("nr"), r.get("run"), r.get("local_peer"))
            ready[key] = fnum(r.get("ready_unix"))

    directional = []
    for r in rows:
        if r.get("row_type") != "handshake":
            continue
        nr = r.get("nr")
        run = r.get("run")
        local = r.get("local_peer")
        remote = r.get("peer")
        local_ready = ready.get((nr, run, local))
        remote_ready = ready.get((nr, run, remote))
        detected = fnum(r.get("handshake_detected_unix"))
        pair_ready = max(x for x in [local_ready, remote_ready] if x is not None) if local_ready is not None and remote_ready is not None else None
        actual = round(detected - pair_ready, 3) if detected is not None and pair_ready is not None else ""
        directional.append({
            "nr": nr,
            "run": run,
            "room": r.get("room"),
            "local_peer": local,
            "remote_peer": remote,
            "local_ready_unix": local_ready if local_ready is not None else "",
            "remote_ready_unix": remote_ready if remote_ready is not None else "",
            "pair_ready_unix": pair_ready if pair_ready is not None else "",
            "handshake_detected_unix": detected if detected is not None else "",
            "elapsed_from_local_ready_s": r.get("elapsed_from_local_ready_s"),
            "actual_pair_elapsed_s": actual,
            "timeout": r.get("timeout"),
            "note": "" if actual != "" else "missing remote ready or handshake timestamp",
            "source_file": r.get("source_file"),
        })

    grouped = defaultdict(list)
    for r in directional:
        pair = tuple(sorted([r["local_peer"], r["remote_peer"]]))
        grouped[(r["nr"], r["run"], pair)].append(r)

    pair_rows = []
    for (nr, run, pair), vals in sorted(grouped.items(), key=lambda x: (x[0][0], int(x[0][1]), x[0][2])):
        times = [fnum(v["actual_pair_elapsed_s"]) for v in vals]
        times = [t for t in times if t is not None]
        pair_rows.append({
            "nr": nr,
            "run": run,
            "peer_a": pair[0],
            "peer_b": pair[1],
            "observations": len(vals),
            "successful_observations": len(times),
            "actual_pair_min_s": round(min(times), 3) if times else "",
            "actual_pair_avg_s": round(sum(times) / len(times), 3) if times else "",
            "actual_pair_max_s": round(max(times), 3) if times else "",
        })

    write_csv(args.out_directional, directional, [
        "nr", "run", "room", "local_peer", "remote_peer",
        "local_ready_unix", "remote_ready_unix", "pair_ready_unix",
        "handshake_detected_unix", "elapsed_from_local_ready_s",
        "actual_pair_elapsed_s", "timeout", "note", "source_file",
    ])
    write_csv(args.out_pairs, pair_rows, [
        "nr", "run", "peer_a", "peer_b", "observations", "successful_observations",
        "actual_pair_min_s", "actual_pair_avg_s", "actual_pair_max_s",
    ])
    print(f"Wrote {args.out_directional}")
    print(f"Wrote {args.out_pairs}")


if __name__ == "__main__":
    main()
