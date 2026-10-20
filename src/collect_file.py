#!/usr/bin/env python3
"""Follow a JSONL source file and append canonical events with a restart offset.

PoC limitations: polling and inode-based rotation detection can miss bytes written
to a renamed old file after rotation. A crash between output fsync and state save
can replay events; consumers should deduplicate by event_id.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from normalize import normalize


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def run(args):
    input_path = Path(args.input)
    output_path = Path(args.output)
    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {"inode": None, "offset": 0}
    while True:
        try:
            stat = input_path.stat()
        except FileNotFoundError:
            if not args.follow:
                raise
            time.sleep(args.interval)
            continue
        if stat.st_ino != state.get("inode") or stat.st_size < state.get("offset", 0):
            state = {"inode": stat.st_ino, "offset": 0}
        with input_path.open("rb") as incoming, output_path.open("a", encoding="utf-8") as outgoing:
            incoming.seek(state["offset"])
            while True:
                start = incoming.tell()
                line = incoming.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # Leave a partial record for the next poll.
                    incoming.seek(start)
                    break
                try:
                    item = json.loads(line)
                    source = args.source or item["source"]
                    raw = item if args.source else item["event"]
                    event = normalize(source, raw, args.host)
                    outgoing.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
                    # Keep the original line and error for review; never print it to stderr.
                    with open(args.rejects, "ab") as rejected:
                        rejected.write(line)
                    print(f"rejected source record at byte {start}: {exc}", file=sys.stderr)
                state["offset"] = incoming.tell()
                save_state(state_path, state)
        if not args.follow:
            return
        time.sleep(args.interval)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", choices=["shell", "docker", "k8s_audit", "auditd", "rootsh", "libvirt", "pve", "containerd"])
    p.add_argument("--host", help="trusted collector host ID")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--rejects", required=True)
    p.add_argument("--follow", action="store_true")
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()
    if args.interval <= 0:
        p.error("--interval must be positive")
    if Path(args.input).resolve() == Path(args.output).resolve():
        p.error("input and output must differ")
    run(args)


if __name__ == "__main__":
    main()
