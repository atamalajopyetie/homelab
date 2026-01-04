#!/usr/bin/env python3
import json
import os
import time
import shlex

HISTORY_FILE = os.path.expanduser("~/.bash_history")
OUTPUT_FILE = "execution_events.json"

USER_AUID = "manas"


# ------------------------
# Inline & Chained Detection
# ------------------------

INLINE_FLAGS = {
    "bash": ["-c"],
    "sh": ["-c"],
    "python": ["-c"],
    "python3": ["-c"],
    "node": ["-e"],
    "pwsh": ["-c", "-command"]
}

CHAIN_MARKERS = ["&&", "||", "|", ";"]


def detect_inline(exe, argv):
    exe = exe.lower()
    for runtime, flags in INLINE_FLAGS.items():
        if runtime in exe:
            return any(flag in argv for flag in flags)
    return False


def detect_chained(raw_cmd):
    return any(marker in raw_cmd for marker in CHAIN_MARKERS)


def classify_flags(exe, argv, raw_cmd):
    return {
        "inline": detect_inline(exe, argv),
        "chained": detect_chained(raw_cmd)
    }


# ------------------------
# Event Generation
# ------------------------

events = []

with open(HISTORY_FILE, "r", errors="ignore") as f:
    for line in f:
        raw_cmd = line.strip()
        if not raw_cmd:
            continue

        try:
            argv = shlex.split(raw_cmd)
        except ValueError:
            # malformed command, skip
            continue

        exe = argv[0]

        events.append({
            "timestamp": int(time.time()),  # approximate for history
            "auid": USER_AUID,
            "exe": exe,
            "parent_exe": "bash",
            "tty": "pts",
            "argc": len(argv),
            "argv": argv,
            "raw_cmd": raw_cmd,
            "cmd_flags": classify_flags(exe, argv, raw_cmd)
        })

with open(OUTPUT_FILE, "w") as f:
    json.dump(events, f, indent=2)

print(f"[+] Generated {len(events)} execution events")
