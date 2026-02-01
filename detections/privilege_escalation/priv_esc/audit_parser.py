#! /usr/bin/env python3


import re
import json
from collections import defaultdict

AUDIT_LOG = "/var/log/audit/audit.log"
OUTPUT_FILE =  "priv_esc_events.json"

# Regex patterns (compiled once)
RE_TIMESTAMP = re.compile(r"audit\((\d+)\.\d+")
RE_PID = re.compile(r"\bpid=(\d+)")
RE_PPID = re.compile(r"\bppid=(\d+)")
RE_AUID = re.compile(r"\bauid=(\d+)")
RE_EUID = re.compile(r"\beuid=(\d+)")
RE_EXE = re.compile(r'exe="([^"]+)"')
RE_KEY = re.compile(r'key="([^"]+)"')
RE_SYSCALL = re.compile(r"syscall=(\d+)")
RE_TTY = re.compile(r'tty=([^\s]+)')
RE_SUCCESS = re.compile(r"success=(yes|no)")
RE_COMM = re.compile(r'comm="([^"]+)"')
RE_EVENT_ID = re.compile(r"audit\(\d+\.\d+:(\d+)\)")

def parse_audit_log(path=AUDIT_LOG):
    """
    Parse audit.log and group records by PID.
    Returns: dict[pid] -> aggregated record
    """
    events = defaultdict(lambda: {
        "event_id": None,
        "timestamp": None,
        "pid": None,
        "ppid": None,
        "auid": None,
        "euid": None,
        "exe": None,
        "audit_keys": set(),

        # debug / forensic
        "syscalls": set(),
        "tty": None,
        "success": None,
        "comm": None,
    })

    with open(path, "r") as f:
        for line in f:
            if "type=SYSCALL" not in line:
                continue

            pid_m = RE_PID.search(line)
            if not pid_m:
                continue

            pid = int(pid_m.group(1))
            event = events[pid]

            # Core identifiers
            event["pid"] = pid

            eid = RE_EVENT_ID.search(line)
            if eid:
                event["event_id"] = int(eid.group(1))

            ts = RE_TIMESTAMP.search(line)
            if ts:
                event["timestamp"] = int(ts.group(1))

            ppid = RE_PPID.search(line)
            if ppid:
                event["ppid"] = int(ppid.group(1))

            auid = RE_AUID.search(line)
            if auid:
                event["auid"] = int(auid.group(1))

            euid = RE_EUID.search(line)
            if euid:
                event["euid"] = int(euid.group(1))

            exe = RE_EXE.search(line)
            if exe:
                event["exe"] = exe.group(1)

            key = RE_KEY.search(line)
            if key:
                event["audit_keys"].add(key.group(1))

            # Debug fields
            syscall = RE_SYSCALL.search(line)
            if syscall:
                event["syscalls"].add(syscall.group(1))

            tty = RE_TTY.search(line)
            if tty and tty.group(1) != "(none)":
                event["tty"] = tty.group(1)

            success = RE_SUCCESS.search(line)
            if success:
                event["success"] = success.group(1) == "yes"

            comm = RE_COMM.search(line)
            if comm:
                event["comm"] = comm.group(1)

    return events

def save_event(events,output_file=OUTPUT_FILE):
    serializable = {}

    for pid, event in events.items():
        serializable[pid] =  {
            **event,
            "audit_keys": list(event["audit_keys"]),
            "syscalls": list(event["syscalls"]),
        }

    with open(output_file, "w") as f:
        json.dump(serializable, f, indent=4)

    print(f"[+] Saved {len(serializable)} raw audit events -> {output_file}")

if __name__ == "__main__":
    events = parse_audit_log()
    save_event(events)
