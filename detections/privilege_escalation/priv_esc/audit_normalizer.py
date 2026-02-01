#! /usr/bin/env python3

import json

INPUT_FILE =  "priv_esc_events.json"
OUTPUT_FILE =  "privesc_candidates.json"
STATE_FILE = ".last_event_id"

def is_privilege_boundary(event):
    """
    Confirm a user → root privilege boundary crossing.
    """
    auid = event.get("auid")
    euid = event.get("euid")
    audit_keys =  event.get("audit_keys", [])

    if euid != 0:
        return False

    if auid is None or auid == 4294967295:
        return False

    if not (
        "sudo_exec" in audit_keys or
        "pkexec_exec" in audit_keys or
        "uid_change" in audit_keys or
        "root_exec" in audit_keys
    ):
        return False

    return True

def load_last_event_id():
    try:
        with open(STATE_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0

def save_last_event_id(event_id):
    with open(STATE_FILE, "w") as f:
        f.write(str(event_id))

def resolve_mechanism(event):
    """
    Determine escalation mechanism from audit keys.
    """
    exe = event.get("exe", "")
    audit_keys = event.get("audit_keys", [])
    syscalls = set(event.get("syscalls", []))

    if "pkexec_exec" in audit_keys or exe.endswith("/pkexec"):
        return "pkexec"
    if "sudo_exec" in audit_keys or exe.endswith("/sudo"):
        return "sudo"
    if "root_exec" in audit_keys:
        return "root_exec"
    UID_SYSCALLS = {
        "105", #setuid
        "106", #setgid
        "113", #setreuid
        "114", #setregid
        "117", #setresuid
        "119", #setresgid
    }

    if syscalls & UID_SYSCALLS:
        return "uid_transition"

    return "implicit"


def load_parsed_events(path=INPUT_FILE):
    with open(path, "r") as f:
        return json.load(f)

def build_privesc_candidates(events):
    candidates = []

    last_event_id = load_last_event_id()
    max_event_id = last_event_id

    for event in events.values():

        eid = event.get("event_id")

        # events without identity are skipped
        if eid is None:
            continue

        # de-duplication logic
        if eid <= last_event_id:
            continue

        # if does not cross privilege boundary then skip
        if not is_privilege_boundary(event):
            continue

        mechanism = resolve_mechanism(event)
        rank = rank_events(event, mechanism)

        candidates.append({
            "event_type": "privesc_candidate",
            "event_id": eid,
            "timestamp": event["timestamp"],
            "pid": event["pid"],
            "ppid": event["ppid"],
            "auid": event["auid"],
            "euid": event["euid"],
            "exe": event["exe"],
            "mechanism": mechanism,
            "rank": rank,
            "audit_keys": list(event["audit_keys"]),

            # execution context (added later)
            "execution_context": None,

            # debug / forensic
            "debug": {
                "syscalls": list(event["syscalls"]),
                "tty": event["tty"],
                "success": event["success"],
                "comm": event["comm"]
            }
        })

        if eid > max_event_id:
            max_event_id = eid

    save_last_event_id(max_event_id)
    return candidates

def rank_events(event, mechanism):
    """
    event risk ranking - asking is 'how risky is this?' (per event)
    """
    exe = event.get("exe", "")
    tty =  event.get("tty")
    audit_keys = event.get("audit_keys", [])

    if mechanism in ("pkexec", "uid_transition", "root_exec"):
        return 4

    if mechanism == "sudo" and tty is None:
        return 3

    if mechanism == "sudo" and "sudo_exec" not in audit_keys:
        return 2

    if mechanism == "sudo" and "sudo_exec" in audit_keys:
        return 1

    return 2

def save_candidates(candidates, output_file=OUTPUT_FILE):
    with open(output_file, "w") as f:
        json.dump(candidates, f, indent=4)

    print(f"[+] Saved {len(candidates)} privesc detections -> {output_file}")
if __name__ == "__main__":
    parsed_events = load_parsed_events()
    candidates = build_privesc_candidates(parsed_events)
    save_candidates(candidates)

