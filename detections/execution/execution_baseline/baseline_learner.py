#!/usr/bin/env python3
import json
import os
from datetime import datetime
from collections import defaultdict

BASELINE_FILE = "execution_baseline.json"
EVENT_FILE = "execution_events.json"

USER_AUID = "" #your auid ex - karan {yourname}

SYSTEM_DAEMONS = {
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/usr/sbin/cron"
}

#-------------------------
#Rehydrate baseline
#-------------------------
def rehydrate_baseline(baseline):
    baseline["temporal"]["active_hours"] = defaultdict(
        int, baseline["temporal"].get("active_hours", {})
    )

    baseline["execution_context"]["common_parent_chains"] = defaultdict(
        int, baseline["execution_context"].get("common_parent_chains", {})
    )

    baseline["interpreters"] = defaultdict(
        int, baseline.get("interpreters", {})
    )

    baseline["sudo_profile"]["tool_categories"] = defaultdict(
        int, baseline["sudo_profile"].get("tool_categories", {})
    )

    baseline["baseline_meta"]["last_processed_ts"] = int(
        baseline["baseline_meta"].get("last_processed_ts", 0)
    )

    return baseline


# ------------------------
# Utility
# ------------------------

def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def hour_from_ts(ts):
    return datetime.fromtimestamp(ts).hour

# ------------------------
# Classification Helpers
# ------------------------

def classify_interpreter(exe):
    if exe.endswith("bash") or exe.endswith("sh"):
        return "bash"
    if "python" in exe or exe.endswith(".py"):
        return "python"
    if exe.endswith("node") or exe.endswith(".js"):
        return "node"
    if exe.endswith("pwsh"):
        return "pwsh"
    return "other"

def is_sudo(exe):
    return exe.endswith("sudo")

def classify_tool_category(exe):
    if exe.endswith(("nano", "vim")):
        return "editor"
    if exe.endswith("systemctl"):
        return "service_control"
    if exe.endswith(("auditctl", "ausearch")):
        return "security_tool"
    if exe.endswith("VBoxManage"):
        return "virtualization"
    return "other"

def parent_chain(parent, exe):
    return f"{os.path.basename(parent)}->{os.path.basename(exe)}"

# ------------------------
# Learning Gate
# ------------------------

def eligible_for_learning(event, baseline):
    event_ts = int(event["timestamp"])
    if event["auid"] != USER_AUID:
        return False
    if event["tty"] in (None, "(none)"):
        return False
    if event["exe"] in SYSTEM_DAEMONS:
        return False
    if baseline["baseline_meta"]["mode"] != "learning":
        return False
    if event_ts <= baseline["baseline_meta"]["last_processed_ts"]:
        return False
    return True

# ------------------------
# Baseline Initialization
# ------------------------

def init_baseline():
    return {
        "baseline_meta": {
            "mode": "learning",
            "confidence": 0.3,
            "created_at": datetime.now().isoformat(),
            "last_updated": None,
            "last_processed_ts": 0,
            "last_run_at": None,
            "last_learned_ts": 0,
            "last_learned_count": 0
        },
        "temporal": {
            "active_hours": defaultdict(int)
        },
        "execution_context": {
            "tty_events": 0,
            "total_events": 0,
            "common_parent_chains": defaultdict(int)
        },
        "interpreters": defaultdict(int),
        "sudo_profile": {
            "sudo_events": 0,
            "tool_categories": defaultdict(int)
        },
        "command_shape": {
            "total": 0,
            "inline_exec": 0,
            "chained": 0
        }
    }

# ------------------------
# Learning Logic
# ------------------------

def learn_event(event, baseline):
    hour = hour_from_ts(event["timestamp"])
    baseline["temporal"]["active_hours"][hour] += 1

    baseline["execution_context"]["total_events"] += 1
    baseline["execution_context"]["tty_events"] += 1

    chain = parent_chain(event["parent_exe"], event["exe"])
    baseline["execution_context"]["common_parent_chains"][chain] += 1

    interpreter = classify_interpreter(event["exe"])
    baseline["interpreters"][interpreter] += 1

    if is_sudo(event["exe"]):
        baseline["sudo_profile"]["sudo_events"] += 1
        category = classify_tool_category(event["parent_exe"])
        baseline["sudo_profile"]["tool_categories"][category] += 1

    baseline["command_shape"]["total"] += 1
    if event["cmd_flags"]["inline"]:
        baseline["command_shape"]["inline_exec"] += 1
    if event["cmd_flags"]["chained"]:
        baseline["command_shape"]["chained"] += 1

# ------------------------
# Main
# ------------------------

def main():
    baseline = load_json(BASELINE_FILE, init_baseline())
    baseline = rehydrate_baseline(baseline)
    events = load_json(EVENT_FILE, [])
    max_ts_seen = baseline["baseline_meta"]["last_processed_ts"]
    learned_count = 0

    for event in events:
        if eligible_for_learning(event, baseline):
            learn_event(event, baseline)
            learned_count += 1
            if event["timestamp"] > max_ts_seen:
                max_ts_seen = event["timestamp"]

    baseline["baseline_meta"]["last_run_at"] = datetime.now().isoformat()

    if learned_count > 0:
        baseline["baseline_meta"]["last_processed_ts"] = max_ts_seen
        baseline["baseline_meta"]["last_learned_ts"] = max_ts_seen
        baseline["baseline_meta"]["last_learned_count"] = learned_count

        baseline["baseline_meta"]["confidence"] = min(
            baseline["baseline_meta"]["confidence"] + 0.01, 1.0
        )

        baseline["baseline_meta"]["last_updated"] = datetime.now().isoformat()

        print(f"[+] Baseline learned {learned_count} new events")

    else:
        baseline["baseline_meta"]["last_learned_count"] = 0
        print("[=] Baseline run completed (no new events)")

    save_json(BASELINE_FILE, baseline)
if __name__ == "__main__":
    main()
