#!/usr/bin/env python3
import json
import os
from datetime import datetime

BASELINE_FILE = "execution_baseline.json"
EVENT_FILE = "execution_events.json"
SHADOW_FILE = "execution_shadow.json"

USER_AUID = "manas"


# ------------------------
# Utilities
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
    return datetime.fromtimestamp(int(ts)).hour


# ------------------------
# Feature Extraction
# ------------------------

def extract_interpreter(exe):
    exe = exe.lower()

    if exe.endswith(("bash", "sh")):
        return "bash"
    if "python" in exe or exe.endswith(".py"):
        return "python"
    if exe.endswith("node") or exe.endswith(".js"):
        return "node"
    if exe.endswith("pwsh"):
        return "pwsh"

    return exe.split("/")[-1]


def build_parent_chain(event):
    return f"{event['parent_exe']}->{event['exe']}"


# ------------------------
# Score Buckets
# ------------------------

def score_range(score):
    if score < 1.5:
        return "normal"
    if score < 3:
        return "observe"
    if score < 5:
        return "clear_anomaly"
    if score < 7:
        return "strong_anomaly"
    return "extreme"


# ------------------------
# Shadow Scoring Logic
# ------------------------

def score_event(event, baseline):
    score = 0.0
    signals = []

    # --- A. Temporal deviation ---
    hour = hour_from_ts(event["timestamp"])
    hour_freq = baseline["temporal"]["active_hours"].get(str(hour), 0)

    if hour_freq == 0:
        score += 1.5
        signals.append("extremely_rare_hour")
    elif hour_freq < 3:
        score += 1.0
        signals.append("rare_hour")

    # --- B. Parent → Child chain ---
    chain = build_parent_chain(event)
    chain_freq = baseline["execution_context"]["common_parent_chains"].get(chain, 0)

    if chain_freq == 0:
        score += 2.5
        signals.append("new_parent_chain")
    elif chain_freq < 3:
        score += 1.5
        signals.append("rare_parent_chain")

    # --- C. Interpreter novelty ---
    interpreter = extract_interpreter(event["exe"])
    interp_freq = baseline["interpreters"].get(interpreter, 0)

    if interp_freq == 0:
        score += 2.0
        signals.append("new_interpreter")
    elif interp_freq < 5:
        score += 1.0
        signals.append("rare_interpreter")

    # --- D. Command shape ---
    inline = event["cmd_flags"].get("inline", False)
    chained = event["cmd_flags"].get("chained", False)

    if inline and chained:
        score += 1.5
        signals.append("inline_and_chained")
    elif inline or chained:
        score += 1.0
        signals.append("compressed_command")

    # --- E. Sudo context anomaly ---
    if event["exe"].endswith("sudo"):
        category = event.get("tool_category", "other")
        cat_freq = baseline["sudo_profile"]["tool_categories"].get(category, 0)

        if cat_freq == 0:
            score += 1.5
            signals.append("new_sudo_category")

        # escalation after prior anomaly
        if score >= 3:
            score += 1.0
            signals.append("sudo_after_anomaly")

    return round(score, 2), signals


# ------------------------
# Main
# ------------------------

def main():
    baseline = load_json(BASELINE_FILE, {})
    events = load_json(EVENT_FILE, [])
    shadow_events = load_json(SHADOW_FILE, [])

    last_shadow_ts = int(baseline["baseline_meta"].get("last_shadow_ts", 0))
    max_ts_seen = last_shadow_ts
    scored = 0

    for event in events:
        if event["auid"] != USER_AUID:
            continue

        ts = int(event["timestamp"])
        if ts <= last_shadow_ts:
            continue

        score, signals = score_event(event, baseline)

        shadow_events.append({
            "event_type": "execution_shadow",
            "timestamp": ts,
            "user": USER_AUID,
            "score": score,
            "range": score_range(score),
            "signals": signals
        })

        scored += 1
        max_ts_seen = max(max_ts_seen, ts)

    baseline["baseline_meta"]["last_shadow_ts"] = max_ts_seen
    baseline["baseline_meta"]["last_shadow_run_at"] = datetime.now().isoformat()

    save_json(SHADOW_FILE, shadow_events)
    save_json(BASELINE_FILE, baseline)

    if scored > 0:
        print(f"[+] Shadow scored {scored} new events")
    else:
        print("[=] Shadow run completed (no new events)")


if __name__ == "__main__":
    main()
