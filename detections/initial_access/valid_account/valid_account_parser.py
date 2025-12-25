#!/usr/bin/env python3

import re
import json
import yaml
import time
import ipaddress
import subprocess
from pathlib import Path
from datetime import datetime

# =========================
# PATHS
# =========================
BASE_DIR = Path(__file__).resolve().parent

BASELINE_FILE = BASE_DIR / "valid_account_baseline.yaml"
STATE_FILE = BASE_DIR / "state.json"
EVENTS_FILE = BASE_DIR / "events.json"

AUTH_LOG = "/var/log/auth.log"
FAILURE_WINDOW_SECONDS = 600  # 10 minutes

# =========================
# LOAD BASELINE & STATE
# =========================
def load_baseline():
    with open(BASELINE_FILE, "r") as f:
        return yaml.safe_load(f)["baseline"]

def load_state():
    if not STATE_FILE.exists():
        return {"last_login_ts": None, "recent_failures": []}

    with open(STATE_FILE, "r") as f:
        state = json.load(f)

    if "last_login_ts" not in state:
        state["last_login_ts"] = None
    if "recent_failures" not in state:
        state["recent_failures"] = []

    return state

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# =========================
# UTILITIES
# =========================
def ip_in_known_ranges(ip, ranges):
    ip_obj = ipaddress.ip_address(ip)
    for cidr in ranges:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False

def get_active_sessions():
    try:
        out = subprocess.check_output(["who"], text=True)
        return len(out.strip().splitlines())
    except Exception:
        return 0

def parse_log_time(line):
    # Example: "Sep 20 14:32:01"
    first_token = line.split()[0]

    if first_token[0:4].isdigit() and "T" in first_token:
        try:
            dt = datetime.fromisoformat(first_token)
            return int(dt.timestamp())
        except ValueError:
            pass

    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    parts = line.split()
    month = months[parts[0]]
    day = int(parts[1])
    h, m, s = map(int, parts[2].split(":"))

    now = datetime.now()
    dt = datetime(
        year=now.year,
        month=month,
        day=day,
        hour=h,
        minute=m,
        second=s,
    )

    return int(dt.timestamp())
#================
# REGEX PATTERNS
# =========================
SUCCESS_RE = re.compile(
    r"Accepted (password|publickey) for (\w+) from ([0-9.]+)"
)

FAIL_RE = re.compile(
    r"(Failed password|Invalid user).* from ([0-9.]+)"
)

# =========================
# PARSE AUTH LOG
# =========================
def parse_auth_log():
    events = []

    with open(AUTH_LOG, "r") as f:
        for line in f:
            success = SUCCESS_RE.search(line)
            if success:
                method, user, ip = success.groups()
                ts = parse_log_time(line)
                events.append(("success", user, method, ip, ts))
                continue

            fail = FAIL_RE.search(line)
            if fail:
                ip = fail.group(2)
                ts = parse_log_time(line)
                events.append(("failure", None, None, ip, ts))

    return events

# =========================
# SCORING
# =========================
def calculate_risk(signals):
    score = 0

    if signals["time_anomaly"]:
        score += 1
    if signals["new_ip"]:
        score += 3
    if signals["auth_password"]:
        score += 2
    if signals["dormant_account"]:
        score += 2
    if signals["concurrent_session"]:
        score += 3
    if signals["fail_then_success"]:
        score += 3
    if signals["failure_burst"]:
        score += 2

    if score >= 7:
        level = "HIGH"
    elif score >= 5:
        level = "LIKELY"
    elif score >= 3:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return score, level

# =========================
# MAIN
# =========================
def main():
    baseline = load_baseline()
    state = load_state()

    now = int(time.time())
    login_hour = time.localtime().tm_hour

    events = parse_auth_log()

    for evt in events:
        if evt[0] == "failure":
            _, _, _, ip, ts = evt
            state["recent_failures"].append({
                "timestamp": ts,
                "src_ip": ip
            })

        if evt[0] == "success":
            user, method, ip, event_ts = evt[1], evt[2], evt[3], evt[4]

            # ---- DEDUPLICATION ----
            if state["last_login_ts"] is not None:
                if event_ts <= state["last_login_ts"]:
                    continue

            # Trim old failures
            state["recent_failures"] = [
                f for f in state["recent_failures"]
                if now - f["timestamp"] <= FAILURE_WINDOW_SECONDS
            ]

            fail_then_success = len(state["recent_failures"]) > 0

            signals = {
                "time_anomaly": not (
                    baseline["login_hours"]["start"]
                    <= login_hour
                    < baseline["login_hours"]["end"]
                ),
                "new_ip": not ip_in_known_ranges(ip, baseline["known_ips"]),
                "auth_password": method == "password",
                "dormant_account": (
                    state["last_login_ts"] is not None
                    and now - state["last_login_ts"] > 7 * 86400
                ),
                "concurrent_session": (
                    get_active_sessions()
                    > baseline["expected_concurrent_sessions"]
                ),
                "fail_then_success": fail_then_success,
                "failure_burst": (
                    len(state["recent_failures"]) >= 3
                    and not fail_then_success
                ),
            }

            score, level = calculate_risk(signals)

            event = {
                "event_type": "initial_access",
                "timestamp": event_ts,
                "user": user,
                "src_ip": ip,
                "auth_method": method,
                "signals": signals,
                "risk_score": score,
                "risk_level": level
            }

            with open(EVENTS_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")

            # Update state
            state["last_login_ts"] = event_ts
            state["recent_failures"] = []

    save_state(state)

# =========================
if __name__ == "__main__":
    main()
