#!/bin/bash
set -e

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root

BASE_DIR="/opt/execution_baseline"

cd "$BASE_DIR"

/usr/bin/python3 history_to_events.py
/usr/bin/python3 baseline_learner.py
