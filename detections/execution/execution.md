# Execution Detection — Command & Scripting Interpreters (TA0002)

## 1. Purpose

Execution is the stage where authenticated access is converted into action.

After a successful login, both legitimate users and attackers:
- spawn processes
- execute commands
- use interpreters and administrative utilities

At this stage, intent is ambiguous.

This detection stage **does not attempt to decide whether activity is malicious**.  
Instead, it measures **how far execution behavior deviates from what is normal for the user**.

The output of this stage is **behavioral context**, not alerts.

## 2. Why Execution Matters

Execution is the pivot point where:
- attacker activity blends with legitimate administrative behavior
- visibility rapidly drops without behavioral context

Poor execution visibility results in:
- missed privilege escalation
- undetected persistence setup
- weak correlation with network activity

Execution detection provides:
- execution flow awareness
- behavioral baselines
- correlation anchors for later ATT&CK tactics

## 3. Threats Covered

This stage focuses on **command and scripting interpreter abuse**, not exploitation.

### In-Scope Behaviors
- Shell-based command execution
- Script execution via interpreters
- Abnormal parent → child execution chains
- Inline command execution
- Chained command execution
- Sudo usage in unusual execution contexts

### Out-of-Scope
- Credential theft
- Authentication events
- Vulnerability exploitation
- Persistence mechanisms
- Network-based command delivery

These are handled by other ATT&CK tactics.

## 4. Detection Philosophy

Execution detection is **behavioral and contextual**.

An executed command is **not malicious by default**.

Principles:
- No signatures
- No allow/deny logic
- No blocking
- No alerts

Instead:
- behavior is compared against a baseline
- deviations are scored
- context is preserved for later correlation

This stage produces **evidence**, not verdicts.

## 5. Data Source

### Current Implementation
- `.bash_history` (user shell history)

This is used as a **bootstrap data source**.

### Design Compatibility
The pipeline is designed around execution semantics (`execve`-like fields).  
Kernel-level telemetry (e.g., `auditd`) is **not used in the current implementation**,  
but the logic is compatible with such sources without redesign.

## 6. Normalization Layer

Raw shell commands are converted into structured execution events.

### Normalized Event Structure

    {
      "timestamp": 1767034001,
      "auid": "manas",
      "exe": "sudo",
      "argv": ["sudo", "systemctl", "restart", "ssh"],
      "parent_exe": "bash",
      "tty": "pts",
      "argc": 4,
      "cmd_flags": {
        "inline": false,
        "chained": false
      }
    }

**NOTE - this is a sample event**

Why Normalization Is Required
- Raw command strings are inconsistent
- Parsing logic should not be duplicated
- Detection should operate on features, not text

All downstream components consume normalized events only.

## 7. Baseline Model

Execution detection relies on a learned behavioral baseline.

### The baseline models:

- Active execution hours
- Common parent → child execution chains
- Interpreter usage frequency
- Sudo usage context
- Command shape characteristics

### Baseline Properties

The baseline is:
- Incrementally learned
- Protected by a timestamp watermark
- Single-user scoped
- Safe for scheduled execution

The baseline learns what is normal, not what is safe.

## 8. Shadow Anomaly Scoring

Definition

Shadow scoring answers one question only:
How far does this execution event deviate from my baseline?

### It does NOT:
- declare compromise
- generate alerts
- block execution

It acts as a behavioral distance metric.

## 9. Shadow Score Ranges

| Score Range | Meaning            | Operational Use                  |
|-------------|--------------------|----------------------------------|
| 0 – 1.5     | Normal             | Ignore                           |
| 1.5 – 3     | Mild deviation     | Observe                          |
| 3 – 5       | Clear anomaly      | Tag for correlation              |
| 5 – 7       | Strong anomaly     | High-interest                    |
| 7+          | Extreme            | Prioritize for investigation     |


Most execution events should fall within 0–2.

## 10. Scoring Logic (Behavioral Signals)

Shadow scoring evaluates execution behavior across five dimensions.

### A. Temporal Deviation

Execution during hours that are rare or absent in the baseline.
Low weight to avoid penalizing flexible schedules.

### B. Parent → Child Chain Novelty

Measures execution flow rarity.

Examples:
- bash → sudo (common)
- python → sudo (less common)
- curl → bash (highly unusual)

Strong signal.

### C. Interpreter Novelty

Measures how frequently an interpreter is used.
- Common interpreter → low score
- Rare interpreter → moderate score
- First-time interpreter → higher score

Derived from baseline statistics, not hardcoded rules.

### D. Command Shape

Detects compressed execution patterns:
- Inline execution (-c, -e)
- Chained commands (&&, ||, |, ;)
- Dense one-liners

Attackers compress intent; humans usually do not.

### E. Sudo Context Shift

Sudo itself is not scored.

Scoring evaluates:
- Rare sudo tool categories
- Sudo usage following prior anomalies

Avoids penalizing legitimate admin behavior.

## 11. Shadow Output Format

Shadow scoring emits non-alerting context events:


    {
      "event_type": "execution_shadow",
      "timestamp": 1767034001,
      "user": "manas",
      "score": 4.8,
      "range": "clear_anomaly",
      "signals": [
        "rare_hour",
        "new_parent_chain",
        "inline_exec"
      ]
    }
**NOTE - this is a sample event**

These events are used for:
- Privilege Escalation correlation
- Persistence correlation
- Command & Control correlation

## 12. Implementation Components

Each script has one responsibility only.

### [history_to_events.py — Execution Normalization](https://github.com/atamalajopyetie/homelab/blob/main/detections/execution/execution_baseline/history_to_events.py "history_to_events.py — Execution Normalization")
Purpose
Converts raw shell history into normalized execution events.

Responsibilities
- Read .bash_history
- Extract executable and arguments
- Determine argument count
- Detect inline and chained execution
- Emit structured execution events

Output
- execution_events.json

### [baseline_learner.py — Execution Baseline Learning](https://github.com/atamalajopyetie/homelab/blob/main/detections/execution/execution_baseline/baseline_learner.py "### baseline_learner.py — Execution Baseline Learning")
Purpose
Learns normal execution behavior for a single user.

Responsibilities
- Learn execution timing patterns
- Learn parent → child execution chains
- Learn interpreter usage frequency
- Learn sudo usage context
- Maintain learning watermark
- Prevent duplicate learning

Output
- execution_baseline.json

### [shadow_scorer.py — Execution Shadow Scoring](https://github.com/atamalajopyetie/homelab/blob/main/detections/execution/execution_baseline/shadow_execution_scorer.py "shadow_scorer.py — Execution Shadow Scoring")
Purpose
Scores execution events based on deviation from baseline.

Responsibilities
- Read execution events
- Read execution baseline
- Compute anomaly score
- Assign severity range
- Emit shadow execution events

Characteristics
- No learning
- No alerts
- No blocking
- No baseline modification

Output
- execution_shadow.json

### [run_learner.sh — Learning Orchestration](https://github.com/atamalajopyetie/homelab/blob/main/detections/execution/execution_baseline/run_learning.sh "run_learner.sh — Learning Orchestration")
Purpose
Provides a cron-safe execution wrapper.

Responsibilities
- Execute normalization
- Execute baseline learning
- Ensure consistent environment
- Redirect logs safely

## 13. Validation Method

Execution detection is validated using:
- Normal daily usage
- Administrative commands
- Script execution
- Controlled anomalous command patterns

Validation confirms:
- Normal behavior scores low
- Anomalies cluster correctly
- No alert spam occurs\

## 14. Limitations

This stage does NOT detect:
- Malware payloads
- Exploitation techniques
- Network-based command-and-control
- Persistence mechanisms

These are addressed by later ATT&CK tactics.

## 15. Key Takeaways

Execution ≠ malicious
Deviation ≠ alert
Context enables correlation
Shadow scoring enables reasoning
