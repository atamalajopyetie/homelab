# Privilege Escalation (TA0004) — Design & Implementation Summary

## Objective

Design and implement Privilege Escalation (TA0004) detection as a deterministic, kernel-truth–based stage, aligned with MITRE ATT&CK, and runs with cron. Integrated cleanly into a multi-stage detection pipeline.The goal was to rank "riskyness", but to emit high-fidelity facts that can be correlated later.

## Why Privilege Escalation Matters

Privilege Escalation is one of the most critical stages in a cyber attack lifecycle because it marks the transition from limited access to full system control.

PrivEsc Is the Security Boundary
- Operating system protections are effectively bypassed
- The attacker can control any part of the system

PrivEsc Enables All High-Impact Actions
- Most users do not escalate privileges frequently (unlike me, my defination of prilege is different than yours)
- Because it is rare, PrivEsc events have: low noise, high signal value

Kernel-Level PrivEsc Detection Is Trustworthy
- Cannot be bypassed by shell tricks
- Is independent of user behavior
- Reflects what actually happened, not what was typed

PrivEsc Is the Bridge Between Execution and Persistence

##  Threats Covered

### Scope 
1. Unauthorized Sudo Usage
examples:
 - Compromised user account abusing sudo
 - Malicious scripts invoking sudo
 - Insider misuse of elevated privileges

2. PolicyKit (pkexec) Privilege Escalation
examples
 -  Exploitation of pkexec vulnerabilities
 - Misconfigured PolicyKit rules
 - Abuse of graphical privilege prompts

3. Setuid / UID Transition Abuse
 examples
   -  Exploitation of vulnerable setuid binaries
   - Unexpected UID transitions in user processes
   - Local privilege escalation exploits

4. Direct Root Execution by Non-Root Context
examples
   -  Misconfigured binaries executing as root
   - Execution through unsafe wrappers
   - Privilege boundary bypasses

5. Non-Interactive Privilege Escalation
examples
   -   Automated attack scripts
   
### Out of scope
This component does not attempt to detect:
- Persistence mechanisms (cron, systemd services)
- Confused-deputy attacks via trusted root services
- Post-root lateral movement
- Kernel-level exploits
- Multi-stage or time-correlated attacks
- Network-based privilege escalation

These require separate detectors or correlation layers.

## Detection Philosophy
This detector focuses on explicit privilege escalation primitives observed at execution time.
It prioritizes high-signal, explainable events over behavioral inference or correlation.

The system:
- Detects what actually happened, not intent
- Uses deterministic audit signals, not heuristics
- Assigns risk ranks instead of making binary judgments
- Avoids noise by scoping detection to known escalation mechanisms

## Data Source and Parsed Event Structure
### Data Source
The detector uses Linux auditd logs as its sole data source, specifically:
/var/log/audit/audit.log
Only type=SYSCALL records related to execution and UID transitions are processed.

### Parsed Event Structure (Raw)
Each audit record is parsed and normalized into a structured JSON object before detection logic is applied.
Example (raw parsed event):
    {
      "event_id": 48192,
      "timestamp": 1768900331,
      "pid": 13499,
      "ppid": 3589,
      "auid": 1000,
      "euid": 0,
      "exe": "/usr/bin/sudo",
      "audit_keys": ["execve", "uid_change"],
      "syscalls": ["59", "117"],
      "tty": "pts0",
      "success": true,
      "comm": "sudo"
    }
    
At this stage:
- No security judgment is made
- Events are only structured and deduplicable
- Multiple syscall records may be aggregated per PID

## Normalization & Candidate Generation
Normalization Logic
- Normalization applies security semantics to parsed events by:
- Filtering for root execution (euid == 0)
- Ensuring user attribution (auid not unset or kernel)
- Requiring an explicit privilege escalation primitive:
   - sudo_exec
   - pkexec_exec
   - uid_change
   - root_exec

Events failing these checks are discarded as non-security-relevant noise.

Candidate Event Structure
Events that pass normalization are emitted as privilege escalation candidates.
Example:
    {
      "event_type": "privesc_candidate",
      "event_id": 48192,
      "timestamp": 1768900331,
      "pid": 13499,
      "ppid": 3589,
      "auid": 1000,
      "euid": 0,
      "exe": "/usr/bin/sudo",
      "mechanism": "sudo",
      "rank": 2,
      "audit_keys": ["execve", "uid_change"],
      "execution_context": null,
      "debug": {
        "syscalls": ["59", "117"],
        "tty": "pts0",
        "success": true,
        "comm": "sudo"
      }
    }

## Scoring Logic
Each candidate is assigned a risk rank (1–4) based on mechanism and execution context.

| Rank | Meaning |
|------|---------|
| 4 | Inherently dangerous escalation (pkexec, UID transitions, root_exec) |
| 3 | Non-interactive sudo execution |
| 2 | Scripted or generic sudo execution |
| 1 | Expected interactive sudo |

Scoring is:
- Single-event
- Deterministic
- Explainable per event

No historical correlation or behavioral profiling is used.

## Implementation Components
| Component | Purpose |
|----------|---------|
| [audit_parser.py](https://github.com/atamalajopyetie/homelab/blob/main/detections/privilege_escalation/priv_esc/audit_parser.py "audit_parser.py") | Parses audit logs, extracts fields, and assigns event IDs |
| [audit_normalizer.py ](https://github.com/atamalajopyetie/homelab/blob/main/detections/privilege_escalation/priv_esc/audit_normalizer.py "audit_normalizer.py ")| Applies boundary logic, mechanism resolution, scoring, and deduplication |
| [run_priv_esc.sh](https://github.com/atamalajopyetie/homelab/blob/main/detections/privilege_escalation/priv_esc/run_priv_esc.sh "run_priv_esc.sh") | Wrapper script for reliable cron execution |
| `cron` | Periodic execution (5-minute interval) |
| `.last_event_id` | Persistent state file used for deduplication |
| `priv_esc_events.json` | Raw parsed audit event storage |
| `privesc_candidates.json` | Final normalized privilege escalation detections |

## Validation Method
Validation was performed using:
- Live audit logs from the host system
- Known privilege escalation actions (e.g., sudo, UID transitions)
- Manual inspection of parsed and normalized events

Key validation checks:
- Correct extraction of audit fields
- Stable event identity across runs
- Absence of duplicate detections
- Reasonable candidate volume
- Expected ranking behavior

No synthetic or simulated audit data was used.

## Key Takeaways
- Explicit privilege escalation primitives provide high-signal detection
- Risk ranking is more effective than binary alerting for local detections
- Deduplication is essential for cron-based pipelines
- Strict scoping prevents alert fatigue and overengineering
- Real audit data is more valuable than simulated attack traces

This implementation establishes a reliable v1 baseline for host-based privilege escalation detection.
