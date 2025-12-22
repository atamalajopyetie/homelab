# Project Overview
This project is an end-to-end detection engineering implementation designed to model how real defensive security teams think, design, and validate detections, rather than how tools are configured.

### Most SIEM projects start with:
- dashboards
- queries
- alerts

### This project intentionally starts with:
- attacker behavior
- detection intent
- log semantics

The goal is to ensure that every detection answers a security question, not a tooling requirement.

## Why This Project Exists
Traditional home-lab SIEM projects often suffer from:
- High alert noise
- Tool dependency (Splunk-only, Elastic-only)
- No explanation of why a detection exists
- No clear attacker model

### This project solves those problems by:
- Designing detections before choosing a SIEM
- Mapping every detection to MITRE ATT&CK
- Validating detections through real attack simulation
- Treating tools as execution layers, not intelligence sources

## Core Design Philosophy
1. Detection logic must be tool-agnostic
Detection logic is written in plain language conditions, not query syntax.
This allows:
- Migration across SIEMs
- SOAR reuse
- Clear reasoning during incident response

2. Behavior > Indicators
- Static IOCs (IPs, hashes) expire quickly.
- Behavior (scanning, brute force, execution) does not.

This project focuses on:
- repeated actions
- temporal patterns
- protocol misuse
- state changes

3. Early-stage detection is prioritized

Stopping attackers early:
- reduces blast radius
- reduces incident cost
- increases analyst confidence

Therefore, Reconnaissance and Initial Access are implemented first.

What This Project Is Not

❌ A dashboard demo
❌ A Splunk licensing exercise
❌ A malware zoo

It is a defensive detection lifecycle project.
