# homelab
This project focuses on designing and implementing an end-to-end detection engineering pipeline for a single-node Linux environment, aligned with the MITRE ATT&amp;CK framework.

## Objectives
- Build a MITRE ATT&CK–mapped detection framework
- Detect real attacker behavior, not noisy events
- Reduce alert fatigue by focusing on behavioral signals
- Maintain tool-agnostic detection logic
- Enable future integration with SIEM/SOAR platforms

## Threat Model & Assumptions

### Environment
- Single Linux laptop (defender)
- One attacker-controlled VM on the same network
- Active internet browsing and development activity
- No enterprise-grade perimeter devices

### Threat Assumptions
- External attacker performing:
  - Network reconnaissance
  - Service discovery
  - SSH-based initial access attempts
- Focus on realistic low-and-slow attacks, not malware detonation

## Repository Structure
siem-detection-engineering-project/
│
├── README.md
│
├── docs/
│   ├── 01-project-overview.md
│   ├── 02-threat-model.md
│   ├── 03-architecture.md
│   ├── 04-mitre-mapping.md
│   ├── 05-log-sources.md
│   ├── 06-detection-logic.md
│   ├── 07-validation-testing.md
│   └── 08-future-work.md
│
├── detections/
│   ├── reconnaissance.md
│   ├── initial_access.md
│   ├── execution.md
│   ├── persistence.md
│   ├── privilege_escalation.md
│   └── command_and_control.md
│
├── configs/              # optional, later
│   ├── suricata/
│   ├── auditd/
│   └── siem/
│
└── diagrams/
    ├── architecture.drawio
    └── mitre-flow.drawio



