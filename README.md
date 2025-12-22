# homelab
This project focuses on designing and implementing an end-to-end detection engineering pipeline for a single-node Linux environment, aligned with the MITRE ATT&CK framework.

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
<img width="604" height="1076" alt="image" src="https://github.com/user-attachments/assets/79d22721-199f-4034-865f-608c7a367814" />




