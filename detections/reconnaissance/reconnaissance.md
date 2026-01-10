# Reconnaissance Detection
## Purpose
Reconnaissance is the earliest observable stage of an attack lifecycle.
At this stage, the attacker has not yet authenticated, not yet executed code, and not yet modified the system.

## This makes reconnaissance detection:
- high value
- low impact
- low false-positive if done correctly
The objective here is intent detection, not compromise confirmation.

## Why recon matters
attackers -> scan -> enumerate -> attempt access -> execute

if reconnaissance is detected:
- defenders gain time
- defenders gain context
- defenders can harden or block before access
once attacker authenticates, defensive cost increases significantly

## Threats covered
This reconnaissance phase focuses on active scanning, not passive intel gathering

in-scope recon:
- TCP-SYN Scan - Half-open port discovery
- TCP FIN Scan -  Firewall evasion attempts
- TCP NULL Scan - Stealth scanning
- Port Sweep - Multiple hosts targetted on single host by specific IP
- Host Sweep - Same ports tasrgetted across multiple hosts

## Detection Philosophy
Recon detections are not full proof of compromise
They are signals of intent

Therefore:
- Alerts are informational to medium severity
- No automated blocking is performed
- Context is preserved for later correlation

## Thresholding Logic
Single packet is NOT attack
Pattern is NOT coincidence

Threshoulds prevent:
- Noise
- alert fatigue
- false attribution

## Validation Method
Recon detection are validated using:
- Nmap scans from seperate VM
- Controlled flag based scans
- Known benign traffic for comparison
Validation confirms:
- alerts trigger when expected
- alerts do NOT trigger on normal browsing

## Limitations
This phase does NOT detect:
- Slow scan over hours
- Distributed scanning from botnets
- Proxy-based scanning
Those require:
- Time correlations
- SIEM aggregation
- Historical analysis

## Output Formats
All reconnaissace alerts are written to:
/var/log/suricata/eve.json
event_type:"alert"
