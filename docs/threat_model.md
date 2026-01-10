# Threat Model

A detection system is meaningless without a clearly defined threat.

This threat model defines:
- what is realistic
- what is valuable
- what is intentionally excluded

## Asset Being Protected
### Primary Asset
A Linux endpoint used for:
- browsing
- development
- SSH access

## Attacker Profile 
### Attacker Capability Level
Low to medium sophistication attacker
Why?
Most real attacks are not APTs

Commodity attackers use:
- scanning
- brute force
- misconfigurations

## Attacker Access
- Network access to host
- No credentials initially
- No assumed exploit capability

## Attacker Goals
- Discover Services
- Identify valid users
- Gain SSH access
- Execute commands
- Maintain access

## Assumptions
- Logs are not tampered with
- Time synchronization is accurate
- Detection is post-event, not preventative|

