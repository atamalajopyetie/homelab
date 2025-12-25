# Initial Access Detection — Valid Accounts (T1078)

## Purpose
Initial Access is the first stage where an attacker successfully authenticates
to the system.

In the case of **Valid Accounts**, access occurs using legitimate credentials,
making this one of the hardest stages to detect.

This stage focuses on **detecting suspicious authentication behavior**, not
proving compromise.

## Why Initial Access matters
attackers -> authenticate -> execute -> escalate -> persist

Once valid access is obtained:
- attacker activity blends with normal user behavior
- defensive visibility drops
- response cost increases sharply

Detecting abuse **at authentication time** provides:
- early warning
- context for downstream detections
- reduced investigation scope

## Threats covered
This phase focuses on **credential abuse**, not credential theft mechanisms.

In-scope Initial Access behaviors:
- Failed authentication followed by success
- Password-based login where keys are expected
- Login from unexpected source IPs
- Concurrent authentication while a session already exists
- Logins outside established usage patterns

Out-of-scope:
- Phishing
- Credential harvesting
- Malware-based access
- Post-auth activity (execution, sudo, persistence)

## Detection Philosophy
Valid Accounts detection is **behavioral**, not signature-based.

A successful login is **not malicious by default**.
Detection relies on **contextual deviation from baseline**.

Therefore:
- Detection is probabilistic
- No single signal is sufficient
- Signals are combined into a risk score
- No automated blocking is performed

This stage produces **evidence**, not verdicts.

## Baseline Model
Detection relies on a **static baseline** describing expected behavior.

Baseline defines:
- Expected login hours
- Trusted source IP ranges
- Expected session concurrency
- Normal authentication patterns

Baseline is:
- Manually curated
- Stable over time
- Treated as trusted input

It is not learned dynamically to avoid attacker contamination.

## Runtime State
Runtime state captures **recent authentication context**, including:
- Last successful login timestamp
- Recent failed authentication attempts

State is:
- Ephemeral
- Resettable
- Used only for short-term correlation

State does not represent historical truth.

## Detection Signals

| Signal | Description |
|------|------------|
| time_anomaly | Login outside baseline hours |
| new_ip | Source IP not in trusted CIDRs |
| auth_password | Password authentication used |
| dormant_account | Login after extended inactivity |
| concurrent_session | New login while a session already exists |
| fail_then_success | One or more failures followed by success |
| failure_burst | Multiple failures without success |

### Signal Semantics
- **fail_then_success** indicates credential discovery or guessing
- **failure_burst** indicates brute force or spraying attempts
- These signals are **mutually exclusive by design**

## Risk Scoring Logic
Signals contribute additively to a risk score.

### Scoring Weights

| Signal | Score |
|------|------|
| Time anomaly | +1 |
| New / non-local IP | +3 |
| Password authentication | +2 |
| Dormant account | +2 |
| Concurrent session | +3 |
| Fail → success | +3 |
| Failure burst | +2 |

### Risk Levels

| Score | Interpretation |
|----|----|
| 0–2 | Normal |
| 3–4 | Suspicious |
| 5–6 | Likely abuse |
| ≥7 | High-confidence abuse |

Scores represent **likelihood**, not confirmation.

## Validation Method
Initial Access detection is validated using:
- Manual SSH authentication attempts
- Controlled failed → success sequences
- Concurrent session testing
- Localhost and LAN-based access

Validation confirms:
- Signals trigger when expected
- Normal usage does not generate alerts
- Risk scores align with operator intuition

## Limitations
This stage does NOT detect:
- Credential theft mechanisms
- Phishing campaigns
- Access via compromised applications
- Long-term low-and-slow authentication abuse

Those require:
- Cross-host correlation
- Long-term baselining
- SIEM or aggregation layers

## Output Format
All Initial Access detections are written as structured events to:events.json

