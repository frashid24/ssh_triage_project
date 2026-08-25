# SSH Log Triage Tool 

A Python script that parses SSH authentication logs to detect brute-force login attempts and flag compromised accounts. Built as a hands-on SOC analyst portfolio project, focused on understanding log analysis fundamentals before layering AI on top in a future version.

## What it does

1. **Parses failed logins** — reads `auth.log` line by line and extracts the source IP and username for every `Failed password` entry
2. **Counts attempts per IP** — uses `collections.Counter` to tally failed login attempts by source IP
3. **Flags suspicious IPs** — any IP with 10+ failed attempts is flagged as a likely brute-force source
4. **Detects compromise** — cross-references successful (`Accepted password`) logins against the flagged IP list to catch cases where a brute-force attacker actually got in

## Sample output

```
Failed attempts from most common IPs in descending order [('185.220.101.45', 47), ('45.155.204.12', 12), ('10.0.0.22', 3), ('172.16.0.5', 2), ('10.0.0.15', 1)]
⚠️ ALERT: 185.220.101.45 made 47 failed login attempts
⚠️ ALERT: 45.155.204.12 made 12 failed login attempts
🚨 CRITICAL: 185.220.101.45 achieved a successful login as 'root' after brute-force attempts
```

## Why build this instead of just using a SIEM?

Tools like Splunk or CrowdStrike do this kind of detection out of the box — but this project isn't meant to replace them. It's meant to demonstrate the underlying logic a SIEM automates: understanding *why* an alert fires, not just reading a dashboard. It's also fully self-contained and reusable as a portfolio piece, unlike a screenshot from a trial SIEM account.

## Files

- `ssh_triage.py` — the detection script
- `auth.log` — a generated sample SSH log simulating a realistic brute-force scenario (two attacking IPs, normal failed logins from legit internal IPs, and one attacker achieving a successful login)

## How to run

```bash
python3 ssh_triage.py
```

No dependencies beyond the Python standard library (`collections.Counter`).

## What I learned building this

- Parsing structured log lines with `.split()` and positional indexing
- Using `Counter` for frequency counts instead of manually managing a dict
- The difference between `most_common(n)` and `most_common()`
- Careful attention to loop/conditional indentation — several early bugs came from blocks running at the wrong scope (e.g., a check running on every line instead of only newly-parsed ones)
- Reading a file object exhausts it — reopening `auth.log` in a fresh `with open(...)` block is required to scan it a second time

## What's next (v2)

- Add a Claude API layer that takes the flagged IPs and breach events and generates a plain-English analyst summary/report on top of this rule-based output
- Refactor into classes (e.g., a `LogAnalyzer` class) once the AI layer is in place
