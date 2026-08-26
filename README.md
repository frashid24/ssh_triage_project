# SSH Log Triage Tool

A Python tool that parses SSH authentication logs to detect brute-force login attempts, flag compromised accounts, and generate an AI-written incident summary on top of it. Built as a hands-on SOC analyst portfolio project — I wanted to show I actually understand log analysis fundamentals *before* bringing AI into the picture, not just prompt my way to an answer.

This repo tracks the project through three stages: rule-based detection (v1), an AI reporting layer (v2), and a cleaner OOP refactor (v3). Each stage is a real commit so you can see the progression.

## What it does

1. **Parses failed logins** — reads `auth.log` line by line and extracts the source IP and username for every `Failed password` entry
2. **Counts attempts per IP** — uses `collections.Counter` to tally failed login attempts by source IP
3. **Flags suspicious IPs** — any IP with 10+ failed attempts gets flagged as a likely brute-force source
4. **Detects compromise** — cross-references successful (`Accepted password`) logins against the flagged IP list to catch cases where a brute-force attacker actually got in
5. **Generates an AI incident report** — takes the parsed events, flagged IPs, and breach data and sends it to the Claude API, which writes it up as a short analyst-style paragraph with recommended next steps

## Sample output (rule-based)

```
Failed attempts from most common IPs in descending order [('185.220.101.45', 47), ('45.155.204.12', 12), ('10.0.0.22', 3), ('172.16.0.5', 2), ('10.0.0.15', 1)]
⚠️ ALERT: 185.220.101.45 made 47 failed login attempts
⚠️ ALERT: 45.155.204.12 made 12 failed login attempts
🚨 CRITICAL: 185.220.101.45 achieved a successful login as 'root' after brute-force attempts
```

## Sample output (AI-generated report)

> During the analysis period, two external IP addresses were flagged for excessive failed authentication attempts, meeting the threshold of 10 or more attempts. IP 185.220.101.45 conducted a broad credential-stuffing/brute-force campaign targeting multiple service accounts... this IP successfully breached the root account, representing the most critical finding of this incident... Immediate recommended actions include blocking both flagged external IPs at the firewall, rotating the compromised root credentials, and enforcing multi-factor authentication on all privileged accounts.

## Why build this instead of just using a SIEM?

Splunk or CrowdStrike would do this detection out of the box — this isn't meant to replace them. It's meant to show I understand the logic a SIEM is automating under the hood, not just how to read a dashboard. It's also fully self-contained, so it's something I actually own and can run/demo anywhere, instead of a screenshot from a trial SIEM account.

## Why separate the AI layer into its own class?

I built the detection logic (`LogAnalyzer`) and the AI reporting piece (`ReportGenerator`) as two separate classes on purpose. `LogAnalyzer` doesn't know or care that AI exists — it just parses logs and flags IPs, no API key or network access required. `ReportGenerator` receives an Anthropic client and the analyzer's results as input, rather than being baked into the detection class. That way the core detection logic stays testable and reusable on its own, even if I swap out the AI piece later or use it somewhere else.

## Project structure (v3)

- **`LogAnalyzer`** — the rule-based detection engine
  - `parse_failed_logins()` — builds `events`, `ip_list`, and `counts_ip`
  - `check_flagged_ips()` — flags any IP over the failed-attempt threshold
  - `check_breaches()` — checks flagged IPs against successful logins
- **`ReportGenerator`** — the AI layer
  - `generate_summary(events, flagged_ips, breached_events)` — sends the analyzer's results to the Claude API and returns a written incident report

Usage now looks like:

```python
analyzer = LogAnalyzer("auth.log")
analyzer.parse_failed_logins()
analyzer.check_flagged_ips()
analyzer.check_breaches()

reporter = ReportGenerator(client)
summary = reporter.generate_summary(analyzer.events, analyzer.flagged_ips, analyzer.breached_events)
print(summary)
```

## Files

- `ssh_triage.py` — v1, pure rule-based detection
- `ssh_triage_v2.py` — v2, adds the Claude API summary layer
- `ssh_triage_v3.py` — v3, refactored into `LogAnalyzer` + `ReportGenerator` classes
- `auth.log` — a generated sample SSH log simulating a realistic brute-force scenario (two attacking IPs, normal failed logins from legit internal IPs, and one attacker achieving a successful login)

## How to run

```bash
python3 ssh_triage_v3.py
```

You'll need your own Anthropic API key for the AI summary piece (v2/v3) — set it as an environment variable or, if you're running this in Colab like I did, store it in Colab's Secrets manager as `ANTHROPIC_API_KEY`. v1 has no dependencies beyond the Python standard library.

## What I learned building this

- Parsing structured log lines with `.split()` and positional indexing
- Using `Counter` for frequency counts instead of manually managing a dict
- The difference between `most_common(n)` and `most_common()`
- Careful attention to loop/conditional indentation — a lot of my early bugs came from a check running at the wrong scope (e.g., running on every line instead of only the ones I'd just parsed)
- Reading a file object exhausts it — you have to reopen it in a fresh `with open(...)` block to scan it a second time
- How to actually call the Claude API from Python instead of just chatting in a browser — turns out it's the same idea, just your code builds the prompt instead of you typing it
- Why you'd separate an AI/API layer into its own class instead of bolting it onto your core logic — keeps the detection logic testable and reusable without needing an API key or network access
- The mental shift from local variables to `self.` attributes when converting a script into a class

## What's next

- Try this against a messier, more realistic log (more noise, more usernames, maybe multiple log types)
- Add a threshold parameter instead of hardcoding 10 failed attempts
- Look into unit tests for `LogAnalyzer` now that it's decoupled from the AI layer
