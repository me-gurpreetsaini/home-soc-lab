# Home SOC Lab

A self-built Security Operations Center lab using Splunk Enterprise as a SIEM,
simulating real attacker behavior and building detections to catch it, from the
initial compromise through post-exploitation activity.

## Why I built this

I'm working toward a SOC analyst role, and I wanted hands-on proof that I can do
the core of the job: get logs into a SIEM, understand what normal looks like, and
write detection logic for abnormal activity, not just read about it.

## Architecture

| Machine | Role | OS |
|---|---|---|
| Splunk-Ubuntu | SIEM (Splunk Enterprise) + Linux log source | Ubuntu Server |
| Win10-Victim | Monitored endpoint (Sysmon + audit logging) | Windows 10 |
| Kali | Attacker machine | Kali Linux |

All three machines run in VMware on an isolated NAT network, so attack traffic
never touches my real network.

**Log pipeline:** Windows Security/Sysmon/PowerShell logs and Linux auth logs are
collected into two separate Splunk indexes (`windows`, `linux`) via the Splunk
Universal Forwarder and native file monitoring, so every detection below is built
on logs I configured and verified myself, not sample data.

## Attacks Simulated & Detections Built

| # | Attack | MITRE ATT&CK | Write-up |
|---|---|---|---|
| 1 | SSH Brute Force | T1110.001 | [detections/01-brute-force-ssh.md](detections/01-brute-force-ssh.md) |
| 2 | PowerShell Encoded Command | T1059.001 | [detections/02-powershell-encoded-command.md](detections/02-powershell-encoded-command.md) |
| 3 | Privilege Escalation (Local Admin Group) | T1098 | [detections/03-privilege-escalation.md](detections/03-privilege-escalation.md) |

Each write-up includes the attack simulation, the log source and fields used, the
full SPL detection logic with reasoning, a screenshot of the alert firing, and a
limitation I identified in my own detection.

## What I learned

- How to build a log pipeline end to end: audit policy, Sysmon, Universal
  Forwarder configuration, and index design.
- How to troubleshoot silent failures, like a missing log source turning out to
  be a permissions issue, not a configuration one.
- How to write SPL from scratch: field extraction with `rex`, aggregation with
  `stats`, and filtering with `where`.
- That every detection has a blind spot. A threshold-based rule that catches a
  fast brute force attack will miss a slower, more patient attacker, and knowing
  that trade-off is part of writing a good detection, not a flaw to hide.

## Status

Complete. Three attacks simulated end to end: initial access (brute force),
execution (PowerShell abuse), and privilege escalation, each with its own
working Splunk detection, a scheduled alert proven to fire, and a documented
limitation.
