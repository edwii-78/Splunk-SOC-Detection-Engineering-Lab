# SOC Investigation Report — Suspicious HTTP Beaconing Investigation

| Field | Value |
|---|---|
| **Case ID** | SOC-LAB-2026-0805-BEACON |
| **Classification** | Detection Engineering Lab / Behavioral Threat Hunting Exercise |
| **Analyst** | Edwin Dominic |
| **Host** | WIN11-CLIENT01 |
| **Process Under Investigation** | InventoryAgent.exe (Windows Service) |
| **Data Source** | Sysmon (Operational log) + Windows System log → Splunk (`index=sysmon`) |
| **Date of Activity** | 2026-08-05 (03:49:06 – 04:08:21 UTC, ongoing at time of capture) |
| **Alert Triggered** | *Periodic Outbound HTTPS from SYSTEM-Level Service — Possible Beaconing* |
| **Severity (Investigated)** | Medium-High — behaviorally consistent with beaconing, requires context to resolve |
| **Outcome** | Resolved as legitimate custom software; **not proven malicious, not proven benign from telemetry alone** |

---

## 1. Objective

Investigate a long-running Windows service exhibiting periodic, encrypted outbound connections to determine whether the behavior represents authorized enterprise software or command-and-control (C2) beaconing. This report deliberately avoids the label "C2 Detection" — no attacker tasking, payload delivery, or malicious execution was observed. What was observed is a behavioral pattern (service-based persistence, SYSTEM execution, regular encrypted check-ins to a fixed destination) that is common to both legitimate management agents and real beacon malware, and the investigation reflects that ambiguity honestly rather than assuming intent either way.

---

## 2. Investigation Scenario & Verdict

A process named `InventoryAgent.exe`, running as a Windows Service under `NT AUTHORITY\SYSTEM`, was observed starting automatically at boot, resolving a fixed internal hostname, and then establishing an HTTPS connection to that host roughly once per minute, indefinitely.

**Verdict: Confirmed benign — controlled simulation.** This is an analyst-authored .NET Worker Service built specifically to produce this telemetry pattern for training purposes; its source code was reviewed directly (Appendix) and confirmed to perform only host registration and periodic status "heartbeats," with no command execution, file operations, or data exfiltration capability. Critically, **this verdict was only reachable through source code review and asset ownership knowledge — not from Sysmon telemetry alone.** The investigation below is written as it would be conducted without that outside knowledge, since that is the realistic starting position for a SOC analyst encountering this pattern on an unfamiliar host.

---

## 3. Initial Detection

**Query**
```spl
index=sysmon EventCode=1 Image="*\\InventoryAgent.exe"
```

**Finding**
`InventoryAgent.exe` (PID 3524, ProcessGuid `{0875a023-b2db-6a72-4500-000000006100}`) started at 03:49:47.378 UTC, parented directly by `services.exe` (PID 964) rather than any interactive shell or user session, running at **System** integrity under **NT AUTHORITY\SYSTEM**.

---

## 4. Initial Assessment — Why the Activity Was Flagged

| Indicator | Detail |
|---|---|
| Service-based execution | Started by `services.exe`, not a user session — indicates a registered Windows Service with automatic startup, not one-off interactive activity |
| SYSTEM-level execution | Maximum local privilege; also the norm for legitimate endpoint agents (EDR, patch management, RMM tools), so this alone is not distinguishing |
| DNS resolution immediately preceding connection | The process resolved a specific hostname just before its first outbound connection — deliberate, configured behavior rather than incidental |
| Regular outbound cadence | Repeated HTTPS connections to the same destination at roughly one-minute intervals, sustained for the full observation window |
| Fixed destination, stable ProcessGuid | Every connection traces to the same process instance and the same destination — a single long-lived channel, not scattered one-off traffic |

None of these indicators, individually or together, distinguish legitimate management software from a C2 beacon — that determination requires evidence outside Sysmon telemetry (Section 10).

---

## 5. Process & Persistence Investigation

**Query**
```spl
index=sysmon EventCode=1 ProcessGuid="{0875a023-b2db-6a72-4500-000000006100}"
```

**Finding**

| Field | Value |
|---|---|
| Image | `C:\Program Files\InventoryAgent\InventoryAgent.exe` |
| Parent | `services.exe` (PID 964) |
| User | NT AUTHORITY\SYSTEM |
| Integrity Level | System |
| LogonId | 0x3E7 (the standard SYSTEM logon session) |
| SHA256 | 14945B284FD3E23F08F8CBE59F7C214453F4BDDC31791D46E0FEA6230D0C39F8 |

The process started 41 seconds after the host itself booted (Windows Event ID 12, `2026-08-05T03:49:06.500Z`), consistent with a service configured for automatic startup rather than delayed or manually triggered start.

**Analyst note — PE metadata artifact:** the binary's `OriginalFileName` field reads `InventoryAgent.dll`, not `.exe` — the same benign .NET single-file-publish artifact observed in the BITS investigation in this series, not evidence of tampering.

---

## 6. DNS Investigation

**Query**
```spl
index=sysmon EventCode=22 ProcessGuid="{0875a023-b2db-6a72-4500-000000006100}"
```

**Finding**
Two DNS queries were issued by the process within the same second, immediately preceding its first network connection:

| Time (UTC) | Query | Result | Purpose |
|---|---|---|---|
| 03:51:19.307 | `WIN11-CLIENT01` (self) | Local IPv4/IPv6 addresses | Resolving its own hostname to enumerate local IP addresses for its registration payload |
| 03:51:19.485 | `inventory.corp.local` | `192.168.56.107` | Resolving its configured remote server before connecting |

---

## 7. Network Activity & Beacon Interval Analysis

**Query**
```spl
index=sysmon EventCode=3 ProcessGuid="{0875a023-b2db-6a72-4500-000000006100}"
```

**Finding**
The first connection (03:51:19.719 UTC, ~92 seconds after process start) established a TCP session to `192.168.56.107:8443` (`inventory.corp.local`), 17 further connections to the same destination followed through the end of the capture window (04:08:21.266 UTC), with the process still running and presumably continuing beyond it.

**Interval statistics** (time between consecutive connections):

| Metric | Value |
|---|---|
| Average interval | 60.0 seconds |
| Minimum interval | 38.1 seconds |
| Maximum interval | 81.1 seconds |
| Destination | `inventory.corp.local` (192.168.56.107:8443), consistent across all 18 connections |

The regularity here (tight clustering around a 60-second mean) is itself an artifact worth noting: genuinely human-driven traffic doesn't look like this, while both legitimate scheduled agents and beacon malware commonly do. The presence of jitter (a 43-second spread rather than a fixed interval) is a detail attackers and legitimate developers alike build in deliberately, to avoid the flat, perfectly-periodic pattern that naive interval-based detection rules look for.

---

## 8. Activity Chain

```
[System Boot — 03:49:06]
        │
        ▼
services.exe (Service Control Manager)
        │
        ▼
InventoryAgent.exe (SYSTEM, auto-start)
        │
        ├── DNS: WIN11-CLIENT01 (self)
        ├── DNS: inventory.corp.local → 192.168.56.107
        │
        ▼
HTTPS connection #1 (Registration) → 192.168.56.107:8443
        │
        ▼
HTTPS connections #2–18 (Heartbeats) → 192.168.56.107:8443
   at ~60s average intervals, ongoing
```

---

## 9. Timeline Reconstruction (UTC)

| Time | Activity |
|---|---|
| 03:49:06.500 | Host boots (Windows Event ID 12) |
| 03:49:47.378 | `InventoryAgent.exe` started by `services.exe` |
| 03:51:19.307 – 19.485 | DNS resolution: self-hostname, then `inventory.corp.local` |
| 03:51:19.719 | First HTTPS connection established |
| 03:51:19.719 – 04:08:21.266 | 17 additional HTTPS connections at ~60s average interval (range 38–81s) |

Total observed window: **~19 minutes**, with the service still active at the end of the capture — this is a sustained, ongoing channel, not a bounded event.

---

## 10. Resolution Criteria — What Would Confirm or Refute Malicious Intent

Sysmon telemetry alone cannot resolve this case. A real investigation would additionally require:

| Check | What It Would Tell You |
|---|---|
| Code signing / digital signature on `InventoryAgent.exe` | Legitimate enterprise agents are almost always signed; an unsigned binary running as SYSTEM is a strong escalation trigger |
| Asset inventory / CMDB cross-reference | Confirms whether this software was ever knowingly deployed to this host by IT/security |
| TLS certificate presented by `inventory.corp.local:8443` | A valid internal PKI certificate supports legitimacy; a self-signed or mismatched certificate is a red flag |
| DNS zone ownership for `corp.local` | Confirms whether the destination is genuinely internal infrastructure or an attacker-controlled name mimicking one |
| Payload content (via TLS inspection/proxy, if available) | Directly distinguishes an inventory JSON payload from C2 tasking data |
| EDR/AV verdict on the binary hash | Independent confirmation from a source other than Sysmon |

**Source-review finding relevant to this checklist:** the agent's source code (Appendix) shows it uses `ServerCertificateCustomValidationCallback = DangerousAcceptAnyServerCertificateValidator`, disabling TLS certificate validation entirely. This is explicitly commented `// LAB ONLY` in the source, but it is worth flagging as a pattern independent of this specific case: **beacon malware very commonly disables certificate validation for the same reason a lab tool does** — to tolerate a self-signed certificate on the far end without a handshake failure. This detail would not be visible from Sysmon alone; it would only surface through binary/traffic analysis (e.g., a TLS inspection proxy or a JA3/JA3S fingerprint that flags non-standard TLS stack behavior).

---

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | `InventoryAgent.exe` registered as an auto-start Windows Service, launched by `services.exe` |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Periodic HTTPS connections to a fixed destination at regular intervals |

---

## 12. Indicators of Interest

*(Named "Indicators of Interest" rather than "Indicators of Compromise" — compromise was not established; these are the artifacts that would carry over into a real investigation of this pattern.)*

| Type | Value |
|---|---|
| Process | InventoryAgent.exe |
| SHA256 | 14945B284FD3E23F08F8CBE59F7C214453F4BDDC31791D46E0FEA6230D0C39F8 |
| Parent Process | services.exe |
| Execution Context | NT AUTHORITY\SYSTEM |
| Destination Host | inventory.corp.local |
| Destination IP | 192.168.56.107 |
| Destination Port | 8443 (HTTPS) |
| Beacon Interval | ~60s average (38–81s range) |
| ProcessGuid | {0875a023-b2db-6a72-4500-000000006100} |

---

## 13. Threat Assessment

This behavioral pattern — SYSTEM-level service, automatic startup, DNS resolution followed by regular encrypted check-ins to a single destination — is functionally identical to how real C2 beacon frameworks operate, and is equally how legitimate management agents (CrowdStrike, Tanium, SentinelOne, RMM tools) behave. That overlap is the point: signature and hash-based detection cannot address this pattern, since a renamed or newly-compiled beacon would produce identical Sysmon telemetry to this lab's benign agent. Effective detection here depends on layered context — asset ownership records, code signing, TLS certificate validation, and destination reputation — rather than any single Sysmon event.

---

## 14. Splunk Threat Hunting & Correlation Queries

**Identify Long-Running Processes with Regular Outbound Connections**
```spl
index=sysmon EventCode=3
| stats count earliest(_time) as first_seen latest(_time) as last_seen by Computer Image DestinationHostname DestinationPort ProcessGuid
| where count > 5
| eval duration_min=round((last_seen-first_seen)/60,1)
| table Computer Image DestinationHostname DestinationPort count duration_min
```
*Purpose:* Surfaces any process making repeated connections to the same destination over a sustained window — the general-purpose version of this investigation, not scoped to a known process name.

**Beacon Interval Analysis**
```spl
index=sysmon EventCode=3 Image="*\\InventoryAgent.exe"
| sort _time
| streamstats current=f last(_time) as PreviousTime
| eval Interval=round(_time-PreviousTime,1)
| table _time Interval DestinationHostname DestinationPort
```
*Purpose:* Quantifies the interval between connections directly, rather than relying on eyeballing timestamps — this produced the 60s average / 38–81s range cited in Section 7.

**Connection Frequency Over Time**
```spl
index=sysmon EventCode=3 Image="*\\InventoryAgent.exe"
| timechart span=1m count
```
*Purpose:* Visualizes the steady cadence at a glance — a flat, near-constant rate per minute is itself the signal worth investigating.

**Correlate Full Process Lineage**
```spl
index=sysmon (ProcessGuid="{0875a023-b2db-6a72-4500-000000006100}" OR ParentProcessGuid="{0875a023-b2db-6a72-4500-000000006100}")
| sort _time
| table _time EventCode Image ParentImage CommandLine
```
*Purpose:* Confirms the process spawned no children during the observation window — relevant because a beacon that receives tasking would typically be expected to eventually spawn a child process or write a file, neither of which occurred here.

---

## 15. Detection Engineering

**Monitoring coverage** — this behavioral pattern is detectable by alerting on:
- New services registered with SYSTEM-level auto-start that were not present in a prior known-good baseline
- Processes generating more than N outbound connections to the same destination within a rolling window, regardless of process name
- Statistical regularity in connection timing (low variance in inter-connection interval) as a standalone signal, independent of destination reputation
- Unsigned or unknown binaries running as SYSTEM with active outbound network activity

**Actionable rule specs:**
1. **Baseline deviation rule:** alert when a newly-registered Windows Service establishes its first outbound network connection within minutes of installation — legitimate software rollouts are typically known in advance via change management, so an unexpected new service phoning home is a meaningful signal on its own.
2. **Beacon-interval rule:** flag processes whose Event ID 3 connections to a single destination show a coefficient of variation below a defined threshold over a rolling 15-connection window — mathematically distinguishing "regular check-in" traffic from ordinary application chatter.
3. **Enrichment requirement:** any alert on this pattern should auto-attach code-signing status and CMDB/asset-inventory lookup results before reaching an analyst, since — per Section 10 — the Sysmon evidence alone cannot resolve the verdict.

---

## 16. Recommended Response Actions

1. **Do not immediately assume compromise** — this pattern alone is insufficient grounds for isolation; escalate to verification first (Section 10 checklist).
2. **Check code signing and hash reputation** on the binary before further action.
3. **Cross-reference asset inventory / CMDB** to confirm whether this software was knowingly deployed.
4. **Inspect the TLS certificate** presented by the destination host, and confirm DNS zone ownership for the resolved domain.
5. **If unresolved after the above**, escalate to network-level inspection (proxy logs, TLS decryption if available) to examine payload content directly.
6. **If confirmed malicious**, stop the service (`sc stop <name>`), remove its service registration, and treat the destination as a confirmed C2 indicator for environment-wide hunting.

---

## 17. Conclusion

This investigation reconstructed a complete behavioral pattern — service-based SYSTEM execution, DNS resolution, and sustained periodic HTTPS connections averaging 60 seconds apart — using Sysmon Event IDs 1, 3, and 22 correlated through a single stable ProcessGuid. The pattern is textbook beaconing behavior from a telemetry standpoint, and the investigation deliberately does not overstate that into a "C2 detected" finding, because the same telemetry is equally consistent with legitimate management software.

The ground truth in this lab (a benign, analyst-authored inventory agent, confirmed via source review) is not something Sysmon telemetry alone could establish — and that is the central lesson of this investigation: behavioral detection surfaces the right cases for review, but resolving them requires context Sysmon does not provide. The resolution criteria in Section 10, not the raw telemetry, are what a real SOC investigation of this pattern would actually turn on.

---

## Appendix: Agent Architecture Summary

The investigated binary is a .NET 8 Worker Service (`InventoryAgent.csproj`, single-file, self-contained, `win-x64`) registered via `AddWindowsService()`. Its `Worker.cs` implements exactly two network operations, both explaining the telemetry above:

- **`RegisterAsync()`** — called once after a randomized 10–90 second startup delay; posts host/user/OS/IP details to `/api/v1/register`. This is the first HTTPS connection observed in Section 7.
- **`HeartbeatAsync()`** — called in a loop with a randomized 50–70 second delay between iterations; posts a status payload to `/api/v1/heartbeat`. This is the source of the ~60-second average interval observed in Section 7, and its built-in single-retry-after-15-seconds logic on failed POSTs accounts for the intervals falling outside the configured 50–70s window (e.g., the observed 38s and 81s outliers).

The `GetIPv4Addresses()` helper calls `Dns.GetHostAddresses(Dns.GetHostName())` — the exact source of the self-hostname DNS query in Section 6. The static `HttpClient` handler disables TLS certificate validation via `DangerousAcceptAnyServerCertificateValidator`, marked `// LAB ONLY` in source — the detail discussed in Section 10.
