# Phase 2 Test Results — Day 38 (9 July 2026)

**Project:** Phase 2 SIEM Testing | **Engineer:** Ahmad Bussti
**Objective:** Run 3 new attack scenarios testing Phase 2 capabilities — CTI enrichment, proactive hunting, and automated response.

---

## Scenario 1 — APT Simulation

### Setup
- Seeded `siem-threat-intel` with a known-actor IOC: `198.51.100.66` → `threat_actor: APT28`, `confidence: 95`, `source: manual-day38`
- Injected an SSH alert (rule 5710, level 10) with `data.srcip = 198.51.100.66`
- Ran `pipeline_runner.py --once`

### Result
```
CTI    matched=True  actor=APT28  conf=95  source=manual-day38
SCORE  confidence_pct=100%  tier=TRIAGE
RESULT triage_result=present
       escalate=True  confidence_pct=75%  technique=T1110
WRITE  verdict='suspicious' → written to ES
```

Final ES document:
- `cti.matched: true`, `cti.threat_actor: APT28`, `cti.confidence: 95`
- `triage.verdict: suspicious`
- `triage.summary` correctly folded in the APT28 actor profile: campaigns (Fancy Bear, Pawn Storm, Sednit), TTPs (T1566 Phishing, T1071 C2, T1078 Valid Accounts), target sectors (Government, Defense, Media) — confirms Day 24's `get_threat_actor_profile()` + `_attach_actor_profile_to_summary()` wiring works end-to-end on a live, non-seed-adjacent alert.

### Checklist
| Check | Result |
|---|---|
| Detected | ✅ |
| Confidence | 100% at scorer (CTI force-route), 75% at triage tier mapping |
| CTI enriched | ✅ matched=true, actor=APT28, conf=95 |
| Triage identifies actor | ✅ full campaign/TTP/sector profile in summary |
| Ticket created | ❌ N/A — `create_ticket` (Day 34) not yet implemented; no ticket field exists in schema |

### Note
A Wazuh API 401 (`wazuh_auth_failed`) appeared in the pipeline log during this run, from an internal call unrelated to CTI/triage — harmless here since no response action was attempted, but the same underlying credential gap resurfaced later in Scenario 3 (see below).

---

## Scenario 2 — Lateral Movement Hunt

### Setup
- Injected 4 PAM login-success events (rule 5501) targeting `agent1`, from 4 distinct source IPs (`203.0.113.11–14`)
- Ran the YAML hunt engine (`hunt_loader.run_all_yaml_hunts()`) — the real Hunts 1–5 live here, not in the Day 26 `HuntPlaybook` engine that Day 29's auto-escalation wiring covers

### Result
```
lateral_movement_ssh: threats_found=1
  findings: [{'key': 'agent1', 'doc_count': 6, 'distinct_src_ips': {'value': 6}}]
  mitre_technique: T1021.004
  escalate: True
```
(6 distinct source IPs total — includes 2 prior test IPs still in the lookback window in addition to today's 4, confirming the aggregation genuinely counts distinct IPs rather than events.)

Manually escalated via `escalate_hunt_to_triage(hunt_name, findings, hunt_summary, mitre_technique)` (see Gap 1 below for why this had to be done by hand). Full pipeline ran:
```
[coordination] rule=hunt:lateral_movement_ssh confidence_pct=85
[triage] Verdict: suspicious | confidence=high (75%) | escalate=True
[hunting_agent] Hunt 2/3 (reactive): no findings — expected, srcip/agent both 'unknown'
[response_agent] No action taken — verdict=suspicious, confidence=75 (below 80% threshold)
```
Written to `siem-hunt-results`: `hunt_name=lateral_movement_ssh`, `findings_count=1`, `escalated=true`.

### Checklist
| Check | Result |
|---|---|
| Hunt 1 detects it | ✅ `threats_found=1`, 6 distinct source IPs → `agent1` |
| MITRE technique | ✅ T1021.004 |
| Escalation reaches triage | ✅ verdict=suspicious, confidence=75%, logged to `siem-hunt-results` |
| Response action | none — correctly withheld, 75% < 80% threshold |

### Gaps Found
1. **`hunt_loader.py`'s YAML engine has no automatic escalation wiring.** Day 29 only wired `summarize_hunt_findings()` / `write_hunt_result_to_es()` / `escalate_hunt_to_triage()` into the Day 26 `HuntPlaybook` engine (`after_hours_logins`, `privilege_escalation_spike`). The real Hunts 1–5 (`lateral_movement_ssh` and friends) still require calling `escalate_hunt_to_triage()` by hand. This confirms the existing P1 backlog item ("Wire Day 29 summary/storage/escalation into `hunt_loader.py`'s `run_yaml_hunt()`") is still open and now has a concrete reproduction.
2. **`build_synthetic_alert_from_hunt()` doesn't populate `agent.name`/`data.srcip` from the finding's `key`.** The finding's `key` was `agent1` (the target host), but the synthetic alert set both `agent.name` and `data.srcip` to `"unknown"`. Triage's own evidence flagged this directly: *"Critical fields (Source IP, Target user, Agent host) are all reported as unknown, hindering investigation and potentially indicating obfuscation."* This is a real quality loss, not cosmetic — a synthetic alert built this way arrives at triage already missing the context an analyst would need. New gap, not previously tracked.
3. **Confidence_pct discrepancy between coordination and top-level state.** Coordination logged `confidence_pct=85` (the pre-scored hunt-escalation override), but the final state shows `confidence_pct: 75` — appears triage's own verdict→pct mapping (`suspicious=75+`) overwrote the pre-set value rather than preserving it, unlike the CTI force-route path in Scenario 1. Low priority, but worth a follow-up check against `triage_agent.py`'s return path.

---

## Scenario 3 — After-Hours Exfiltration

### Setup
- Injected a firewall-accept alert (rule 100001, level 8) with `data.srcip=192.0.2.199`, `data.login_hour=3`, `data.is_new_ip=true`, `data.bytes_out=500000000` (500MB)
- **Methodology note:** the alert's `@timestamp` had to be set to the actual injection time (not literally 3am) for the poller's lookback window to pick it up — `data.login_hour` (a plain field read by the scorer) is what drives the after-hours boost, independent of the real `@timestamp`. Not a bug; just a detail of how the scorer and poller interact in a synthetic test.

### Result
```
SCORE  confidence_pct=78%  tier=TRIAGE   (53 base + 15 after-hours + 10 new-IP)
RESULT triage_result=present
       escalate=False  confidence_pct=40%  technique=None
WRITE  verdict='unknown' → written to ES
```
Triage summary: *"There is no threat intelligence match for the source IP... Without further context on the packet's nature (e.g., protocol, port, destination), it is unclear if this moderate severity alert represents a real threat."*

### Checklist
| Check | Result |
|---|---|
| Alert fires | ✅ 78% confidence at scorer, correctly reached TRIAGE tier |
| CTI checked | ✅ `matched=false` — correct, IP not seeded in `siem-threat-intel` |
| Response agent blocks IP | ❌ did not fire automatically — `escalate=False` (verdict came back `unknown`, not `suspicious`) |
| Manual block attempted | Attempted via `response_tools.block_ip()` directly — failed with `wazuh_auth_failed` (401); correctly logged to `siem-response-log` with `success: false` |

### Gaps Found

**Gap 1 (headline finding) — Triage prompt has no data-volume awareness.** `data.bytes_out` (500MB) is never included in the prompt built by `triage_agent.py`. The confidence scorer correctly applied the after-hours and new-IP boosts (53→78%, TRIAGE tier), but the LLM only saw a generic "packet accepted" firewall event with no signal that a large transfer was involved, and returned `verdict=unknown` — which dropped the effective confidence to 40% and left `escalate=False`. **This is more consequential than the response-wiring gap below**: a real large-scale exfiltration event could reach the TRIAGE tier on scorer signals alone and still be waved through as non-escalating because the volume itself is invisible to the LLM. Recommend adding `data.bytes_out` (and ideally a baseline comparison, similar to Hunt 5's `outbound_conn_per_hour` baseline-deviation pattern) to the triage prompt — P1 follow-up.

**Gap 2 — `select_response_action()` still doesn't call `response_tools.block_ip()`/`isolate_endpoint()` automatically.** Confirmed the existing P1 backlog item: Day 31's decision logic only ever selects and logs an action *name*; nothing wires that selection to Day 32/33's real functions. Even if Gap 1 weren't present and the verdict had been `suspicious` at 75%+, no block would have fired without a manual call.

**Gap 3 — Wazuh API auth failure blocked the manual block attempt in this session.** `block_ip()` failed with a 401 because `WAZUH_API_USER`/`WAZUH_API_PASS` weren't exported in the current shell (per Day 33, the real credentials are `wazuh-wui` / `MyS3cr37P450r.*-`, not documented anywhere convenient — same discoverability gap Day 33 already flagged). **Positively confirmed the audit trail works as designed**: the failed attempt was still written to `siem-response-log` with `action_type=block_ip`, `success=false`, `detail=wazuh_auth_failed` — consistent with Day 32/33's requirement to log failures, not just successes.

---

## Summary

| Scenario | Detected | Confidence | CTI Enriched | Hunt Found | Response Action | Verdict Quality |
|---|---|---|---|---|---|---|
| 1 — APT Simulation | ✅ | 100% (scorer) / 75% (triage) | ✅ APT28, conf=95 | — | N/A (ticket not built) | 5/5 — full actor profile in summary |
| 2 — Lateral Movement | ✅ | 85% (hunt escalation) / 75% (triage) | n/a | ✅ 6 distinct IPs, T1021.004 | none (75% < 80% threshold, correct) | 4/5 — correct verdict, but lost srcip/agent context |
| 3 — After-Hours Exfil | ✅ | 78% (scorer) / 40% (triage) | ✅ correctly not matched | n/a | attempted manually, failed (auth) | 2/5 — verdict `unknown`, missed the exfil signal entirely |

### Consolidated Gap List (carried into backlog)
| Priority | Gap | Scenario |
|---|---|---|
| P1 | Triage prompt omits `data.bytes_out` / transfer-volume context — real exfil can score high yet verdict `unknown` | 3 |
| P1 | `hunt_loader.py`'s `run_yaml_hunt()` still lacks Day 29's automatic summarize/write/escalate wiring (existing backlog item, now reproduced) | 2 |
| P1 | `select_response_action()` doesn't call `block_ip()`/`isolate_endpoint()` — selection never reaches real execution (existing backlog item, now reproduced) | 3 |
| P2 | `build_synthetic_alert_from_hunt()` doesn't map finding `key` into `agent.name`/`data.srcip` — degrades triage context on hunt-originated alerts | 2 |
| P2 | Ticket creation (`create_ticket`, Day 34) not yet implemented — no ticket-URL field anywhere in schema | 1 |
| P3 | Confidence_pct set by coordination (pre-scored hunt override) appears overwritten by triage's own verdict mapping rather than preserved | 2 |
| P3 | Wazuh API credentials (`wazuh-wui` / real password) still undocumented in project.md's Infrastructure section — caused a live auth failure during testing (same gap flagged Day 33) | 3 |

### Files
- This report: `~/elastic/docs/phase2-test-results.md`
