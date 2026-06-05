# Day 17 — End-to-End Pipeline Trace

**Generated:** 2026-06-02T06:41:06.899328+00:00  
**Test:** SSH brute-force alert (rule 5710, level 10)  

---

## Hop 1 — Wazuh → Elasticsearch

The Wazuh agent (agent1) detected repeated SSH login failures and generated
a rule 5710 alert. Filebeat shipped it to Elasticsearch.

| Field | Value |
|---|---|
| Rule ID | `5710` |
| Rule desc | sshd: Attempt to login using a non-existent user |
| Rule level | `10` |
| Source IP | `192.168.56.101` |
| Dest user | `root(uid=0)` |
| Timestamp | `2026-06-02T06:37:36.000Z` |
| ES index | `.ds-logs-wazuh.alerts-2026.06.02-2026.06.02-000001` |
| ES doc id | `yFINh54BlQuuLx3uTBIe` |

---

## Hop 2 — Confidence scorer

```
rule.level = 10  →  base_score = int((10/15)*100) = 66
  +10  authentication_failed in rule.groups
  +10  sshd in rule.groups
  + 5  level >= 10
  = 91%   →   tier: TRIAGE
```

---

## Hop 3 — Coordination agent

confidence_pct = **91%** → threshold > 70 → routed to **TRIAGE AGENT**.

Pipeline notes appended by each agent:

- e2e_test: injected rule=5710 level=10 src=192.168.56.101
- [triage] Alert: rule 5710 | level 10 | src=192.168.56.101 | user=root(uid=0)
- [triage] get_recent_events(192.168.56.101) → 1 events in last 60 min
- [triage] get_user_login_history(root) → 1 events in last 7 days
- [triage] No pre-classifier match — calling Ollama llama3.2 for analysis...
- [triage] Verdict: suspicious | The alert indicates an attempt to login using a non-existent user, which is unus...
- [triage] confidence=high (75%) | escalate=True
- [hunting] stub — not yet implemented
- [response] stub — not yet implemented

---

## Hop 4 — Triage agent (Ollama llama3.2:3b)

| Field | Value |
|---|---|
| Verdict | `suspicious` |
| Confidence pct (final) | `75%` |
| Escalate | `True` |
| MITRE technique | `not set` |

**Summary:**  
The alert indicates an attempt to login using a non-existent user, which is unusual and potentially malicious. The source IP has recently made multiple attempts with the same user, suggesting a pattern of activity. The lack of context notes also suggests that this may not be a false positive.

**Evidence:**

- Multiple recent attempts by the same IP address with the same non-existent user
- Lack of context notes on the alert
- Pattern of activity from the source IP

---

## Hop 5 — ES write-back

After triage, the pipeline called `write_triage_result_to_es()` to update
the original alert document with the triage fields.

Fields written:

| ES field | Value |
|---|---|
| `triage.verdict` | `suspicious` |
| `triage.summary` | The alert indicates an attempt to login using a non-existent user, which is unus… |
| `triage.confidence_pct` | `75` |
| `triage.processed_at` | `2026-06-02T06:41:05.467114+00:00` |
| `triage.pipeline_version` | `day17-v1` |

**Verification:** document read back from ES confirmed `triage.verdict` present. ✅

---

## Summary

```
Wazuh agent1
  → rule 5710 fired (level 10, sshd brute force)
  → Filebeat → Elasticsearch (logs-wazuh.alerts-*)
  → pipeline_runner.py polls ES, finds unprocessed alert
  → confidence_scorer: 91% → TRIAGE tier
  → coordination_agent: routes to triage_node
  → triage_agent (Ollama): fetches ES context, calls LLM
  → verdict: suspicious  escalate: True
  → write_triage_result_to_es(): patches original ES document
  → verified: triage.verdict present on document ✅
```
