# UEBA + Feedback Loop Test Results — Day 50 (31 July 2026)

**Project:** Phase 3 SIEM Testing | **Engineer:** Ahmad Bussti
**Objective:** Full test pass on UEBA profiling, anomaly scoring, the analyst feedback loop, and insider threat detection — the last review point before Week 10 sign-off. Confirm whether the feedback loop actually changes confidence outcomes on subsequent alerts.

**Test harness:** `test_day50.py` (new, combined mocked/live suite, same convention as `test_day46.py`/`test_day48.py`/`test_day49.py`). Run live against the real stack: `python3 test_day50.py --live`.

---

## Test 1 — UEBA Profile + Anomaly Scoring

### Setup
Built a baseline profile for a synthetic user (`day50-testuser`) via `ueba_engine.write_ueba_profile_to_es()`, then ran 3 synthetic events through `ueba_scorer.score_anomaly()`.

### First Attempt — Test Design Flaw, Not a Product Bug
The first version of this test isolated one anomaly dimension per event (new IP only, rare command only, volume only) and got 40/20/26 — all correctly under the 60 threshold. This was **not a scorer bug**: each event genuinely only contained one anomalous field, so `command_rarity`/`volume_spike`/`source_ip_novelty` correctly scored 0 wherever no matching field existed on that alert. The math checked out exactly against `confidence_scorer.py`'s documented per-dimension logic (Day 47). Re-verified this wasn't a live scorer defect by re-running the *combined* events below.

### Corrected Test — Combined Dimensions Per Event (Matches Day 47's Own Self-Test Pattern)
Each event now stacks after-hours login + new source IP + rare command + high-volume transfer together, same pattern Day 47's original self-test used to reach 80/100.

### Result
```
Event A — after-hours + new IP + rare command + volume spike: anomaly_score=80 ✓
Event B — after-hours + new IP + rare command (different values): anomaly_score=80 ✓
Event C — after-hours + new IP + rare command (different values again): anomaly_score=80 ✓
```

### Checklist
| Check | Result |
|---|---|
| Profile written to ES | ✅ |
| Event A anomaly_score > 60 | ✅ 80/100 |
| Event B anomaly_score > 60 | ✅ 80/100 |
| Event C anomaly_score > 60 | ✅ 80/100 |
| Per-dimension math consistent with Day 47's documented scoring rules | ✅ verified on both the isolated and combined event designs |

**Verdict: 5/5 — pass.**

---

## Test 2 — Feedback Loop: 30 Analyst Verdicts → `retrain_weights()`

### Setup
Injected 30 synthetic analyst verdicts (mixed TP/FP, FP-heavy in the 40-70 and 70-100 confidence buckets) via `feedback_loop.record_verdict()`, then ran `retrain_weights()`.

### Result (final live run)
```
weights before injection: {'rule_severity': 0.2, 'anomaly': 0.15, 'time_factor': 0.25}
new_weights:               {'rule_severity': 0.1, 'anomaly': 0.15, 'time_factor': 0.25}
adjustments:
  bucket 40-70  → rule_severity 0.2  → 0.15  (fp_rate=0.4   > 0.3)
  bucket 70-100 → rule_severity 0.15 → 0.1   (fp_rate=0.4   > 0.3)
```

### Checklist
| Check | Result |
|---|---|
| 30/30 verdicts injected successfully | ✅ |
| High-FP buckets identified correctly | ✅ both 40-70 and 70-100 flagged |
| Dominant factor reduced by 0.05 per over-threshold bucket | ✅ |
| Untouched buckets/factors left alone | ✅ `time_factor` never adjusted |
| Every cycle audited to `siem-weight-history` | ✅ |

**Verdict: 5/5 — pass.**

### ⚠️ Follow-Up: Cumulative Weight Drift Across Repeated Test Runs
This test was iterated several times during today's debugging session (fixing the test harness itself, not the product), and each `--live` run injects another 30 FP-heavy verdicts on top of whatever's already in `siem-analyst-verdicts`. As a result, `rule_severity` has now been pushed down across multiple cycles today (0.4 → 0.35 → 0.3 → 0.25 → 0.2 → 0.1 over the course of this session). **This is a testing artifact, not a real production signal** — it reflects repeated synthetic FP injection during script debugging, not 5 independent days of real analyst decisions. Recommend either:
- Clearing `siem-analyst-verdicts`/`siem-weight-history` of today's synthetic test docs before this is mistaken for a genuine trend, or
- Noting the current `rule_severity=0.1` weight is test-session residue, not a validated production value, until real analyst verdicts accumulate.

This is the same "test data left in a real index" class already tracked for Day 28 (baseline contamination) and Day 48 (`day48-tp-*`/`day48-fp-*` docs).

---

## Test 3 — Does Retraining Actually Change Confidence Outcomes?

### Setup
Replayed the same sample alert (CTI-matched, after-hours SSH alert, scorer would normally output 100%) through `confidence_scorer.score()` immediately before and after a `retrain_weights()` cycle.

### Result
```
confidence_pct before retrain: 100
confidence_pct after retrain:  100
```

**Unchanged.** This is the one test in the suite designed to surface a known gap rather than pass: `confidence_scorer.py`'s `score()`/`score_and_tier()` never call `feedback_loop.get_current_weights()`. The retrain loop correctly computes and audits new weights to `siem-weight-history` — but nothing downstream actually consumes them yet.

### Verdict
**Confirmed live: the feedback loop does NOT yet change confidence outcomes on subsequent alerts.** This directly answers the Day 50 plan's central question ("verify the feedback loop actually changes confidence outcomes") — as of today, it does not. This reproduces, with hard before/after evidence, the existing **Day 48 P1 backlog item**: *"Wire `retrain_weights()`'s output back into `confidence_scorer.py`'s actual boosts."* No new bug — same gap, now demonstrated live rather than inferred from code reading.

---

## Test 4 — Insider Threat (Data Staging) End-to-End

### Setup
Wrote a synthetic baseline (`avg_outbound_bytes_per_day=1,500,000`) for `day50-insider`, then injected a staging alert at ~15-45x that baseline (varied slightly across re-runs) and ran the full detection → escalation → coordination → triage chain.

### Result
```
detect_data_staging(): 45,000,000 bytes/24h vs. 1,500,000/day baseline — 45.0x
  escalate=True, mitre_technique=T1074, status='ok'

escalate_insider_finding_to_coordination():
  [coordination] confidence_pct=90 (insider pre-score override)
  [triage] verdict=benign | confidence=low (20%) | escalate=False
```

### Checklist
| Check | Result |
|---|---|
| `detect_data_staging()` fires at high multiple of baseline | ✅ 45.0x, well above the 10x threshold |
| Correct MITRE technique tagged | ✅ T1074 |
| Pre-scored insider override reaches coordination | ✅ confidence_pct=90 |
| Full pipeline reached (coordination → triage → hunting → response) | ✅ no errors |
| Final verdict/escalation matches expectation | ⚠️ see note below |

**Verdict: 4/5 — the detection and pipeline wiring are fully confirmed working end-to-end. One real finding surfaced, documented below rather than scored as a failure.**

### ⚠️ Finding: Non-Deterministic Triage Outcome on the Same Underlying Signal
Two live runs of this same scenario today produced **different final verdicts** on functionally the same finding:

| Run | Bytes ratio | Triage verdict | Confidence | Escalate |
|---|---|---|---|---|
| 1 | 30.0x baseline | suspicious | 75% | True |
| 2 | 45.0x baseline | benign | 20% | False |

In both runs, `insider_threat.py`'s own detection correctly fired (`escalate=True`, `status='ok'`) and coordination correctly force-routed at `confidence_pct=90`. The divergence happened **inside `triage_agent.py`'s Gemini call**. In Run 2, Gemini's evidence explicitly cited: *"UEBA anomaly score is 0/100, indicating the reported activity is fully typical... suggesting the alert is likely a false positive."*

**Root cause:** the synthetic test profile only sets `avg_outbound_bytes_per_day` — it has no `typical_login_hours`/`typical_source_ips`/`typical_commands` history. `ueba_scorer.score_anomaly()` correctly returns `0/100` for a profile with nothing anomalous to compare against on those dimensions — but a `0/100` UEBA score reads to the LLM as **"confirmed normal behavior,"** not **"insufficient profile data to judge."** That's enough for Gemini to override the hunt's own `escalate=True` decision and downgrade to `benign`.

**This is a real, worth-tracking interaction, not a test artifact:** a genuine insider-threat finding backed by real behavioral deviation (the entire point of `insider_threat.py`) can be talked down by the *same* UEBA context block if the profile is partial or newly-built. A brand-new employee, or any user without a mature profile yet, would hit this exact pattern for real.

**Recommended follow-up (new, add to Phase 3 backlog):** the UEBA context block in `triage_agent.py`'s prompt should distinguish "0/100 — genuinely matches an established, data-rich baseline" from "0/100 — profile is incomplete/sparse, insufficient basis to judge." Otherwise sparse profiles function as an accidental "get out of triage free" signal for exactly the users (new hires, rarely-active accounts) where insider-threat detection matters most.

---

## Test 5 — Scheduled UEBA Profile Refresh

### Setup
Ran `profile_scheduler.run_all_profiles_once()` directly (one cycle, no scheduler wait).

### Result
```
[profile_scheduler] Rebuilding user profile: devadmin
[profile_scheduler] Rebuilding user profile: root
[profile_scheduler] Rebuilding user profile: www-data
[profile_scheduler] Rebuilding host profile: agent1
[profile_scheduler] Rebuilding host profile: redteam-target-win10
errors=0
```

### Checklist
| Check | Result |
|---|---|
| Cycle completes without exceptions | ✅ |
| All 3 seeded users rebuilt | ✅ |
| Both hosts rebuilt | ✅ |
| Zero errors | ✅ |

**Verdict: 5/5 — pass.** (Note: the test harness's own "refreshed" count is approximate/cosmetic — `run_all_profiles_once()`'s return shape wasn't fully confirmed against the harness's parsing logic, but this doesn't affect the actual refresh cycle, which is confirmed clean via the `errors=0` result and direct log output.)

---

## Summary

| Test | Result | Notes |
|---|---|---|
| 1 — UEBA anomaly scoring | ✅ 5/5 | All 3 combined-dimension events scored 80/100, correctly >60 |
| 2 — Feedback retrain (30 verdicts) | ✅ 5/5 | Weights shift correctly on high-FP buckets; see weight-drift follow-up |
| 3 — Retrain → scorer output | ❌ (expected) | Confirms live: feedback loop does NOT yet change confidence outcomes — Day 48 P1 |
| 4 — Insider threat E2E | ⚠️ 4/5 | Detection/escalation/pipeline wiring all confirmed; triage verdict non-deterministic on sparse profiles (new finding) |
| 5 — Scheduled UEBA refresh | ✅ 5/5 | Clean cycle, 0 errors, all entities rebuilt |

### Consolidated Follow-Ups (new/reconfirmed from today)
| Priority | Item | Source |
|---|---|---|
| P1 (existing) | Wire `retrain_weights()`'s output into `confidence_scorer.py`'s actual boosts | Reconfirmed live — Test 3, Day 48 backlog |
| P2 (new) | Distinguish "0/100 — genuinely normal" from "0/100 — profile too sparse to judge" in `triage_agent.py`'s UEBA prompt block | Test 4 |
| P2 (existing) | Clean up synthetic `siem-analyst-verdicts` test docs before real analyst data accumulates | Reconfirmed — Test 2, same class as Day 28/48 |
| P3 (new) | Document that today's `rule_severity=0.1` weight reflects repeated test-session injection, not a validated production trend | Test 2 |

### Files
- Test harness: `test_day50.py`
- This report: `~/elastic/docs/ueba-test-results.md`
