# hunting_agent.py
# Proactive threat hunting agent — runs after the triage agent.
# Previously a stub (Day 15 skipped). Now implements correlated hunting
# for the T1078 after-hours + new-IP + privilege-escalation pattern.
# Day 19: full implementation (B3 fix)
# Day 26: added a SECOND, alert-independent hunting engine below
#         (HuntPlaybook / run_hunt / run_all_default_hunts). See the
#         banner comment further down for the boundary between the two.
# Day 39: bug fix — escalate_hunt_to_triage() now sets state["_pre_scored"]
#         = True on the synthetic-alert state it hands to graph.pipeline, so
#         triage_agent.py's confidence_pct preservation fix (companion Day 39
#         change) actually has something to key off of. Confirmed against
#         Phase 2 Scenario 2 testing: coordination logged confidence_pct=85
#         but the final state showed 75, because triage_agent.py had no way
#         to know 85 was a deliberate pre-scored override rather than a
#         stale default.

import logging
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone, timedelta
from tools.hunt_summarizer import summarize_hunt_findings
from tools.elastic_tools import (
    get_alerts_by_src_ip,
    get_user_login_history,
    get_high_severity_alerts,
    _post,
    write_hunt_result_to_es,
)

logger = logging.getLogger("hunting_agent")


# How far back to look when correlating related events
CORRELATION_WINDOW_MINUTES = 10

# Privilege-escalation rule IDs to look for after a suspicious login
PRIV_ESC_RULE_IDS = {"5402", "5403"}  # sudo to ROOT, first-time sudo


def hunting_node(state: dict) -> dict:
    """
    LangGraph node — proactive hunting on top of what triage already found.

    Runs three hunts in sequence and appends findings to state['notes'].
    Does NOT make a verdict — that stays with the triage agent.
    Sets state['escalate'] = True if a high-confidence hunt pattern fires.

    Hunts implemented:
      Hunt 1 — After-hours + new-IP correlation (T1078)
      Hunt 2 — Privilege escalation within 10 min of suspicious login (T1078/T1059)
      Hunt 3 — Lateral movement: same IP seen on multiple agents (T1021)
    """
    alert  = state.get("alert", {})
    notes  = state.get("notes", [])
    src_ip = alert.get("data", {}).get("srcip", "")
    user   = _extract_username(alert)
    ts     = alert.get("@timestamp", "")

    notes.append("[hunting_agent] starting proactive hunts")

    # ── Hunt 1: After-hours + new IP ──────────────────────────────────────
    # Already partially caught by confidence_scorer; here we verify by
    # looking for corroborating events in the same window.
    after_hours = _is_after_hours(ts)
    if after_hours:
        notes.append(
            "[hunting_agent] Hunt 1: login timestamp is outside business hours"
        )
        # Look for any other suspicious activity from the same IP today
        recent = get_alerts_by_src_ip(src_ip, minutes=60) if src_ip else []
        suspicious_recent = [
            a for a in recent
            if "authentication_failed" in a.get("rule", {}).get("groups", [])
        ]
        if suspicious_recent:
            count = len(suspicious_recent)
            notes.append(
                f"[hunting_agent] Hunt 1 HIT: {count} prior auth failures "
                f"from {src_ip} in last 60 min — escalating"
            )
            state["escalate"] = True
        else:
            notes.append(
                f"[hunting_agent] Hunt 1: no prior failures from {src_ip} — "
                "after-hours login is isolated, not escalating"
            )

    # ── Hunt 2: Privilege escalation within 10 min of login ───────────────
    # If the same user ran sudo shortly after this alert, that's a strong
    # indicator of intentional privilege escalation.
    if user:
        login_history = get_user_login_history(user, days=1)
        priv_esc_events = [
            e for e in login_history
            if str(e.get("rule", {}).get("id", "")) in PRIV_ESC_RULE_IDS
            and _within_window(ts, e.get("@timestamp", ""), CORRELATION_WINDOW_MINUTES)
        ]
        if priv_esc_events:
            notes.append(
                f"[hunting_agent] Hunt 2 HIT: privilege escalation by '{user}' "
                f"within {CORRELATION_WINDOW_MINUTES} min of this login — escalating"
            )
            state["escalate"] = True
            # Tag the MITRE technique if not already set
            if not state.get("technique"):
                state["technique"] = "T1078+T1059"
        else:
            notes.append(
                f"[hunting_agent] Hunt 2: no privilege escalation by '{user}' "
                f"in ±{CORRELATION_WINDOW_MINUTES} min window"
            )

    # ── Hunt 3: Lateral movement — same IP on multiple agents ─────────────
    # If this IP has triggered alerts on more than one Wazuh agent in the
    # last hour, it may be moving laterally through the network.
    if src_ip:
        recent_all = get_alerts_by_src_ip(src_ip, minutes=60)
        agents_seen = {
            a.get("agent", {}).get("name", "")
            for a in recent_all
            if a.get("agent", {}).get("name")
        }
        if len(agents_seen) > 1:
            notes.append(
                f"[hunting_agent] Hunt 3 HIT: {src_ip} seen on multiple agents "
                f"{agents_seen} — possible lateral movement — escalating"
            )
            state["escalate"] = True
            if not state.get("technique"):
                state["technique"] = "T1021"
        else:
            notes.append(
                f"[hunting_agent] Hunt 3: {src_ip} confined to single agent — "
                "no lateral movement detected"
            )

    notes.append("[hunting_agent] hunts complete")
    state["notes"] = notes
    return state


# ---------------------------------------------------------------------------
# Helpers (Day 19)
# ---------------------------------------------------------------------------

def _extract_username(alert: dict) -> str:
    """
    Pull the destination username out of a Wazuh alert.
    Tries data.dstuser first (SSH/PAM), then data.user, then falls back
    to an empty string so callers never receive None.
    """
    data = alert.get("data", {})
    raw  = data.get("dstuser") or data.get("user") or ""
    # Strip uid suffix e.g. "root(uid=0)" → "root"
    return raw.split("(")[0].strip()


def _is_after_hours(ts_str: str) -> bool:
    """
    Return True if the ISO-8601 timestamp falls outside 06:00–22:00 UTC.
    Returns False if the timestamp cannot be parsed (safe default).
    """
    if not ts_str:
        return False
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        return not (6 <= dt.hour < 22)
    except (ValueError, TypeError):
        return False


def _within_window(ts_anchor: str, ts_event: str, window_minutes: int) -> bool:
    """
    Return True if ts_event falls within ±window_minutes of ts_anchor.
    Both strings must be ISO-8601. Returns False on parse error.
    """
    try:
        anchor = datetime.fromisoformat(ts_anchor.replace("Z", "+00:00"))
        event  = datetime.fromisoformat(ts_event.replace("Z", "+00:00"))
        delta  = abs((event - anchor).total_seconds())
        return delta <= window_minutes * 60
    except (ValueError, TypeError):
        return False


# ============================================================================
# Day 26 — Proactive Hunting Engine (scheduled, alert-independent)
# ============================================================================
# Everything ABOVE this line is the Day 19 hunting_node — REACTIVE. It only
# ever runs once an alert has already cleared coordination + triage in the
# main graph (graph.py: triage -> hunting -> response).
#
# Everything BELOW this line is NEW. It is a generic, playbook-driven engine
# that runs on a timer with no triggering alert at all — give it a name, a
# lookback window, and a raw Elastic DSL clause, and it runs. Wired into
# graph.py as its own parallel branch (scheduled_hunt_node / hunt_pipeline)
# and invoked by the scheduler in pipeline_runner.py every 6 hours.
# ============================================================================

ALERTS_INDEX = "logs-wazuh.alerts-*"

# Escalate as soon as a scheduled hunt turns up at least this many hits.
# Tune upward later if this proves too noisy.
ESCALATION_THRESHOLD = 1


@dataclass
class HuntPlaybook:
    hunt_name: str
    time_window: int          # lookback window, in hours
    hunt_query: dict           # Elastic DSL clause; {} = match_all
    index: str = ALERTS_INDEX
    mitre_technique: str | None = None  # Day 29: optional, feeds the Gemini prompt
                                          # and the synthetic alert's hunt_origin block


def _build_time_ranged_query(hunt_query: dict, time_window: int) -> dict:
    """
    Wrap a playbook's hunt_query with a time range filter for the last
    `time_window` hours. Handles three shapes of hunt_query:
      - {}                      -> match_all within the window
      - {"bool": {...}}         -> graft the range filter into it
      - {<bare query clause>}   -> wrap it in a bool/must
    """
    range_filter = {
        "range": {
            "@timestamp": {
                "gte": f"now-{time_window}h",
                "lte": "now",
            }
        }
    }

    if not hunt_query:
        # Empty query → match_all in-window. This is exactly the Day 26
        # acceptance check: "run with an empty hunt query, verify no crash."
        return {
            "size": 100,
            "query": {
                "bool": {
                    "must": [{"match_all": {}}],
                    "filter": [range_filter],
                }
            },
            "sort": [{"@timestamp": "desc"}],
        }

    if "bool" in hunt_query:
        merged = dict(hunt_query["bool"])
        merged.setdefault("filter", [])
        merged["filter"] = merged["filter"] + [range_filter]
        return {
            "size": 100,
            "query": {"bool": merged},
            "sort": [{"@timestamp": "desc"}],
        }

    return {
        "size": 100,
        "query": {
            "bool": {
                "must": [hunt_query],
                "filter": [range_filter],
            }
        },
        "sort": [{"@timestamp": "desc"}],
    }


def run_hunt(playbook: HuntPlaybook) -> dict:
    """
    Execute one hunt playbook against Elasticsearch. Always returns the
    standard contract — never raises, even on ES errors or malformed
    queries, since this runs unattended on a scheduler.

    Day 29:
      1. On an ES query error, the failed cycle is still written to
         siem-hunt-results (so the index has a complete history of every
         cycle, not just successful ones), then returns immediately.
      2. On success, hunt_summary is now generated by Gemini
         (summarize_hunt_findings) instead of the old fixed-template string.
         summarize_hunt_findings() never raises — it falls back to a
         templated summary on any Gemini failure — so this call is always
         safe to make.
      3. Every cycle's result (hunt_name, findings_count, summary, escalated,
         timestamp) is written to siem-hunt-results via write_hunt_result_to_es().
      4. If escalate is True, the top finding is reshaped into a synthetic
         alert and handed to coordination_agent (via the graph) for triage,
         through escalate_hunt_to_triage().

    Returns:
        {threats_found: int, findings: list[dict], hunt_summary: str, escalate: bool}
    """
    es_body = _build_time_ranged_query(playbook.hunt_query, playbook.time_window)

    try:
        resp = _post(f"{playbook.index}/_search", es_body)
    except Exception as exc:
        logger.error("Hunt '%s' failed to query ES: %s", playbook.hunt_name, exc)
        hunt_summary = f"Hunt '{playbook.hunt_name}' errored before returning results: {exc}"
        write_hunt_result_to_es(playbook.hunt_name, 0, hunt_summary, False)
        return {
            "threats_found": 0,
            "findings": [],
            "hunt_summary": hunt_summary,
            "escalate": False,
        }

    hits = resp.get("hits", {}).get("hits", [])

    findings: list[dict[str, Any]] = []
    for hit in hits:
        src = hit.get("_source", {})
        findings.append({
            "es_id": hit.get("_id"),
            "timestamp": src.get("@timestamp"),
            "rule_id": src.get("rule", {}).get("id"),
            "rule_description": src.get("rule", {}).get("description"),
            "agent_name": src.get("agent", {}).get("name"),
            "src_ip": src.get("data", {}).get("srcip"),
            "dst_user": src.get("data", {}).get("dstuser"),
        })

    threats_found = len(findings)
    escalate = threats_found >= ESCALATION_THRESHOLD

    # Day 29: Gemini-generated summary replaces the old fixed-template string.
    hunt_summary = summarize_hunt_findings(
        playbook.hunt_name, findings, playbook.mitre_technique
    )

    write_hunt_result_to_es(
        hunt_name=playbook.hunt_name,
        findings_count=threats_found,
        summary=hunt_summary,
        escalated=escalate,
    )

    if escalate and findings:
        escalate_hunt_to_triage(
            playbook.hunt_name, findings, hunt_summary, playbook.mitre_technique
        )

    return {
        "threats_found": threats_found,
        "findings": findings,
        "hunt_summary": hunt_summary,
        "escalate": escalate,
    }


# ---------------------------------------------------------------------------
# Day 29 — Gemini summary storage + escalation to coordination_agent
# Day 39 — _pre_scored flag added to the escalation state (bug fix)
# ---------------------------------------------------------------------------

# Synthetic alerts skip confidence_scorer.py entirely and are pre-scored here,
# because they already passed a hunt's own ESCALATION_THRESHOLD — equivalent
# in spirit to Day 24's CTI > 80 override: a signal already validated upstream
# walks straight into triage instead of being re-scored as a raw, unvetted alert.
HUNT_ESCALATION_CONFIDENCE_PCT = 85


def build_synthetic_alert_from_hunt(
    hunt_name: str, findings: list[dict], mitre_technique: str | None = None
) -> dict:
    """
    Reshapes a hunt finding into the same alert shape coordination_agent and
    triage_agent already expect (see "Wazuh Alert Field Schema" in project.md).
    This means zero changes are needed in coordination_agent.py or
    triage_agent.py to accept a hunt-originated alert — it just looks like
    any other alert dict going into the graph.

    Day 39 note: this function trusts findings[0] to already carry flat
    "src_ip" / "dst_user" / "agent_name" keys. That normalization is done by
    the caller — run_hunt() above builds findings with those keys directly
    from hit._source, and hunt_loader.py's _normalize_findings_for_summary()
    (Day 39 bug fix there) now does the same for aggregation-based YAML hunts
    before calling this function. If you add a new finding source, normalize
    it to these three keys before calling build_synthetic_alert_from_hunt() —
    don't special-case a new key shape in here.
    """
    top = findings[0] if findings else {}
    src_ip = top.get("src_ip") or "unknown"
    dst_user = top.get("dst_user") or "unknown"
    agent_name = top.get("agent_name") or "unknown"

    return {
        "rule": {
            "id": f"hunt:{hunt_name}",
            "description": f"Proactive hunt '{hunt_name}' surfaced {len(findings)} finding(s)",
            "level": 12,  # fixed high level — this alert already passed a hunt threshold
            "groups": ["hunting", "proactive"],
        },
        "agent": {"name": agent_name},
        "data": {"srcip": src_ip, "dstuser": dst_user},
        "hunt_origin": {
            "hunt_name": hunt_name,
            "mitre_technique": mitre_technique,
            "finding_count": len(findings),
        },
        "@timestamp": datetime.now(timezone.utc).isoformat(),
    }


def escalate_hunt_to_triage(
    hunt_name: str,
    findings: list[dict],
    hunt_summary: str,
    mitre_technique: str | None = None,
) -> dict | None:
    """
    Builds a synthetic alert from a hunt finding and hands it to the alert
    pipeline (coordination_agent onward) for triage — the same path a real
    Wazuh alert takes once it's pre-scored above the triage threshold.

    graph.py already imports from this module (hunting_agent.py) to wire
    scheduled_hunt_node, so importing graph.py back at the top of this file
    would create a circular import. The import is done lazily, inside this
    function, instead — it only runs at escalation time, never at module load.

    Never raises — an import or pipeline failure here must not crash the
    hunt cycle that triggered it. Returns None on failure, the pipeline's
    result dict on success.

    Day 39 bug fix: the invoke state now includes "_pre_scored": True
    alongside "confidence_pct": HUNT_ESCALATION_CONFIDENCE_PCT. Previously
    only confidence_pct was set, with no signal telling triage_agent.py that
    this value was a deliberate upstream override rather than an unset
    default — triage_node() would always recompute confidence_pct from the
    verdict (75/20/40) and silently discard the 85% override. Confirmed as
    the root cause of the Phase 2 Scenario 2 test's confidence_pct
    discrepancy (coordination logged 85, final state showed 75).
    """
    synthetic_alert = build_synthetic_alert_from_hunt(hunt_name, findings, mitre_technique)
    synthetic_alert["hunt_origin"]["gemini_summary"] = hunt_summary

    try:
        from graph import pipeline
    except ImportError as exc:
        logger.error("Could not import graph.pipeline to escalate hunt '%s': %s", hunt_name, exc)
        return None

    try:
        return pipeline.invoke({
            "alert": synthetic_alert,
            "confidence_pct": HUNT_ESCALATION_CONFIDENCE_PCT,
            "_pre_scored": True,  # Day 39 fix — see docstring above
            "notes": [f"[hunting_agent] synthetic alert from proactive hunt '{hunt_name}'"],
        })
    except Exception as exc:
        logger.error("Pipeline invocation failed for hunt '%s' escalation: %s", hunt_name, exc)
        return None


# ---------------------------------------------------------------------------
# Default hunt playbook registry
# ---------------------------------------------------------------------------
# Add new hunting hypotheses here — name + lookback window + DSL clause.
# No code changes needed to add a hunt; that's the whole point of this
# scaffold vs. the hardcoded Hunt 1/2/3 logic in hunting_node() above.

DEFAULT_PLAYBOOKS: list[HuntPlaybook] = [
    HuntPlaybook(
        hunt_name="after_hours_logins",
        time_window=24,
        hunt_query={
            "bool": {
                "must": [{"terms": {"rule.groups": ["authentication_success"]}}],
                "filter": [{
                    "script": {
                        "script": {
                            "source": (
                                "doc['data.login_hour'].size() > 0 && "
                                "(doc['data.login_hour'].value < 6 || "
                                "doc['data.login_hour'].value > 22)"
                            )
                        }
                    }
                }],
            }
        },
    ),
    HuntPlaybook(
        hunt_name="privilege_escalation_spike",
        time_window=6,
        hunt_query={"bool": {"must": [{"terms": {"rule.groups": ["sudo"]}}]}},
    ),
    # NOTE: a match_all/empty-query playbook deliberately does NOT live here.
    # With ESCALATION_THRESHOLD=1, a match_all hunt would escalate on every
    # single 6h cycle as long as ANY log exists — pure noise. The empty-query
    # acceptance check (Day 26 deliverable 6) is exercised standalone in the
    # __main__ block below instead, via a one-off HuntPlaybook that never
    # gets registered into the scheduled production run.
]


def run_all_default_hunts() -> list[dict]:
    """
    Run every playbook in DEFAULT_PLAYBOOKS. Called by scheduled_hunt_node
    in graph.py (which is in turn invoked by the scheduler in
    pipeline_runner.py every 6 hours), and by the standalone smoke test below.
    """
    results = []
    for playbook in DEFAULT_PLAYBOOKS:
        logger.info("Running hunt playbook: %s", playbook.hunt_name)
        result = run_hunt(playbook)
        result["hunt_name"] = playbook.hunt_name
        results.append(result)
    return results


if __name__ == "__main__":
    # Day 29 note: run_hunt() now also calls Gemini (summarize_hunt_findings),
    # writes to siem-hunt-results (write_hunt_result_to_es), and — if any
    # playbook escalates — tries to invoke graph.pipeline. None of these can
    # crash this smoke test: summarize_hunt_findings() falls back to a
    # templated summary on any Gemini error, write_hunt_result_to_es() logs
    # and returns None on an ES error, and escalate_hunt_to_triage() logs and
    # returns None on an import or pipeline error. Set GEMINI_API_KEY first
    # to see real Gemini output instead of the fallback text.
    logging.basicConfig(level=logging.INFO)
    print("=== Hunting Agent — Day 26 standalone smoke test ===\n")

    # Required Day 26 acceptance check: empty hunt query must not crash.
    empty_playbook = HuntPlaybook(hunt_name="manual_empty_test", time_window=1, hunt_query={})
    result = run_hunt(empty_playbook)
    print(f"[empty query test] threats_found={result['threats_found']} escalate={result['escalate']}")
    print(f"  summary: {result['hunt_summary']}\n")

    print("=== Running all default (production) playbooks ===")
    for r in run_all_default_hunts():
        print(f"- {r['hunt_name']}: threats_found={r['threats_found']} escalate={r['escalate']}")
        print(f"  {r['hunt_summary']}")

    # Day 39 regression test: confirm the _pre_scored flag actually reaches
    # graph.pipeline's invoke() call when a hunt escalates. This doesn't
    # require a real ES/Gemini connection to check — it inspects the dict
    # passed to pipeline.invoke() directly.
    print("\n=== Day 39 regression test — _pre_scored flag on escalation ===")
    test_findings = [{"src_ip": "203.0.113.11", "dst_user": "svc-app", "agent_name": "agent1"}]
    try:
        from unittest.mock import patch
        with patch("graph.pipeline") as mock_pipeline:
            mock_pipeline.invoke.return_value = {"confidence_pct": 85}
            escalate_hunt_to_triage("lateral_movement_ssh", test_findings, "test summary", "T1021.004")
            called_state = mock_pipeline.invoke.call_args[0][0]
            assert called_state.get("_pre_scored") is True, "Day 39 fix missing: _pre_scored not set"
            assert called_state.get("confidence_pct") == HUNT_ESCALATION_CONFIDENCE_PCT
            print("PASS — escalate_hunt_to_triage() sets _pre_scored=True and confidence_pct=85")
    except ImportError:
        print("SKIPPED — unittest.mock or graph module not available in this environment")
