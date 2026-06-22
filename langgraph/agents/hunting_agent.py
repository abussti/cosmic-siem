# hunting_agent.py
# Proactive threat hunting agent — runs after the triage agent.
# Previously a stub (Day 15 skipped). Now implements correlated hunting
# for the T1078 after-hours + new-IP + privilege-escalation pattern.
# Day 19: full implementation (B3 fix)
# Day 26: added a SECOND, alert-independent hunting engine below
#         (HuntPlaybook / run_hunt / run_all_default_hunts). See the
#         banner comment further down for the boundary between the two.

import logging
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone, timedelta
from tools.elastic_tools import (
    get_alerts_by_src_ip,
    get_user_login_history,
    get_high_severity_alerts,
    _post,
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

    Returns:
        {threats_found: int, findings: list[dict], hunt_summary: str, escalate: bool}
    """
    es_body = _build_time_ranged_query(playbook.hunt_query, playbook.time_window)

    try:
        resp = _post(f"{playbook.index}/_search", es_body)
    except Exception as exc:
        logger.error("Hunt '%s' failed to query ES: %s", playbook.hunt_name, exc)
        return {
            "threats_found": 0,
            "findings": [],
            "hunt_summary": f"Hunt '{playbook.hunt_name}' errored before returning results: {exc}",
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

    if threats_found == 0:
        hunt_summary = (
            f"Hunt '{playbook.hunt_name}' ran over the last {playbook.time_window}h "
            f"window and found nothing of interest."
        )
    else:
        top = findings[0]
        hunt_summary = (
            f"Hunt '{playbook.hunt_name}' found {threats_found} matching event(s) "
            f"in the last {playbook.time_window}h. "
            f"Top hit: rule {top['rule_id']} ({top['rule_description']}) from {top['src_ip']}."
        )

    return {
        "threats_found": threats_found,
        "findings": findings,
        "hunt_summary": hunt_summary,
        "escalate": escalate,
    }


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