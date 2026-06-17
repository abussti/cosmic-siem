"""
coordination_agent.py — LangGraph node: Coordination Agent.

Day 16 — initial routing logic (archive / review / triage tiers)
Day 17 — fixed to read pre-scored confidence_pct from state instead of
          recalculating from rule.level directly
Day 19 — burst detection (not shown in this excerpt — keep your existing
          implementation if you have one wired in elsewhere)
Day 24 — CTI override: if cti.confidence > 80, force-route to triage in
          route_after_coordination() regardless of confidence_pct tier.

NOTE: this file previously had a bug — coordination_node referenced an
undefined `rule` variable (leftover from a refactor), which would raise a
NameError on every call. That line is fixed below: confidence_pct now
falls back to _rule_level_to_confidence(alert) instead of a bare `rule.get(...)`.
"""

import json
import datetime
import requests
from state import AgentState

# ── Config ──────────────────────────────────────────────────────────────────
ES_URL  = "http://localhost:9201"
ES_AUTH = ("elastic", "changeme")
ARCHIVE_PATH = "/home/wazuh-manager/elastic/logs/archived-alerts.jsonl"
REVIEW_INDEX = "siem-review-queue"

# ── Thresholds ───────────────────────────────────────────────────────────────
ARCHIVE_MAX   = 39   # confidence_pct <= 39  → archive
REVIEW_MAX    = 70   # confidence_pct 40–70  → analyst review queue
# confidence_pct > 70 → triage agent

# [Day 24] CTI override threshold — a CTI confidence above this forces
# routing to triage regardless of the base confidence_pct tier.
CTI_OVERRIDE_THRESHOLD = 80


# ── Helpers ──────────────────────────────────────────────────────────────────

def _rule_level_to_confidence(alert: dict) -> int:
    """Convert Wazuh rule.level (1–15) to confidence_pct (0–100)."""
    level = alert.get("rule", {}).get("level", 1)
    # level 1–4 → 10–35, level 5–9 → 40–65, level 10–15 → 70–100
    return min(100, int((level / 15) * 100))


def _archive_alert(alert: dict, confidence_pct: int) -> None:
    """Append alert to JSONL archive file."""
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "confidence_pct": confidence_pct,
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
        "alert": alert,
    }
    with open(ARCHIVE_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[COORDINATION] ARCHIVED (confidence={confidence_pct}): rule {record['rule_id']}")


def _send_to_review_queue(alert: dict, confidence_pct: int) -> None:
    """Index alert into Elastic siem-review-queue."""
    doc = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "confidence_pct": confidence_pct,
        "status": "pending_analyst_review",
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
        "agent_name": alert.get("agent", {}).get("name"),
        "src_ip": alert.get("data", {}).get("srcip"),
        "alert": alert,
    }
    resp = requests.post(
        f"{ES_URL}/{REVIEW_INDEX}/_doc",
        json=doc,
        auth=ES_AUTH,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if resp.status_code in (200, 201):
        print(f"[COORDINATION] REVIEW QUEUE (confidence={confidence_pct}): rule {doc['rule_id']}")
    else:
        print(f"[COORDINATION] ERROR writing to review queue: {resp.status_code} {resp.text}")


def _get_cti_confidence(alert: dict) -> int:
    """
    [Day 24] Reads the CTI confidence score already attached to the alert
    by pipeline_runner.enrich_with_cti() (flat dotted key, matching the
    style used throughout triage_agent.py — alert['cti.confidence']).
    Returns 0 if no CTI fields are present.
    """
    return alert.get("cti.confidence", 0) or 0


# ── Main node ─────────────────────────────────────────────────────────────────

def coordination_node(state: AgentState) -> AgentState:
    alert = state["alert"]
    rule_id = alert.get("rule", {}).get("id", "unknown")

    # Fixed Day 24: was referencing an undefined `rule` variable here.
    # Prefer a pre-computed confidence_pct from pipeline_runner /
    # confidence_scorer.py if present in state; otherwise derive a basic
    # one from rule.level as a fallback so this node never crashes if it's
    # called standalone (e.g. in a unit test) without the scorer upstream.
    confidence_pct = state.get("confidence_pct")
    if confidence_pct is None:
        confidence_pct = _rule_level_to_confidence(alert)

    state["confidence_pct"] = confidence_pct

    notes = list(state.get("notes", []))
    notes.append(f"[coordination] rule={rule_id} confidence_pct={confidence_pct}")

    cti_confidence = _get_cti_confidence(alert)
    if cti_confidence > CTI_OVERRIDE_THRESHOLD:
        notes.append(
            f"[coordination] CTI confidence {cti_confidence} > {CTI_OVERRIDE_THRESHOLD} — "
            f"will force-route to triage regardless of confidence_pct={confidence_pct}"
        )

    state["notes"] = notes
    return state


# ── Router (used as conditional edge function in graph.py) ───────────────────

def route_after_coordination(state: AgentState) -> str:
    """
    Return the next node name based on confidence_pct.

    [Day 24] CTI override: a CTI confidence > 80 forces routing to triage
    even if confidence_pct alone would have sent this to archive or review.
    A strong external threat-intel signal is independently meaningful and
    shouldn't be suppressed by a quiet base score (e.g. a low-severity
    successful login from an IP that happens to be a known-bad IOC).
    """
    alert = state.get("alert", {})
    pct = state.get("confidence_pct", 0)

    cti_confidence = _get_cti_confidence(alert)
    if cti_confidence > CTI_OVERRIDE_THRESHOLD:
        return "triage"

    if pct > REVIEW_MAX:
        return "triage"
    return "end"