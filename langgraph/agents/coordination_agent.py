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


# ── Main node ─────────────────────────────────────────────────────────────────

def coordination_node(state: AgentState) -> AgentState:
    alert = state["alert"]
    confidence_pct = _rule_level_to_confidence(alert)
    rule_id = alert.get("rule", {}).get("id", "unknown")

    state["confidence_pct"] = confidence_pct
    state["notes"] = state.get("notes", [])

    if confidence_pct <= ARCHIVE_MAX:
        _archive_alert(alert, confidence_pct)
        state["notes"].append(
            f"[coordination] confidence={confidence_pct} → ARCHIVED (rule {rule_id})"
        )

    elif confidence_pct <= REVIEW_MAX:
        _send_to_review_queue(alert, confidence_pct)
        state["notes"].append(
            f"[coordination] confidence={confidence_pct} → ANALYST REVIEW QUEUE (rule {rule_id})"
        )

    else:
        print(f"[COORDINATION] TRIAGE (confidence={confidence_pct}): rule {rule_id}")
        state["notes"].append(
            f"[coordination] confidence={confidence_pct} → TRIAGE AGENT (rule {rule_id})"
        )

    return state


# ── Router (used as conditional edge function in graph.py) ───────────────────

def route_after_coordination(state: AgentState) -> str:
    """Return the next node name based on confidence_pct."""
    pct = state.get("confidence_pct", 0)
    if pct > REVIEW_MAX:
        return "triage"
    return "end"
