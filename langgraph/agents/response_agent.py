"""
agents/response_agent.py
=========================
Automated response agent — Day 31 scaffold (Phase 2, Week 7).

Receives a triage verdict + confidence and SELECTS a response action from
a pre-approved list. This is a SCAFFOLD ONLY: no real action is executed
yet. block_ip / unblock_ip land Day 32, isolate_endpoint / unisolate_endpoint
Day 33, create_ticket Day 34 (all in tools/response_tools.py, which does
not exist yet). Every decision is logged to siem-response-log regardless
of whether a real action fires, so the audit trail exists from day one —
same principle Day 29's write_hunt_result_to_es() established for hunts.

Replaces the Day 19 stub (which only held the Phase 2 playbook roadmap as
comments). The function name `response_node` is unchanged, so no edit is
needed in graph.py — it already imports and wires this node.
"""

import logging

from tools.elastic_tools import write_response_log_entry

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

# Per the Day 31 plan: verdict == 'suspicious' AND confidence > 80 →
# eligible for an automated response action.
RESPONSE_CONFIDENCE_THRESHOLD = 80

# Default approved actions, priority order. Names only at this stage —
# real implementations don't exist until Day 32-34. A scaffold-stage agent
# SELECTS a name; it never calls anything in tools/response_tools.py.
DEFAULT_APPROVED_ACTIONS = ["block_ip", "isolate_endpoint", "create_ticket"]


# ──────────────────────────────────────────────────────────────────────────
# Decision logic
# ──────────────────────────────────────────────────────────────────────────

def select_response_action(triage_verdict, confidence, approved_actions):
    """
    Returns an action name from approved_actions, or None if no action
    is warranted.

    Day 31 logic only: suspicious + confidence > 80 → first entry in
    approved_actions. Day 32+ will replace the "first entry" rule with
    technique-aware selection (e.g. T1110 brute force -> block_ip,
    T1059 command execution -> isolate_endpoint) once those tools exist.
    """
    if not approved_actions:
        return None
    if triage_verdict == "suspicious" and confidence is not None \
            and confidence > RESPONSE_CONFIDENCE_THRESHOLD:
        return approved_actions[0]
    return None


def _extract_target(alert):
    """Best-effort target for logging — srcip first, falls back to agent name."""
    data = alert.get("data", {}) or {}
    agent = alert.get("agent", {}) or {}
    return data.get("srcip") or agent.get("name") or "unknown"


# ──────────────────────────────────────────────────────────────────────────
# Graph node
# ──────────────────────────────────────────────────────────────────────────

def response_node(state):
    """
    LangGraph node. Already wired after hunting_node in the main alert
    pipeline (confidence_pct > 70 branch: coordination -> triage -> hunting
    -> response -> END). The "runs after triage_agent if verdict is
    suspicious" requirement from the Day 31 plan is enforced HERE, inside
    the node, rather than as a new conditional graph edge — the node
    always runs in that branch, but only ever selects/logs an action when
    triage_result['verdict'] == 'suspicious'. Benign/unknown verdicts hit
    the "no action" path below and still get logged.

    Reads from state:
      alert            (dict)  - raw alert payload
      triage_result     (dict)  - {verdict, summary, evidence, technique}
      confidence_pct    (int)   - set upstream by confidence_scorer.py
      approved_actions  (list)  - optional; falls back to
                                  DEFAULT_APPROVED_ACTIONS if not present
                                  on state (AgentState has no such field
                                  yet — see note below)

    Writes to state:
      notes             (list)  - appends a human-readable decision line
      response_action   (str | None) - the action selected, if any

    No real action is executed. confidence here is read from state, not
    passed as a separate function arg, to stay consistent with how every
    other node in this graph (coordination_node, triage_node) already
    reads confidence_pct off state rather than threading it through
    function signatures.
    """
    alert = state.get("alert", {}) or {}
    triage_result = state.get("triage_result") or {}
    verdict = triage_result.get("verdict")
    confidence_pct = state.get("confidence_pct")
    approved_actions = state.get("approved_actions") or DEFAULT_APPROVED_ACTIONS

    target = _extract_target(alert)
    action = select_response_action(verdict, confidence_pct, approved_actions)

    if action is None:
        note = (f"[response_agent] No action taken — verdict={verdict}, "
                 f"confidence={confidence_pct}")
        state.setdefault("notes", []).append(note)
        write_response_log_entry(
            action_type="none",
            target=target,
            agent="response_agent",
            reversible=False,
            reversed_=False,
            verdict=verdict,
            confidence=confidence_pct,
        )
        logger.info(note)
        state["response_action"] = None
        return state

    # Scaffold stage: SELECT and LOG the action. Do NOT execute it.
    note = (f"[response_agent] Selected action='{action}' for target={target} "
             f"(verdict={verdict}, confidence={confidence_pct}) — "
             f"NOT EXECUTED (Day 31 scaffold; real execution lands Day 32-34)")
    state.setdefault("notes", []).append(note)

    write_response_log_entry(
        action_type=action,
        target=target,
        agent="response_agent",
        reversible=True,   # all 3 planned actions are designed to be reversible
        reversed_=False,
        verdict=verdict,
        confidence=confidence_pct,
    )

    logger.info(note)
    state["response_action"] = action
    return state


if __name__ == "__main__":
    # Smoke test (deliverable 6): pass a test alert, verify the agent runs
    # and logs an entry without taking real action.
    logging.basicConfig(level=logging.INFO)

    print("=== Test 1: suspicious + high confidence -> action selected ===")
    test_state_1 = {
        "alert": {"data": {"srcip": "203.0.113.77"}, "agent": {"name": "agent1"}},
        "triage_result": {"verdict": "suspicious", "summary": "SSH brute force",
                           "technique": "T1110"},
        "confidence_pct": 91,
        "notes": [],
    }
    result_1 = response_node(test_state_1)
    print("response_action:", result_1["response_action"])
    print("notes:", result_1["notes"])

    print("\n=== Test 2: suspicious but confidence below threshold -> no action ===")
    test_state_2 = {
        "alert": {"data": {"srcip": "198.51.100.5"}},
        "triage_result": {"verdict": "suspicious"},
        "confidence_pct": 76,
        "notes": [],
    }
    result_2 = response_node(test_state_2)
    print("response_action:", result_2["response_action"])
    print("notes:", result_2["notes"])

    print("\n=== Test 3: benign verdict -> no action ===")
    test_state_3 = {
        "alert": {"agent": {"name": "agent1"}},
        "triage_result": {"verdict": "benign"},
        "confidence_pct": 95,
        "notes": [],
    }
    result_3 = response_node(test_state_3)
    print("response_action:", result_3["response_action"])
    print("notes:", result_3["notes"])
