"""
agents/response_agent.py
=========================
Automated response agent — Day 35 update (Phase 2, Week 7), Day 39 bug fixes.

Day 31 built the decision scaffold (select a name, log it, execute nothing).
Day 32-34 built the real actions (block_ip, isolate_endpoint, create_ticket)
in tools/response_tools.py. Day 35 wired select/execute together for
block_ip and create_ticket (isolate_endpoint stays manual-only by design —
see below).

Day 39 fixes two real issues found during Phase 2 Scenario 3 testing and a
follow-up code read:
  1. block_ip() was being called with whatever _extract_target() returned,
     with no validation. When an alert has no data.srcip (e.g. a synthetic
     or malformed alert), _extract_target() falls back to the agent name —
     which is not an IP, and would produce a doomed/nonsensical
     "block this hostname at the firewall" API call that only fails after
     a real network round-trip. Added _looks_like_ip() and skip block_ip
     (log "target not blockable" instead) when the target isn't IP-shaped.
  2. Added RESPONSE_AUTO_EXECUTE as an operator kill-switch (defaults to
     "true" so existing Day 35 behavior is unchanged out of the box) so a
     bad triage verdict pattern can be shut off instance-wide without a
     code deploy, without disabling the decision-logging path itself.

isolate_endpoint remains a MANUAL-ONLY action (per the Day 35 plan:
"Manually trigger isolate_endpoint on the test host") — it is intentionally
NOT part of the automatic decision path here. It's still exposed for
direct/manual invocation via tools/response_tools.isolate_endpoint().

Logging convention:
  - block_ip() and create_ticket() (in tools/response_tools.py) already log
    every attempt — success or failure — to siem-response-log via their own
    _log_response_action() helper. response_node() does NOT double-log
    these; it only adds a state["notes"] trace line for pipeline visibility.
  - The "no action taken" path (verdict not suspicious, confidence below
    threshold, OR target not valid, OR auto-execute disabled) still logs
    through elastic_tools.write_response_log_entry(), unchanged from Day 31
    — every cycle is still recorded, actioned or not.
"""

import logging
import os
import re

from tools.elastic_tools import write_response_log_entry
from tools.response_tools import block_ip, create_ticket

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

# Per the Day 31 plan: verdict == 'suspicious' AND confidence > 80 →
# eligible for automated response actions.
RESPONSE_CONFIDENCE_THRESHOLD = 80

# [Day 35] Same override precedent as coordination_agent.CTI_OVERRIDE_THRESHOLD
# — a CTI confidence above this independently justifies action even when
# triage's own confidence_pct sits at its flat "suspicious" floor (75%).
CTI_OVERRIDE_THRESHOLD = 80

# Actions executed AUTOMATICALLY when the threshold above is met.
# isolate_endpoint is deliberately excluded — Day 35 plan treats it as a
# manual-trigger-only action, not part of the automatic decision path.
AUTO_APPROVED_ACTIONS = ["block_ip", "create_ticket"]

# [Day 39] Operator kill-switch. Defaults to "true" so this ships with the
# same behavior Day 35 already had in production — set to "false" in any
# environment where you want decisions logged but nothing actually executed
# (e.g. while validating a new confidence threshold, or during an incident
# where you don't trust the current triage signal). This does NOT affect
# the "no action" logging path — every cycle is still recorded either way.
AUTO_EXECUTE_ENABLED = os.environ.get("RESPONSE_AUTO_EXECUTE", "true").lower() == "true"

# [Day 39] Simple IPv4 shape check used to guard block_ip() — not a full
# validator (doesn't reject e.g. 999.999.999.999), just enough to catch the
# real failure mode seen in testing: a hostname/agent-name string landing in
# the "target" slot because the alert had no source IP at all.
_IPV4_SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


# ──────────────────────────────────────────────────────────────────────────
# Decision logic
# ──────────────────────────────────────────────────────────────────────────

def _extract_target(alert):
    """Best-effort source IP / target for logging — srcip first, falls back
    to agent name."""
    data = alert.get("data", {}) or {}
    agent = alert.get("agent", {}) or {}
    return data.get("srcip") or agent.get("name") or "unknown"


def _extract_agent_name(alert):
    agent = alert.get("agent", {}) or {}
    return agent.get("name") or "unknown"


def _get_cti_confidence(alert):
    """
    Reads the CTI confidence score attached by pipeline_runner.enrich_with_cti()
    (flat dotted key alert['cti.confidence']) — same helper/convention as
    coordination_agent._get_cti_confidence().
    """
    return alert.get("cti.confidence", 0) or 0


def _looks_like_ip(value: str) -> bool:
    """
    [Day 39] True if `value` is shaped like an IPv4 address. Used to avoid
    calling block_ip() with a hostname/agent-name that _extract_target()
    fell back to when the alert had no data.srcip — that call would only
    ever fail, after a real Wazuh API round-trip, and pollutes
    siem-response-log with a confusing "block_ip failed" entry that was
    never actionable in the first place.
    """
    if not value or value == "unknown":
        return False
    return bool(_IPV4_SHAPE.match(value))


def is_actionable(triage_verdict, confidence, cti_confidence=0):
    """
    True if this alert clears the bar for automatic response actions.

    NOTE (Day 35 finding): triage_agent.py overwrites state['confidence_pct']
    with a flat verdict-derived value once triage runs — "suspicious=75+"
    per project.md, and every live test (Day 17/23/24) observed exactly 75%
    for a suspicious verdict, regardless of how high the pre-triage
    CTI-boosted confidence_scorer.py score was. That means a plain
    confidence_pct > 80 check here would almost never fire for a genuine
    suspicious verdict, since 75 is triage's floor, not its usual case.

    coordination_agent.py already establishes the right precedent for this
    exact situation: a CTI confidence > 80 independently overrides a quiet
    score, because "a strong external threat-intel signal is independently
    meaningful and shouldn't be suppressed by a quiet base score" (its own
    docstring). Response actions honor the same override here, using the
    same >80 boundary (== does not trigger, matching Day 24's confirmed
    exclusive boundary at exactly 80).

    NOTE (Day 39): triage_agent.py's companion confidence_pct-preservation
    fix means a hunt-escalated alert can now arrive here with
    confidence_pct=85 (preserved, instead of being silently overwritten to
    75) — which correctly clears RESPONSE_CONFIDENCE_THRESHOLD on its own
    merits, no separate override needed for that path.
    """
    if triage_verdict != "suspicious":
        return False
    if confidence is not None and confidence > RESPONSE_CONFIDENCE_THRESHOLD:
        return True
    if cti_confidence > CTI_OVERRIDE_THRESHOLD:
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────
# Graph node
# ──────────────────────────────────────────────────────────────────────────

def response_node(state):
    """
    LangGraph node. Runs after hunting_node in the main alert pipeline
    (confidence_pct > 70 branch: coordination -> triage -> hunting ->
    response -> END).

    Reads from state:
      alert            (dict)  - raw alert payload
      triage_result     (dict)  - {verdict, summary, evidence, technique}
      confidence_pct    (int)   - set upstream by confidence_scorer.py
      approved_actions  (list)  - optional; falls back to
                                  AUTO_APPROVED_ACTIONS if not present

    Writes to state:
      notes             (list)            - human-readable decision trace
      response_actions  (list[str])       - action names actually executed
      response_results  (dict)            - {action_name: result_dict}

    block_ip / create_ticket are REAL calls now (Day 35) — they hit the
    Wazuh API and the GitHub Issues API respectively via
    tools/response_tools.py. isolate_endpoint is NOT called automatically
    here; trigger it manually via tools.response_tools.isolate_endpoint().

    Day 39: two guards added before block_ip actually fires — target must
    look like a real IP (_looks_like_ip), and the instance-wide
    AUTO_EXECUTE_ENABLED switch must be on. Both are additive: the decision
    (which action would have been selected) is still logged either way.
    """
    alert = state.get("alert", {}) or {}
    triage_result = state.get("triage_result") or {}
    verdict = triage_result.get("verdict")
    confidence_pct = state.get("confidence_pct")
    approved_actions = state.get("approved_actions") or AUTO_APPROVED_ACTIONS

    target_ip = _extract_target(alert)
    agent_name = _extract_agent_name(alert)
    cti_confidence = _get_cti_confidence(alert)

    if not is_actionable(verdict, confidence_pct, cti_confidence):
        note = (f"[response_agent] No action taken — verdict={verdict}, "
                 f"confidence={confidence_pct}")
        state.setdefault("notes", []).append(note)
        write_response_log_entry(
            action_type="none",
            target=target_ip,
            agent="response_agent",
            reversible=False,
            reversed_=False,
            verdict=verdict,
            confidence=confidence_pct,
        )
        logger.info(note)
        state["response_actions"] = []
        state["response_results"] = {}
        return state

    if not AUTO_EXECUTE_ENABLED:
        note = (f"[response_agent] Actionable (verdict={verdict}, "
                 f"confidence={confidence_pct}) but RESPONSE_AUTO_EXECUTE is "
                 f"disabled — decision logged, nothing executed")
        state.setdefault("notes", []).append(note)
        write_response_log_entry(
            action_type="none",
            target=target_ip,
            agent="response_agent",
            reversible=False,
            reversed_=False,
            verdict=verdict,
            confidence=confidence_pct,
        )
        logger.warning(note)
        state["response_actions"] = []
        state["response_results"] = {}
        return state

    executed = []
    results = {}

    if "block_ip" in approved_actions:
        if _looks_like_ip(target_ip):
            block_result = block_ip(target_ip, agent_name)
            results["block_ip"] = block_result
            executed.append("block_ip")
            note = (f"[response_agent] block_ip executed — target={target_ip} "
                     f"endpoint={agent_name} success={block_result['success']}")
            state.setdefault("notes", []).append(note)
            logger.info(note)
        else:
            # Day 39 fix: don't call block_ip() against a non-IP fallback
            # target (usually an agent name substituted when data.srcip was
            # missing). Log the skip explicitly rather than silently doing
            # nothing, and still record it to siem-response-log so the audit
            # trail shows why no block happened for an otherwise-actionable alert.
            note = (f"[response_agent] block_ip skipped — target '{target_ip}' "
                     f"is not a valid IP (likely missing data.srcip on the alert)")
            state.setdefault("notes", []).append(note)
            # Day 39 hotfix: write_response_log_entry() (elastic_tools.py) does
            # NOT accept success/detail kwargs — confirmed by the live
            # TypeError this call originally raised. Match the exact kwarg
            # set the "no action" branch above already uses successfully.
            # The skip reason itself is preserved in state["notes"] instead.
            write_response_log_entry(
                action_type="block_ip",
                target=target_ip,
                agent=agent_name,
                reversible=False,
                reversed_=False,
                verdict=verdict,
                confidence=confidence_pct,
            )
            logger.warning(note)

    if "create_ticket" in approved_actions:
        technique = triage_result.get("technique")
        triage_summary = triage_result.get("summary", "")
        ticket_result = create_ticket(
            alert=alert,
            triage_summary=triage_summary,
            confidence=confidence_pct,
            technique=technique,
        )
        results["create_ticket"] = ticket_result
        executed.append("create_ticket")
        note = (f"[response_agent] create_ticket executed — "
                 f"success={ticket_result['success']} "
                 f"url={ticket_result.get('target')}")
        state.setdefault("notes", []).append(note)
        logger.info(note)

    state["response_actions"] = executed
    state["response_results"] = results
    return state


if __name__ == "__main__":
    # Smoke test: high-confidence suspicious alert -> block_ip + create_ticket
    # both fire for real against whatever WAZUH_API_URL / ES_URL / GITHUB_*
    # env vars are set. Requires those env vars to be configured — see
    # docs/response-test.md for the full Day 35 run.
    logging.basicConfig(level=logging.INFO)

    print("=== Test 1: confidence_pct > 80 directly -> action fires ===")
    test_state_1 = {
        "alert": {
            "rule": {"description": "sshd: Attempt to login using non-existent user", "level": 10},
            "data": {"srcip": "141.60.162.150", "dstuser": "root(uid=0)"},
            "agent": {"name": "agent1"},
        },
        "triage_result": {
            "verdict": "suspicious",
            "summary": "Repeated failed SSH logins from a known-malicious IP "
                        "(CTI match, OTX) targeting root. Consistent with T1110.",
            "technique": "T1110",
        },
        "confidence_pct": 98,
        "notes": [],
    }
    result_1 = response_node(test_state_1)
    print("response_actions:", result_1["response_actions"])
    for name, r in result_1["response_results"].items():
        print(f"  {name}: success={r['success']} detail={r['detail']}")

    print("\n=== Test 2: realistic case — confidence_pct=75 (triage's flat "
          "'suspicious' floor), cti.confidence=95 -> CTI override fires ===")
    test_state_2 = {
        "alert": {
            "rule": {"description": "sshd: Attempt to login using non-existent user", "level": 10},
            "data": {"srcip": "141.60.162.150", "dstuser": "root(uid=0)"},
            "agent": {"name": "agent1"},
            "cti.matched": True,
            "cti.confidence": 95,
            "cti.source": "otx",
        },
        "triage_result": {
            "verdict": "suspicious",
            "summary": "Known-bad IP per CTI match.",
            "technique": "T1110",
        },
        "confidence_pct": 75,
        "notes": [],
    }
    result_2 = response_node(test_state_2)
    print("response_actions:", result_2["response_actions"])
    for name, r in result_2["response_results"].items():
        print(f"  {name}: success={r['success']} detail={r['detail']}")

    print("\n=== Test 3: confidence_pct=75, no CTI -> no action ===")
    test_state_3 = {
        "alert": {"agent": {"name": "agent1"}},
        "triage_result": {"verdict": "suspicious"},
        "confidence_pct": 75,
        "notes": [],
    }
    result_3 = response_node(test_state_3)
    print("response_actions:", result_3["response_actions"])

    print("\n=== Day 39 Test 4: actionable but target is not an IP "
          "(missing data.srcip) -> block_ip skipped, not attempted ===")
    test_state_4 = {
        "alert": {
            "rule": {"description": "Synthetic hunt-escalated alert", "level": 12},
            "data": {"dstuser": "unknown"},   # no srcip on purpose
            "agent": {"name": "agent1"},
        },
        "triage_result": {"verdict": "suspicious", "summary": "Hunt escalation.", "technique": "T1021"},
        "confidence_pct": 85,
        "notes": [],
    }
    result_4 = response_node(test_state_4)
    print("response_actions:", result_4["response_actions"])
    assert "block_ip" not in result_4["response_actions"], "Day 39 fix regressed — block_ip should be skipped"
    print("PASS — block_ip correctly skipped for non-IP target")

    print("\n=== Day 39 Test 5: AUTO_EXECUTE disabled -> decision logged, nothing fires ===")
    os.environ["RESPONSE_AUTO_EXECUTE"] = "false"
    import importlib
    import agents.response_agent as _self
    importlib.reload(_self)  # pick up the env var change for this test only
    result_5 = _self.response_node(test_state_1)
    print("response_actions:", result_5["response_actions"])
    assert result_5["response_actions"] == [], "Day 39 fix regressed — kill switch should block execution"
    print("PASS — RESPONSE_AUTO_EXECUTE=false correctly prevents execution")
