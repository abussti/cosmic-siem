# response_agent.py
# Response agent — selects and executes response playbooks after triage.
# Currently a stub: passes state through unchanged.
#
# Phase 2 plan:
#   - Receive triage_result from triage_agent
#   - Select the appropriate playbook based on MITRE technique
#   - For low-risk actions (IP block, account lock): execute autonomously
#   - For high-risk actions (endpoint isolation): require human approval
#   - Write action log to ES index siem-response-log
#
# Day 16: stub created
# Day 19: inline comments added (B5)

def response_node(state: dict) -> dict:
    """
    LangGraph node — placeholder for the response orchestrator.

    Args:
        state: AgentState dict — receives the fully-triaged alert with
               triage_result, confidence_pct, technique, and escalate flag.

    Returns:
        state: Unchanged. Will execute playbooks in Phase 2.
    """
    # Log that the response agent was reached so the audit trail is complete
    notes = state.get("notes", [])
    notes.append(
        "[response_agent] stub — no automated response taken. "
        "Phase 2 will add playbook execution here."
    )
    state["notes"] = notes

    # TODO Phase 2: implement playbook selection and execution
    # Suggested structure:
    #   technique = state.get("technique")
    #   playbook  = select_playbook(technique)
    #   if playbook.risk == "low":
    #       execute_playbook(playbook, state["alert"])
    #   else:
    #       notify_analyst(playbook, state["alert"])

    return state
