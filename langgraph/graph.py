from langgraph.graph import StateGraph, END
from state import AgentState
from agents.coordination_agent import coordination_node, route_after_coordination
from agents.triage_agent import triage_node
from agents.hunting_agent import hunting_node, run_all_default_hunts
# hunting_node            — Day 19, REACTIVE: only runs after triage, per alert
# run_all_default_hunts   — Day 26, PROACTIVE: runs on a timer, no alert needed
from agents.response_agent import response_node    # stub — returns state unchanged


def build_graph():
    g = StateGraph(AgentState)

    # ── Nodes ─────────────────────────────────────────────────────────────
    g.add_node("coordination", coordination_node)
    g.add_node("triage",       triage_node)
    g.add_node("hunting",      hunting_node)
    g.add_node("response",     response_node)

    # ── Entry point ───────────────────────────────────────────────────────
    g.set_entry_point("coordination")

    # ── Conditional edge out of coordination ──────────────────────────────
    g.add_conditional_edges(
        "coordination",
        route_after_coordination,
        {
            "triage": "triage",
            "end":    END,
        },
    )

    # ── Linear path for high-confidence alerts ────────────────────────────
    g.add_edge("triage",   "hunting")
    g.add_edge("hunting",  "response")
    g.add_edge("response", END)

    return g.compile()


# ============================================================================
# Day 26 — proactive hunting branch
# ============================================================================
# This is intentionally a SECOND, separate StateGraph rather than a node
# bolted onto the graph above. A node only runs if something routes to it
# through edges — there's no way to make a node inside the alert graph
# "independent of the alert pipeline" while still living in that graph.
# So: own node, own entry point, own compiled graph. pipeline_runner.py's
# scheduler calls hunt_pipeline.invoke(...) directly, on a 6h timer, and
# that call never touches coordination/triage/route_after_coordination.
# ============================================================================

def scheduled_hunt_node(state: AgentState) -> AgentState:
    """
    Runs the full DEFAULT_PLAYBOOKS set against Elasticsearch with no
    triggering alert. Appends findings to state['notes'] and sets
    state['escalate'] if any playbook found enough hits to warrant it.
    """
    results = run_all_default_hunts()
    state["notes"] = state.get("notes", []) + [r["hunt_summary"] for r in results]
    state["escalate"] = state.get("escalate", False) or any(r["escalate"] for r in results)
    return state


def build_hunt_graph():
    """
    The 'parallel branch' called for in the Day 26 task — a single-node
    graph with its own entry point, no edges to or from the main
    alert-routing graph above.
    """
    g = StateGraph(AgentState)
    g.add_node("scheduled_hunt", scheduled_hunt_node)
    g.set_entry_point("scheduled_hunt")
    g.add_edge("scheduled_hunt", END)
    return g.compile()


graph = build_graph()
pipeline = graph

hunt_graph = build_hunt_graph()
hunt_pipeline = hunt_graph   # imported by pipeline_runner.py's Day 26 scheduler


if __name__ == "__main__":
    print("[graph] Graph compiled successfully.")
    print("[graph] Nodes:", list(graph.nodes))
    print("[graph] Hunt graph compiled successfully.")
    print("[graph] Hunt graph nodes:", list(hunt_graph.nodes))