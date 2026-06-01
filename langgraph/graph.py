from langgraph.graph import StateGraph, END
from state import AgentState
from agents.coordination_agent import coordination_node, route_after_coordination
from agents.triage_agent import triage_node
from agents.hunting_agent import hunting_node      # stub — returns state unchanged
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

graph = build_graph()

if __name__ == "__main__":
    print("[graph] Graph compiled successfully.")
    print("[graph] Nodes:", list(graph.nodes))
