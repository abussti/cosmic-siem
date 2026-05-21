"""
graph.py — LangGraph StateGraph for the SIEM agentic pipeline.

Pipeline (Day 14 / Week 3 Thursday):

  START
    └─► coordination_node      (always runs — decides what to do)
          │
          ├─► [confidence_pct > 60] ──► triage_node  ──► hunting_node ──► response_node ──► END
          │
          └─► [confidence_pct ≤ 60] ──────────────────────────────────────────────────────► END

Place this file at:  ~/elastic/langgraph/graph.py

Run:
  cd ~/elastic/langgraph
  python3 graph.py
"""

import json
import sys
import os

# Allow running from within langgraph/ or from project root
sys.path.insert(0, os.path.dirname(__file__))

from langgraph.graph import StateGraph, END
from typing import TypedDict, Optional

# ── AgentState ─────────────────────────────────────────────────────────────────

class AgentState(TypedDict, total=False):
    alert:          dict            # raw Wazuh alert payload
    confidence:     Optional[str]   # 'low' | 'medium' | 'high'
    confidence_pct: int             # numeric 0–100 (set by triage_node)
    technique:      Optional[str]   # MITRE ATT&CK ID e.g. T1110
    notes:          list            # append-only activity log
    escalate:       bool            # True = route to human analyst
    triage_result:  Optional[dict]  # {'verdict', 'summary', 'evidence'}


# ── import agent nodes ─────────────────────────────────────────────────────────

from agents.triage_agent import triage_node

# Stub nodes for agents not yet built (Day 15–17).
# Replace each stub with the real import as you build them.
def hunting_node(state: AgentState) -> AgentState:
    notes = list(state.get("notes", []))
    notes.append("[hunting] 🔶 Hunting agent stub — not yet implemented (Day 15)")
    return {**state, "notes": notes}

def response_node(state: AgentState) -> AgentState:
    notes = list(state.get("notes", []))
    notes.append("[response] 🔶 Response agent stub — not yet implemented (Day 16)")
    return {**state, "notes": notes}


# ── coordination node ──────────────────────────────────────────────────────────

def coordination_node(state: AgentState) -> AgentState:
    """
    Entry point. Inspects the incoming alert and sets an initial
    confidence_pct so the router can decide whether to run triage.

    Strategy:
      - rule.level ≥ 12  → treat as high priority (confidence_pct = 80)
      - rule.level ≥ 8   → medium priority (confidence_pct = 65)
      - rule.level < 8   → low priority (confidence_pct = 30) → skip triage
    """
    alert  = state.get("alert", {})
    notes  = list(state.get("notes", []))

    rule   = alert.get("rule", {})
    level  = rule.get("level") or alert.get("rule.level", 0)
    rid    = rule.get("id") or alert.get("rule.id", "?")
    desc   = rule.get("description") or alert.get("rule.description", "")
    src_ip = alert.get("data", {}).get("srcip") or alert.get("data.srcip", "?")

    notes.append(f"[coordination] Alert in: rule={rid} level={level} src={src_ip}")
    notes.append(f"[coordination] Description: {desc[:80]}")

    if int(level) >= 12:
        confidence_pct = 80
        notes.append(f"[coordination] High-priority alert (level {level}) → confidence_pct={confidence_pct}")
    elif int(level) >= 8:
        confidence_pct = 65
        notes.append(f"[coordination] Medium-priority alert (level {level}) → confidence_pct={confidence_pct}")
    else:
        confidence_pct = 30
        notes.append(f"[coordination] Low-priority alert (level {level}) → confidence_pct={confidence_pct} (skip triage)")

    return {
        **state,
        "notes":          notes,
        "confidence_pct": confidence_pct,
        "confidence":     None,    # triage_node will set this
        "escalate":       False,
    }


# ── conditional router ─────────────────────────────────────────────────────────

def route_after_coordination(state: AgentState) -> str:
    """
    Router: if confidence_pct > 60 run triage; otherwise end immediately.
    LangGraph reads the return value as the name of the next node.
    """
    pct = state.get("confidence_pct", 0)
    if pct > 60:
        return "triage"
    else:
        return END          # skip straight to end for low-priority alerts


# ── build graph ────────────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("coordination", coordination_node)
    graph.add_node("triage",       triage_node)
    graph.add_node("hunting",      hunting_node)
    graph.add_node("response",     response_node)

    # Entry point
    graph.set_entry_point("coordination")

    # Conditional edge after coordination
    graph.add_conditional_edges(
        "coordination",
        route_after_coordination,
        {
            "triage": "triage",  # confidence_pct > 60 → run triage
            END: END             # confidence_pct ≤ 60 → done
        }
    )

    # Linear path after triage
    graph.add_edge("triage",   "hunting")
    graph.add_edge("hunting",  "response")
    graph.add_edge("response", END)

    return graph.compile()


# ── entry point ────────────────────────────────────────────────────────────────

def run_pipeline(alert: dict) -> AgentState:
    """Run the full agentic pipeline for one alert. Returns final state."""
    app = build_graph()
    initial_state: AgentState = {
        "alert":          alert,
        "notes":          [],
        "confidence":     None,
        "confidence_pct": 0,
        "technique":      None,
        "escalate":       False,
        "triage_result":  None,
    }
    return app.invoke(initial_state)


# ── manual test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Brute-force SSH alert — level 10, should trigger triage
    brute_force_alert = {
        "rule": {
            "id": "5710",
            "description": "sshd: Attempt to login using non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "level": 10
        },
        "data": {
            "srcip": "127.0.0.1",
            "dstuser": "root"
        },
        "agent": {"name": "agent1"},
        "@timestamp": "2026-05-21T08:00:00Z"
    }

    print("=" * 60)
    print("SIEM Agentic Pipeline — Manual Test")
    print("Alert: Brute-force SSH (rule 5710, level 10)")
    print("=" * 60)

    final = run_pipeline(brute_force_alert)

    print("\n── PIPELINE NOTES (in order) ──")
    for note in final.get("notes", []):
        print(f"  {note}")

    if final.get("triage_result"):
        print("\n── TRIAGE RESULT ──")
        print(json.dumps(final["triage_result"], indent=2))
        print(f"\n  Confidence : {final.get('confidence')} ({final.get('confidence_pct')}%)")
        print(f"  Escalate   : {final.get('escalate')}")
    else:
        print("\n  ⚠ Triage did not run (alert confidence_pct ≤ 60).")

    print("\n✅ Pipeline complete.")

