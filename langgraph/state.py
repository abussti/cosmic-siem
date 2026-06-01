"""
state.py — Shared AgentState for the SIEM LangGraph pipeline.

Every node in the graph reads from and writes to this TypedDict.
Fields are intentionally broad at this scaffold stage; add sub-fields
as each agent is implemented in later days.
"""

from __future__ import annotations
from typing import Optional
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """
    The single state object passed through the entire LangGraph.

    Fields
    ------
    alert : dict
        Raw alert payload from Elasticsearch / Wazuh.
        Expected keys: rule_id, rule_description, rule_groups,
        agent_name, src_ip, timestamp, raw (full JSON).

    confidence : Optional[str]
        Set by the triage agent after analysis.
        Values: "low" | "medium" | "high"

    technique : Optional[str]
        MITRE ATT&CK technique ID assigned during triage.
        Example: "T1110" (Brute Force), "T1078" (Valid Accounts).

    notes : list[str]
        Running log of observations and decisions made by each agent.
        Every agent appends its findings — never overwrites.

    escalate : bool
        Flag set to True when the coordination agent decides a human
        analyst must review this incident.
    """

    alert: dict
    confidence: Optional[str]
    confidence_pct: int
    technique: Optional[str]
    notes: list
    escalate: bool
    triage_result: Optional[dict]
