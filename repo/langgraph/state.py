# state.py
# Cosmic Info Solutions — cosmic-siem
# Shared AgentState TypedDict — implementation starts Week 3

from typing import TypedDict

class AgentState(TypedDict):
    alert: dict          # Original Elastic alert document
    confidence: int      # Score 0–100 from confidence scorer
    technique: str       # MITRE ATT&CK technique ID (e.g. T1110)
    notes: list          # Running log of agent observations
    escalate: bool       # True = route to human analyst
    verdict: str         # suspicious | benign | unknown
    summary: str         # Human-readable investigation summary
    evidence: list       # Supporting events and context
