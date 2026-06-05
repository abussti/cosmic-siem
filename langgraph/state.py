"""
state.py
========
AgentState TypedDict — shared across all LangGraph nodes.

Day 17 additions
----------------
  alert_es_id    : str | None  — Elasticsearch document _id of the source alert
  alert_es_index : str | None  — Elasticsearch index name (e.g. .ds-logs-wazuh.alerts-2026.06.02-000001)

These two fields let elastic_tools.write_triage_result_to_es() write
triage.verdict and triage.summary back to the *exact* original document
after the pipeline finishes.
"""

from __future__ import annotations
from typing import TypedDict


class AgentState(TypedDict, total=False):
    # ── Core alert payload ───────────────────────────────────────────────────
    alert: dict                     # Raw Wazuh alert (_source from ES hit)
    alert_es_id: str | None         # ES document _id  (Day 17)
    alert_es_index: str | None      # ES index name    (Day 17)

    # ── Confidence routing ───────────────────────────────────────────────────
    confidence: str | None          # "low" / "medium" / "high"  (triage agent)
    confidence_pct: int             # 0–100  (coordination agent → graph router)

    # ── Classification ───────────────────────────────────────────────────────
    technique: str | None           # MITRE ATT&CK ID, e.g. "T1110"

    # ── Pipeline log ────────────────────────────────────────────────────────
    notes: list[str]                # Append-only trace from every agent

    # ── Routing flags ────────────────────────────────────────────────────────
    escalate: bool                  # True → human analyst should review

    # ── Triage output ────────────────────────────────────────────────────────
    triage_result: dict | None      # {verdict, summary, evidence}  (triage agent)
