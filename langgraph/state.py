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

Day 35 addition
----------------
  response_actions  : list[str]        — action names actually executed by response_node
  response_results  : dict             — {action_name: result_dict} from tools/response_tools.py

IMPORTANT: LangGraph's StateGraph only tracks/merges dict keys that are
declared here. A node can set state["some_new_key"] = ... and it will work
fine *inside* that node's own execution, but if the key isn't part of this
schema, LangGraph silently drops it when merging into the graph's final
output — the same class of bug the Day 19 `technique` propagation fix
addressed. response_actions/response_results hit exactly this: they were
being set correctly inside response_node but vanished from
pipeline.invoke()'s return value until added here (found during Day 35
testing).
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
    # ── Response output (Day 35) ─────────────────────────────────────────────
    response_actions: list[str]     # action names executed by response_node
    response_results: dict          # {action_name: result_dict}
