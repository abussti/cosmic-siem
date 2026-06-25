"""
tools/hunt_summarizer.py
─────────────────────────
Day 29 — Gemini-powered hunt summarizer.

Plan said "call Claude API" — this project uses the Gemini free API
everywhere else (triage_agent.py, LLM_BACKEND="gemini", gemini-2.5-flash),
so this module follows that same convention instead of introducing a
second LLM provider.

Kept as its own module (not bolted into triage_agent.py) so both the
reactive triage agent and the proactive hunting agent can share one
Gemini call pattern without a circular import between agents/.

Install (same as triage_agent.py):
    pip install google-genai --break-system-packages
    export GEMINI_API_KEY=...
"""

import os
import json

_GEMINI_MODEL = "gemini-2.5-flash"
_client = None  # lazy singleton


def _get_gemini_client():
    """
    Lazy-init so importing this module never requires GEMINI_API_KEY to be set.
    Same reasoning as run_hunt() in hunting_agent.py — importing must never crash,
    only the actual call should fail (and even then, gracefully — see below).
    """
    global _client
    if _client is None:
        from google import genai
        _client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    return _client


def build_hunt_prompt(hunt_name: str, findings: list, mitre_technique: str | None = None) -> str:
    """
    Implements the Day 29 prompt spec:
    "These hosts showed suspicious behaviour during a threat hunt for [hunt_name].
     Summarise the risk and recommend next steps."

    Findings are capped at 15 in the prompt — full findings are already going to
    siem-hunt-results / the original index, Gemini only needs enough to reason
    about risk, not a full dump (keeps tokens + free-tier usage down).
    """
    sample = findings[:15]
    technique_line = f"MITRE ATT&CK technique: {mitre_technique}\n" if mitre_technique else ""

    return (
        f"These hosts showed suspicious behaviour during a threat hunt for "
        f"'{hunt_name}'.\n"
        f"{technique_line}"
        f"Total findings: {len(findings)}\n\n"
        f"Findings sample (JSON):\n{json.dumps(sample, indent=2, default=str)}\n\n"
        "Summarise the risk and recommend next steps for a SOC analyst, in "
        "2-4 plain sentences. Name specific hosts/IPs/users from the data where "
        "possible. Do not use markdown headers or bullet points."
    )


def summarize_hunt_findings(hunt_name: str, findings: list, mitre_technique: str | None = None) -> str:
    """
    Calls Gemini to turn raw hunt findings into a readable analyst-facing summary.

    Never raises — on any Gemini failure (no API key, 503, rate limit, etc.) it
    falls back to a templated summary instead of crashing the hunt cycle. This is
    the same lesson Day 24 already learned the hard way with the Gemini 503 outage
    during the threat-actor-profile test: the deterministic parts of the pipeline
    (ES write, escalation) must keep working even if the LLM call itself fails.
    """
    if not findings:
        return f"Hunt '{hunt_name}' completed with no findings — no suspicious activity detected."

    prompt = build_hunt_prompt(hunt_name, findings, mitre_technique)

    try:
        client = _get_gemini_client()
        response = client.models.generate_content(
            model=_GEMINI_MODEL,
            contents=prompt,
        )
        text = (response.text or "").strip()
        if text:
            return text
        raise ValueError("Empty response from Gemini")
    except Exception as e:
        return (
            f"[Gemini unavailable: {e}] Hunt '{hunt_name}' found {len(findings)} "
            f"finding(s). Manual analyst review recommended."
        )


if __name__ == "__main__":
    # Standalone smoke test — same pattern as hunting_agent.py's own __main__ block.
    # Requires GEMINI_API_KEY to actually call the API; otherwise exercises the
    # fallback path and still proves the function doesn't crash.
    fake_findings = [
        {"agent": {"name": "agent1"}, "data": {"srcip": "203.0.113.10"}},
        {"agent": {"name": "agent1"}, "data": {"srcip": "203.0.113.45"}},
    ]
    print(summarize_hunt_findings("lateral_movement_ssh", fake_findings, "T1021.004"))
