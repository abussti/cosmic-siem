"""
tools/redteam_reporter.py

Day 44 — Wire Red Team Results to Gemini for Executive Summaries.

The Day 44 plan text says "Claude API" — but per this project's own
standing convention (see hunt_summarizer.py / triage_agent.py, and the
Day 29 write-up: "The plan specified the Claude API — this project
standardizes on the Gemini free API everywhere else... so Gemini was
used instead"), this uses Gemini 2.5 Flash via the same google-genai SDK
and LLM_BACKEND convention already in use project-wide, not a second LLM
provider.

Called by agents/attack_chain_simulator.py's run_attack_chain() after
every chain simulation completes. Given the full chain_result +
blast-radius data, produces two summaries:
  1. A technical summary for SOC analysts
  2. A 5-sentence executive brief for management with business impact

Never raises — any Gemini error falls back to a templated string, same
philosophy as summarize_hunt_findings() in tools/hunt_summarizer.py.
"""

import os
import json
import datetime

try:
    from google import genai
    _CLIENT = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
except Exception as _import_err:
    _CLIENT = None
    _CLIENT_ERROR = str(_import_err)
else:
    _CLIENT_ERROR = None

GEMINI_MODEL = os.environ.get("REDTEAM_REPORT_MODEL", "gemini-2.5-flash")

TECHNICAL_PROMPT_TEMPLATE = """Given this attack chain simulation result:

{chain_result}

Blast radius: {blast_data}

Summarise: which steps succeeded, which were blocked, what is the realistic impact, what should the SOC team do immediately."""

EXECUTIVE_PROMPT_TEMPLATE = """Given this attack simulation: {summary}

Write a 5-sentence executive brief: what happened, what could happen if not addressed, business impact estimate, recommended action, urgency level."""


def _call_gemini(prompt: str):
    """
    Thin call into the Gemini API, same pattern triage_agent.py and
    hunt_summarizer.py already use. Never raises — returns None on any
    failure (missing key, SDK not installed, network error, API error,
    including the free-tier 503s this project has already seen twice on
    Day 24 and Day 29), so callers apply a templated fallback.
    """
    if _CLIENT is None:
        print(f"[redteam_reporter] Gemini client unavailable "
              f"({_CLIENT_ERROR or 'GEMINI_API_KEY not set'}) — using fallback")
        return None
    try:
        resp = _CLIENT.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        text = (getattr(resp, "text", None) or "").strip()
        return text or None
    except Exception as e:
        print(f"[redteam_reporter] Gemini API error: {e}")
        return None


def generate_technical_summary(chain_result, blast_data=None) -> str:
    """
    Technical summary for SOC analysts. Never raises — falls back to a
    templated summary on any Gemini error.
    """
    prompt = TECHNICAL_PROMPT_TEMPLATE.format(
        chain_result=json.dumps(chain_result, indent=2, default=str),
        blast_data=json.dumps(blast_data or {}, indent=2, default=str),
    )
    result = _call_gemini(prompt)
    if result:
        return result

    n_steps = len(chain_result) if isinstance(chain_result, list) else 0
    n_exploitable = sum(1 for r in (chain_result or []) if isinstance(r, dict) and r.get("exploitable"))
    return (
        f"[Gemini unavailable — fallback summary] Chain simulation produced {n_steps} "
        f"step result(s), {n_exploitable} exploitable / {n_steps - n_exploitable} blocked. "
        f"Manual analyst review of the raw chain_result is recommended."
    )


def generate_executive_summary(technical_summary: str) -> str:
    """
    5-sentence executive brief built from the technical summary. Never
    raises — falls back to a templated brief on any Gemini error.
    """
    prompt = EXECUTIVE_PROMPT_TEMPLATE.format(summary=technical_summary)
    result = _call_gemini(prompt)
    if result:
        return result

    return (
        "[Gemini unavailable — fallback] A red-team attack chain simulation was run against "
        "a test target. Some steps in the simulated attack path were not fully validated. "
        "Business impact cannot be confidently estimated until this is reviewed by an analyst. "
        "Recommended action: have the SOC team review the technical summary directly. "
        "Urgency: Medium (unconfirmed — pending manual review)."
    )


def generate_reports(chain_result, blast_data=None) -> dict:
    """
    Convenience wrapper used by run_attack_chain() — produces both
    summaries plus a timestamp, ready to hand to
    elastic_tools.write_redteam_report_to_es().
    """
    technical = generate_technical_summary(chain_result, blast_data)
    executive = generate_executive_summary(technical)
    return {
        "technical_summary": technical,
        "executive_summary": executive,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    print(f"GEMINI_MODEL = {GEMINI_MODEL!r}")
    print(f"Client available: {_CLIENT is not None}")

    sample_chain_result = [
        {"step": "T1190", "name": "Exploit Public-Facing App", "exploitable": False,
         "evidence": "No red-team handler registered for T1190.", "blocked_by": "no handler"},
        {"step": "T1059", "name": "LOLBins execution", "exploitable": False,
         "evidence": "[DRY RUN] would attempt a benign LOLBin execution probe", "blocked_by": "dry_run mode"},
    ]
    sample_blast = {"target_agent": "redteam-target-win10", "fully_exploitable": False, "blocked_steps": 2}

    reports = generate_reports(sample_chain_result, sample_blast)
    print("\n=== Technical summary ===")
    print(reports["technical_summary"])
    print("\n=== Executive summary ===")
    print(reports["executive_summary"])
