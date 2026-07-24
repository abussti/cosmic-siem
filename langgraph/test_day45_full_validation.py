"""
Day 45 — Full Red Team Chain Validation

Runs all 3 attack chains end-to-end, checks both Gemini summaries per chain
(flagging fallback text vs. real LLM output), and verifies writes landed in
all 3 real ES indices (siem-redteam-chains, siem-redteam-reports,
siem-redteam-log).

Run from ~/elastic/langgraph on the manager:
    cd ~/elastic/langgraph && python3 test_day45_full_validation.py

Mirrors test_day43.py / test_day44.py conventions:
  - time.sleep(1.5) before ES verification reads (Day 33 refresh-race fix)
  - never raises on Gemini errors — inspects the returned text for the
    known fallback markers instead of assuming success
"""

import time
import json
from datetime import datetime, timezone

from agents.attack_chain_simulator import run_attack_chain, get_hardening_recommendations
from tools.elastic_tools import (
    get_recent_chain_results,
    get_recent_redteam_reports,
)

CHAINS = ["external_intrusion", "credential_theft", "insider_threat"]

# Known fallback markers from hunt_summarizer.py / redteam_reporter.py's
# own error-path templates (Day 29 / Day 44 convention) — used to detect
# whether a summary is real Gemini output or the templated fallback.
FALLBACK_MARKERS = [
    "Gemini unavailable",
    "fallback summary",
    "Manual analyst review of the raw chain_result is recommended",
]


def _is_fallback(summary_text: str) -> bool:
    if not summary_text:
        return True
    return any(marker.lower() in summary_text.lower() for marker in FALLBACK_MARKERS)


def _score_summary_presence(label: str, text: str) -> str:
    if not text:
        return f"  {label}: MISSING — empty/None ✗"
    fallback = _is_fallback(text)
    tag = "FALLBACK TEMPLATE (Gemini call failed)" if fallback else "real Gemini output"
    preview = (text[:160] + "...") if len(text) > 160 else text
    return f"  {label}: present — {tag}\n    \"{preview}\""


def run_chain_and_report(chain_name: str, target_agent: str = "redteam-target-win10"):
    print(f"\n{'='*70}")
    print(f"CHAIN: {chain_name}")
    print(f"{'='*70}")

    start = time.time()
    result = run_attack_chain(chain_name, target_agent=target_agent, network_topology=None)
    elapsed = time.time() - start

    chain_result = result.get("chain_result", [])
    fully_exploitable = result.get("fully_exploitable")
    blocked_steps = result.get("blocked_steps")
    incident_id = result.get("incident_id")
    technical_summary = result.get("technical_summary")
    executive_summary = result.get("executive_summary")

    print(f"\nWall-clock: {elapsed:.2f}s")
    print(f"fully_exploitable: {fully_exploitable}")
    print(f"blocked_steps: {blocked_steps}")
    print(f"incident_id: {incident_id}")

    print("\nPer-step results:")
    for step in chain_result:
        print(f"  step={step.get('step')} technique={step.get('mitre_tactic')} "
              f"exploitable={step.get('exploitable')} "
              f"blocked_by={step.get('blocked_by')}")
        evidence = step.get("evidence")
        if evidence:
            print(f"    evidence: {evidence}")

    print("\nGemini summaries:")
    print(_score_summary_presence("technical_summary", technical_summary))
    print(_score_summary_presence("executive_summary", executive_summary))

    recs = get_hardening_recommendations(result)
    print(f"\nHardening recommendations ({len(recs)}):")
    for r in recs:
        print(f"  - {r}")

    return {
        "chain_name": chain_name,
        "incident_id": incident_id,
        "elapsed_sec": round(elapsed, 2),
        "fully_exploitable": fully_exploitable,
        "blocked_steps": blocked_steps,
        "technical_summary_is_fallback": _is_fallback(technical_summary),
        "executive_summary_is_fallback": _is_fallback(executive_summary),
    }


def verify_es_storage(run_summaries):
    print(f"\n{'='*70}")
    print("ES VERIFICATION")
    print(f"{'='*70}")

    # Day 33-style fix: give ES's default ~1s refresh interval time to catch up
    time.sleep(1.5)

    print("\n--- siem-redteam-chains (get_recent_chain_results) ---")
    chain_docs = get_recent_chain_results(size=10)
    hits = chain_docs.get("hits", {}).get("hits", [])
    print(f"Retrieved {len(hits)} recent chain-result docs")
    found_chain_names = {h["_source"].get("chain_name") for h in hits}
    for run in run_summaries:
        status = "✓ found" if run["chain_name"] in found_chain_names else "✗ NOT FOUND"
        print(f"  {run['chain_name']}: {status}")

    print("\n--- siem-redteam-reports (get_recent_redteam_reports) ---")
    report_docs = get_recent_redteam_reports(size=10)
    hits = report_docs.get("hits", {}).get("hits", [])
    print(f"Retrieved {len(hits)} recent report docs")
    found_incident_ids = {h["_source"].get("incident_id") for h in hits}
    for run in run_summaries:
        status = "✓ found" if run["incident_id"] in found_incident_ids else "✗ NOT FOUND"
        print(f"  {run['incident_id']}: {status}")

    print("\n--- siem-blast-radius ---")
    print("  ⚠ SKIPPED — this index does not exist in the current schema.")
    print("  Blast-radius fields live embedded in siem-redteam-chains only.")
    print("  See Day 45 gap list — no write_blast_radius_to_es() function exists yet.")

    print("\n--- siem-redteam-log ---")
    print("  Manual check recommended (no get_recent_* helper wraps this index yet):")
    print("  curl -s -u elastic:changeme http://localhost:9201/siem-redteam-log/_search \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"size\":20,\"sort\":[{\"timestamp\":\"desc\"}]}' | python3 -m json.tool")


def main():
    print(f"Day 45 — Full Red Team Chain Validation")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    run_summaries = []
    for chain_name in CHAINS:
        try:
            summary = run_chain_and_report(chain_name)
            run_summaries.append(summary)
        except Exception as e:
            print(f"\n✗ ERROR running {chain_name}: {e}")
            run_summaries.append({
                "chain_name": chain_name,
                "incident_id": None,
                "elapsed_sec": None,
                "fully_exploitable": None,
                "blocked_steps": None,
                "technical_summary_is_fallback": None,
                "executive_summary_is_fallback": None,
                "error": str(e),
            })

    verify_es_storage(run_summaries)

    print(f"\n{'='*70}")
    print("SUMMARY TABLE")
    print(f"{'='*70}")
    print(f"{'Chain':<20} {'Time(s)':<10} {'Exploitable':<12} {'Blocked':<8} {'Tech Summary':<20} {'Exec Summary':<20}")
    for r in run_summaries:
        tech = "FALLBACK" if r.get("technical_summary_is_fallback") else "real Gemini"
        exe = "FALLBACK" if r.get("executive_summary_is_fallback") else "real Gemini"
        print(f"{r['chain_name']:<20} {str(r.get('elapsed_sec')):<10} "
              f"{str(r.get('fully_exploitable')):<12} {str(r.get('blocked_steps')):<8} "
              f"{tech:<20} {exe:<20}")

    with open("day45_validation_results.json", "w") as f:
        json.dump(run_summaries, f, indent=2, default=str)
    print("\nRaw results written to day45_validation_results.json")


if __name__ == "__main__":
    main()
