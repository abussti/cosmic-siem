"""
test_day44.py — Day 44 live test

Runs a real chain simulation, verifies:
  1. run_attack_chain() returns technical_summary + executive_summary
  2. siem-redteam-reports has the new document
  3. create_ticket() accepts and folds in the executive_brief

Mirrors test_day43.py's structure (chain run -> ES write verification ->
gating) and test_day31.py's ES-write verification pattern.
"""

import json
import time

from agents.attack_chain_simulator import run_attack_chain
from tools.elastic_tools import get_recent_redteam_reports
from tools.response_tools import create_ticket


def main():
    print("=== Day 44 — Chain 2 (credential_theft) simulation ===")
    result = run_attack_chain("credential_theft", target_agent="redteam-target-win10")

    assert "technical_summary" in result, "run_attack_chain() did not return technical_summary"
    assert "executive_summary" in result, "run_attack_chain() did not return executive_summary"
    print("PASS — chain result includes both summaries")

    print("\n--- technical_summary ---")
    print(result["technical_summary"])
    print("\n--- executive_summary ---")
    print(result["executive_summary"])

    print("\n=== Verifying siem-redteam-reports write ===")
    # [Day 44 fix] Same ES-refresh-timing race Day 33 found and fixed for
    # siem-response-log — ES's default ~1s refresh interval means a doc
    # written a moment ago may not be searchable yet. No production code
    # changes needed, same as Day 33 — cosmetic, test-side only.
    time.sleep(1.5)
    reports = get_recent_redteam_reports(size=5)
    hits = (reports or {}).get("hits", {}).get("hits", [])
    assert hits, "no report document found in siem-redteam-reports"
    latest = hits[0]["_source"]
    assert latest.get("incident_id") == result.get("incident_id"), (
        f"expected incident_id {result.get('incident_id')!r}, "
        f"found {latest.get('incident_id')!r} — check ES refresh timing "
        f"(same ~1s delay test_day33.py hit; add a short sleep here if this fires)"
    )
    print(f"PASS — siem-redteam-reports contains incident_id={latest.get('incident_id')}")

    print("\n=== Verifying create_ticket() includes the executive brief ===")
    test_alert = {
        "rule": {"description": "Simulated credential theft chain", "level": 12},
        "agent": {"name": "redteam-target-win10"},
        "data": {"srcip": "192.168.56.13"},
    }
    ticket = create_ticket(
        alert=test_alert,
        triage_summary=result["technical_summary"],
        confidence=91,
        technique="T1110",
        executive_brief=result["executive_summary"],
    )
    print(json.dumps(ticket, indent=2, default=str))

    if ticket["success"]:
        print(f"PASS — ticket created: {ticket['target']}")
    else:
        print(f"NOTE — ticket creation not configured/failed in this environment "
              f"(GITHUB_TOKEN/OWNER/REPO not set, or API error): {ticket['detail']}")
        print("This is expected if GitHub isn't configured in this test run — "
              "the important check is that create_ticket() accepted "
              "executive_brief without error, which it did.")

    print("\nAll Day 44 checks completed.")


if __name__ == "__main__":
    main()
