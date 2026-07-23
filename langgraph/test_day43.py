"""
test_day43.py — Day 43 live test

Runs Chain 1 (external_intrusion) end-to-end through
attack_chain_simulator.run_attack_chain(), against the disposable
redteam-target-win10 VM stood up on Day 41, and verifies:
  1. All 4 steps produce a chain_result entry
  2. The chain summary lands in siem-redteam-chains
  3. Gating (chain_node) correctly skips below threshold and runs above it

Run in dry_run (default) unless REDTEAM_MODE=live is explicitly exported —
same safety default as test_day41's redteam_simulator test.
"""

import json
import time

from agents.attack_chain_simulator import (
    run_attack_chain,
    get_hardening_recommendations,
    chain_node,
    REDTEAM_MODE,
)
from tools.elastic_tools import get_recent_chain_results


def verify_logged(chain_name, timeout_s=5):
    """Poll siem-redteam-chains briefly — same ES-refresh-timing fix
    Day 33 identified (test_day33.py false negative), applied here too."""
    time.sleep(1.5)
    raw = get_recent_chain_results(size=10)
    hits = raw.get("hits", {}).get("hits", [])
    for hit in hits:
        src = hit.get("_source", {})
        if src.get("chain_name") == chain_name and "chain_result" in src:
            return src
    return None


def main():
    print(f"REDTEAM_MODE = '{REDTEAM_MODE}'\n")

    print("=== Test 1: Chain 1 (external_intrusion) full run ===")
    result = run_attack_chain("external_intrusion", target_agent="redteam-target-win10")
    print(json.dumps(result, indent=2, default=str))
    assert len(result["chain_result"]) == 4, "expected 4 steps in chain_result"
    print("PASS — chain_result has all 4 steps\n")

    print("=== Test 2: verify write to siem-redteam-chains ===")
    logged = verify_logged("external_intrusion")
    assert logged is not None, "chain summary not found in siem-redteam-chains"
    print("PASS — chain summary confirmed written to ES\n")

    print("=== Test 3: hardening recommendations for any blocked steps ===")
    recs = get_hardening_recommendations(result)
    for rec in recs:
        print(f"  - [{rec['technique']}] {rec['recommendation']}")
    print(f"PASS — {len(recs)} recommendation(s) generated from blocked steps\n")

    print("=== Test 4: chain_node gating ===")
    low_conf_state = {
        "triage_result": {"verdict": "suspicious"},
        "confidence_pct": 60,
        "technique": "T1190",
        "alert": {"agent": {"name": "redteam-target-win10"}},
    }
    out = chain_node(dict(low_conf_state))
    assert "chain_result" not in out, "chain should NOT have run below threshold"
    print("PASS — gating correctly skipped at confidence_pct=60")

    high_conf_state = {
        "triage_result": {"verdict": "suspicious"},
        "confidence_pct": 91,
        "technique": "T1190",
        "alert": {"agent": {"name": "redteam-target-win10"}},
    }
    out = chain_node(dict(high_conf_state))
    assert "chain_result" in out, "chain should have run above threshold"
    print("PASS — gating correctly ran at confidence_pct=91")

    print("\nAll Day 43 tests passed.")


if __name__ == "__main__":
    main()
