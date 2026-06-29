"""
test_day31.py — live test for the Day 31 response agent scaffold.

Pattern matches test_day24.py / test_day29.py: real ES write, no mocking
of elastic_tools. Run from ~/elastic/langgraph/.
"""

from agents.response_agent import response_node
from tools.elastic_tools import get_recent_response_actions


def test_suspicious_high_confidence_logs_action():
    state = {
        "alert": {"data": {"srcip": "203.0.113.77"}, "agent": {"name": "agent1"}},
        "triage_result": {"verdict": "suspicious", "summary": "SSH brute force",
                           "technique": "T1110"},
        "confidence_pct": 91,
        "notes": [],
    }
    result = response_node(state)
    assert result["response_action"] == "block_ip", result
    assert any("Selected action" in n for n in result["notes"])
    print("PASS — suspicious+high-confidence selects 'block_ip', logged, not executed")


def test_below_threshold_no_action():
    state = {
        "alert": {"data": {"srcip": "198.51.100.5"}},
        "triage_result": {"verdict": "suspicious"},
        "confidence_pct": 76,
        "notes": [],
    }
    result = response_node(state)
    assert result["response_action"] is None, result
    print("PASS — confidence below threshold takes no action")


def test_benign_verdict_no_action():
    state = {
        "alert": {"agent": {"name": "agent1"}},
        "triage_result": {"verdict": "benign"},
        "confidence_pct": 95,
        "notes": [],
    }
    result = response_node(state)
    assert result["response_action"] is None, result
    print("PASS — benign verdict takes no action even at high confidence")


def verify_es_write():
    # get_recent_response_actions() returns the raw ES response dict (same
    # convention as get_recent_hunt_results) — hits live at
    # raw["hits"]["hits"], each with the doc under "_source".
    raw = get_recent_response_actions(size=5)
    hits = (raw or {}).get("hits", {}).get("hits", [])
    print(f"\nMost recent {len(hits)} entries in siem-response-log:")
    for hit in hits:
        entry = hit.get("_source", {})
        print(f"  {entry.get('timestamp')} | action={entry.get('action_type')} "
              f"| target={entry.get('target')} | verdict={entry.get('verdict')}")
    assert len(hits) > 0, "No entries found in siem-response-log — check index exists"
    print("PASS — siem-response-log contains entries from this test run")


if __name__ == "__main__":
    test_suspicious_high_confidence_logs_action()
    test_below_threshold_no_action()
    test_benign_verdict_no_action()
    verify_es_write()
    print("\nAll Day 31 scaffold tests passed — no real response action was executed.")
