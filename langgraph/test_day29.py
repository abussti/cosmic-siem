"""
test_day29.py
─────────────
Save to ~/elastic/langgraph/test_day29.py

Live test, same style as test_day24.py — runs against your REAL Gemini key,
REAL Elasticsearch, and REAL graph pipeline. The only thing simulated is the
ES *search results* for Hunt 1 (lateral movement), so the test doesn't
depend on matching log data already existing in your cluster.

What's real:
  - The Gemini call in summarize_hunt_findings() (needs GEMINI_API_KEY set —
    if it's not set, you'll see the templated fallback text instead, and the
    test still passes, just without a true LLM-generated summary)
  - The write to siem-hunt-results via write_hunt_result_to_es()
  - The escalation into graph.pipeline -> coordination_agent -> triage_agent

What's simulated:
  - Only the ES *search hits themselves* (3 SSH/PAM logins to agent1 from
    3 distinct external source IPs — the Day 27 lateral_movement_ssh
    hypothesis), via a one-call monkeypatch of hunting_agent._post. This
    avoids depending on that exact pattern already existing in your data,
    same reasoning as the synthetic events used in test_pipeline_e2e.py /
    inject_test_events.py.

Run:
    cd ~/elastic/langgraph && python3 test_day29.py
"""

import agents.hunting_agent as hunting_agent
from tools.elastic_tools import get_recent_hunt_results

SIMULATED_HITS = {
    "hits": {
        "hits": [
            {"_id": "sim1", "_source": {
                "@timestamp": "2026-06-25T01:10:00Z",
                "rule": {"id": "5501", "description": "PAM: Login session opened."},
                "agent": {"name": "agent1"},
                "data": {"srcip": "203.0.113.10", "dstuser": "ubuntu"},
            }},
            {"_id": "sim2", "_source": {
                "@timestamp": "2026-06-25T01:14:00Z",
                "rule": {"id": "5501", "description": "PAM: Login session opened."},
                "agent": {"name": "agent1"},
                "data": {"srcip": "203.0.113.45", "dstuser": "ubuntu"},
            }},
            {"_id": "sim3", "_source": {
                "@timestamp": "2026-06-25T01:19:00Z",
                "rule": {"id": "5501", "description": "PAM: Login session opened."},
                "agent": {"name": "agent1"},
                "data": {"srcip": "203.0.113.99", "dstuser": "ubuntu"},
            }},
        ]
    }
}

_real_post = hunting_agent._post


def _simulated_post(path, body):
    """Only fakes the lateral-movement search itself; anything else (e.g. the
    real write_hunt_result_to_es call inside run_hunt) goes through untouched."""
    if path.endswith("_search"):
        return SIMULATED_HITS
    return _real_post(path, body)


def main():
    print("=" * 70)
    print("DAY 29 LIVE TEST — Hunt 1 (lateral_movement_ssh) with simulated data")
    print("=" * 70)

    playbook = hunting_agent.HuntPlaybook(
        hunt_name="lateral_movement_ssh",
        time_window=24,
        hunt_query={"bool": {"must": [{"terms": {"rule.groups": ["pam"]}}]}},
        mitre_technique="T1021.004",
    )

    hunting_agent._post = _simulated_post
    try:
        result = hunting_agent.run_hunt(playbook)
    finally:
        hunting_agent._post = _real_post  # restore real ES access immediately after

    print("\n--- run_hunt() result ---")
    print(f"threats_found: {result['threats_found']}")
    print(f"escalate:      {result['escalate']}")
    print(f"hunt_summary:\n  {result['hunt_summary']}")

    assert result["threats_found"] == 3, "Expected 3 simulated findings"
    assert result["escalate"] is True, "3 findings should clear ESCALATION_THRESHOLD=1"
    assert len(result["hunt_summary"]) > 20, "Summary looks too short to be useful"
    print("\n✓ Gemini produced a summary (real call if GEMINI_API_KEY is set, "
          "fallback text otherwise — either way, no crash)")

    print("\n--- Verifying the write to siem-hunt-results ---")
    recent = get_recent_hunt_results(5)
    hits = (recent or {}).get("hits", {}).get("hits", [])
    matches = [h for h in hits if h["_source"].get("hunt_name") == "lateral_movement_ssh"]
    assert matches, "Expected at least one lateral_movement_ssh doc in siem-hunt-results"
    print(f"✓ Found {len(matches)} lateral_movement_ssh doc(s) in siem-hunt-results, "
          f"most recent: {matches[0]['_source']}")

    print("\nNote: escalation also tried to invoke graph.pipeline with a synthetic")
    print("alert (confidence_pct=85). Check logs above for any [ERROR] from")
    print("escalate_hunt_to_triage — if coordination_agent/triage_agent ran without")
    print("errors, the synthetic alert reached triage same as a real one would.")

    print("\n" + "=" * 70)
    print("DAY 29 TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
