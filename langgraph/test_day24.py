"""
Day 24 — LIVE test script. Run this on wazuh-manager-VirtualBox after
applying the elastic_tools.py / triage_agent.py / coordination_agent.py
patches.

Location: ~/elastic/langgraph/test_day24.py

Run:
    cd ~/elastic/langgraph && python3 test_day24.py

What it does:
  1. Calls get_threat_actor_profile() against your real siem-threat-intel
     index for an actor that should already have IOCs (use a real
     threat_actor value you've seen in your Day 22 test results, or
     'APT28' if you've added it to the seed table).
  2. Calls get_ioc_history() for the known-bad IP from Day 22/23 testing
     (141.60.162.150) to confirm it finds the matching alerts.
  3. Builds a synthetic alert with cti.confidence=95 and runs it through
     coordination_agent.route_alert() (or equivalent) to confirm force-route.
  4. Runs the full alert through triage_agent and prints the final summary,
     checking that it contains threat-actor context.
"""
import sys
sys.path.insert(0, ".")

from tools.elastic_tools import get_threat_actor_profile, get_ioc_history

print("=" * 70)
print("STEP 1 — get_threat_actor_profile()")
print("=" * 70)

# Replace 'APT28' with an actual threat_actor value present in your
# siem-threat-intel index if you haven't added a seed entry for it.
actor_name = "APT28"
profile = get_threat_actor_profile(actor_name)
print(f"Profile for '{actor_name}':")
for k, v in profile.items():
    print(f"  {k}: {v}")

assert "found" in profile, "Profile missing 'found' key"
print("\n[OK] get_threat_actor_profile returned a structured result.\n")


print("=" * 70)
print("STEP 2 — get_ioc_history()")
print("=" * 70)

known_bad_ip = "141.60.162.150"  # from your Day 22 ioc_matcher test
history = get_ioc_history(known_bad_ip)
print(f"History for '{known_bad_ip}':")
print(f"  match_count: {history['match_count']}")
for a in history["alerts"][:5]:
    print(f"  - {a}")

print("\n[OK] get_ioc_history executed against live ES.\n")
print("NOTE: match_count may be 0 if you haven't injected any alerts")
print("containing this IP into logs-wazuh.alerts-* yet. If so, inject a")
print("test alert with data.srcip=141.60.162.150 first, then re-run.\n")


print("=" * 70)
print("STEP 3 — coordination_agent force-route on CTI confidence > 80")
print("=" * 70)

try:
    from agents.coordination_agent import coordination_node, route_after_coordination
except ImportError as e:
    print(f"[SKIP] Could not import coordination_node/route_after_coordination: {e}")
    coordination_node = None
    route_after_coordination = None

if coordination_node and route_after_coordination:
    synthetic_alert = {
        "rule": {"id": "5710", "level": 8, "description": "sshd: Attempt to login using non-existent user"},
        "data": {"srcip": known_bad_ip},
        "cti.matched": True,
        "cti.threat_actor": actor_name,
        "cti.confidence": 95,
        "cti.source": "otx",
    }
    test_state = {"confidence_pct": 53, "alert": synthetic_alert, "notes": []}
    test_state = coordination_node(test_state)
    decision = route_after_coordination(test_state)
    print(f"Routing decision: {decision}")
    print(f"notes: {test_state.get('notes')}")
    assert decision == "triage", "Expected force-route to 'triage'!"
    print("\n[OK] CTI confidence > 80 correctly forces route to triage.\n")


print("=" * 70)
print("STEP 4 — Full triage_agent run with CTI-matched alert")
print("=" * 70)

try:
    from agents.triage_agent import triage_node
except ImportError as e:
    print(f"[SKIP] Could not import triage_node: {e}")
    triage_node = None

if triage_node:
    synthetic_state = {
        "alert": {
            "rule": {"id": "5710", "level": 8, "description": "sshd: Attempt to login using non-existent user"},
            "data": {"srcip": known_bad_ip, "dstuser": "root(uid=0)"},
            "cti.matched": True,
            "cti.threat_actor": actor_name,
            "cti.confidence": 95,
            "cti.source": "otx",
        },
        "notes": [],
    }
    result_state = triage_node(synthetic_state)
    summary = result_state.get("triage_result", {}).get("summary", "")
    print(f"Final summary:\n{summary}\n")

    contains_profile_context = any(
        keyword in summary for keyword in ("campaign", "TTP", "threat actor", "Threat actor")
    )
    if contains_profile_context:
        print("[OK] Summary includes threat actor profile context. Day 24 test PASSED.")
    else:
        print("[FAIL] Summary does not appear to include threat actor profile context.")
        print("       Check that _attach_actor_profile_to_summary() is being called")
        print("       on both return paths in triage_agent.py.")

print("\nDone.")