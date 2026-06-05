"""
Day 16 test — feed 10 alerts with varying rule.level values and verify routing.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from graph import graph

# Build 10 synthetic alerts spanning rule levels 1–15
TEST_ALERTS = [
    {"rule": {"id": "1001", "level": 1,  "description": "Low noise event"},         "data": {"srcip": "10.0.0.1"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1002", "level": 3,  "description": "Routine syslog"},           "data": {"srcip": "10.0.0.2"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1003", "level": 5,  "description": "PAM login success"},        "data": {"srcip": "10.0.0.3"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1004", "level": 6,  "description": "Firewall packet accepted"}, "data": {"srcip": "10.0.0.4"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1005", "level": 7,  "description": "SCA failure"},              "data": {"srcip": "10.0.0.5"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1006", "level": 8,  "description": "New principal access"},     "data": {"srcip": "10.0.0.6"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1007", "level": 9,  "description": "Auth on unseen host"},      "data": {"srcip": "10.0.0.7"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1008", "level": 11, "description": "Sudo to ROOT"},             "data": {"srcip": "10.0.0.8"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1009", "level": 13, "description": "Brute force spike"},        "data": {"srcip": "10.0.0.9"}, "agent": {"name": "agent1"}},
    {"rule": {"id": "1010", "level": 15, "description": "SSH non-existent user"},    "data": {"srcip": "127.0.0.1","dstuser": "root"}, "agent": {"name": "agent1"}},
]

EXPECTED_ROUTES = {
    1:  "archive",   # 6%
    3:  "archive",   # 20%
    5:  "archive",    # 33%
    6:  "review",    # 40%
    7:  "review",    # 46%
    8:  "review",    # 53%
    9:  "review",    # 60%
    11: "triage",    # 73%
    13: "triage",    # 86%
    15: "triage",    # 100%
}

print("=" * 60)
print("DAY 16 — Coordination Agent Routing Test")
print("=" * 60)

passed = 0
failed = 0

for alert in TEST_ALERTS:
    level = alert["rule"]["level"]
    pct = min(100, int((level / 15) * 100))
    expected = EXPECTED_ROUTES[level]

    state = {
        "alert": alert,
        "confidence": None,
        "confidence_pct": 0,
        "technique": None,
        "notes": [],
        "escalate": False,
        "triage_result": None,
    }

    try:
        result = graph.invoke(state)
        actual_pct = result["confidence_pct"]
        notes = result["notes"]

        if expected == "archive":
            ok = actual_pct <= 39
        elif expected == "review":
            ok = 40 <= actual_pct <= 70
        else:  # triage
            ok = actual_pct > 70

        status = "✅ PASS" if ok else "❌ FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"{status} | level={level:2d} | pct={actual_pct:3d}% | expected={expected:7s} | {notes[0]}")

    except Exception as e:
        failed += 1
        print(f"❌ FAIL | level={level:2d} | ERROR: {e}")

print("=" * 60)
print(f"Results: {passed}/10 passed, {failed}/10 failed")
print("=" * 60)
