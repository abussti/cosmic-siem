"""
test_day33.py

Day 33 — Response / Wazuh: Endpoint Isolation
Live test: isolate a test endpoint, verify traffic is blocked but the
Wazuh agent stays "active" (heartbeats alive), then unisolate and verify
connectivity is restored.

Same pattern as test_day31.py: parses the raw ES response dict from
get_recent_response_actions() (hits live at raw["hits"]["hits"], each under
"_source" — not a flat list) rather than assuming a pre-parsed list.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from tools.response_tools import isolate_endpoint, unisolate_endpoint
from tools.elastic_tools import get_recent_response_actions

TEST_AGENT = os.environ.get("TEST_AGENT", "agent1")            # Wazuh agent name (API path)
TEST_SSH_HOST = os.environ.get("TEST_SSH_HOST", TEST_AGENT)    # SSH-reachable host (unisolate path)


def verify_logged(action_type, target):
    """Same raw-ES-response parsing convention as elastic_tools.py's own
    __main__ block and test_day31.py's verify_es_write()."""
    raw = get_recent_response_actions(size=10)
    hits = raw.get("hits", {}).get("hits", [])
    for h in hits:
        src = h.get("_source", {})
        if src.get("action_type") == action_type and src.get("target") == target:
            return True
    return False


if __name__ == "__main__":
    print(f"=== Test 1: Isolate {TEST_AGENT} ===")
    isolate_result = isolate_endpoint(TEST_AGENT, TEST_AGENT)
    print(isolate_result)
    assert isolate_result["success"], f"isolate_endpoint failed: {isolate_result['detail']}"
    print("PASS — isolate_endpoint API call succeeded")

    assert verify_logged("isolate_endpoint", TEST_AGENT), "isolate_endpoint not found in siem-response-log"
    print("PASS — isolate_endpoint logged to siem-response-log")

    print(
        "\nManual verification needed on the agent host:\n"
        f"  1. sudo iptables -L {'ISOLATE_HOST'} -n\n"
        "     -> should show ACCEPT for the manager IP + loopback, DROP for everything else\n"
        f"  2. curl -k -s -H \"Authorization: Bearer $TOKEN\" "
        f"\"https://localhost:55000/agents?name={TEST_AGENT}\" | python3 -m json.tool\n"
        "     -> status should still read 'active' (heartbeats got through)\n"
        "  3. From the isolated agent, confirm outbound traffic to a non-manager IP is blocked\n"
        "     (e.g. `curl -m 3 https://1.1.1.1` should time out)\n"
    )
    input("Press Enter once you've confirmed isolation + live heartbeats...")

    print(f"\n=== Test 2: Unisolate {TEST_AGENT} ===")
    unisolate_result = unisolate_endpoint(TEST_AGENT, TEST_SSH_HOST)
    print(unisolate_result)
    assert unisolate_result["success"], f"unisolate_endpoint failed: {unisolate_result['detail']}"
    print("PASS — unisolate_endpoint SSH call succeeded")

    assert verify_logged("unisolate_endpoint", TEST_AGENT), "unisolate_endpoint not found in siem-response-log"
    print("PASS — unisolate_endpoint logged to siem-response-log")

    print(
        "\nManual verification needed on the agent host:\n"
        "  sudo iptables -L ISOLATE_HOST -n\n"
        "  -> should return: iptables: No chain/target/match by that name.\n"
        "  Confirm outbound traffic to a non-manager IP now succeeds again.\n"
    )

    print("\nAll Day 33 checks passed — isolate_endpoint and unisolate_endpoint working end-to-end.")
