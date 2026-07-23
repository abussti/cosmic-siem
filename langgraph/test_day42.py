"""
test_day42.py — live test for tools/blast_radius.py

Synthetic scenario: 3 SSH connections from one compromised host
('agent1' acting as srcip source, per Hunt-1's field convention) to 3
distinct target hosts, injected as separate agent.name docs — same
overall shape as inject_day28_test_events.py.

Run:
    cd ~/elastic/langgraph && python3 test_day42.py
"""

import time
import datetime
import requests

ES_URL = "http://localhost:9201"
ES_AUTH = ("elastic", "changeme")
TEST_INDEX = "logs-wazuh.alerts-day42test"

COMPROMISED_HOST_IP = "203.0.113.50"  # stand-in "srcip" for agent1 in this test
TARGET_HOSTS = ["victim1", "victim2", "victim3"]


def inject_ssh_connection(target_host, src_ip):
    """
    One synthetic SSH alert: target_host is the agent.name (the host that
    logged the event, i.e. the one reached), src_ip is the compromised
    host's IP — matches the same (agent.name, data.srcip) shape Hunt 1
    (lateral_movement_ssh) and Hunt 5 (beaconing) already use.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    doc = {
        "@timestamp": now,
        "rule": {
            "id": "5501",
            "level": 5,
            "description": "PAM: Login session opened",
            "groups": ["pam", "authentication_success", "sshd"],
        },
        "agent": {"name": target_host},
        "data": {"srcip": src_ip, "dstuser": "svc_deploy"},
    }
    resp = requests.post(
        f"{ES_URL}/{TEST_INDEX}/_doc",
        auth=ES_AUTH,
        json=doc,
        headers={"Content-Type": "application/json"},
    )
    return resp.status_code, resp.text


def cleanup():
    """Data stream, not a plain index — same gotcha Day 28 hit."""
    requests.delete(f"{ES_URL}/_data_stream/{TEST_INDEX}", auth=ES_AUTH)


def force_refresh():
    """
    Force the target data stream to refresh before querying it.
    Found necessary during the live Day 42 run: a fixed sleep(1.5) was not
    reliable enough — the 3 injected docs were still unsearchable when
    map_blast_radius() queried, so signal 1 came back empty. Same class of
    bug test_day33.py hit with siem-response-log. An explicit _refresh call
    is deterministic; a sleep is a guess.
    """
    resp = requests.post(f"{ES_URL}/{TEST_INDEX}/_refresh", auth=ES_AUTH)
    return resp.status_code


if __name__ == "__main__":
    print("=== Injecting 3 synthetic SSH connections ===")
    for host in TARGET_HOSTS:
        status, body = inject_ssh_connection(host, COMPROMISED_HOST_IP)
        print(f"  -> {host}: HTTP {status}")

    print("Forcing index refresh (see force_refresh() docstring)...")
    status = force_refresh()
    print(f"  _refresh -> HTTP {status}")
    time.sleep(0.5)  # small safety margin after refresh confirms

    # NOTE: map_blast_radius() as written queries ALERTS_INDEX =
    # "logs-wazuh.alerts-*", which this test index (logs-wazuh.alerts-day42test)
    # matches, so no code changes needed to pick this up.
    #
    # disable_signals=["subnet"]: the shared 203.0.113.0/24 test range has
    # accumulated IPs from many earlier days' test injections (Day 18, 32,
    # 38...). Subnet-matching against that shared range pulls all of that
    # historical noise in alongside this test's 3 real connections, which
    # defeats the "exactly 3 reachable nodes" check below. Signal 2 is
    # disabled here to isolate signals 1+3 for this assertion; subnet
    # matching still works normally in production calls that don't pass
    # this override. See blast_radius.py's KNOWN LIMITATION note.
    from tools.blast_radius import map_blast_radius, write_blast_radius_to_es

    result = map_blast_radius(
        COMPROMISED_HOST_IP, network_data={"disable_signals": ["subnet"]}
    )
    print("\n=== map_blast_radius result ===")
    print("reachable_hosts:", result["reachable_hosts"])
    print("blast_score:", result["blast_score"])
    print("errors:", result["errors"])

    expected = set(TARGET_HOSTS)
    actual = set(result["reachable_hosts"])
    if actual == expected:
        print(f"PASS — reachable_hosts is exactly the 3 injected hosts: {expected}")
    elif expected.issubset(actual):
        print(f"PARTIAL — all 3 injected hosts present, but extra hosts also returned: {actual - expected}")
    else:
        print(f"FAIL — expected {expected}, got {actual} (missing: {expected - actual})")

    write_result = write_blast_radius_to_es(result, incident_id="test-day42-001")
    print("\nwrite_blast_radius_to_es:", write_result)

    print("\nVerify with:")
    print(
        "  curl -s -u elastic:changeme "
        f"'{ES_URL}/siem-blast-radius/_search' -H 'Content-Type: application/json' "
        "-d '{\"query\":{\"term\":{\"incident_id\":\"test-day42-001\"}}}' | python3 -m json.tool"
    )

    print("\nCleaning up test data stream...")
    cleanup()
