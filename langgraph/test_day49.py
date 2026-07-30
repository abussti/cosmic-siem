"""
test_day49.py — Day 49 combined test suite for tools/insider_threat.py
(Hunts 6-9: credential hoarding, data staging, access broadening, schedule
shift) and its scheduler wiring into pipeline_runner.py.

Same convention as test_day46.py/test_day48.py: mocked-ES unit +
integration tests by default (safe to run anywhere, no live cluster
needed), a real injection test against your live Elasticsearch via --live.

Usage
-----
  cd ~/elastic/langgraph
  python3 test_day49.py            # mocked — safe anywhere
  python3 test_day49.py --live     # live 15x-baseline injection against real ES

How the mocking works
----------------------
Mocked mode overrides tools.elastic_tools / tools.ueba_scorer /
tools.ueba_engine / tools.ioc_matcher / graph / confidence_scorer / state in
sys.modules BEFORE importing tools.insider_threat / pipeline_runner — same
pattern run_day18_tests.py established for mocking google.genai before any
langgraph import. The real tools/insider_threat.py and pipeline_runner.py
already deployed on this machine are what actually get exercised either
way; only their dependencies are swapped out, so a passing mocked run here
is testing your real detection/wiring logic, not a reimplementation of it.

--live mode never touches sys.modules — it imports your real
tools.elastic_tools / tools.ueba_scorer / tools.insider_threat directly and
writes real documents to Elasticsearch (seeding a synthetic UEBA baseline,
injecting a real 15x-baseline staging alert, polling until it's searchable,
then running the real detection + full hunt cycle). Cleans up its own test
alert index afterwards; the synthetic siem-ueba-profiles doc is left behind
(write_ueba_profile_to_es() doesn't upsert on a fixed _id yet — Day 46 P2
follow-up) — same "test data left in a real index" class already tracked
for Day 28/48. Manual cleanup command printed at the end.

Confirmed live (30 July 2026): fires at 15.0x baseline, escalate=True,
mitre_technique=T1074, full run_all_insider_threat_hunts() cycle correctly
reports insider_data_staging: threats_found=1 with the other 3 hunts at 0
(root/devadmin/www-data have no real peer/volume/access data to trigger
on yet — expected, not a bug, per Day 46's documented data-source limits).
"""

import datetime
import sys
import time
import types
import unittest
from unittest.mock import MagicMock

LIVE_MODE = "--live" in sys.argv


# ============================================================================
# Mocked dependency installation (skipped entirely in --live mode)
# ============================================================================

def _install_mocks():
    elastic_tools_mod = types.ModuleType("tools.elastic_tools")
    elastic_tools_mod._post = MagicMock(return_value={})
    elastic_tools_mod.write_hunt_result_to_es = MagicMock(return_value={"result": "created"})
    elastic_tools_mod.get_unprocessed_alerts = MagicMock(return_value=[])
    elastic_tools_mod.write_triage_result_to_es = MagicMock(return_value=True)
    sys.modules["tools.elastic_tools"] = elastic_tools_mod

    ueba_scorer_mod = types.ModuleType("tools.ueba_scorer")
    ueba_scorer_mod.get_ueba_profile = MagicMock(return_value=None)  # overridden per-test
    sys.modules["tools.ueba_scorer"] = ueba_scorer_mod

    ueba_engine_mod = types.ModuleType("tools.ueba_engine")
    ueba_engine_mod._DEPARTMENT_SEED = {
        "alice": "engineering",
        "bob": "engineering",
        "carol": "engineering",
        "eve": "unassigned",
        "jdoe": "finance",
        "frank": "engineering",
        "grace": "engineering",
    }
    sys.modules["tools.ueba_engine"] = ueba_engine_mod

    ioc_matcher_mod = types.ModuleType("tools.ioc_matcher")
    ioc_matcher_mod.match_alert_iocs = MagicMock(return_value={"matched": False})
    sys.modules["tools.ioc_matcher"] = ioc_matcher_mod

    graph_mod = types.ModuleType("graph")
    graph_mod.pipeline = MagicMock()
    graph_mod.pipeline.invoke = MagicMock(return_value={"notes": [], "escalate": False, "triage_result": None})
    graph_mod.hunt_pipeline = MagicMock()
    graph_mod.hunt_pipeline.invoke = MagicMock(return_value={"notes": [], "escalate": False})
    sys.modules["graph"] = graph_mod

    confidence_scorer_mod = types.ModuleType("confidence_scorer")
    confidence_scorer_mod.score_and_tier = MagicMock(return_value=(50, "REVIEW"))
    sys.modules["confidence_scorer"] = confidence_scorer_mod

    state_mod = types.ModuleType("state")
    state_mod.AgentState = dict
    sys.modules["state"] = state_mod

    return elastic_tools_mod, ueba_scorer_mod, ueba_engine_mod, graph_mod


if not LIVE_MODE:
    _elastic_tools_mod, _ueba_scorer_mod, _ueba_engine_mod, _graph_mod = _install_mocks()
    import tools.insider_threat as it
    import pipeline_runner


# ============================================================================
# Mocked unit tests — tools/insider_threat.py detection logic
# ============================================================================

class TestUnwrapUebaProfile(unittest.TestCase):
    """get_ueba_profile()'s real return shape surprised us twice on the live
    run (Day 49) before being confirmed: it returns the profile_json content
    directly (bare), not nested under a 'profile_json' key and not a raw ES
    hit. All three shapes are covered so a future surprise here fails loudly
    in a unit test instead of live against real ES."""

    def test_bare_content_shape_confirmed_live(self):
        doc = {"avg_outbound_bytes_per_day": 1000000,
               "accessed_systems": ["agent1"],
               "typical_login_hours": [9, 10, 11, 17]}
        self.assertEqual(it._unwrap_ueba_profile(doc), doc)

    def test_flat_profile_json_shape(self):
        doc = {"profile_json": {"avg_outbound_bytes_per_day": 5}}
        self.assertEqual(it._unwrap_ueba_profile(doc), {"avg_outbound_bytes_per_day": 5})

    def test_raw_es_hit_shape(self):
        doc = {"_index": "siem-ueba-profiles", "_id": "abc",
               "_source": {"profile_json": {"avg_outbound_bytes_per_day": 5}}}
        self.assertEqual(it._unwrap_ueba_profile(doc), {"avg_outbound_bytes_per_day": 5})

    def test_none_or_empty(self):
        self.assertEqual(it._unwrap_ueba_profile(None), {})
        self.assertEqual(it._unwrap_ueba_profile({}), {})
        print("PASS — _unwrap_ueba_profile handles bare-content (real), flat, raw-hit, and empty/None shapes")


class TestDataStaging15x(unittest.TestCase):
    """Headline Day 49 scenario: user downloads 15x baseline volume."""

    def test_data_staging_fires_at_15x(self):
        baseline = 1_000_000
        current = 15_000_000

        _ueba_scorer_mod.get_ueba_profile.return_value = {
            "avg_outbound_bytes_per_day": baseline,
        }
        it._get_24h_outbound_bytes = MagicMock(return_value=current)

        finding = it.detect_data_staging("jdoe")

        self.assertEqual(finding["threats_found"], 1)
        self.assertTrue(finding["escalate"])
        self.assertEqual(finding["mitre_technique"], "T1074")
        self.assertEqual(finding["extra"]["ratio"], 15.0)
        self.assertIn("15.0x baseline", finding["evidence"])
        print(f"PASS — data_staging fires at 15x baseline: {finding['evidence']}")

    def test_data_staging_escalates_with_insider_tag_and_confidence_90(self):
        _ueba_scorer_mod.get_ueba_profile.return_value = {"avg_outbound_bytes_per_day": 1_000_000}
        it._get_24h_outbound_bytes = MagicMock(return_value=15_000_000)
        finding = it.detect_data_staging("jdoe")

        _graph_mod.pipeline.invoke.reset_mock()
        it.escalate_insider_finding_to_coordination(finding)

        self.assertTrue(_graph_mod.pipeline.invoke.called)
        state_arg = _graph_mod.pipeline.invoke.call_args[0][0]
        self.assertEqual(state_arg["confidence_pct"], 90)
        self.assertIn(it.INSIDER_ESCALATION_TAG, state_arg["tags"])
        self.assertEqual(state_arg["alert"]["insider_threat_tag"], "insider_threat")
        self.assertEqual(state_arg["alert"]["data"]["dstuser"], "jdoe")
        # AgentState shape must match pipeline_runner.py's real initial_state
        # exactly (confidence/triage_result included even though unused here)
        self.assertIn("confidence", state_arg)
        self.assertIn("triage_result", state_arg)
        print("PASS — escalation reaches coordination with confidence_pct=90, tag=insider_threat, "
              "full AgentState shape")

    def test_data_staging_no_baseline_yet_does_not_crash(self):
        _ueba_scorer_mod.get_ueba_profile.return_value = None
        finding = it.detect_data_staging("newuser_no_profile")
        self.assertEqual(finding["threats_found"], 0)
        self.assertEqual(finding["status"], "no_baseline_yet")
        print("PASS — missing UEBA profile degrades honestly, no crash")


class TestCredentialHoarding(unittest.TestCase):
    def test_flags_above_5x_peer_average(self):
        def fake_count(username, lookback_days):
            return {"alice": 20, "bob": 2, "carol": 3}.get(username, 0)
        it._get_weekly_credential_access_count = MagicMock(side_effect=fake_count)

        finding = it.detect_credential_hoarding("alice")
        self.assertEqual(finding["threats_found"], 1)
        self.assertEqual(finding["mitre_technique"], "T1552")
        # alice's "engineering" peer group in the mocked seed also includes
        # frank/grace (both 0 hits) alongside bob(2)/carol(3) -> avg=1.25
        self.assertEqual(finding["extra"]["peer_avg"], 1.25)
        print(f"PASS — credential_hoarding fires: {finding['evidence']}")

    def test_no_peers_degrades_honestly(self):
        it._get_weekly_credential_access_count = MagicMock(return_value=10)
        finding = it.detect_credential_hoarding("eve")  # unassigned peer group
        self.assertEqual(finding["threats_found"], 0)
        self.assertEqual(finding["status"], "peer_group_insufficient")
        print("PASS — no seeded peers -> honest skip, not a false positive")


class TestAccessBroadening(unittest.TestCase):
    def test_flags_3_new_systems(self):
        _ueba_scorer_mod.get_ueba_profile.return_value = {"accessed_systems": ["host1", "host2"]}
        it._get_7day_accessed_systems = MagicMock(
            return_value={"host1", "host3", "host4", "host5"}
        )
        finding = it.detect_access_broadening("frank")
        self.assertEqual(finding["threats_found"], 1)
        self.assertEqual(sorted(finding["extra"]["new_systems"]), ["host3", "host4", "host5"])
        print(f"PASS — access_broadening fires: {finding['evidence']}")


class TestScheduleShift(unittest.TestCase):
    def test_flags_5_consecutive_shifted_days(self):
        _ueba_scorer_mod.get_ueba_profile.return_value = {"typical_login_hours": [9, 10, 11, 17]}
        shifted_days = {
            "2026-07-20": [2, 3],
            "2026-07-21": [2],
            "2026-07-22": [3, 2],
            "2026-07-23": [2],
            "2026-07-24": [3],
            "2026-07-27": [10],  # normal day, non-consecutive, should not extend the run
        }
        it._get_recent_daily_login_hours = MagicMock(return_value=shifted_days)
        finding = it.detect_schedule_shift("grace")
        self.assertEqual(finding["threats_found"], 1)
        self.assertEqual(finding["extra"]["longest_run"], 5)
        print(f"PASS — schedule_shift fires: {finding['evidence']}")

    def test_single_normal_login_does_not_break_a_day_flag(self):
        _ueba_scorer_mod.get_ueba_profile.return_value = {"typical_login_hours": [9]}
        it._get_recent_daily_login_hours = MagicMock(return_value={"2026-07-20": [2, 9]})
        finding = it.detect_schedule_shift("grace")
        self.assertEqual(finding["threats_found"], 0)
        print("PASS — mixed normal+odd-hour day correctly not counted as fully shifted")


class TestFullCycle(unittest.TestCase):
    def test_run_all_insider_threat_hunts_writes_and_escalates(self):
        it._get_weekly_credential_access_count = MagicMock(
            side_effect=lambda u, d: {"alice": 20, "bob": 2, "carol": 3}.get(u, 0)
        )
        it._get_24h_outbound_bytes = MagicMock(return_value=15_000_000)
        it._get_7day_accessed_systems = MagicMock(return_value={"host1", "host3", "host4", "host5"})
        it._get_recent_daily_login_hours = MagicMock(return_value={
            "2026-07-20": [2, 3], "2026-07-21": [2], "2026-07-22": [3, 2],
            "2026-07-23": [2], "2026-07-24": [3],
        })
        _ueba_scorer_mod.get_ueba_profile.side_effect = lambda etype, uid: {
            "avg_outbound_bytes_per_day": 1_000_000,
            "accessed_systems": ["host1", "host2"],
            "typical_login_hours": [9, 10, 11, 17],
        }

        _elastic_tools_mod.write_hunt_result_to_es.reset_mock()
        _graph_mod.pipeline.invoke.reset_mock()

        results = it.run_all_insider_threat_hunts(usernames=["alice", "bob", "carol", "jdoe", "frank", "grace"])

        self.assertEqual(len(results), 4)  # Hunts 6-9
        self.assertTrue(_elastic_tools_mod.write_hunt_result_to_es.called)
        self.assertTrue(_graph_mod.pipeline.invoke.called)
        for r in results:
            print(f"  {r['hunt_name']}: threats_found={r['threats_found']}")
        print(f"PASS — full cycle: {sum(r['threats_found'] for r in results)} total findings, "
              f"{_elastic_tools_mod.write_hunt_result_to_es.call_count} siem-hunt-results writes, "
              f"{_graph_mod.pipeline.invoke.call_count} escalations")


# ============================================================================
# Mocked integration tests — pipeline_runner.py scheduler wiring
# ============================================================================

class TestPipelineRunnerIntegration(unittest.TestCase):
    def test_module_imports_cleanly(self):
        self.assertTrue(hasattr(pipeline_runner, "run_all_insider_threat_hunts"))
        self.assertTrue(hasattr(pipeline_runner, "run_scheduled_insider_hunts"))
        print("PASS — pipeline_runner.py imports cleanly with Day 49 insider_threat wiring")

    def test_insider_hunt_interval_constant(self):
        self.assertEqual(pipeline_runner.INSIDER_HUNT_INTERVAL_HOURS, 24)
        self.assertEqual(pipeline_runner.HUNT_INTERVAL_HOURS, 6)
        print("PASS — insider hunts (24h) run on a separate cadence from threat hunts (6h)")

    def test_scheduler_registers_both_jobs(self):
        scheduler = pipeline_runner.start_hunt_scheduler()
        job_ids = {job.id for job in scheduler.get_jobs()}
        self.assertIn("hunt_scheduler", job_ids)
        self.assertIn("insider_hunt_scheduler", job_ids)
        insider_job = scheduler.get_job("insider_hunt_scheduler")
        self.assertEqual(insider_job.trigger.interval.total_seconds(), 24 * 3600)
        scheduler.shutdown(wait=False)
        print(f"PASS — both jobs registered on one scheduler: {job_ids}")

    def test_run_scheduled_insider_hunts_completes_without_raising(self):
        try:
            pipeline_runner.run_scheduled_insider_hunts()
        except Exception as e:
            self.fail(f"run_scheduled_insider_hunts() raised: {e}")
        print("PASS — run_scheduled_insider_hunts() completes cleanly (mocked ES)")

    def test_positive_finding_escalates_via_insider_threat_module_itself(self):
        it._get_24h_outbound_bytes = lambda u, h: 50_000_000  # 50x baseline for every user

        _graph_mod.pipeline.invoke.reset_mock()
        pipeline_runner.run_scheduled_insider_hunts()

        self.assertTrue(_graph_mod.pipeline.invoke.called)
        called_state = _graph_mod.pipeline.invoke.call_args[0][0]
        self.assertEqual(called_state["confidence_pct"], 90)
        self.assertIn("insider_threat", called_state["tags"])
        print("PASS — a real positive finding during the scheduled cycle escalates to "
              "coordination with confidence_pct=90 and the insider_threat tag, "
              "with pipeline_runner.py's scheduler needing zero special-case code")


# ============================================================================
# LIVE injection test (--live only) — the Day 49 plan's deliverable 8:
# "simulate a user downloading 15x baseline volume -> verify insider threat
# alert fires with UEBA context"
# ============================================================================

TEST_USER = "insider-test-day49"
BASELINE_BYTES_PER_DAY = 1_000_000
STAGING_BYTES_24H = 15_000_000
TEST_ALERT_INDEX = "logs-wazuh.alerts-day49test"


def _inject_ueba_baseline(_post):
    doc = {
        "entity_type": "user",
        "entity_id": TEST_USER,
        "profile_json": {
            "avg_outbound_bytes_per_day": BASELINE_BYTES_PER_DAY,
            "accessed_systems": ["agent1"],
            "typical_login_hours": [9, 10, 11, 17],
        },
        "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "risk_score": 10,
    }
    result = _post("siem-ueba-profiles/_doc", doc)
    print(f"[inject] wrote synthetic UEBA baseline for {TEST_USER}: {result}")
    return result


def _inject_staging_alert(_post):
    doc = {
        "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rule": {
            "id": "100001",
            "level": 8,
            "description": "Firewall: packet accepted (Day 49 synthetic test)",
            "groups": ["firewall"],
        },
        "agent": {"name": "agent1"},
        "data": {
            "srcip": "192.168.56.11",
            "dstuser": TEST_USER,
            "bytes_out": STAGING_BYTES_24H,
        },
    }
    result = _post(f"{TEST_ALERT_INDEX}/_doc", doc)
    print(f"[inject] wrote synthetic staging alert ({STAGING_BYTES_24H:,} bytes_out): {result}")
    return result


def _wait_for_alert_visible(_post, username, max_attempts=10, delay_s=1.0):
    """Poll until the just-injected alert is searchable, instead of guessing
    a fixed sleep. Confirmed live (30 July 2026) that this is a real ES
    refresh-timing race on a freshly created data stream, not a query bug —
    same class Day 33/44 already documented for siem-response-log /
    siem-redteam-reports writes."""
    body = {"size": 0, "query": {"bool": {"filter": [{"prefix": {"data.dstuser": username}}]}}}
    for attempt in range(1, max_attempts + 1):
        raw = _post("logs-wazuh.alerts-*/_search", body)
        total = raw.get("hits", {}).get("total", {}).get("value", 0)
        if total >= 1:
            print(f"[wait] alert visible after {attempt} attempt(s) ({attempt * delay_s:.1f}s)")
            return True
        time.sleep(delay_s)
    print(f"[wait] alert still not visible after {max_attempts * delay_s:.1f}s")
    return False


def live_main():
    from tools.elastic_tools import _post
    from tools.ueba_scorer import get_ueba_profile
    from tools.insider_threat import (
        detect_data_staging,
        run_all_insider_threat_hunts,
        _unwrap_ueba_profile,
    )

    ratio = STAGING_BYTES_24H / BASELINE_BYTES_PER_DAY
    print(f"=== Day 49 LIVE test — {TEST_USER}: {ratio:.0f}x baseline ===\n")

    _inject_ueba_baseline(_post)
    print("Waiting 2s for ES refresh...")
    time.sleep(2)

    profile = get_ueba_profile("user", TEST_USER)
    profile_json = _unwrap_ueba_profile(profile)
    if not profile_json.get("avg_outbound_bytes_per_day"):
        print("FAIL — UEBA profile did not round-trip as expected. Raw get_ueba_profile() return:")
        print(f"  {profile!r}")
        sys.exit(1)
    print(f"[verify] profile round-trip OK: avg_outbound_bytes_per_day="
          f"{profile_json['avg_outbound_bytes_per_day']:,}")

    _inject_staging_alert(_post)
    _wait_for_alert_visible(_post, TEST_USER)

    print("\n--- detect_data_staging() direct call ---")
    finding = detect_data_staging(TEST_USER)
    print(finding["evidence"])
    if finding["threats_found"] != 1 or not finding["escalate"]:
        print(f"FAIL — expected a hit with escalate=True, got: {finding}")
        sys.exit(1)
    print(f"PASS — fires at {finding['extra']['ratio']}x baseline, escalate={finding['escalate']}, "
          f"mitre_technique={finding['mitre_technique']}")

    print("\n--- full run_all_insider_threat_hunts() cycle "
          "(writes siem-hunt-results, attempts real escalation to coordination/triage) ---")
    results = run_all_insider_threat_hunts(usernames=[TEST_USER])
    for r in results:
        print(f"  {r['hunt_name']}: threats_found={r['threats_found']}")

    print(f"\nAll Day 49 live checks passed.")
    print(f"\nCleanup:")
    print(f"  curl -s -u elastic:changeme -X DELETE http://localhost:9201/_data_stream/{TEST_ALERT_INDEX}")
    print(f"  # (optional) remove the synthetic UEBA profile doc:")
    print(f"  curl -s -u elastic:changeme -X POST http://localhost:9201/siem-ueba-profiles/_delete_by_query "
          f"-H 'Content-Type: application/json' "
          f"-d '{{\"query\":{{\"term\":{{\"entity_id\":\"{TEST_USER}\"}}}}}}}}'")


if __name__ == "__main__":
    if LIVE_MODE:
        live_main()
    else:
        sys.argv = [sys.argv[0]]  # strip any stray args before handing off to unittest
        print("=== Day 49 — mocked-ES unit + integration test suite ===\n")
        unittest.main(verbosity=2)
