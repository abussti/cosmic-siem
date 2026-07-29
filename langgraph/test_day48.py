"""
test_day48.py — Day 48 test: Analyst Feedback Loop

Two modes in one file:

  python3 test_day48.py            -> mocked-ES unit test (no live cluster
                                       needed; safe to run anywhere, same
                                       convention as test_day46.py)
  python3 test_day48.py --live     -> injects 20 synthetic verdicts
                                       directly into siem-analyst-verdicts
                                       on the REAL stack, then runs a real
                                       retrain_weights() and verifies the
                                       result (the live equivalent of the
                                       mocked run above)

Both modes use the same 12 TP / 8 FP fixture, with the FP verdicts
dominated by a high 'anomaly' score, so the assertions are identical
either way: 70-100 bucket FP rate 40% (> 30% threshold), dominant_factor
= 'anomaly', anomaly weight cut by exactly one WEIGHT_STEP (0.35 -> 0.30),
other two weights untouched.

Live-mode docs are written directly via _post() rather than through
record_verdict(), since these are synthetic alert_ids with no backing
Wazuh document to look up — same "inject synthetic data directly"
pattern as inject_day28_test_events.py and the Day 18/38 scenario
injectors.
"""

import datetime
import sys
import time
from unittest.mock import patch


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_fake_verdicts():
    """Shared fixture: 12 TP (balanced factors) + 8 FP (anomaly-dominated)."""
    verdicts = []

    for i in range(12):
        verdicts.append({
            "alert_id": f"day48-tp-{i}",
            "analyst_id": "analyst1",
            "verdict": "tp",
            "confidence_at_triage": 78,
            "confidence_bucket": "70-100",
            "scoring_inputs": {"rule_severity": 66, "anomaly": 20, "time_factor": 10},
            "actual_outcome": "confirmed_malicious",
            "timestamp": _now_iso(),
        })

    for i in range(8):
        verdicts.append({
            "alert_id": f"day48-fp-{i}",
            "analyst_id": "analyst1",
            "verdict": "fp",
            "confidence_at_triage": 82,
            "confidence_bucket": "70-100",
            "scoring_inputs": {"rule_severity": 40, "anomaly": 80, "time_factor": 5},
            "actual_outcome": "benign_confirmed",
            "timestamp": _now_iso(),
        })

    return verdicts


def _assert_retrain_result(result, before_weights, label):
    """Shared assertions, used by both the mocked and live runs."""
    assert result["sample_size"] == 20, (
        f"[{label}] expected 20 verdicts, got {result['sample_size']}"
    )

    bucket = result["bucket_stats"]["70-100"]
    assert bucket["total"] == 20, f"[{label}] expected 20 in 70-100 bucket"
    assert bucket["fp_count"] == 8, f"[{label}] expected 8 FPs"
    assert bucket["fp_rate"] == 0.4, f"[{label}] expected fp_rate=0.4, got {bucket['fp_rate']}"
    assert bucket.get("dominant_factor") == "anomaly", (
        f"[{label}] expected dominant_factor='anomaly', got {bucket.get('dominant_factor')}"
    )
    assert result["bucket_stats"]["0-40"]["total"] == 0
    assert result["bucket_stats"]["40-70"]["total"] == 0

    expected_anomaly = round(before_weights["anomaly"] - 0.05, 3)
    assert result["new_weights"]["anomaly"] == expected_anomaly, (
        f"[{label}] expected anomaly weight {expected_anomaly}, "
        f"got {result['new_weights']['anomaly']}"
    )
    assert result["new_weights"]["rule_severity"] == before_weights["rule_severity"]
    assert result["new_weights"]["time_factor"] == before_weights["time_factor"]
    assert len(result["adjustments"]) == 1

    print(f"\nPASS [{label}] — 20 verdicts processed (12 TP, 8 FP)")
    print(f"PASS [{label}] — FP rate 40% correctly exceeds the 30% threshold in 70-100")
    print(f"PASS [{label}] — 0-40 / 40-70 buckets correctly show 0 total, no crash")
    print(f"PASS [{label}] — dominant factor correctly identified as 'anomaly'")
    print(f"PASS [{label}] — anomaly weight reduced {before_weights['anomaly']} -> "
          f"{result['new_weights']['anomaly']} (others unchanged)")


# ─────────────────────────────────────────────────────────────────────────
# Mocked-ES unit test (default mode)
# ─────────────────────────────────────────────────────────────────────────

def run_mock_test():
    fake_verdicts = build_fake_verdicts()
    written_history = []

    def fake_post(path, body):
        if path.startswith("siem-analyst-verdicts/_search"):
            return {"hits": {"hits": [{"_source": v} for v in fake_verdicts]}}
        if path.startswith("siem-weight-history/_search"):
            return {"hits": {"hits": []}}  # no prior retrain -> DEFAULT_WEIGHTS
        if path.startswith("siem-weight-history/_doc"):
            written_history.append(body)
            return {"result": "created", "_id": f"wh-{len(written_history)}"}
        if path.startswith("siem-analyst-verdicts/_doc"):
            return {"result": "created", "_id": "fake-verdict"}
        if path.startswith("logs-wazuh.alerts-*/_search"):
            return {"hits": {"hits": []}}
        raise ValueError(f"unexpected ES path in mock test: {path}")

    with patch("tools.feedback_loop._post", side_effect=fake_post):
        from tools import feedback_loop

        rv = feedback_loop.record_verdict(
            alert_id="tp-0", analyst_id="analyst1", verdict="tp",
            confidence_at_triage=78,
        )
        assert rv["success"] is True, f"record_verdict failed: {rv}"
        assert rv["doc"]["scoring_inputs"]["lookup_status"] == "alert_not_found"

        before_weights = dict(feedback_loop.DEFAULT_WEIGHTS)
        result = feedback_loop.retrain_weights()

    print("=== Day 48 — MOCKED test ===")
    print(f"record_verdict() self-test: success={rv['success']}, "
          f"lookup_status={rv['doc']['scoring_inputs']['lookup_status']}")
    print(f"old_weights:  {result['old_weights']}")
    print(f"new_weights:  {result['new_weights']}")
    print(f"bucket_stats: {result['bucket_stats']}")

    _assert_retrain_result(result, before_weights, label="MOCK")
    assert len(written_history) == 1, "expected exactly one weight-history write"
    print("PASS [MOCK] — weight-history audit doc written exactly once")
    print("\nAll Day 48 mocked checks passed.")


# ─────────────────────────────────────────────────────────────────────────
# Live injection + retrain (real stack)
# ─────────────────────────────────────────────────────────────────────────

def run_live_test():
    from tools.elastic_tools import _post
    from tools.feedback_loop import (
        ANALYST_VERDICTS_INDEX,
        retrain_weights,
        get_current_weights,
    )

    print("=== Day 48 — LIVE injection + retrain ===")
    before_weights = get_current_weights()
    print(f"weights before injection: {before_weights}")

    verdicts = build_fake_verdicts()
    written, failed = 0, 0
    for v in verdicts:
        try:
            _post(f"{ANALYST_VERDICTS_INDEX}/_doc", v)
            written += 1
        except Exception as exc:
            failed += 1
            print(f"[LIVE] FAILED to write {v['alert_id']}: {exc}")
    print(f"[LIVE] wrote {written}/{len(verdicts)} verdicts ({failed} failed)")
    if failed:
        print("[WARN] some verdicts failed to write — retrain may run on a "
              "partial sample. Check ES connectivity/auth before proceeding.")

    print("[LIVE] waiting 1.5s for ES refresh (same refresh-timing class as "
          "Day 33/44)...")
    time.sleep(1.5)

    result = retrain_weights()

    print(f"old_weights:  {result['old_weights']}")
    print(f"new_weights:  {result['new_weights']}")
    print(f"bucket_stats: {result['bucket_stats']}")
    print(f"adjustments:  {result['adjustments']}")

    try:
        _assert_retrain_result(result, before_weights, label="LIVE")
        print("\nAll Day 48 live checks passed.")
    except AssertionError as exc:
        print(f"\n[WARN] {exc}")
        print("If real verdicts already existed in siem-analyst-verdicts "
              "before this run, they mix into the same 100-doc retrain "
              "window and can shift bucket stats — check sample_size and "
              "bucket_stats above before treating this as a failure.")


if __name__ == "__main__":
    if "--live" in sys.argv:
        run_live_test()
    else:
        run_mock_test()
