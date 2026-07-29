"""
tools/feedback_loop.py — Day 48: Analyst Feedback Loop

Captures every analyst verdict (true positive / false positive / needs
investigation) from the SOC dashboard and uses accumulated verdicts to
retrain confidence-scoring weights. This is the "feedback loop" arrow in
the architecture diagram — analyst decisions flow back to the AI triage
engine instead of disappearing once a case is closed.

Follows this project's standing conventions:
  - all ES access goes through the existing _post() helper
    (tools/elastic_tools.py) — no separate ES client introduced
  - every public function is designed to never raise; ES/data errors
    degrade to a safe, logged/returned fallback instead of crashing a
    caller (same convention as ueba_scorer.py, hunt_summarizer.py, etc.)
  - weight adjustments are transparent/additive (same philosophy as
    confidence_scorer.py and ueba_engine.py's risk_score) — no black-box
    ML; every adjustment is inspectable and traceable to a specific
    bucket's FP rate and dominant factor
"""

import datetime
from collections import defaultdict

from tools.elastic_tools import _post

ANALYST_VERDICTS_INDEX = "siem-analyst-verdicts"
WEIGHT_HISTORY_INDEX = "siem-weight-history"
ALERTS_INDEX_PATTERN = "logs-wazuh.alerts-*"

VALID_VERDICTS = {"tp", "fp", "needs_review"}

# Starting weights for the 3 confidence factors this loop tunes. These are
# a simplified, named decomposition of confidence_scorer.py's existing
# boosts, purpose-built for retraining:
#   rule_severity -> base score derived from rule.level
#   anomaly       -> UEBA anomaly-score boost (Day 47)
#   time_factor   -> after-hours / new-IP boost (Day 19)
DEFAULT_WEIGHTS = {
    "rule_severity": 0.40,
    "anomaly": 0.35,
    "time_factor": 0.25,
}

CONFIDENCE_BUCKETS = [(0, 40), (40, 70), (70, 100)]
FP_RATE_THRESHOLD = 0.30
WEIGHT_STEP = 0.05
MIN_WEIGHT = 0.05
RETRAIN_SAMPLE_SIZE = 100


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _bucket_for(confidence_pct):
    for lo, hi in CONFIDENCE_BUCKETS:
        if (lo <= confidence_pct < hi) or (hi == 100 and confidence_pct == 100):
            return f"{lo}-{hi}"
    return "unknown"


def _get_alert_scoring_inputs(alert_id):
    """
    Looks up the original alert doc by ES _id and extracts a simplified
    3-factor breakdown used by this feedback loop. Never raises — returns
    an all-zero breakdown with a 'lookup_status' flag on any ES error or
    missing doc, so record_verdict() can still write the verdict itself
    even if the source alert can't be found (e.g. it's aged out of the
    index, or alert_id was a synthetic/hunt-originated alert with no
    backing doc — same gap Day 29 flagged for triage on synthetic alerts).
    """
    try:
        body = {"query": {"term": {"_id": alert_id}}, "size": 1}
        resp = _post(f"{ALERTS_INDEX_PATTERN}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return {
                "rule_severity": 0.0,
                "anomaly": 0.0,
                "time_factor": 0.0,
                "lookup_status": "alert_not_found",
            }

        src = hits[0].get("_source", {})

        rule_level = src.get("rule", {}).get("level", 0) or 0
        rule_severity = round(min(100, (rule_level / 15) * 100), 2)

        anomaly = src.get("ueba", {}).get("anomaly_score")
        anomaly = float(anomaly) if isinstance(anomaly, (int, float)) else 0.0

        login_hour = src.get("data", {}).get("login_hour")
        is_new_ip = bool(src.get("data", {}).get("is_new_ip", False))
        time_factor = 0.0
        if isinstance(login_hour, (int, float)) and not (6 <= login_hour <= 22):
            time_factor += 15.0
        if is_new_ip:
            time_factor += 10.0

        return {
            "rule_severity": rule_severity,
            "anomaly": anomaly,
            "time_factor": time_factor,
            "lookup_status": "ok",
        }
    except Exception as exc:
        return {
            "rule_severity": 0.0,
            "anomaly": 0.0,
            "time_factor": 0.0,
            "lookup_status": f"lookup_failed: {exc}",
        }


def record_verdict(alert_id, analyst_id, verdict, confidence_at_triage=None,
                    actual_outcome=None):
    """
    Records one analyst verdict against an alert.

    If confidence_at_triage isn't supplied by the caller (e.g. the
    dashboard doesn't already have it in hand), it and the alert's
    scoring-input breakdown are looked up from the original alert doc via
    _get_alert_scoring_inputs(). Never raises — returns
    {'success': False, ...} on any failure rather than propagating, same
    convention as write_hunt_result_to_es()/write_response_log_entry().
    """
    verdict = (verdict or "").lower().strip()
    if verdict not in VALID_VERDICTS:
        return {
            "success": False,
            "error": f"invalid verdict '{verdict}' — must be one of {sorted(VALID_VERDICTS)}",
        }

    scoring_inputs = _get_alert_scoring_inputs(alert_id)

    if confidence_at_triage is None:
        confidence_at_triage = round(
            scoring_inputs.get("rule_severity", 0)
            + scoring_inputs.get("anomaly", 0)
            + scoring_inputs.get("time_factor", 0),
            2,
        )
        confidence_at_triage = max(0, min(100, confidence_at_triage))

    doc = {
        "alert_id": alert_id,
        "analyst_id": analyst_id,
        "verdict": verdict,
        "confidence_at_triage": confidence_at_triage,
        "confidence_bucket": _bucket_for(confidence_at_triage),
        "scoring_inputs": scoring_inputs,
        "actual_outcome": actual_outcome,
        "timestamp": _now_iso(),
    }

    try:
        resp = _post(f"{ANALYST_VERDICTS_INDEX}/_doc", doc)
        return {"success": True, "doc": doc, "detail": resp}
    except Exception as exc:
        return {"success": False, "error": str(exc), "doc": doc}


def get_current_weights():
    """
    Returns the most recently retrained weight set, or DEFAULT_WEIGHTS if
    no retrain has ever run yet (i.e. siem-weight-history is empty).
    Never raises.
    """
    try:
        body = {"size": 1, "sort": [{"timestamp": "desc"}]}
        resp = _post(f"{WEIGHT_HISTORY_INDEX}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return dict(DEFAULT_WEIGHTS)
        return hits[0]["_source"].get("new_weights", dict(DEFAULT_WEIGHTS))
    except Exception:
        return dict(DEFAULT_WEIGHTS)


def _get_recent_verdicts(size=RETRAIN_SAMPLE_SIZE):
    try:
        body = {"size": size, "sort": [{"timestamp": "desc"}]}
        resp = _post(f"{ANALYST_VERDICTS_INDEX}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception:
        return []


def _dominant_factor(fp_verdicts):
    """
    Given a list of FP-verdict records (each carrying a 'scoring_inputs'
    breakdown), returns the factor name with the highest average value —
    i.e. the factor most responsible for pushing these false positives
    into their confidence bucket in the first place. Returns None if no
    usable scoring_inputs are present on any of them.
    """
    totals = defaultdict(float)
    counts = defaultdict(int)
    for v in fp_verdicts:
        inputs = v.get("scoring_inputs", {}) or {}
        for factor in DEFAULT_WEIGHTS:
            val = inputs.get(factor)
            if isinstance(val, (int, float)):
                totals[factor] += val
                counts[factor] += 1
    averages = {f: totals[f] / counts[f] for f in totals if counts[f] > 0}
    if not averages:
        return None
    return max(averages, key=averages.get)


def retrain_weights():
    """
    Pulls the last RETRAIN_SAMPLE_SIZE analyst verdicts, computes the
    false-positive rate per confidence bucket (0-40 / 40-70 / 70-100),
    and — for any bucket whose FP rate exceeds FP_RATE_THRESHOLD (30%) —
    reduces the weight of that bucket's dominant contributing factor by
    WEIGHT_STEP (0.05), floored at MIN_WEIGHT. Writes an audit entry to
    siem-weight-history with the before/after weights and the bucket
    stats that drove the decision, whether or not anything changed this
    cycle. Never raises.
    """
    verdicts = _get_recent_verdicts()
    old_weights = get_current_weights()
    new_weights = dict(old_weights)

    bucket_stats = {}
    adjustments = []

    by_bucket = defaultdict(list)
    for v in verdicts:
        by_bucket[v.get("confidence_bucket", "unknown")].append(v)

    for lo, hi in CONFIDENCE_BUCKETS:
        bucket_key = f"{lo}-{hi}"
        bucket_verdicts = by_bucket.get(bucket_key, [])
        total = len(bucket_verdicts)
        fp_verdicts = [v for v in bucket_verdicts if v.get("verdict") == "fp"]
        fp_count = len(fp_verdicts)
        fp_rate = round(fp_count / total, 3) if total else 0.0

        bucket_stats[bucket_key] = {
            "total": total,
            "fp_count": fp_count,
            "fp_rate": fp_rate,
        }

        if total == 0 or fp_rate <= FP_RATE_THRESHOLD:
            continue

        dominant = _dominant_factor(fp_verdicts)
        if dominant is None:
            continue

        before = new_weights.get(dominant, DEFAULT_WEIGHTS.get(dominant, 0.0))
        after = max(MIN_WEIGHT, round(before - WEIGHT_STEP, 3))
        new_weights[dominant] = after

        bucket_stats[bucket_key]["dominant_factor"] = dominant
        adjustments.append({
            "bucket": bucket_key,
            "factor": dominant,
            "before": before,
            "after": after,
            "reason": f"fp_rate={fp_rate} > {FP_RATE_THRESHOLD} in bucket {bucket_key}",
        })

    history_doc = {
        "old_weights": old_weights,
        "new_weights": new_weights,
        "bucket_stats": bucket_stats,
        "adjustments": adjustments,
        "sample_size": len(verdicts),
        "timestamp": _now_iso(),
    }

    try:
        resp = _post(f"{WEIGHT_HISTORY_INDEX}/_doc", history_doc)
        history_doc["_write_detail"] = resp
    except Exception as exc:
        history_doc["_write_detail"] = {"success": False, "error": str(exc)}

    return history_doc


def run_daily_retrain():
    """Entry point for the scheduler — runs one retrain cycle and prints a summary."""
    result = retrain_weights()
    print(f"[feedback_loop] retrain complete — sample_size={result['sample_size']}")
    print(f"[feedback_loop] old_weights={result['old_weights']}")
    print(f"[feedback_loop] new_weights={result['new_weights']}")
    if result["adjustments"]:
        for adj in result["adjustments"]:
            print(f"[feedback_loop]   adjusted {adj['factor']}: "
                  f"{adj['before']} -> {adj['after']} ({adj['reason']})")
    else:
        print("[feedback_loop]   no adjustments this cycle")
    return result


def start_scheduler(hour=22, minute=0):
    """
    Starts a daily APScheduler job at the given hour:minute (default
    22:00 UTC — after a typical analyst shift ends), same pattern as
    profile_scheduler.py (Day 46) / feed_manager.py (Day 21).
    """
    from apscheduler.schedulers.blocking import BlockingScheduler

    scheduler = BlockingScheduler()
    scheduler.add_job(run_daily_retrain, "cron", hour=hour, minute=minute)
    print(f"[feedback_loop] scheduler started — daily retrain at {hour:02d}:{minute:02d} UTC")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("[feedback_loop] scheduler stopped")


if __name__ == "__main__":
    import sys

    if "--schedule" in sys.argv:
        start_scheduler()
    else:
        # --once, or no flag at all: run a single retrain cycle
        run_daily_retrain()
