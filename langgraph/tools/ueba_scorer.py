"""
tools/ueba_scorer.py — Day 47

UEBA Anomaly Scoring Engine.

Compares an incoming alert's user/entity behavior against the profile
built by tools/ueba_engine.py (Day 46) and produces a 0-100 anomaly
score, broken into 5 independently-inspectable dimensions (0-20 each) —
same "transparent, additive, no black-box ML" philosophy already used
by confidence_scorer.py and ueba_engine.py's own risk_score.

Never raises. Any missing profile / missing field / query failure
degrades that one dimension to a 0-contribution neutral score with a
recorded reason, rather than crashing the pipeline — same convention as
every other tool in this project (hunt_summarizer.py, redteam_reporter.py,
ueba_engine.py, run_hunt(), etc.).
"""

import datetime
import json
import re

from tools.elastic_tools import _post

UEBA_INDEX = "siem-ueba-profiles"

DIMENSION_WEIGHT = 20  # each of the 5 dimensions maxes out at 20pp
NUM_DIMENSIONS = 5
MAX_SCORE = DIMENSION_WEIGHT * NUM_DIMENSIONS  # 100

VOLUME_SPIKE_MULTIPLIER = 5  # 5x daily average -> full volume_spike score


# ─────────────────────────────────────────────────────────────────────────
# Profile lookup
# ─────────────────────────────────────────────────────────────────────────

def get_ueba_profile(entity_type: str, entity_id: str):
    """
    Fetch the most recent UEBA profile for a given entity from
    siem-ueba-profiles. Returns the parsed profile_json dict, or None if
    no profile exists yet (new user/host, or the engine hasn't run for
    it). Never raises.
    """
    if not entity_id or entity_id in ("unknown", "none", None):
        return None
    try:
        body = {
            "size": 1,
            "sort": [{"last_updated": "desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"entity_type": entity_type}},
                        {"term": {"entity_id": entity_id}},
                    ]
                }
            },
        }
        raw = _post(f"{UEBA_INDEX}/_search", body)
        hits = raw.get("hits", {}).get("hits", [])
        if not hits:
            return None
        source = hits[0]["_source"]
        profile = source.get("profile_json")
        if isinstance(profile, str):
            profile = json.loads(profile)
        return profile
    except Exception as e:
        print(f"[ueba_scorer] get_ueba_profile error (non-fatal): {e}")
        return None


def _clean_username(dstuser) -> str | None:
    """
    Strips the "(uid=0)"-style decoration Wazuh adds to some dstuser
    values before profile lookup. Same bug class Day 46 (ueba_engine.py
    bug #2) found and fixed with a prefix-match query -- here we simply
    normalise before an exact-match lookup, same effect.
    """
    if not dstuser:
        return None
    cleaned = re.sub(r"\(.*?\)", "", str(dstuser)).strip()
    return cleaned or None


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

def _extract_login_hour(alert: dict):
    """
    Prefer the scorer-convenience data.login_hour field (Day 19); fall
    back to deriving the hour from @timestamp (same fallback
    ueba_engine.py uses per Day 46 bug #3) so this also works on raw
    alerts that never got the convenience field stamped on.
    """
    data = alert.get("data", {}) or {}
    if "login_hour" in data:
        try:
            return int(data["login_hour"])
        except (TypeError, ValueError):
            pass
    ts = alert.get("@timestamp")
    if ts:
        try:
            dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.hour
        except Exception:
            return None
    return None


def _extract_command(alert: dict):
    data = alert.get("data", {}) or {}
    for key in ("command", "cmd", "argv", "process"):
        if key in data and data[key]:
            return str(data[key])
    return alert.get("rule", {}).get("description") or None


# ─────────────────────────────────────────────────────────────────────────
# Per-dimension scorers (each returns (score 0-20, reason str))
# ─────────────────────────────────────────────────────────────────────────

def _score_login_time_deviation(alert: dict, profile: dict) -> tuple:
    if not profile:
        return 0, "no_profile"
    typical_hours = profile.get("typical_login_hours") or []
    hour = _extract_login_hour(alert)
    if hour is None:
        return 0, "no_login_hour_on_alert"
    if not typical_hours:
        return 0, "no_typical_hours_in_profile"
    if hour in typical_hours:
        return 0, f"hour={hour} is within typical_login_hours"
    nearest_dist = min(min(abs(hour - h), 24 - abs(hour - h)) for h in typical_hours)
    if nearest_dist >= 3:
        return DIMENSION_WEIGHT, f"hour={hour} is {nearest_dist}h from nearest typical hour"
    if nearest_dist >= 1:
        partial = int(DIMENSION_WEIGHT * (nearest_dist / 3))
        return partial, f"hour={hour} is {nearest_dist}h from nearest typical hour (partial)"
    return 0, f"hour={hour} is adjacent to a typical hour"


def _score_source_ip_novelty(alert: dict, profile: dict) -> tuple:
    srcip = (alert.get("data", {}) or {}).get("srcip")
    if not srcip or srcip == "unknown":
        return 0, "no_srcip_on_alert"
    if not profile:
        return DIMENSION_WEIGHT, "no_profile - treating IP as novel"
    typical_ips = profile.get("typical_source_ips") or []
    coverage = profile.get("source_ip_coverage")
    if coverage not in (None, "ok", "ok_via_other_rule_types"):
        # e.g. "no_logins_matched" -- no reliable IP baseline to compare against
        return 0, f"source_ip_coverage={coverage} - skipping, no reliable baseline"
    if srcip in typical_ips[:5]:
        return 0, f"{srcip} is in top-5 typical_source_ips"
    if srcip in typical_ips:
        return int(DIMENSION_WEIGHT * 0.25), f"{srcip} is known but outside top-5 typical IPs"
    return DIMENSION_WEIGHT, f"{srcip} never seen in profile"


def _score_command_rarity(alert: dict, profile: dict) -> tuple:
    command = _extract_command(alert)
    if not command:
        return 0, "no_command_on_alert"
    if not profile:
        return DIMENSION_WEIGHT, "no_profile - treating command as rare"
    typical_commands = profile.get("typical_commands") or []
    if not typical_commands:
        return 0, "no_typical_commands_in_profile"
    normalized_typical = [str(c).strip().lower() for c in typical_commands]
    if command.strip().lower() in normalized_typical:
        return 0, f"'{command}' is in typical_commands"
    return DIMENSION_WEIGHT, f"'{command}' not in user's typical top-20 commands"


def _score_peer_deviation(alert: dict, profile: dict) -> tuple:
    """
    Reuses ueba_engine.py's own additive risk_score (Day 46) as the peer
    baseline signal rather than re-deriving peer statistics here. Real
    per-peer-group z-scoring is tracked as a Phase 3 backlog item (Day 46
    open follow-ups, P2) once enough profile history accumulates.
    """
    if not profile:
        return 0, "no_profile"
    peer_group = profile.get("peer_group", "unassigned")
    risk_score = profile.get("risk_score")
    if risk_score is None:
        return 0, "no_risk_score_in_profile"
    if peer_group == "unassigned":
        score = int(DIMENSION_WEIGHT * 0.5) if risk_score >= 50 else 0
        return score, f"peer_group=unassigned, risk_score={risk_score}"
    if risk_score >= 50:
        return DIMENSION_WEIGHT, f"peer_group={peer_group}, risk_score={risk_score} (>=50)"
    if risk_score >= 25:
        return int(DIMENSION_WEIGHT * 0.5), f"peer_group={peer_group}, risk_score={risk_score} (>=25)"
    return 0, f"peer_group={peer_group}, risk_score={risk_score}"


def _score_volume_spike(alert: dict, profile: dict) -> tuple:
    bytes_out = (alert.get("data", {}) or {}).get("bytes_out")
    if bytes_out in (None, ""):
        return 0, "no_bytes_out_on_alert"
    try:
        bytes_out = float(bytes_out)
    except (TypeError, ValueError):
        return 0, "bytes_out_not_numeric"
    if not profile:
        return 0, "no_profile"
    coverage = profile.get("volume_field_coverage")
    avg_bytes = profile.get("avg_outbound_bytes_per_day")
    if coverage not in (None, "ok") or not avg_bytes:
        return 0, f"volume_field_coverage={coverage} - no reliable baseline"
    ratio = bytes_out / avg_bytes if avg_bytes else 0
    if ratio >= VOLUME_SPIKE_MULTIPLIER:
        return DIMENSION_WEIGHT, f"bytes_out={bytes_out:.0f} is {ratio:.1f}x daily average"
    if ratio >= (VOLUME_SPIKE_MULTIPLIER / 2):
        return int(DIMENSION_WEIGHT * 0.5), f"bytes_out={bytes_out:.0f} is {ratio:.1f}x daily average (partial)"
    return 0, f"bytes_out={bytes_out:.0f} is {ratio:.1f}x daily average"


# ─────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────

def score_anomaly(alert: dict, profile: dict = None) -> dict:
    """
    Returns:
    {
        "anomaly_score": int (0-100),
        "breakdown": {
            "login_time_deviation": {"score": int, "reason": str},
            "source_ip_novelty":    {"score": int, "reason": str},
            "command_rarity":       {"score": int, "reason": str},
            "peer_deviation":       {"score": int, "reason": str},
            "volume_spike":         {"score": int, "reason": str},
        },
        "profile_used": bool,
    }

    If `profile` isn't passed in, looks it up automatically via
    get_ueba_profile("user", <cleaned data.dstuser>) -- the username is
    stripped of any "(uid=0)"-style decoration first (same normalisation
    class as Day 46's dstuser bug fix in ueba_engine.py). Never raises --
    a failure in any one dimension scores that dimension 0 with the error
    recorded as the reason, rather than crashing the whole pass.
    """
    if profile is None:
        dstuser = (alert.get("data", {}) or {}).get("dstuser")
        clean_user = _clean_username(dstuser)
        profile = get_ueba_profile("user", clean_user) if clean_user else None

    dimensions = {
        "login_time_deviation": _score_login_time_deviation,
        "source_ip_novelty": _score_source_ip_novelty,
        "command_rarity": _score_command_rarity,
        "peer_deviation": _score_peer_deviation,
        "volume_spike": _score_volume_spike,
    }

    breakdown = {}
    total = 0
    for name, fn in dimensions.items():
        try:
            score, reason = fn(alert, profile)
        except Exception as e:
            score, reason = 0, f"error (non-fatal): {e}"
        score = max(0, min(DIMENSION_WEIGHT, int(score)))
        breakdown[name] = {"score": score, "reason": reason}
        total += score

    return {
        "anomaly_score": max(0, min(MAX_SCORE, total)),
        "breakdown": breakdown,
        "profile_used": profile is not None,
    }


if __name__ == "__main__":
    # Day 47 deliverable #11: after-hours login from a new IP against a
    # normal-hours profile should score > 60.
    fake_profile = {
        "typical_login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        "typical_source_ips": ["198.51.100.10", "198.51.100.11", "198.51.100.12"],
        "typical_commands": ["ls", "cat /var/log/auth.log", "sudo systemctl status"],
        "peer_group": "engineering",
        "risk_score": 55,  # already flagged as moderately elevated by ueba_engine.py
        "source_ip_coverage": "ok",
        "volume_field_coverage": "ok",
        "avg_outbound_bytes_per_day": 1_000_000,
    }

    test_alert = {
        "@timestamp": "2026-07-28T03:14:00Z",
        "rule": {"id": "5501", "level": 5, "description": "PAM: Login session opened."},
        "agent": {"name": "agent1"},
        "data": {
            "srcip": "203.0.113.250",       # never seen in profile
            "dstuser": "devadmin(uid=0)",   # decorated -- exercises _clean_username too
            "login_hour": 3,                # well outside typical 08-17
        },
    }

    result = score_anomaly(test_alert, fake_profile)
    print("=== Day 47 self-test: after-hours login, new IP ===")
    print(json.dumps(result, indent=2))
    assert result["anomaly_score"] > 60, (
        f"expected anomaly_score > 60, got {result['anomaly_score']}"
    )
    print(f"\nPASS - anomaly_score={result['anomaly_score']} > 60")

    # Sanity check: a normal-looking alert should score low
    normal_profile = dict(fake_profile)
    normal_profile["risk_score"] = 20
    normal_profile["typical_commands"] = fake_profile["typical_commands"] + [
        "PAM: Login session opened."
    ]
    normal_alert = {
        "@timestamp": "2026-07-28T10:00:00Z",
        "rule": {"id": "5501", "level": 3, "description": "PAM: Login session opened."},
        "agent": {"name": "agent1"},
        "data": {
            "srcip": "198.51.100.10",
            "dstuser": "devadmin",
            "login_hour": 10,
        },
    }
    normal_result = score_anomaly(normal_alert, normal_profile)
    print("\n=== Sanity check: normal-hours login, known IP ===")
    print(json.dumps(normal_result, indent=2))
    assert normal_result["anomaly_score"] < 30, (
        f"expected low anomaly_score for normal behavior, got {normal_result['anomaly_score']}"
    )
    print(f"\nPASS - anomaly_score={normal_result['anomaly_score']} < 30 (normal behavior)")
