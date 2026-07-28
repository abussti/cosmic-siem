"""
confidence_scorer.py
====================
Maps a raw Wazuh alert dict to a confidence_pct integer (0-100).

Single source of truth for the confidence formula used by both
pipeline_runner.py and coordination_agent.py.

Formula
-------
  Base score  : min(100, int((rule.level / 15) * 100))
  Boost rules :
    +10  if rule.groups contains 'authentication_failed'
    +10  if rule.groups contains 'sshd'
    +5   if rule.level >= 10
    -10  if rule.groups contains 'sca'      (SCA compliance noise)
    +15  if data.login_hour outside 06-22   (after-hours - Day 19)
    +10  if data.is_new_ip == True          (new IP boost - Day 19)
    +20  if cti.matched == True             (CTI IOC match - Day 23)
    +15  if data.bytes_out > 100MB          (large single-event transfer - Day 39)
    +0-20 scaled from the UEBA anomaly score (0-100) -- Day 47
  Final score is clamped to [0, 100].

Routing tiers:
  0-39   -> ARCHIVE
  40-70  -> ANALYST REVIEW QUEUE
  71-100 -> TRIAGE AGENT

Day 39 bug fix
--------------
Phase 2 Scenario 3 testing (phase2-test-results.md) found a 500MB after-hours
outbound transfer scored 78% at this layer (correctly reaching TRIAGE) but the
LLM in triage_agent.py never saw the byte count and returned verdict=unknown,
dropping the effective confidence to 40% and leaving escalate=False. Two
changes close this:
  1. This file now also boosts the score directly when a single event moves
     an unusually large volume of data, so a scorer-only view of the alert
     already reflects the risk (not just the LLM's read of the volume).
  2. triage_agent.py (companion fix) now surfaces data.bytes_out /
     data.bytes_in / data.conn_count directly in the Gemini prompt so the
     verdict itself accounts for it, not just the routing tier.
The threshold (100MB) is deliberately conservative -- tune down if smaller
transfers should also be flagged once real traffic volume is observed in
production.

Day 47 — UEBA anomaly-score boost
----------------------------------
tools/ueba_scorer.py (Day 47) compares the alert's user/entity against the
behavioral profile ueba_engine.py (Day 46) builds nightly, and returns a
transparent 0-100 anomaly_score across 5 named dimensions (login-hour
deviation, source-IP novelty, command rarity, peer-group deviation, volume
spike vs. the user's own baseline). That score is scaled into a 0-20pp
boost here -- the same "additive, inspectable, no black-box" philosophy the
rest of this file already uses.

This boost is deliberately independent of, and can overlap with, the
existing after-hours/new-IP/volume boosts above: those are static rule
thresholds that apply the same way to every alert, while the UEBA boost is
*relative to this specific user's own learned baseline* (e.g. an analyst
who regularly logs in at 3am gets no after-hours-deviation boost here even
though the static after-hours boost above still fires for them). Both are
useful signals and are allowed to stack.

If no UEBA profile exists yet for the entity (new user, or ueba_engine.py
hasn't run), score_anomaly() returns anomaly_score=0 and this boost is
simply 0 -- never a crash, never a penalty for lacking history.
"""

from __future__ import annotations

from tools.ueba_scorer import score_anomaly


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Day 39: single-event outbound transfer size (bytes) that earns a boost.
LARGE_TRANSFER_BYTES_THRESHOLD = 100_000_000  # 100MB

# Day 47: scales the 0-100 UEBA anomaly_score into a 0-20pp scorer boost.
# 0.2 -> anomaly_score=100 contributes the full +20pp; anomaly_score=50
# contributes +10pp. Tune this constant if UEBA signal should carry more
# or less weight relative to the other boosts once real profile data
# accumulates in production.
UEBA_BOOST_SCALE = 0.2


def score(alert: dict, ueba_profile: dict | None = None) -> int:
    """
    Return confidence_pct (int 0-100) for a raw Wazuh alert dict.

    Parameters
    ----------
    alert : dict
        The ``_source`` field of a Wazuh alert document from Elasticsearch.
        Must already be CTI-enriched by pipeline_runner.enrich_with_cti()
        before this is called so that cti.matched is present.
    ueba_profile : dict | None
        [Day 47] Optional pre-fetched UEBA profile (from
        tools.ueba_scorer.get_ueba_profile()). Pass this in if the caller
        already resolved the profile elsewhere in the same cycle (e.g.
        triage_agent.py) to avoid a second Elasticsearch round-trip. If
        omitted, score_anomaly() resolves it itself from data.dstuser.

    Returns
    -------
    int
        Confidence percentage in [0, 100].
    """
    rule  = alert.get("rule", {})
    data  = alert.get("data", {})

    level: int       = _safe_int(rule.get("level", 0))
    groups: list[str] = rule.get("groups", [])

    # -- Base score from rule severity level -----------------------------------
    base = min(100, int((level / 15) * 100))

    boost = 0

    # -- Standard boosts (Days 1-17) --------------------------------------------
    if "authentication_failed" in groups:
        boost += 10
    if "sshd" in groups:
        boost += 10
    if level >= 10:
        boost += 5
    if "sca" in groups:
        boost -= 10

    # -- After-hours boost (Day 19) ----------------------------------------------
    login_hour = data.get("login_hour")
    if login_hour is not None:
        h = _safe_int(login_hour)
        if not (6 <= h <= 22):          # outside 06:00-22:00
            boost += 15

    # -- New-IP boost (Day 19) ----------------------------------------------------
    if data.get("is_new_ip") is True:
        boost += 10

    # -- CTI IOC match boost (Day 23) ---------------------------------------------
    if alert.get("cti.matched") is True:
        boost += 20

    # -- Large single-event transfer boost (Day 39) --------------------------------
    bytes_out = data.get("bytes_out")
    if bytes_out is not None:
        bytes_out_int = _safe_int(bytes_out)
        if bytes_out_int > LARGE_TRANSFER_BYTES_THRESHOLD:
            boost += 15

    # -- UEBA anomaly-score boost (Day 47) ------------------------------------------
    # Never allowed to crash scoring -- a UEBA lookup/query failure (missing
    # profile, ES hiccup, etc.) degrades to anomaly_score=0 / boost=0,
    # exactly like every other tool in this project degrades on failure
    # rather than raising.
    try:
        ueba_result = score_anomaly(alert, profile=ueba_profile)
        anomaly_score = ueba_result["anomaly_score"]
        boost += int(anomaly_score * UEBA_BOOST_SCALE)
    except Exception:
        pass

    return max(0, min(100, base + boost))


def score_verbose(alert: dict, ueba_profile: dict | None = None) -> dict:
    """
    [Day 47] Same as score(), but also returns the UEBA breakdown so
    callers (pipeline_runner.py logging, analyst-facing tooling) can see
    exactly which of the 5 UEBA dimensions fired, without recomputing the
    anomaly score a second time. Never raises.
    """
    try:
        ueba_result = score_anomaly(alert, profile=ueba_profile)
    except Exception as e:
        ueba_result = {"anomaly_score": 0, "breakdown": {}, "profile_used": False,
                        "error": str(e)}
    return {
        "confidence_pct": score(alert, ueba_profile=ueba_profile),
        "ueba_anomaly_score": ueba_result.get("anomaly_score", 0),
        "ueba_breakdown": ueba_result.get("breakdown", {}),
        "ueba_profile_used": ueba_result.get("profile_used", False),
    }


def tier(confidence_pct: int) -> str:
    """Return the routing tier label for a given confidence_pct."""
    if confidence_pct <= 39:
        return "ARCHIVE"
    if confidence_pct <= 70:
        return "ANALYST_REVIEW"
    return "TRIAGE"


def score_and_tier(alert: dict, ueba_profile: dict | None = None) -> tuple[int, str]:
    """Convenience wrapper -- returns (confidence_pct, tier_label)."""
    pct = score(alert, ueba_profile=ueba_profile)
    return pct, tier(pct)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Quick self-test (run directly: python3 confidence_scorer.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_cases = [
        # (description, alert_dict, expected_tier)
        (
            "SSH brute force level=10",
            {"rule": {"level": 10, "groups": ["syslog", "sshd", "authentication_failed"]}},
            "TRIAGE",
        ),
        (
            "SCA compliance level=5",
            {"rule": {"level": 5, "groups": ["sca"]}},
            "ARCHIVE",
        ),
        (
            "PAM login level=6",
            {"rule": {"level": 6, "groups": ["pam", "authentication_success"]}},
            "ANALYST_REVIEW",
        ),
        (
            "High severity level=13",
            {"rule": {"level": 13, "groups": ["high"]}},
            "TRIAGE",
        ),
        (
            "Low noise level=1",
            {"rule": {"level": 1, "groups": ["ossec"]}},
            "ARCHIVE",
        ),
        (
            "After-hours login level=8 (T1078)",
            {
                "rule": {"level": 8, "groups": ["pam", "authentication_success"]},
                "data": {"login_hour": 2, "is_new_ip": True},
            },
            "TRIAGE",                        # 53 base + 15 after-hours + 10 new-IP = 78%
        ),
        (
            "Known-bad IP (CTI match) level=6",
            {
                "rule": {"level": 6, "groups": ["sshd", "authentication_failed"]},
                "cti.matched": True,
                "cti.confidence": 85,
            },
            "TRIAGE",                        # 40 base + 10 auth_failed + 10 sshd + 20 CTI = 80%
        ),
        (
            "Day 39: after-hours 500MB exfil, level=8 (Scenario 3 regression test)",
            {
                "rule": {"level": 8, "groups": ["firewall"]},
                "data": {"login_hour": 3, "is_new_ip": True, "bytes_out": 500_000_000},
            },
            "TRIAGE",                        # 53 base + 15 after-hours + 10 new-IP + 15 volume = 93%
        ),
        (
            "Day 39: small transfer, no boost expected",
            {
                "rule": {"level": 8, "groups": ["firewall"]},
                "data": {"bytes_out": 5_000_000},   # 5MB, well under threshold
            },
            "ANALYST_REVIEW",                # 53 base, no boosts -> stays in review tier
        ),
    ]

    print(f"{'Description':<55} {'Score':>6}  {'Tier':<16}  {'Expected':<16}  {'OK'}")
    print("-" * 110)
    all_ok = True
    for desc, alert, expected in test_cases:
        # No UEBA profile exists for any of these synthetic test users in a
        # fresh environment, so score_anomaly() resolves anomaly_score=0
        # and these cases are unaffected by the Day 47 boost -- confirms
        # the new boost doesn't change pre-existing behaviour by default.
        pct, t = score_and_tier(alert)
        ok = "✅" if t == expected else "❌"
        if t != expected:
            all_ok = False
        print(f"{desc:<55} {pct:>5}%  {t:<16}  {expected:<16}  {ok}")

    print()
    print("All tests passed ✅" if all_ok else "Some tests FAILED ❌")

    # -- Day 47: UEBA boost wiring check (explicit profile, no ES needed) ------
    print()
    print("=== Day 47 — UEBA boost wiring check (explicit profile, bypasses ES) ===")
    elevated_profile = {
        "typical_login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        "typical_source_ips": ["198.51.100.10"],
        "typical_commands": ["ls"],
        "peer_group": "engineering",
        "risk_score": 55,
        "source_ip_coverage": "ok",
        "volume_field_coverage": "ok",
        "avg_outbound_bytes_per_day": 1_000_000,
    }
    ueba_test_alert = {
        "rule": {"level": 5, "groups": ["pam", "authentication_success"]},
        "data": {"srcip": "203.0.113.250", "dstuser": "devadmin", "login_hour": 3},
    }
    baseline_pct = score(ueba_test_alert)  # no profile -> anomaly boost = 0
    boosted_pct  = score(ueba_test_alert, ueba_profile=elevated_profile)
    detail       = score_verbose(ueba_test_alert, ueba_profile=elevated_profile)
    print(f"  Without UEBA profile : {baseline_pct}%")
    print(f"  With elevated profile: {boosted_pct}%  "
          f"(ueba_anomaly_score={detail['ueba_anomaly_score']}/100)")
    assert boosted_pct > baseline_pct, "expected the UEBA-boosted score to exceed the baseline"
    print("  PASS — UEBA anomaly score is correctly increasing confidence_pct")
