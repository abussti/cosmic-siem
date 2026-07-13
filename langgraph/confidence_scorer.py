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
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Day 39: single-event outbound transfer size (bytes) that earns a boost.
LARGE_TRANSFER_BYTES_THRESHOLD = 100_000_000  # 100MB


def score(alert: dict) -> int:
    """
    Return confidence_pct (int 0-100) for a raw Wazuh alert dict.

    Parameters
    ----------
    alert : dict
        The ``_source`` field of a Wazuh alert document from Elasticsearch.
        Must already be CTI-enriched by pipeline_runner.enrich_with_cti()
        before this is called so that cti.matched is present.

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

    return max(0, min(100, base + boost))


def tier(confidence_pct: int) -> str:
    """Return the routing tier label for a given confidence_pct."""
    if confidence_pct <= 39:
        return "ARCHIVE"
    if confidence_pct <= 70:
        return "ANALYST_REVIEW"
    return "TRIAGE"


def score_and_tier(alert: dict) -> tuple[int, str]:
    """Convenience wrapper -- returns (confidence_pct, tier_label)."""
    pct = score(alert)
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
        pct, t = score_and_tier(alert)
        ok = "✅" if t == expected else "❌"
        if t != expected:
            all_ok = False
        print(f"{desc:<55} {pct:>5}%  {t:<16}  {expected:<16}  {ok}")

    print()
    print("All tests passed ✅" if all_ok else "Some tests FAILED ❌")
