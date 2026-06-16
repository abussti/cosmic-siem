"""
confidence_scorer.py
====================
Maps a raw Wazuh alert dict to a confidence_pct integer (0–100).

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
    +15  if data.login_hour outside 06–22   (after-hours — Day 19)
    +10  if data.is_new_ip == True          (new IP boost — Day 19)
    +20  if cti.matched == True             (CTI IOC match — Day 23)
  Final score is clamped to [0, 100].

Routing tiers:
  0–39   → ARCHIVE
  40–70  → ANALYST REVIEW QUEUE
  71–100 → TRIAGE AGENT
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score(alert: dict) -> int:
    """
    Return confidence_pct (int 0–100) for a raw Wazuh alert dict.

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

    # ── Base score from rule severity level ───────────────────────────────────
    base = min(100, int((level / 15) * 100))

    boost = 0

    # ── Standard boosts (Days 1–17) ───────────────────────────────────────────
    if "authentication_failed" in groups:
        boost += 10
    if "sshd" in groups:
        boost += 10
    if level >= 10:
        boost += 5
    if "sca" in groups:
        boost -= 10

    # ── After-hours boost (Day 19) ────────────────────────────────────────────
    login_hour = data.get("login_hour")
    if login_hour is not None:
        h = _safe_int(login_hour)
        if not (6 <= h <= 22):          # outside 06:00–22:00
            boost += 15

    # ── New-IP boost (Day 19) ─────────────────────────────────────────────────
    if data.get("is_new_ip") is True:
        boost += 10

    # ── CTI IOC match boost (Day 23) ─────────────────────────────────────────
    if alert.get("cti.matched") is True:
        boost += 20

    return max(0, min(100, base + boost))


def tier(confidence_pct: int) -> str:
    """Return the routing tier label for a given confidence_pct."""
    if confidence_pct <= 39:
        return "ARCHIVE"
    if confidence_pct <= 70:
        return "ANALYST_REVIEW"
    return "TRIAGE"


def score_and_tier(alert: dict) -> tuple[int, str]:
    """Convenience wrapper — returns (confidence_pct, tier_label)."""
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
    ]

    print(f"{'Description':<45} {'Score':>6}  {'Tier':<16}  {'Expected':<16}  {'OK'}")
    print("-" * 100)
    all_ok = True
    for desc, alert, expected in test_cases:
        pct, t = score_and_tier(alert)
        ok = "✅" if t == expected else "❌"
        if t != expected:
            all_ok = False
        print(f"{desc:<45} {pct:>5}%  {t:<16}  {expected:<16}  {ok}")

    print()
    print("All tests passed ✅" if all_ok else "Some tests FAILED ❌")