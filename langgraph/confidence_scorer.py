"""
confidence_scorer.py
====================
Maps a raw Wazuh alert dict to a confidence_pct integer (0–100).

This module is the single source of truth for the confidence formula so that
pipeline_runner.py and coordination_agent.py both produce identical scores.

Formula
-------
  Base score  : min(100, int((rule.level / 15) * 100))
  Boost rules :
    +10  if rule.groups contains 'authentication_failed'
    +10  if rule.groups contains 'sshd'
    +5   if rule.level >= 10
    -10  if rule.groups contains 'sca'   (SCA compliance noise — lower urgency)
  Final score is clamped to [0, 100].

Routing tiers (same thresholds used by coordination_agent.py):
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
        A single hit from Elasticsearch, i.e. the ``_source`` field of a
        Wazuh alert document.

    Returns
    -------
    int
        Confidence percentage in [0, 100].
    """
    level: int = _safe_int(alert.get("rule", {}).get("level", 0))
    groups: list[str] = alert.get("rule", {}).get("groups", [])

    # Base score from rule severity level
    base = min(100, int((level / 15) * 100))

    # Contextual boosts / penalties
    boost = 0
    if "authentication_failed" in groups:
        boost += 10
    if "sshd" in groups:
        boost += 10
    if level >= 10:
        boost += 5
    if "sca" in groups:          # SCA compliance alerts are noisy
        boost -= 10

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
    ]

    print(f"{'Description':<40} {'Score':>6}  {'Tier':<16}  {'Expected':<16}  {'OK'}")
    print("-" * 95)
    all_ok = True
    for desc, alert, expected in test_cases:
        pct, t = score_and_tier(alert)
        ok = "✅" if t == expected else "❌"
        if t != expected:
            all_ok = False
        print(f"{desc:<40} {pct:>5}%  {t:<16}  {expected:<16}  {ok}")

    print()
    print("All tests passed ✅" if all_ok else "Some tests FAILED ❌")
