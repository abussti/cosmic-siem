"""
confidence_scorer.py
Phase 1 — Week 3, Day 11
Cosmic Info Solutions · Ahmad Bussti

Reads an Elastic/Wazuh alert dict and returns the original alert
with a new 'confidence' field (int 0–100).

Formula:
  confidence = (0.4 × rule_severity_normalised)
             + (0.4 × anomaly_score)
             + (0.2 × time_factor)

Components:
  rule_severity_normalised : Wazuh rule.level (1–15) scaled to 0–100
  anomaly_score            : Elastic ML score (0–100); if absent, inferred
                             from rule level (not a flat 50 default)
  time_factor              : 100 if event is outside 08:00–20:00 LOCAL time,
                             else 50.  Set LOCAL_TZ_OFFSET_HOURS below.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

# ── Timezone config ──────────────────────────────────────────────────────────
# Set this to your local UTC offset so business-hours detection is correct.
# Ajman / Dubai = UTC+4
LOCAL_TZ_OFFSET_HOURS = 4
LOCAL_TZ = timezone(timedelta(hours=LOCAL_TZ_OFFSET_HOURS))

# ── Business hours (local time) ───────────────────────────────────────────────
BUSINESS_HOURS_START = 8   # 08:00 local
BUSINESS_HOURS_END   = 20  # 20:00 local


# ---------------------------------------------------------------------------
# Individual scoring components
# ---------------------------------------------------------------------------

def _severity_score(rule_level: Optional[int]) -> float:
    """Scale Wazuh rule level (1–15) to 0–100. Returns 0 if unknown."""
    if rule_level is None:
        return 0.0
    level = max(1, min(15, int(rule_level)))
    return round((level - 1) / 14 * 100, 2)


def _anomaly_score(ml_score: Optional[float], rule_level: Optional[int]) -> float:
    """
    Return ML anomaly score (0–100).
    If no ML score is present, infer a proxy from rule level rather than
    defaulting to a flat 50 — a level-3 PAM login should not score the same
    as a level-12 brute force on the ML component.

    Inference table (when no ML score):
      level 1–4  → 10   (routine noise)
      level 5–7  → 30   (minor anomaly)
      level 8–10 → 55   (moderate)
      level 11–13 → 75  (significant)
      level 14–15 → 90  (critical)
    """
    if ml_score is not None:
        return round(max(0.0, min(100.0, float(ml_score))), 2)

    # No ML score — infer from rule level
    lvl = int(rule_level) if rule_level is not None else 3
    if lvl <= 4:
        return 10.0
    elif lvl <= 7:
        return 30.0
    elif lvl <= 10:
        return 55.0
    elif lvl <= 13:
        return 75.0
    else:
        return 90.0


def _time_factor(timestamp_str: Optional[str]) -> float:
    """
    Return 100 if the event occurred outside business hours in LOCAL time
    (before BUSINESS_HOURS_START or after BUSINESS_HOURS_END), else 50.
    Falls back to 50 if timestamp is missing or unparseable.
    """
    if not timestamp_str:
        return 50.0
    try:
        ts = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts).astimezone(LOCAL_TZ)
        hour = dt.hour
        is_offhours = (hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END)
        return 100.0 if is_offhours else 50.0
    except (ValueError, AttributeError):
        return 50.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_alert(alert: dict) -> dict:
    """
    Accept an alert dict and return a copy with an added 'confidence' key.

    Expected alert fields (all optional — scorer degrades gracefully):
        rule.level          : int   — Wazuh severity level (1–15)
        ml.anomaly_score    : float — Elastic ML score (0–100)
        @timestamp          : str   — ISO-8601 timestamp
    """
    rule_level  = _get_nested(alert, "rule", "level")
    ml_score    = _get_nested(alert, "ml", "anomaly_score")
    timestamp   = alert.get("@timestamp")

    sev   = _severity_score(rule_level)
    anom  = _anomaly_score(ml_score, rule_level)
    ttime = _time_factor(timestamp)

    raw = (0.4 * sev) + (0.4 * anom) + (0.2 * ttime)
    confidence = int(round(min(100, max(0, raw))))

    result = dict(alert)
    result["confidence"] = confidence
    result["_scoring_detail"] = {
        "rule_severity_normalised": sev,
        "anomaly_score_used": anom,
        "time_factor": ttime,
        "raw_score": round(raw, 2),
    }
    return result


def score_alerts(alerts: list[dict]) -> list[dict]:
    """Score a list of alerts. Returns a list of scored alert dicts."""
    return [score_alert(a) for a in alerts]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_nested(d: dict, *keys):
    """Safely retrieve a nested key, e.g. _get_nested(d, 'rule', 'level')."""
    for key in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


# ---------------------------------------------------------------------------
# CLI — score alerts from a JSON file
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python confidence_scorer.py <alerts.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    alerts_in = data if isinstance(data, list) else [data]
    scored = score_alerts(alerts_in)

    for a in scored:
        print(
            f"[{a.get('rule', {}).get('description', 'unknown')[:50]:<50}] "
            f"level={a.get('rule', {}).get('level', '?'):>2}  "
            f"confidence={a['confidence']:>3}"
        )
