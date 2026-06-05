# hunting_agent.py
# Proactive threat hunting agent — runs after the triage agent.
# Previously a stub (Day 15 skipped). Now implements correlated hunting
# for the T1078 after-hours + new-IP + privilege-escalation pattern.
# Day 19: full implementation (B3 fix)

from datetime import datetime, timezone, timedelta
from tools.elastic_tools import (
    get_alerts_by_src_ip,
    get_user_login_history,
    get_high_severity_alerts,
)


# How far back to look when correlating related events
CORRELATION_WINDOW_MINUTES = 10

# Privilege-escalation rule IDs to look for after a suspicious login
PRIV_ESC_RULE_IDS = {"5402", "5403"}  # sudo to ROOT, first-time sudo


def hunting_node(state: dict) -> dict:
    """
    LangGraph node — proactive hunting on top of what triage already found.

    Runs three hunts in sequence and appends findings to state['notes'].
    Does NOT make a verdict — that stays with the triage agent.
    Sets state['escalate'] = True if a high-confidence hunt pattern fires.

    Hunts implemented:
      Hunt 1 — After-hours + new-IP correlation (T1078)
      Hunt 2 — Privilege escalation within 10 min of suspicious login (T1078/T1059)
      Hunt 3 — Lateral movement: same IP seen on multiple agents (T1021)
    """
    alert  = state.get("alert", {})
    notes  = state.get("notes", [])
    src_ip = alert.get("data", {}).get("srcip", "")
    user   = _extract_username(alert)
    ts     = alert.get("@timestamp", "")

    notes.append("[hunting_agent] starting proactive hunts")

    # ── Hunt 1: After-hours + new IP ──────────────────────────────────────
    # Already partially caught by confidence_scorer; here we verify by
    # looking for corroborating events in the same window.
    after_hours = _is_after_hours(ts)
    if after_hours:
        notes.append(
            "[hunting_agent] Hunt 1: login timestamp is outside business hours"
        )
        # Look for any other suspicious activity from the same IP today
        recent = get_alerts_by_src_ip(src_ip, minutes=60) if src_ip else []
        suspicious_recent = [
            a for a in recent
            if "authentication_failed" in a.get("rule", {}).get("groups", [])
        ]
        if suspicious_recent:
            count = len(suspicious_recent)
            notes.append(
                f"[hunting_agent] Hunt 1 HIT: {count} prior auth failures "
                f"from {src_ip} in last 60 min — escalating"
            )
            state["escalate"] = True
        else:
            notes.append(
                f"[hunting_agent] Hunt 1: no prior failures from {src_ip} — "
                "after-hours login is isolated, not escalating"
            )

    # ── Hunt 2: Privilege escalation within 10 min of login ───────────────
    # If the same user ran sudo shortly after this alert, that's a strong
    # indicator of intentional privilege escalation.
    if user:
        login_history = get_user_login_history(user, days=1)
        priv_esc_events = [
            e for e in login_history
            if str(e.get("rule", {}).get("id", "")) in PRIV_ESC_RULE_IDS
            and _within_window(ts, e.get("@timestamp", ""), CORRELATION_WINDOW_MINUTES)
        ]
        if priv_esc_events:
            notes.append(
                f"[hunting_agent] Hunt 2 HIT: privilege escalation by '{user}' "
                f"within {CORRELATION_WINDOW_MINUTES} min of this login — escalating"
            )
            state["escalate"] = True
            # Tag the MITRE technique if not already set
            if not state.get("technique"):
                state["technique"] = "T1078+T1059"
        else:
            notes.append(
                f"[hunting_agent] Hunt 2: no privilege escalation by '{user}' "
                f"in ±{CORRELATION_WINDOW_MINUTES} min window"
            )

    # ── Hunt 3: Lateral movement — same IP on multiple agents ─────────────
    # If this IP has triggered alerts on more than one Wazuh agent in the
    # last hour, it may be moving laterally through the network.
    if src_ip:
        recent_all = get_alerts_by_src_ip(src_ip, minutes=60)
        agents_seen = {
            a.get("agent", {}).get("name", "")
            for a in recent_all
            if a.get("agent", {}).get("name")
        }
        if len(agents_seen) > 1:
            notes.append(
                f"[hunting_agent] Hunt 3 HIT: {src_ip} seen on multiple agents "
                f"{agents_seen} — possible lateral movement — escalating"
            )
            state["escalate"] = True
            if not state.get("technique"):
                state["technique"] = "T1021"
        else:
            notes.append(
                f"[hunting_agent] Hunt 3: {src_ip} confined to single agent — "
                "no lateral movement detected"
            )

    notes.append("[hunting_agent] hunts complete")
    state["notes"] = notes
    return state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_username(alert: dict) -> str:
    """
    Pull the destination username out of a Wazuh alert.
    Tries data.dstuser first (SSH/PAM), then data.user, then falls back
    to an empty string so callers never receive None.
    """
    data = alert.get("data", {})
    raw  = data.get("dstuser") or data.get("user") or ""
    # Strip uid suffix e.g. "root(uid=0)" → "root"
    return raw.split("(")[0].strip()


def _is_after_hours(ts_str: str) -> bool:
    """
    Return True if the ISO-8601 timestamp falls outside 06:00–22:00 UTC.
    Returns False if the timestamp cannot be parsed (safe default).
    """
    if not ts_str:
        return False
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).astimezone(timezone.utc)
        return not (6 <= dt.hour < 22)
    except (ValueError, TypeError):
        return False


def _within_window(ts_anchor: str, ts_event: str, window_minutes: int) -> bool:
    """
    Return True if ts_event falls within ±window_minutes of ts_anchor.
    Both strings must be ISO-8601. Returns False on parse error.
    """
    try:
        anchor = datetime.fromisoformat(ts_anchor.replace("Z", "+00:00"))
        event  = datetime.fromisoformat(ts_event.replace("Z", "+00:00"))
        delta  = abs((event - anchor).total_seconds())
        return delta <= window_minutes * 60
    except (ValueError, TypeError):
        return False
