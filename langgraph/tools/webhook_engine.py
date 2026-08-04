"""
tools/webhook_engine.py  —  Day 53

Forwards triage/response results to external notification channels
(Slack, Microsoft Teams, email, arbitrary custom webhook) based on each
tenant's own notification_rules, stored on their tenant_config document
(multi_tenant.tenant_manager, Day 51).

Design conventions carried over from the rest of this project:
  - No new HTTP client library — plain `requests`, same as elastic_tools.py
    / response_tools.py / tenant_manager.py.
  - Never raises out of send_notifications(). Every channel send is
    independently wrapped; one channel failing (bad webhook URL, SMTP
    down, rate limit) never blocks the others or the caller.
  - Every attempt — success or failure — is logged to a new
    `siem-notification-log` index via the shared `_post()` helper in
    elastic_tools.py, same "log everything, including failures" discipline
    already established for siem-response-log (Day 31) and
    siem-redteam-log (Day 41).
  - Per-tenant config comes from tenant_manager.get_tenant_config() —
    no new config store. A tenant with no notification_rules configured
    simply gets no notifications (fails safe/quiet, not loud).
"""

from __future__ import annotations

import datetime
import json
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import requests

from tools.elastic_tools import _post  # shared requests-based ES helper

NOTIFICATION_LOG_INDEX = "siem-notification-log"

# Same severity banding confidence_scorer.py / coordination_agent.py
# already use for tiering (ARCHIVE / REVIEW / TRIAGE), extended one step
# further so notification rules can target "critical" (red-team-confirmed
# exploitable / insider-threat-tier findings) separately from "high".
SEVERITY_THRESHOLDS = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (0, "low"),
]

DEFAULT_TIMEOUT_SECONDS = 8
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", "siem-alerts@cosmic-info-solutions.local")
SOC_DASHBOARD_BASE_URL = os.environ.get(
    "SOC_DASHBOARD_BASE_URL", "http://localhost:5601/app/dashboards"
)


# ── severity resolution ──────────────────────────────────────────────

def resolve_severity(alert: Dict[str, Any]) -> str:
    """
    Maps an alert's confidence_pct (or, for red-team/chain results,
    risk_score) to a severity band. Never raises — an alert with no
    numeric signal at all resolves to 'low' rather than crashing the
    notification path.
    """
    pct = alert.get("confidence_pct")
    if pct is None:
        pct = alert.get("chain_result", {}).get("risk_score") if isinstance(
            alert.get("chain_result"), dict
        ) else None
    try:
        pct = int(pct)
    except (TypeError, ValueError):
        pct = 0
    for threshold, label in SEVERITY_THRESHOLDS:
        if pct >= threshold:
            return label
    return "low"


# ── rule matching ────────────────────────────────────────────────────

def _matching_channels(severity: str, notification_rules: List[Dict[str, Any]]) -> List[str]:
    """
    notification_rules shape (stored on tenant_config):
        [{"severity": "high", "channels": ["slack", "email"]},
         {"severity": "critical", "channels": ["slack", "teams", "email", "custom_webhook"]}]
    A rule's severity is treated as a minimum floor, not an exact match —
    a 'critical' finding also fires every channel configured under 'high'
    unless the tenant explicitly wants otherwise (documented behavior,
    tunable via `exact_match` on the rule if ever needed).
    """
    order = [label for _, label in SEVERITY_THRESHOLDS][::-1]  # low..critical
    if severity not in order:
        return []
    severity_rank = order.index(severity)

    channels: List[str] = []
    for rule in notification_rules or []:
        rule_sev = rule.get("severity")
        if rule_sev not in order:
            continue
        exact = rule.get("exact_match", False)
        rule_rank = order.index(rule_sev)
        fires = (rule_rank == severity_rank) if exact else (severity_rank >= rule_rank)
        if fires:
            for ch in rule.get("channels", []):
                if ch not in channels:
                    channels.append(ch)
    return channels


# ── formatters ───────────────────────────────────────────────────────

def _dashboard_link(alert: Dict[str, Any]) -> str:
    alert_id = alert.get("alert_es_id") or alert.get("id") or "unknown"
    return f"{SOC_DASHBOARD_BASE_URL}?alert={alert_id}"


def _summary_fields(alert: Dict[str, Any]) -> Dict[str, str]:
    triage = alert.get("triage_result") or {}
    return {
        "rule_description": (alert.get("alert", {}) or {}).get("rule", {}).get(
            "description", "N/A"
        ) if isinstance(alert.get("alert"), dict) else alert.get("rule_description", "N/A"),
        "technique": alert.get("technique") or triage.get("technique") or "N/A",
        "verdict": triage.get("verdict", alert.get("verdict", "unknown")),
        "confidence_pct": str(alert.get("confidence_pct", "N/A")),
        "summary": triage.get("summary", "No triage summary available."),
        "src_ip": ((alert.get("alert", {}) or {}).get("data", {}) or {}).get(
            "srcip", "N/A"
        ) if isinstance(alert.get("alert"), dict) else "N/A",
    }


_SEVERITY_COLOR = {
    "critical": "#8b0000",
    "high": "#e01e37",
    "medium": "#f59e0b",
    "low": "#64748b",
}


def format_slack_message(alert: Dict[str, Any], severity: str) -> Dict[str, Any]:
    f = _summary_fields(alert)
    color = _SEVERITY_COLOR.get(severity, "#64748b")
    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 {severity.upper()} — {f['rule_description']}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*MITRE Technique:*\n{f['technique']}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{f['confidence_pct']}%"},
                    {"type": "mrkdwn", "text": f"*Verdict:*\n{f['verdict']}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{f['src_ip']}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Summary:*\n{f['summary'][:800]}"}},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View in Dashboard"},
                        "url": _dashboard_link(alert),
                    }
                ],
            },
        ],
        "attachments": [{"color": color, "blocks": []}],
    }


def format_teams_card(alert: Dict[str, Any], severity: str) -> Dict[str, Any]:
    f = _summary_fields(alert)
    color = _SEVERITY_COLOR.get(severity, "#64748b").lstrip("#")
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{severity.upper()} — {f['rule_description']}",
                            "weight": "bolder",
                            "size": "medium",
                            "color": "attention" if severity in ("critical", "high") else "default",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Technique", "value": f["technique"]},
                                {"title": "Confidence", "value": f"{f['confidence_pct']}%"},
                                {"title": "Verdict", "value": f["verdict"]},
                                {"title": "Source IP", "value": f["src_ip"]},
                            ],
                        },
                        {"type": "TextBlock", "text": f["summary"][:800], "wrap": True},
                    ],
                    "actions": [
                        {"type": "Action.OpenUrl", "title": "View in Dashboard", "url": _dashboard_link(alert)},
                        {
                            "type": "Action.Http",
                            "title": "Acknowledge",
                            "method": "POST",
                            "url": f"{SOC_DASHBOARD_BASE_URL}/ack",
                            "body": json.dumps({"alert_id": alert.get("alert_es_id")}),
                        },
                        {
                            "type": "Action.Http",
                            "title": "Escalate",
                            "method": "POST",
                            "url": f"{SOC_DASHBOARD_BASE_URL}/escalate",
                            "body": json.dumps({"alert_id": alert.get("alert_es_id")}),
                        },
                    ],
                    "msteams": {"width": "Full"},
                },
                "color": color,
            }
        ],
    }


def format_email_html(alert: Dict[str, Any], severity: str) -> str:
    f = _summary_fields(alert)
    color = _SEVERITY_COLOR.get(severity, "#64748b")
    blast = ""
    chain = alert.get("chain_result")
    if isinstance(chain, dict) and chain.get("blast_radius") is not None:
        blast = f"<tr><td><b>Blast radius</b></td><td>{chain.get('blast_radius')} host(s)</td></tr>"
    return f"""\
<html><body style="font-family:sans-serif;color:#1a1a1a;">
  <h2 style="color:{color};">{severity.upper()} — {f['rule_description']}</h2>
  <table cellpadding="6" style="border-collapse:collapse;">
    <tr><td><b>MITRE Technique</b></td><td>{f['technique']}</td></tr>
    <tr><td><b>Confidence</b></td><td>{f['confidence_pct']}%</td></tr>
    <tr><td><b>Verdict</b></td><td>{f['verdict']}</td></tr>
    <tr><td><b>Source IP</b></td><td>{f['src_ip']}</td></tr>
    {blast}
  </table>
  <p><b>Summary</b><br/>{f['summary']}</p>
  <p><b>Recommended action</b><br/>Review in the SOC dashboard and confirm/dismiss the verdict.</p>
  <p><a href="{_dashboard_link(alert)}">Open in SOC dashboard →</a></p>
</body></html>
"""


# ── senders (each independent, never raises) ────────────────────────

def _log_notification(
    tenant_id: str, channel: str, severity: str, alert_ref: str, success: bool, detail: Any
) -> None:
    doc = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "channel": channel,
        "severity": severity,
        "alert_ref": alert_ref,
        "success": success,
        "detail": detail if isinstance(detail, (dict, list, str, int, float, type(None))) else str(detail),
    }
    try:
        _post(f"{NOTIFICATION_LOG_INDEX}/_doc", doc)
    except Exception as exc:  # never let logging itself break the pipeline
        print(f"[webhook_engine] WARNING — failed to write notification log entry: {exc}")


def _send_slack(webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        resp = requests.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT_SECONDS)
        ok = resp.status_code == 200 and resp.text.strip() in ("ok", "")
        return {"success": ok, "status_code": resp.status_code, "body": resp.text[:300]}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _send_teams(connector_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        resp = requests.post(connector_url, json=payload, timeout=DEFAULT_TIMEOUT_SECONDS)
        return {"success": resp.status_code in (200, 202), "status_code": resp.status_code, "body": resp.text[:300]}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _send_custom_webhook(url: str, headers: Optional[Dict[str, str]], payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        resp = requests.post(url, json=payload, headers=headers or {}, timeout=DEFAULT_TIMEOUT_SECONDS)
        return {"success": 200 <= resp.status_code < 300, "status_code": resp.status_code, "body": resp.text[:300]}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _send_email(to_addrs: List[str], subject: str, html_body: str) -> Dict[str, Any]:
    if not to_addrs:
        return {"success": False, "error": "no recipient addresses configured"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = ", ".join(to_addrs)
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=DEFAULT_TIMEOUT_SECONDS) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_addrs, msg.as_string())
        return {"success": True}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ── main entry point ────────────────────────────────────────────────

def send_notifications(alert: Dict[str, Any], tenant_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called from pipeline_runner.py after the response agent completes.

    alert           — the AgentState-shaped dict (or a chain_result dict)
                       for the finding that just finished processing
    tenant_config    — the tenant's tenant_config document (Day 51 schema),
                       expected to carry a `notification_rules` list and a
                       `channel_config` block with per-channel destinations:
                         {
                           "notification_rules": [...],
                           "channel_config": {
                             "slack":   {"webhook_url": "..."},
                             "teams":   {"connector_url": "..."},
                             "email":   {"to": ["soc@client.com"]},
                             "custom_webhook": {"url": "...", "headers": {...}}
                           }
                         }

    Never raises. Returns a per-channel result summary; every attempt is
    also independently logged to siem-notification-log regardless of
    whether the caller inspects the return value.
    """
    tenant_id = tenant_config.get("tenant_id", "unknown")
    alert_ref = alert.get("alert_es_id") or alert.get("id") or "unsourced"
    severity = resolve_severity(alert)
    rules = tenant_config.get("notification_rules", [])
    channel_config = tenant_config.get("channel_config", {})

    channels = _matching_channels(severity, rules)
    results: Dict[str, Any] = {"tenant_id": tenant_id, "severity": severity, "channels_attempted": channels, "results": {}}

    if not channels:
        # Not an error — a tenant with no rule for this severity gets no
        # notification. Still worth one quiet audit line.
        _log_notification(tenant_id, "none", severity, alert_ref, True, "no matching notification_rules")
        return results

    for channel in channels:
        cfg = channel_config.get(channel, {})
        outcome: Dict[str, Any]

        if channel == "slack":
            webhook_url = cfg.get("webhook_url")
            if not webhook_url:
                outcome = {"success": False, "error": "no slack webhook_url configured for tenant"}
            else:
                outcome = _send_slack(webhook_url, format_slack_message(alert, severity))

        elif channel == "teams":
            connector_url = cfg.get("connector_url")
            if not connector_url:
                outcome = {"success": False, "error": "no teams connector_url configured for tenant"}
            else:
                outcome = _send_teams(connector_url, format_teams_card(alert, severity))

        elif channel == "email":
            to_addrs = cfg.get("to", [])
            f = _summary_fields(alert)
            subject = f"[{severity.upper()}] {f['rule_description']} — {f['technique']}"
            outcome = _send_email(to_addrs, subject, format_email_html(alert, severity))

        elif channel == "custom_webhook":
            url = cfg.get("url")
            if not url:
                outcome = {"success": False, "error": "no custom_webhook url configured for tenant"}
            else:
                payload = {
                    "tenant_id": tenant_id,
                    "severity": severity,
                    "alert": _summary_fields(alert),
                    "dashboard_link": _dashboard_link(alert),
                }
                outcome = _send_custom_webhook(url, cfg.get("headers"), payload)

        elif channel == "pagerduty_webhook":
            # Treated as a flavor of custom_webhook — PagerDuty's Events
            # API v2 just wants a POST with a routing_key + payload, same
            # transport as any other custom_webhook target.
            url = cfg.get("url", "https://events.pagerduty.com/v2/enqueue")
            f = _summary_fields(alert)
            payload = {
                "routing_key": cfg.get("routing_key"),
                "event_action": "trigger",
                "payload": {
                    "summary": f"{severity.upper()} — {f['rule_description']}",
                    "severity": {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}.get(
                        severity, "info"
                    ),
                    "source": "siem-webhook-engine",
                    "custom_details": f,
                },
            }
            outcome = _send_custom_webhook(url, cfg.get("headers"), payload)

        else:
            outcome = {"success": False, "error": f"unknown channel type '{channel}'"}

        results["results"][channel] = outcome
        _log_notification(tenant_id, channel, severity, alert_ref, bool(outcome.get("success")), outcome)

    return results


if __name__ == "__main__":
    # Standalone smoke test — no real network calls, no real tenant_config.
    # Exercises severity resolution + rule matching + formatters only.
    sample_alert = {
        "alert_es_id": "smoketest-001",
        "confidence_pct": 95,
        "technique": "T1110",
        "triage_result": {
            "verdict": "suspicious",
            "technique": "T1110",
            "summary": "Repeated SSH brute-force attempts detected from a known-bad IP.",
        },
        "alert": {"rule": {"description": "sshd: brute force"}, "data": {"srcip": "203.0.113.77"}},
    }
    sev = resolve_severity(sample_alert)
    print(f"[smoketest] resolved severity: {sev}")

    rules = [
        {"severity": "high", "channels": ["slack", "email"]},
        {"severity": "critical", "channels": ["slack", "teams", "email", "custom_webhook"]},
    ]
    matched = _matching_channels(sev, rules)
    print(f"[smoketest] matched channels: {matched}")

    slack_msg = format_slack_message(sample_alert, sev)
    print(f"[smoketest] slack blocks: {len(slack_msg['blocks'])}")

    teams_card = format_teams_card(sample_alert, sev)
    print(f"[smoketest] teams facts: {len(teams_card['attachments'][0]['content']['body'][1]['facts'])}")

    email_html = format_email_html(sample_alert, sev)
    print(f"[smoketest] email html length: {len(email_html)} chars")

    print("[smoketest] all formatters ran without error.")
