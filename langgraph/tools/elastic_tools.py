"""
elastic_tools.py — Elasticsearch query helpers for the SIEM agentic layer.

Usage:
    ES is on localhost:9201, creds elastic / changeme.
    All functions return a plain dict or list — no ES SDK objects leak out.

Place this file at:  ~/elastic/langgraph/tools/elastic_tools.py
"""

import json
from datetime import datetime, timezone
from typing import Optional

import requests

# ── connection config ──────────────────────────────────────────────────────────
ES_URL  = "http://localhost:9201"
ES_AUTH = ("elastic", "changeme")
INDEX   = "logs-wazuh.alerts-*"
HEADERS = {"Content-Type": "application/json"}


def _post(path: str, body: dict) -> dict:
    """Internal helper — POST to Elasticsearch, return parsed JSON."""
    url = f"{ES_URL}/{path}"
    resp = requests.post(url, auth=ES_AUTH, headers=HEADERS,
                         data=json.dumps(body), timeout=10)
    resp.raise_for_status()
    return resp.json()


def _get(path: str) -> dict:
    """Internal helper — GET from Elasticsearch, return parsed JSON."""
    url = f"{ES_URL}/{path}"
    resp = requests.get(url, auth=ES_AUTH, timeout=10)
    resp.raise_for_status()
    return resp.json()


# ── Day 13 (already implemented) ──────────────────────────────────────────────

def es_health() -> dict:
    """Return cluster health summary."""
    return _get("_cluster/health")


# ── Day 14 functions ───────────────────────────────────────────────────────────

def get_recent_alerts(size: int = 10) -> list[dict]:
    """Return the latest N Wazuh alerts, newest first."""
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "agent.name", "data.srcip", "data.dstuser", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


def get_alerts_by_rule_id(rule_id: str, size: int = 20) -> list[dict]:
    """Return recent alerts matching a specific Wazuh rule ID."""
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "term": {"rule.id": str(rule_id)}
        },
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "agent.name", "data.srcip", "data.dstuser", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


def get_alerts_by_src_ip(src_ip: str, minutes: int = 60) -> list[dict]:
    """Return all alerts from a given source IP within the last N minutes."""
    body = {
        "size": 50,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"data.srcip": src_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}
                ]
            }
        },
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "agent.name", "data.srcip", "data.dstuser", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


def count_alerts_by_group(group: str, minutes: int = 60) -> int:
    """Count how many alerts belong to a rule group within the last N minutes."""
    body = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"rule.groups": group}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}
                ]
            }
        }
    }
    raw = _post(f"{INDEX}/_count", body)
    return raw.get("count", 0)


def get_high_severity_alerts(min_level: int = 10, size: int = 20) -> list[dict]:
    """Return recent alerts at or above a given rule.level severity."""
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "range": {"rule.level": {"gte": min_level}}
        },
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "agent.name", "data.srcip", "data.dstuser", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


# ── Day 14 (TODAY) — new functions ────────────────────────────────────────────

def get_recent_events(source_ip: str, minutes: int = 60, size: int = 30) -> list[dict]:
    """
    Return the last N events from a given source IP within the time window.

    Used by the triage agent to build full context around an alert's origin IP:
    how many attempts, which rule IDs fired, which usernames were tried, etc.

    Args:
        source_ip: The IP address to look up (matches data.srcip).
        minutes:   How far back to look. Default 60 minutes.
        size:      Max results to return. Default 30.

    Returns:
        List of event dicts, newest first. Empty list if nothing found.
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"data.srcip": source_ip}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}
                ]
            }
        },
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "data.srcip", "data.dstuser", "agent.name", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


def get_user_login_history(username: str, days: int = 7, size: int = 50) -> list[dict]:
    """
    Return a user's recent login events (success and failure) over the last N days.

    Searches on data.dstuser for the username string. Wazuh stores it as
    'root(uid=0)' or plain 'root' depending on the rule, so we use a
    wildcard match to catch both forms.

    Args:
        username: The username to search for (e.g. 'root', 'ahmad').
        days:     How many days of history to pull. Default 7.
        size:     Max results. Default 50.

    Returns:
        List of login event dicts, newest first.
        Each dict includes rule.id, rule.description, rule.groups,
        data.srcip, data.dstuser, agent.name, @timestamp.
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    # wildcard catches 'root', 'root(uid=0)', etc.
                    {"wildcard": {"data.dstuser": f"*{username}*"}},
                    {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}},
                    # only login-relevant rule groups
                    {"terms": {"rule.groups": [
                        "authentication_success",
                        "authentication_failed",
                        "pam",
                        "sshd"
                    ]}}
                ]
            }
        },
        "_source": [
            "rule.id", "rule.description", "rule.groups", "rule.level",
            "data.srcip", "data.dstuser", "agent.name", "@timestamp"
        ]
    }
    raw = _post(f"{INDEX}/_search", body)
    return [hit["_source"] for hit in raw.get("hits", {}).get("hits", [])]


# ── quick CLI test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Cluster health ===")
    print(json.dumps(es_health(), indent=2))

    print("\n=== Last 3 alerts ===")
    for evt in get_recent_alerts(3):
        rule = evt.get('rule', {})
        print(f"  [{evt.get('@timestamp','')}] rule {rule.get('id','?')} "
              f"lv={rule.get('level','?')} — {rule.get('description','')[:60]}")

    print("\n=== get_recent_events('192.168.1.10', minutes=120) ===")
    evts = get_recent_events("192.168.1.10", minutes=120)
    print(f"  Found {len(evts)} events")
    for e in evts[:3]:
        rule = e.get('rule', {})
        print(f"  {e.get('@timestamp','')} | rule {rule.get('id','?')} "
              f"| {rule.get('description','')[:50]}")

    print("\n=== get_user_login_history('root', days=7) ===")
    logins = get_user_login_history("root", days=7)
    print(f"  Found {len(logins)} login events")
    for l in logins[:3]:
        print(f"  {l.get('@timestamp','')} | groups={l.get('rule',{}).get('groups',[])} "
              f"| from {l.get('data',{}).get('srcip','?')}")
