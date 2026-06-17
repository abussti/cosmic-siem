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
# ---------------------------------------------------------------------------
# NEW FUNCTION 1 — write triage result back to the original alert document
# ---------------------------------------------------------------------------
 
def write_triage_result_to_es(
    es_index: str,
    es_id: str,
    verdict: str,
    summary: str,
    evidence: list[str] | None = None,
    confidence_pct: int | None = None,
    technique: str | None = None,
) -> bool:
    """
    Write triage results back to the original Wazuh alert document in ES
    using the Update API (_update endpoint).
 
    Adds the following fields to the document:
        triage.verdict          str   e.g. "suspicious" / "benign" / "unknown"
        triage.summary          str   LLM-generated summary
        triage.evidence         list  evidence bullets from LLM
        triage.confidence_pct   int   numeric confidence score
        triage.technique        str   MITRE ATT&CK ID (if known)
        triage.processed_at     str   ISO-8601 timestamp of when triage ran
        triage.pipeline_version str   always "day17-v1"
 
    Parameters
    ----------
    es_index : str
        The full index name of the alert document (e.g. .ds-logs-wazuh.alerts-2026.06.02-000001).
        Use the _index field from the ES search hit.
    es_id : str
        The document _id. Use the _id field from the ES search hit.
    verdict : str
        One of: "suspicious", "benign", "unknown".
    summary : str
        Human-readable triage summary from the LLM.
    evidence : list[str], optional
        List of evidence bullet strings.
    confidence_pct : int, optional
        Numeric confidence score (0–100).
    technique : str, optional
        MITRE ATT&CK technique ID.
 
    Returns
    -------
    bool
        True if the update succeeded (HTTP 200), False otherwise.
    """
    from datetime import datetime, timezone
 
    url = f"{ES_URL}/{es_index}/_update/{es_id}"
    payload = {
        "doc": {
            "triage": {
                "verdict": verdict,
                "summary": summary,
                "evidence": evidence or [],
                "confidence_pct": confidence_pct,
                "technique": technique,
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "pipeline_version": "day17-v1",
            }
        }
    }
    try:
        resp = requests.post(url, json=payload, auth=ES_AUTH, timeout=15)
        if resp.status_code == 200:
            result = resp.json().get("result", "")
            print(f"[ES WRITE-BACK] ✅ doc {es_id[:12]}… → triage.verdict={verdict!r}  (result={result})")
            return True
        else:
            print(f"[ES WRITE-BACK] ❌ HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as exc:
        print(f"[ES WRITE-BACK] ❌ Exception: {exc}")
        return False
 
 
# ---------------------------------------------------------------------------
# NEW FUNCTION 2 — poll for unprocessed alerts (used by pipeline_runner.py)
# ---------------------------------------------------------------------------
 
def get_unprocessed_alerts(since_timestamp: str, size: int = 50) -> list[dict]:
    """
    Return up to `size` Wazuh alerts that:
      1. Were indexed after `since_timestamp` (ISO-8601 string)
      2. Do NOT yet have a `triage.verdict` field (i.e. not yet processed)
 
    Parameters
    ----------
    since_timestamp : str
        ISO-8601 datetime string, e.g. "2026-06-02T10:00:00.000Z".
        Only alerts with @timestamp > this value are returned.
    size : int
        Maximum number of alerts to return per poll cycle. Default 50.
 
    Returns
    -------
    list[dict]
        Each item is a dict with keys: _id, _index, _source.
        Pass _id and _index to write_triage_result_to_es() after triage.
    """
    url = f"{ES_URL}/logs-wazuh.alerts-*/_search"
    query = {
        "size": size,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gt": since_timestamp}}}
                ],
                "must_not": [
                    {"exists": {"field": "triage.verdict"}}
                ]
            }
        },
        "_source": True
    }
    try:
        resp = requests.get(url, json=query, auth=ES_AUTH, timeout=15)
        hits = resp.json().get("hits", {}).get("hits", [])
        return [
            {"_id": h["_id"], "_index": h["_index"], "_source": h["_source"]}
            for h in hits
        ]
    except Exception as exc:
        print(f"[ES POLL] ❌ Exception: {exc}")
        return []


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

def get_ip_seen_before(src_ip: str, lookback_days: int = 30) -> bool:
    """
    Check whether a source IP has appeared in Wazuh alerts before today.
    Returns True if the IP is known (seen in the last `lookback_days` days),
    False if it is brand new — which triggers a confidence boost in the scorer.

    Uses a date range query that excludes the last 60 seconds so the alert
    that triggered this call does not count as 'prior history'.
    """
    if not src_ip:
        return True  # no IP → assume known, don't boost

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"data.srcip": src_ip}},
                    {"range": {
                        "@timestamp": {
                            # look back N days, but stop 60s ago so the
                            # triggering alert itself does not count
                            "gte": f"now-{lookback_days}d/d",
                            "lte": "now-60s"
                        }
                    }}
                ]
            }
        },
        "size": 0  # we only need the count, not the documents
    }

    try:
        resp = requests.get(
            f"{ES_URL}/logs-wazuh.alerts-*/_count",
            auth=ES_AUTH,
            json=query,
            timeout=10
        )
        resp.raise_for_status()
        count = resp.json().get("count", 0)
        return count > 0   # True = seen before, False = brand new IP
    except Exception as e:
        # If the query fails, assume the IP is known — conservative default
        print(f"[elastic_tools] get_ip_seen_before error: {e}")
        return True

# ── Day 24 additions to tools/elastic_tools.py ──────────────────────────────
# Paste these two functions into elastic_tools.py (after get_ip_seen_before).
#
# CORRECTED: this file has no `es` client object — every other function uses
# the _post()/_get() helpers (or raw requests.get with a json body, as in
# get_unprocessed_alerts / get_ip_seen_before) against ES_URL/ES_AUTH defined
# at the top of the file. Both functions below now use _post(), matching the
# rest of the file's convention exactly.

# Seed table — curated profiles for known actors. Extend this dict as you
# encounter named actors in your OTX/URLhaus tags. Keys are lowercased for
# case-insensitive lookup.
_THREAT_ACTOR_SEED = {
    "apt28": {
        "known_campaigns": ["Fancy Bear", "Pawn Storm", "Sednit"],
        "ttps": ["T1566 Phishing", "T1071 C2 over web protocols", "T1078 Valid Accounts"],
        "target_sectors": ["Government", "Defense", "Media"],
    },
    "apt29": {
        "known_campaigns": ["Cozy Bear", "The Dukes"],
        "ttps": ["T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1003 Credential Dumping"],
        "target_sectors": ["Government", "Think Tanks", "Healthcare"],
    },
    "lazarus group": {
        "known_campaigns": ["Operation Dream Job", "AppleJeus"],
        "ttps": ["T1566 Phishing", "T1486 Data Encrypted for Impact", "T1071 C2 over HTTP"],
        "target_sectors": ["Finance", "Cryptocurrency", "Defense"],
    },
    "fin7": {
        "known_campaigns": ["Carbanak"],
        "ttps": ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1003 Credential Dumping"],
        "target_sectors": ["Retail", "Hospitality", "Finance"],
    },
}


def get_threat_actor_profile(actor_name: str) -> dict:
    """
    Day 24 — returns known campaigns, TTPs, and target sectors for a threat actor.

    Lookup order:
      1. Curated seed table (_THREAT_ACTOR_SEED) for named APT/crimeware groups.
      2. Fallback: live aggregation from siem-threat-intel (via _post, same as
         every other query in this file) — counts IOCs attributed to this
         actor, collects sources and tags as a TTP/context proxy, and returns
         last_seen.

    Returns:
        {
            'actor_name': str,
            'found': bool,
            'known_campaigns': list[str],
            'ttps': list[str],
            'target_sectors': list[str],
            'ioc_count': int,            # from siem-threat-intel, always populated
            'sources': list[str],        # e.g. ['otx', 'urlhaus']
            'last_seen': str | None,     # ISO timestamp of most recent IOC
            'profile_source': 'seed' | 'aggregated' | 'not_found',
        }
    """
    if not actor_name:
        return {
            "actor_name": actor_name,
            "found": False,
            "known_campaigns": [],
            "ttps": [],
            "target_sectors": [],
            "ioc_count": 0,
            "sources": [],
            "last_seen": None,
            "profile_source": "not_found",
        }

    key = actor_name.strip().lower()

    # Always pull live aggregate stats from siem-threat-intel, regardless of
    # seed match, so ioc_count/sources/last_seen stay accurate.
    agg_query = {
        "size": 0,
        "query": {"term": {"threat_actor": actor_name}},
        "aggs": {
            "sources": {"terms": {"field": "source", "size": 10}},
            "tags": {"terms": {"field": "tags", "size": 20}},
            "last_seen": {"max": {"field": "last_seen"}},
        },
    }

    ioc_count = 0
    sources = []
    tags = []
    last_seen = None

    try:
        raw = _post("siem-threat-intel/_search", agg_query)
        ioc_count = raw.get("hits", {}).get("total", {}).get("value", 0)
        aggs = raw.get("aggregations", {})
        sources = [b["key"] for b in aggs.get("sources", {}).get("buckets", [])]
        tags = [b["key"] for b in aggs.get("tags", {}).get("buckets", [])]
        last_seen = aggs.get("last_seen", {}).get("value_as_string")
    except Exception as e:
        # Index may not have this actor, or ES may be briefly unavailable —
        # degrade gracefully rather than crashing the agent.
        print(f"[get_threat_actor_profile] aggregation query failed: {e}")

    seed = _THREAT_ACTOR_SEED.get(key)

    if seed:
        return {
            "actor_name": actor_name,
            "found": True,
            "known_campaigns": seed["known_campaigns"],
            "ttps": seed["ttps"],
            "target_sectors": seed["target_sectors"],
            "ioc_count": ioc_count,
            "sources": sources,
            "last_seen": last_seen,
            "profile_source": "seed",
        }

    if ioc_count > 0:
        # No curated profile, but we have live IOC data — build a best-effort
        # profile from what's actually in the index. Tags stand in for TTPs
        # since that's the closest field we ingest today.
        return {
            "actor_name": actor_name,
            "found": True,
            "known_campaigns": [],
            "ttps": tags,
            "target_sectors": [],
            "ioc_count": ioc_count,
            "sources": sources,
            "last_seen": last_seen,
            "profile_source": "aggregated",
        }

    return {
        "actor_name": actor_name,
        "found": False,
        "known_campaigns": [],
        "ttps": [],
        "target_sectors": [],
        "ioc_count": 0,
        "sources": [],
        "last_seen": None,
        "profile_source": "not_found",
    }


def get_ioc_history(ioc_value: str) -> dict:
    """
    Day 24 — returns all alerts in the last 30 days that matched this IOC.

    Searches logs-wazuh.alerts-* (same INDEX pattern used elsewhere in this
    file) across the common IOC-bearing fields (data.srcip, data.dstip,
    data.url, data.hash) for an exact match on ioc_value, sorted
    most-recent-first.

    Returns:
        {
            'ioc_value': str,
            'match_count': int,
            'alerts': [
                {
                    'timestamp': str,
                    'rule_id': str,
                    'rule_description': str,
                    'rule_level': int,
                    'agent_name': str,
                    'matched_field': str,   # which field matched, e.g. 'data.srcip'
                },
                ...
            ],
        }
    """
    query = {
        "size": 50,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-30d"}}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"data.srcip": ioc_value}},
                                {"term": {"data.dstip": ioc_value}},
                                {"term": {"data.url": ioc_value}},
                                {"term": {"data.hash": ioc_value}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
        "_source": ["@timestamp", "rule.id", "rule.description", "rule.level", "agent.name",
                    "data.srcip", "data.dstip", "data.url", "data.hash"],
    }

    alerts = []
    match_count = 0

    try:
        raw = _post(f"{INDEX}/_search", query)
        match_count = raw.get("hits", {}).get("total", {}).get("value", 0)
        for hit in raw.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            data = src.get("data", {})

            matched_field = None
            for field in ("srcip", "dstip", "url", "hash"):
                if data.get(field) == ioc_value:
                    matched_field = f"data.{field}"
                    break

            alerts.append({
                "timestamp": src.get("@timestamp"),
                "rule_id": src.get("rule", {}).get("id"),
                "rule_description": src.get("rule", {}).get("description"),
                "rule_level": src.get("rule", {}).get("level"),
                "agent_name": src.get("agent", {}).get("name"),
                "matched_field": matched_field,
            })
    except Exception as e:
        print(f"[get_ioc_history] query failed: {e}")

    return {
        "ioc_value": ioc_value,
        "match_count": match_count,
        "alerts": alerts,
    }