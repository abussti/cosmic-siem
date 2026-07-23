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
    cti_matched: bool | None = None,
    cti_threat_actor: str | None = None,
    cti_campaign: str | None = None,
    cti_confidence: int | None = None,
    cti_source: str | None = None,
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

        [Day 36] cti.matched          bool   whether an IOC matched siem-threat-intel
        [Day 36] cti.threat_actor     str    actor name from the matched IOC, if any
        [Day 36] cti.campaign         str    campaign name, if any (usually None —
                                              not in current siem-threat-intel schema)
        [Day 36] cti.confidence       int    CTI confidence score of the matched IOC
        [Day 36] cti.source           str    feed source, e.g. "otx" / "urlhaus"

    Bug fixed (Day 36): enrich_with_cti() in pipeline_runner.py computed these
    CTI fields on the in-memory alert dict, and the SOC dashboard's "CTI Matches"
    panel queried for cti.matched on the persisted ES document — but this
    function never accepted or wrote CTI fields, so cti.* was silently lost
    after the pipeline run finished. Confirmed via Day 36 dashboard build:
    a live pipeline run logged "CTI matched=True" but the resulting ES document
    had no cti object at all.

    The cti_* parameters are optional and default to None so existing callers
    (e.g. test_pipeline_e2e.py) that don't pass CTI data keep working
    unchanged — the cti block is only added to the payload if the caller
    actually supplies it.

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
    cti_matched : bool, optional
        Whether any IOC in the alert matched siem-threat-intel.
    cti_threat_actor : str, optional
        Threat actor name attributed to the matched IOC.
    cti_campaign : str, optional
        Campaign name attributed to the matched IOC.
    cti_confidence : int, optional
        CTI confidence score (0–100) of the highest-confidence matched IOC.
    cti_source : str, optional
        Feed source of the matched IOC, e.g. "otx" or "urlhaus".

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

    # [Day 36 fix] Only add the cti block if the caller actually passed CTI
    # data — keeps old call sites that don't pass cti_* args working exactly
    # as before, while new calls (pipeline_runner.py) get real persistence.
    if cti_matched is not None:
        payload["doc"]["cti"] = {
            "matched": cti_matched,
            "threat_actor": cti_threat_actor,
            "campaign": cti_campaign,
            "confidence": cti_confidence,
            "source": cti_source,
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
# NEW FUNCTIONS — Day 29: hunt result storage (siem-hunt-results)
# ---------------------------------------------------------------------------
# Same _post() convention as every other write/read in this file — no new
# client, no new auth pattern.

HUNT_RESULTS_INDEX = "siem-hunt-results"


def write_hunt_result_to_es(hunt_name, findings_count, summary, escalated):
    """
    Writes one hunt-cycle result to siem-hunt-results.

    Fields (per Day 29 spec): hunt_name, findings_count, summary, escalated, timestamp.

    Never raises — an ES write failure here must not crash the hunt cycle that's
    calling it (same defensive philosophy as run_hunt(): a storage hiccup shouldn't
    take down detection).
    """
    doc = {
        "hunt_name": hunt_name,
        "findings_count": findings_count,
        "summary": summary,
        "escalated": bool(escalated),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        return _post(f"{HUNT_RESULTS_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[write_hunt_result_to_es] ES write failed: {e}")
        return None


def get_recent_hunt_results(size=20):
    """
    Optional helper (not in the Day 29 spec, but handy for Day 30's full test /
    Week 6 review) — latest hunt-cycle results, newest first.
    """
    body = {
        "size": size,
        "sort": [{"timestamp": "desc"}],
    }
    try:
        return _post(f"{HUNT_RESULTS_INDEX}/_search", body)
    except Exception as e:
        print(f"[get_recent_hunt_results] ES read failed: {e}")
        return None


# ---------------------------------------------------------------------------
# NEW FUNCTIONS — Day 31: response agent logging (siem-response-log)
# ---------------------------------------------------------------------------
# Same _post() convention as everything else in this file. Called by
# agents/response_agent.py's response_node() on every decision — including
# the "no action taken" case — so the audit trail is complete from the
# scaffold stage onward (same "log every cycle" philosophy as Day 29's
# write_hunt_result_to_es above).

RESPONSE_LOG_INDEX = "siem-response-log"


def write_response_log_entry(action_type, target, agent, reversible,
                              reversed_=False, verdict=None, confidence=None):
    """
    Writes one entry to siem-response-log.

    Fields (per Day 31 spec): timestamp, action_type, target, agent,
    reversible, reversed. verdict/confidence are extra context, included
    the same way write_triage_result_to_es carries extra context fields
    beyond the bare minimum.

    action_type   str   e.g. "block_ip", "isolate_endpoint", "create_ticket",
                         or "none" if no action was warranted this cycle
    target        str   the IP / agent name / username the action targets
    agent         str   which agent made the decision (currently always
                         "response_agent")
    reversible    bool  whether this action type can be undone
    reversed_     bool  whether it HAS been undone — trailing underscore
                         avoids shadowing the reversed() builtin, same
                         defensive naming habit the Day 24 NameError fix
                         on coordination_agent.py established
    verdict       str | None   the triage verdict that triggered this
    confidence    int | None   confidence_pct at decision time

    Never raises — mirrors every other write_* function in this file.

    NOTE: response_tools.py (Day 32-34) uses its own, separately-shaped
    _log_response_action() helper writing to the same siem-response-log
    index (fields: action_type, target, endpoint, reversible, success,
    detail, timestamp). Both write to siem-response-log but are not the
    same function — response_node() in agents/response_agent.py calls this
    one; block_ip()/isolate_endpoint()/create_ticket() in response_tools.py
    call the other one internally.
    """
    doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": action_type,
        "target": target,
        "agent": agent,
        "reversible": reversible,
        "reversed": reversed_,
    }
    if verdict is not None:
        doc["verdict"] = verdict
    if confidence is not None:
        doc["confidence"] = confidence

    try:
        return _post(f"{RESPONSE_LOG_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[write_response_log_entry] ES write failed: {e}")
        return None


def get_recent_response_actions(size=20):
    """
    Optional helper (not in the Day 31 spec, but matches get_recent_hunt_results
    above, and feeds the Week 8 SOC dashboard's response-actions panel later) —
    latest response-log entries, newest first.
    """
    body = {
        "size": size,
        "sort": [{"timestamp": "desc"}],
    }
    try:
        return _post(f"{RESPONSE_LOG_INDEX}/_search", body)
    except Exception as e:
        print(f"[get_recent_response_actions] ES read failed: {e}")
        return None


# ---------------------------------------------------------------------------
# NEW FUNCTION — Day 34: write GitHub ticket URL back onto the alert doc
# ---------------------------------------------------------------------------
# Same _update-API pattern as write_triage_result_to_es() (Day 17), but
# using the _post() helper convention like every other function in this
# section, rather than a raw requests.post call.

def update_alert_with_ticket_url(es_index: str, es_id: str, ticket_url: str):
    """
    Writes the GitHub ticket URL back onto the original Wazuh alert document
    via ES's _update API, adding a `response.ticket_url` field.

    Parameters
    ----------
    es_index : str
        The full index name of the alert document (the `_index` field from
        the ES search hit, or alert_es_index in AgentState).
    es_id : str
        The document `_id` (or alert_es_id in AgentState).
    ticket_url : str
        The GitHub issue's html_url, as returned by response_tools.create_ticket().

    Returns
    -------
    dict | None
        The parsed ES response on success, None on failure. Never raises —
        matches every other write_* function in this file; a failed
        write-back here must not lose the ticket that was already created.
    """
    body = {"doc": {"response": {"ticket_url": ticket_url}}}
    try:
        return _post(f"{es_index}/_update/{es_id}", body)
    except Exception as e:
        print(f"[update_alert_with_ticket_url] ES write failed: {e}")
        return None


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


# ---------------------------------------------------------------------------
# NEW FUNCTIONS — Day 43: attack chain simulation storage (siem-redteam-chains)
# ---------------------------------------------------------------------------
# Same _post() convention as write_hunt_result_to_es (Day 29) and
# write_response_log_entry (Day 31). Called by
# agents/attack_chain_simulator.py's run_attack_chain() once per chain run.

CHAIN_LOG_INDEX = "siem-redteam-chains"


def write_chain_result_to_es(chain_name, target_agent, chain_result,
                              fully_exploitable, mode):
    """
    Writes one attack-chain simulation result to siem-redteam-chains.

    Fields (per Day 43 spec): chain_name, target_agent, chain_result
    (the full per-step list), fully_exploitable, blocked_count, mode,
    timestamp.

    chain_name         str    e.g. "external_intrusion"
    target_agent       str    Wazuh agent name the chain was run against
    chain_result       list   [{step, name, mitre_tactic, exploitable,
                                evidence, blocked_by}, ...] — same shape
                               attack_chain_simulator.run_attack_chain()
                               builds internally
    fully_exploitable  bool   True only if every step in chain_result
                               came back exploitable=True
    mode               str    the REDTEAM_MODE the run executed under
                               ("dry_run" / "live")

    Never raises — mirrors every other write_* function in this file; a
    storage hiccup here must not crash a chain simulation mid-run.
    """
    doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "chain_name": chain_name,
        "target_agent": target_agent,
        "chain_result": chain_result,
        "fully_exploitable": bool(fully_exploitable),
        "blocked_count": sum(1 for r in chain_result if not r.get("exploitable")),
        "mode": mode,
    }
    try:
        return _post(f"{CHAIN_LOG_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[write_chain_result_to_es] ES write failed: {e}")
        return None


def get_recent_chain_results(size=10):
    """
    Latest chain-simulation results, newest first — matches
    get_recent_hunt_results() / get_recent_response_actions()'s convention
    exactly. Used by test_day43.py to verify a chain run was persisted.
    """
    body = {
        "size": size,
        "sort": [{"timestamp": "desc"}],
    }
    try:
        return _post(f"{CHAIN_LOG_INDEX}/_search", body)
    except Exception as e:
        print(f"[get_recent_chain_results] ES read failed: {e}")
        return None


# ---------------------------------------------------------------------------
# NEW FUNCTIONS — Day 44: Gemini-generated technical/executive reports
# (siem-redteam-reports)
# ---------------------------------------------------------------------------
# Written by agents/attack_chain_simulator.py's run_attack_chain() right
# after chain_result is finalized, via tools/redteam_reporter.py (Gemini —
# same LLM_BACKEND convention as triage_agent.py / hunt_summarizer.py, not
# a second LLM provider). Same never-raises convention as every other
# write_* function in this file.

REDTEAM_REPORTS_INDEX = "siem-redteam-reports"


def write_redteam_report_to_es(incident_id, technical_summary, executive_summary,
                                chain_name=None, target_agent=None, timestamp=None):
    """
    Writes one Gemini-generated report pair to siem-redteam-reports.

    Fields (per Day 44 spec): incident_id, technical_summary,
    executive_summary, timestamp. chain_name/target_agent are extra context
    fields, same pattern write_response_log_entry() uses for verdict/confidence.

    Never raises — mirrors every other write_* function in this file; a
    storage hiccup here must not crash a chain simulation mid-run.
    """
    doc = {
        "incident_id": incident_id,
        "technical_summary": technical_summary,
        "executive_summary": executive_summary,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
    }
    if chain_name is not None:
        doc["chain_name"] = chain_name
    if target_agent is not None:
        doc["target_agent"] = target_agent

    try:
        return _post(f"{REDTEAM_REPORTS_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[write_redteam_report_to_es] ES write failed: {e}")
        return None


def get_recent_redteam_reports(size=10):
    """
    Latest Gemini-generated report pairs, newest first — matches
    get_recent_chain_results()'s convention exactly. Used by test_day44.py
    to verify a report was persisted.
    """
    body = {
        "size": size,
        "sort": [{"timestamp": "desc"}],
    }
    try:
        return _post(f"{REDTEAM_REPORTS_INDEX}/_search", body)
    except Exception as e:
        print(f"[get_recent_redteam_reports] ES read failed: {e}")
        return None


# ── quick CLI test ─────────────────────────────────────────────────────────────
# (Moved here from mid-file — was previously sitting between get_user_login_history
# and get_ip_seen_before, which meant later functions only existed below an
# if __name__ block. Harmless in practice since module-level defs run regardless,
# but confusing to read. Belongs at the true end of the file like every other
# module's __main__ block in this project.)

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

    print("\n=== get_recent_hunt_results(5)  [Day 29] ===")
    hunt_results = get_recent_hunt_results(5)
    hits = (hunt_results or {}).get("hits", {}).get("hits", [])
    print(f"  Found {len(hits)} hunt result(s)")
    for h in hits[:5]:
        src = h.get("_source", {})
        print(f"  {src.get('timestamp','')} | {src.get('hunt_name','?')} "
              f"| findings={src.get('findings_count','?')} escalated={src.get('escalated','?')}")

    print("\n=== get_recent_response_actions(5)  [Day 31] ===")
    response_results = get_recent_response_actions(5)
    resp_hits = (response_results or {}).get("hits", {}).get("hits", [])
    print(f"  Found {len(resp_hits)} response log entry(ies)")
    for h in resp_hits[:5]:
        src = h.get("_source", {})
        print(f"  {src.get('timestamp','')} | action={src.get('action_type','?')} "
              f"| target={src.get('target','?')} | verdict={src.get('verdict','?')}")

    print("\n=== get_recent_chain_results(5)  [Day 43] ===")
    chain_results = get_recent_chain_results(5)
    chain_hits = (chain_results or {}).get("hits", {}).get("hits", [])
    print(f"  Found {len(chain_hits)} chain result(s)")
    for h in chain_hits[:5]:
        src = h.get("_source", {})
        print(f"  {src.get('timestamp','')} | chain={src.get('chain_name','?')} "
              f"| fully_exploitable={src.get('fully_exploitable','?')} "
              f"| blocked={src.get('blocked_count','?')}")

    print("\n=== get_recent_redteam_reports(5)  [Day 44] ===")
    report_results = get_recent_redteam_reports(5)
    report_hits = (report_results or {}).get("hits", {}).get("hits", [])
    print(f"  Found {len(report_hits)} redteam report(s)")
    for h in report_hits[:5]:
        src = h.get("_source", {})
        print(f"  {src.get('timestamp','')} | incident={src.get('incident_id','?')} "
              f"| chain={src.get('chain_name','?')}")
