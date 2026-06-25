"""
tools/baseline_builder.py — Day 28

Computes 7-day behavioural baselines and writes them to siem-baselines, so
hunts (and later, hunt_loader.py's baseline_check) can flag deviation instead
of just absolute thresholds.

Two baselines, both averaged over BASELINE_DAYS (default 7):
  1. login_count_per_day    — per user  (data.dstuser, authentication_success)
  2. outbound_conn_per_hour — per host  (agent.name, rule.groups:firewall)

Reuses _post()/_get() from elastic_tools.py — no new ES client, no new auth.
Re-run weekly to keep baselines current (same cadence idea as
feed_manager.py's scheduler — not wired to APScheduler yet, see follow-ups).

Note (Day 28 field check): firewall alerts in this dataset only carry
data.srcip + data.dstuser — there is no destination-IP field. The "host"
side of outbound_conn_per_hour is agent.name; the "peer" side hunt_beaconing.yml
groups by is data.srcip. This baseline's entity values are agent.name (hosts),
matching how hunt_loader.py's baseline_check looks them up.
"""
import argparse
from datetime import datetime, timezone

from tools.elastic_tools import _post, _get

BASELINE_INDEX = "siem-baselines"
ALERTS_INDEX = "logs-wazuh.alerts-*"
BASELINE_DAYS = 7


def _login_counts_by_user(days: int) -> dict:
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"rule.groups": "authentication_success"}},
            {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "data.dstuser", "size": 1000},
            "aggs": {"login_count": {"value_count": {"field": "@timestamp"}}},
        }},
    }
    resp = _post(f"{ALERTS_INDEX}/_search", body)
    buckets = resp.get("aggregations", {}).get("by_user", {}).get("buckets", [])
    return {b["key"]: b["doc_count"] for b in buckets}


def _outbound_counts_by_host(days: int) -> dict:
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"rule.groups": "firewall"}},
            {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        ]}},
        "aggs": {"by_host": {
            "terms": {"field": "agent.name", "size": 1000},
            "aggs": {"conn_count": {"value_count": {"field": "@timestamp"}}},
        }},
    }
    resp = _post(f"{ALERTS_INDEX}/_search", body)
    buckets = resp.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    return {b["key"]: b["doc_count"] for b in buckets}


def _write_baseline(baseline_type: str, entity: str, avg_count: float,
                     raw_total: int, days: int) -> None:
    doc_id = f"{baseline_type}:{entity}"
    body = {
        "baseline_type": baseline_type,
        "entity": entity,
        "avg_count": round(avg_count, 2),
        "raw_total_count": raw_total,
        "sample_days": days,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
    _post(f"{BASELINE_INDEX}/_doc/{doc_id}", body)


def build_login_baseline(days: int = BASELINE_DAYS) -> int:
    counts = _login_counts_by_user(days)
    for user, total in counts.items():
        _write_baseline("login_count_per_day", user, total / days, total, days)
    return len(counts)


def build_outbound_baseline(days: int = BASELINE_DAYS) -> int:
    counts = _outbound_counts_by_host(days)
    for host, total in counts.items():
        _write_baseline("outbound_conn_per_hour", host, total / (days * 24), total, days)
    return len(counts)


def get_baseline(baseline_type: str, entity: str) -> dict | None:
    """Used by hunt_loader.py's baseline_check (Day 28). Returns None if no
    baseline exists yet for this entity — caller must handle that, not crash."""
    try:
        resp = _get(f"{BASELINE_INDEX}/_doc/{baseline_type}:{entity}")
    except Exception:
        return None
    return resp.get("_source") if resp else None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=BASELINE_DAYS)
    args = parser.parse_args()

    n_users = build_login_baseline(args.days)
    n_hosts = build_outbound_baseline(args.days)
    print(f"login_count_per_day baseline written for {n_users} users")
    print(f"outbound_conn_per_hour baseline written for {n_hosts} hosts")
