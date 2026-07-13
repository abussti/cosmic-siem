"""
tools/baseline_builder.py — Day 28, bug fix Day 39

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

Day 39 bug fix — outbound_conn_per_hour contamination (tracked bug #8):
    Root cause found: build_outbound_baseline() (and build_login_baseline())
    only ever WRITE a baseline doc for entities present in the CURRENT
    aggregation results (`for host, total in counts.items(): _write_baseline(...)`).
    If an entity had events during a previous (e.g. contaminated test) run
    but has ZERO matching events in the current window, it simply never
    appears in `counts` — so its old document in siem-baselines is left
    completely untouched, no matter how many times the builder is re-run.
    This exactly matches the Day 28 observation: a clean rebuild logged
    "outbound_conn_per_hour baseline written for 0 hosts" (correct — no
    firewall events for any host in the last 7 days after test cleanup) but
    an immediate follow-up search still showed the stale contaminated
    document for agent1 with raw_total_count=25, because nothing had ever
    told that document it needed to change.
    Fixed by querying siem-baselines for every entity CURRENTLY baselined
    under a given type before writing, then explicitly zeroing out (not
    deleting — zeroing preserves the audit trail of "this used to have
    activity, now it doesn't") any previously-baselined entity that has no
    events in the current window.
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


def _existing_baseline_entities(baseline_type: str) -> set:
    """
    [Day 39] Returns every entity currently baselined under `baseline_type`
    in siem-baselines, so callers can detect entities that USED TO have a
    baseline but have zero matching events in the current window — those
    need to be explicitly zeroed out, or their old value silently persists
    forever (the root cause of bug #8). Never raises — returns an empty set
    on any query failure, which just means "nothing to zero out this run",
    a safe default.
    """
    body = {
        "size": 1000,
        "query": {"term": {"baseline_type": baseline_type}},
        "_source": ["entity"],
    }
    try:
        resp = _post(f"{BASELINE_INDEX}/_search", body)
        if not resp:
            return set()
        hits = resp.get("hits", {}).get("hits", [])
        return {
            h.get("_source", {}).get("entity")
            for h in hits
            if h.get("_source", {}).get("entity")
        }
    except Exception as e:
        print(f"[baseline_builder] failed to list existing '{baseline_type}' "
              f"baselines (treating as none): {e}")
        return set()


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

    # [Day 39 fix] Find any user previously baselined who has zero logins in
    # the current window, and zero out their stale baseline explicitly.
    existing = _existing_baseline_entities("login_count_per_day")
    stale = existing - set(counts.keys())

    for user, total in counts.items():
        _write_baseline("login_count_per_day", user, total / days, total, days)
    for user in stale:
        _write_baseline("login_count_per_day", user, 0.0, 0, days)

    if stale:
        print(f"[baseline_builder] zeroed {len(stale)} stale login_count_per_day "
              f"entries with no activity in the last {days}d: {sorted(stale)}")

    return len(counts)


def build_outbound_baseline(days: int = BASELINE_DAYS) -> int:
    counts = _outbound_counts_by_host(days)

    # [Day 39 fix — bug #8] This is the exact scenario that produced the
    # Day 28 contamination: a host (agent1) had a baseline from a
    # test-injected run, then the test data was deleted, and a clean rebuild
    # found 0 real hosts with firewall activity — but without this step, the
    # stale agent1 document from the contaminated run would never be
    # touched again, no matter how many times build_outbound_baseline() runs.
    existing = _existing_baseline_entities("outbound_conn_per_hour")
    stale = existing - set(counts.keys())

    for host, total in counts.items():
        _write_baseline("outbound_conn_per_hour", host, total / (days * 24), total, days)
    for host in stale:
        _write_baseline("outbound_conn_per_hour", host, 0.0, 0, days)

    if stale:
        print(f"[baseline_builder] zeroed {len(stale)} stale outbound_conn_per_hour "
              f"entries with no activity in the last {days}d: {sorted(stale)}")

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

    # Day 39 regression test for bug #8 — simulates the exact contamination
    # scenario using a fake/mocked _post, without needing a live ES cluster.
    # Run with `python3 -m tools.baseline_builder --self-test` style checks
    # are intentionally NOT wired into argparse here (this file's __main__
    # is meant to run for real against ES); see docs/DAY39-BUGFIXES.md for
    # the live-cluster reproduction steps (delete confirmed -> single build
    # -> immediate fresh search).
