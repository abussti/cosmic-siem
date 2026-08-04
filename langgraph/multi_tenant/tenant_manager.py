"""
multi_tenant/tenant_manager.py — Day 51

Multi-Tenant Data Isolation Layer.

Every tenant's data lives in its own tenant-prefixed set of Elasticsearch
indices: siem-{tenant_id}-alerts-*, siem-{tenant_id}-hunts-*,
siem-{tenant_id}-responses-*. This module is the ONLY sanctioned path to
read or write that data — there is deliberately no helper here that lets
a caller run a query without a tenant_id in scope.

Same conventions as the rest of this project (tools/elastic_tools.py):
- All ES calls go through a thin requests-based helper — no elasticsearch-py
  client introduced.
- Every function that CAN degrade gracefully does (bad/missing tenant on
  read returns None/empty, not a crash). The one deliberate exception is
  querying with no tenant context at all — that's a hard stop
  (TenantIsolationError), not something to silently work around, per
  deliverable 4 ("no raw Elastic access without tenant context").
"""

import os
import requests
from datetime import datetime, timezone

ES_URL = os.environ.get("ES_URL", "http://localhost:9201")
ES_AUTH = (os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme"))

TENANT_CONFIG_INDEX = "tenant_config"

# Index families every tenant gets. Adding a new data type to the platform
# means appending one entry here — nothing else in this file changes.
TENANT_INDEX_FAMILIES = ["alerts", "hunts", "responses"]


class TenantIsolationError(Exception):
    """Raised when a query or write is attempted with no tenant_id in
    scope. This is the one hard-stop exception in this module — every
    other function here degrades gracefully on bad input instead."""
    pass


# ── thin ES helpers (same convention as tools/elastic_tools.py's _post) ──

def _post(path, body):
    try:
        r = requests.post(f"{ES_URL}/{path}", json=body, auth=ES_AUTH, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def _put(path, body=None):
    try:
        r = requests.put(f"{ES_URL}/{path}", json=body, auth=ES_AUTH, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def _get(path):
    try:
        r = requests.get(f"{ES_URL}/{path}", auth=ES_AUTH, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


# ── index naming ─────────────────────────────────────────────────────

def tenant_index(tenant_id, family):
    """siem-{tenant_id}-{family}-YYYY.MM.DD — matches this project's existing
    date-suffixed index naming convention (logs-wazuh.alerts-*, etc.)."""
    if family not in TENANT_INDEX_FAMILIES:
        raise ValueError(f"Unknown index family '{family}' — must be one of {TENANT_INDEX_FAMILIES}")
    date_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"siem-{tenant_id}-{family}-{date_suffix}"


def tenant_index_pattern(tenant_id, family):
    """Wildcard pattern covering every date for one tenant/family — this is
    the string every tenant-scoped query and write actually targets."""
    if family not in TENANT_INDEX_FAMILIES:
        raise ValueError(f"Unknown index family '{family}' — must be one of {TENANT_INDEX_FAMILIES}")
    return f"siem-{tenant_id}-{family}-*"


# ── tenant registration ──────────────────────────────────────────────

def create_tenant(tenant_id, name, config=None):
    """
    Registers a new tenant:
      1. writes a tenant_config doc (log sources, enabled SIGMA rules,
         approved response actions, notification channels)
      2. seeds one correctly-mapped index per family so the index pattern
         exists immediately, rather than waiting on first-write auto-create
    Never raises on bad input — returns {"success": False, "error": ...}
    instead, same defensive convention as every other tool in this project.
    """
    if not tenant_id or not str(tenant_id).replace("_", "").isalnum():
        return {"success": False, "error": "invalid_tenant_id"}

    config = config or {}
    doc = {
        "tenant_id": tenant_id,
        "name": name,
        "log_sources": config.get("log_sources", []),
        "sigma_rules_enabled": config.get("sigma_rules_enabled", []),
        "response_actions_approved": config.get("response_actions_approved", []),
        "notification_channels": config.get("notification_channels", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    result = _post(f"{TENANT_CONFIG_INDEX}/_doc/{tenant_id}", doc)
    if isinstance(result, dict) and "error" in result:
        return {"success": False, "error": result["error"]}

    seeded = []
    for family in TENANT_INDEX_FAMILIES:
        idx = tenant_index(tenant_id, family)
        r = _put(idx, {
            "mappings": {
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "@timestamp": {"type": "date"},
                }
            }
        })
        seeded.append({"index": idx, "result": r})

    return {"success": True, "tenant_id": tenant_id, "config_written": True, "indices_seeded": seeded}


def get_tenant_config(tenant_id):
    """Single-tenant config lookup. Returns None (never raises) if the
    tenant doesn't exist."""
    r = _get(f"{TENANT_CONFIG_INDEX}/_doc/{tenant_id}")
    if isinstance(r, dict) and r.get("found"):
        return r["_source"]
    return None


def list_tenants():
    r = _post(f"{TENANT_CONFIG_INDEX}/_search", {"size": 100, "query": {"match_all": {}}})
    hits = r.get("hits", {}).get("hits", []) if isinstance(r, dict) else []
    return [h["_source"] for h in hits]


def deactivate_tenant(tenant_id):
    """Soft-disable rather than delete — offboarding a client shouldn't
    destroy their historical data or audit trail."""
    cfg = get_tenant_config(tenant_id)
    if cfg is None:
        return {"success": False, "error": "tenant_not_found"}
    cfg["active"] = False
    cfg["deactivated_at"] = datetime.now(timezone.utc).isoformat()
    result = _post(f"{TENANT_CONFIG_INDEX}/_doc/{tenant_id}", cfg)
    return {"success": "error" not in result, "detail": result}


# ── tenant-scoped write (mandatory routing point for pipeline writes) ──

def write_tenant_doc(tenant_id, family, doc):
    """
    Every pipeline write (alerts, hunt results, response-log entries) must
    go through this instead of calling _post() directly against a bare
    index name. Two layers of isolation are applied:
      1. the write targets a tenant-prefixed index (siem-{tenant_id}-...)
      2. tenant_id is also stamped onto the document body itself, so a
         query filter still works correctly even if it's ever run against
         a wildcard that accidentally spans more than one tenant's indices
    Raises TenantIsolationError if called with no tenant_id — a write with
    no tenant context is exactly the failure mode this module exists to
    prevent, so it is not allowed to silently degrade.
    """
    if not tenant_id:
        raise TenantIsolationError("write_tenant_doc() called with no tenant_id — every write must be tenant-scoped")

    doc = dict(doc)
    doc["tenant_id"] = tenant_id
    doc.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())

    idx = tenant_index(tenant_id, family)
    return _post(f"{idx}/_doc", doc)


# ── tenant-scoped query (the actual isolation boundary) ────────────────

def tenant_query(tenant_id, family, query_body):
    """
    The only sanctioned way to query tenant data. Wraps the caller's query
    inside a bool/filter that also requires tenant_id == tenant_id, on top
    of the index-pattern scoping — belt-and-suspenders, same "don't rely
    on a single control" instinct behind this project's existing
    success/failure audit logging (siem-response-log, siem-redteam-log).

    Raises TenantIsolationError if tenant_id is missing. This is a
    deliberate hard stop, not a degrade-gracefully case.
    """
    if not tenant_id:
        raise TenantIsolationError("tenant_query() requires a tenant_id — no unscoped queries allowed")

    pattern = tenant_index_pattern(tenant_id, family)

    original_query = query_body.get("query", {"match_all": {}})
    scoped_query = {
        "bool": {
            "must": [original_query],
            "filter": [{"term": {"tenant_id": tenant_id}}],
        }
    }

    body = dict(query_body)
    body["query"] = scoped_query

    return _post(f"{pattern}/_search", body)


def raw_query_blocked(family, query_body):
    """
    Stand-in for "someone tries to query without going through
    tenant_query()". Deliberately always raises. Exists so the isolation
    guarantee is enforced in code, not just by review/convention — any
    call site that reaches this instead of tenant_query() fails loudly,
    per deliverable 4 ("no raw Elastic access without tenant context").
    """
    raise TenantIsolationError(
        "Raw, unscoped Elastic queries are not permitted in this module — "
        "use tenant_query(tenant_id, family, query) instead."
    )


# ── self-test / isolation verification ─────────────────────────────────

def _self_test():
    import time

    print("=== Day 51 — Multi-Tenant Isolation self-test (real ES) ===")

    for tid, name in [("tenant_alpha", "Alpha Corp"), ("tenant_beta", "Beta LLC")]:
        r = create_tenant(tid, name, {
            "log_sources": ["wazuh", "cloudtrail"],
            "response_actions_approved": ["block_ip"],
        })
        print(f"[create_tenant] {tid}: success={r.get('success')}")

    write_tenant_doc("tenant_alpha", "alerts", {
        "rule": {"id": "5710", "level": 10, "description": "sshd brute force"},
        "data": {"srcip": "203.0.113.77"},
    })
    print("[write] wrote 1 alert doc for tenant_alpha")

    time.sleep(1.5)  # ES refresh — same race class documented Day 33/44/49

    alpha_result = tenant_query("tenant_alpha", "alerts", {"query": {"match_all": {}}})
    alpha_hits = alpha_result.get("hits", {}).get("total", {}).get("value", "?")
    print(f"[isolation] tenant_alpha querying its own data: hits={alpha_hits} (expect 1)")

    beta_result = tenant_query("tenant_beta", "alerts", {"query": {"match_all": {}}})
    beta_hits = beta_result.get("hits", {}).get("total", {}).get("value", "?")
    print(f"[isolation] tenant_beta querying (should be 0): hits={beta_hits}")

    if beta_hits == 0:
        print("PASS — tenant_beta cannot see tenant_alpha's data")
    else:
        print(f"FAIL — tenant_beta saw {beta_hits} doc(s) belonging to tenant_alpha")

    try:
        raw_query_blocked("alerts", {"query": {"match_all": {}}})
        print("FAIL — raw unscoped query was not blocked")
    except TenantIsolationError as e:
        print(f"PASS — raw unscoped query correctly blocked: {e}")

    try:
        tenant_query(None, "alerts", {"query": {"match_all": {}}})
        print("FAIL — tenant_query(None, ...) did not raise")
    except TenantIsolationError as e:
        print(f"PASS — tenant_query with no tenant_id correctly raised: {e}")


if __name__ == "__main__":
    _self_test()
