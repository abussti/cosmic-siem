"""
tools/blast_radius.py

Day 42 — Blast Radius Mapper

Given a compromised host, builds an adjacency graph of hosts it can reach,
via three independent signals:
  1. Recent network connections (last 30d) — same (agent.name, data.srcip)
     field pattern Hunt 1 (lateral_movement_ssh) and Hunt 5 (beaconing) use.
  2. Subnet co-location — best-effort, IP-prefix based (see Gap 1 below).
  3. Shared user access — same user seen authenticating successfully on
     other hosts, same pattern as the lateral-movement hunt.

Follows this project's existing conventions:
  - all ES access goes through _post() from tools.elastic_tools (no direct
    elasticsearch-py client — matches every other tool in this repo)
  - never raises; ES errors are caught and folded into the result with an
    'error' note, same as run_hunt() / run_yaml_hunt()
  - every call is written to siem-blast-radius, success or not, same
    "every cycle recorded" principle as write_hunt_result_to_es()
"""

import json
import datetime
from tools.elastic_tools import _post

ALERTS_INDEX = "logs-wazuh.alerts-*"
BLAST_RADIUS_INDEX = "siem-blast-radius"
LOOKBACK_DAYS = 30

# ── connection-type inference ──────────────────────────────────────────────
# Inferred from rule.groups (and, where present, a data.port-style field).
# Extend this table as new rule.groups values are observed in real data —
# same "registry is plain data" philosophy as DEFAULT_PLAYBOOKS (Day 26).
#
# Split into a priority tier (specific protocol) and a fallback tier
# (generic auth). Found necessary during the Day 42 live test: an SSH
# login alert carries BOTH "sshd" and "authentication_success" in
# rule.groups, and a naive first-match-in-list-order scan returned "AUTH"
# instead of "SSH" whenever the generic group happened to appear earlier
# in the list — order in rule.groups isn't a reliable priority signal.
PROTOCOL_GROUP_TO_CONN_TYPE = {
    "sshd": "SSH",
    "ssh": "SSH",
    "smb": "SMB",
    "cifs": "SMB",
    "rdp": "RDP",
    "web": "HTTP",
    "http": "HTTP",
}
AUTH_GROUP_TO_CONN_TYPE = {
    "authentication_success": "AUTH",
    "authentication_failed": "AUTH",
}
# Kept for backward compatibility with anything importing the old name.
GROUP_TO_CONN_TYPE = {**AUTH_GROUP_TO_CONN_TYPE, **PROTOCOL_GROUP_TO_CONN_TYPE}

# GAP: no asset/criticality table exists yet in this project (no CMDB,
# no `siem-assets` index). Using a flat placeholder so blast_score is
# computable today. Flagged here rather than blocking on building a real
# criticality index — same "gap, not a blocker" pattern used throughout
# this project's daily logs (e.g. Day 24's actor-seed table, Day 28's
# baseline placeholders).
DEFAULT_CRITICALITY_SCORE = 50


def _infer_connection_type(rule_groups):
    """
    rule_groups: list[str] from an alert's rule.groups field.
    Checks protocol-specific groups first (SSH/SMB/RDP/HTTP), then falls
    back to generic auth groups, then 'unknown'. Order within rule_groups
    itself is NOT trusted as a priority signal (see table comment above) —
    both tiers are scanned fully before falling back.
    """
    if not rule_groups:
        return "unknown"
    lowered = [g.lower() for g in rule_groups]
    for group in lowered:
        conn_type = PROTOCOL_GROUP_TO_CONN_TYPE.get(group)
        if conn_type:
            return conn_type
    for group in lowered:
        conn_type = AUTH_GROUP_TO_CONN_TYPE.get(group)
        if conn_type:
            return conn_type
    return "unknown"


def _time_range_filter(days=LOOKBACK_DAYS):
    return {"range": {"@timestamp": {"gte": f"now-{days}d"}}}


def _query_recent_connections(compromised_host):
    """
    Signal 1 — hosts compromised_host has connected to/from in the last
    LOOKBACK_DAYS. Same field pattern as Hunt 1 (lateral_movement_ssh) and
    Hunt 5 (beaconing_c2_pattern): agent.name = the host that logged the
    event, data.srcip = the source of the connection. Firewall/auth alerts
    in this schema carry no data.dstip (confirmed Day 28), so "X connected
    to Y" is inferred as: Y is the agent.name on an alert where
    data.srcip matches an IP known to belong to compromised_host, OR
    compromised_host itself is the agent.name and some other host's IP
    shows up as data.srcip talking to it.

    We treat `compromised_host` as matching EITHER agent.name or
    data.srcip so it works whether the caller passes a hostname or an IP.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [_time_range_filter()],
                "should": [
                    {"term": {"agent.name": compromised_host}},
                    {"term": {"data.srcip": compromised_host}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "peer_hosts": {
                "terms": {"field": "agent.name", "size": 100},
                "aggs": {
                    "groups": {
                        "terms": {"field": "rule.groups", "size": 10}
                    }
                },
            },
            "peer_ips": {
                "terms": {"field": "data.srcip", "size": 100},
                "aggs": {
                    "groups": {
                        "terms": {"field": "rule.groups", "size": 10}
                    }
                },
            },
        },
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        return raw, None
    except Exception as e:
        return None, str(e)


def _query_same_subnet(compromised_host, subnet_prefix=None):
    """
    Signal 2 — hosts sharing the same subnet as compromised_host.

    GAP: there is no asset/CMDB index in this project mapping hostnames to
    IPs/subnets, so this is a best-effort IP-prefix match against whatever
    IPs already appear in logs-wazuh.alerts-*. If `subnet_prefix` isn't
    supplied by the caller (e.g. "192.168.56."), and compromised_host
    doesn't look like an IP itself, this signal is skipped and flagged
    rather than guessed at — same "don't fabricate, flag it" discipline
    used for get_threat_actor_profile()'s not_found path (Day 24).

    KNOWN LIMITATION (found Day 42 live test): a wildcard match on a shared
    test range (e.g. 203.0.113.0/24, reused across many earlier days' test
    injections) pulls in every historical IP ever logged in that prefix
    within the lookback window, not just currently-relevant neighbors —
    there's no way to distinguish "real subnet member" from "leftover test
    data" without an asset inventory. Caller can pass
    network_data={"disable_signals": ["subnet"]} to exclude this signal
    entirely (e.g. for isolating the other two signals in a test).
    """
    if subnet_prefix is None:
        if compromised_host.count(".") == 3:
            subnet_prefix = ".".join(compromised_host.split(".")[:3]) + "."
        else:
            return None, "skipped — no subnet_prefix given and compromised_host is not an IP (GAP: no asset/CMDB index to resolve hostname -> subnet)"

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [_time_range_filter()],
                "must": [
                    {
                        "wildcard": {
                            "data.srcip": f"{subnet_prefix}*"
                        }
                    }
                ],
            }
        },
        "aggs": {
            "subnet_ips": {"terms": {"field": "data.srcip", "size": 200}}
        },
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        return raw, None
    except Exception as e:
        return None, str(e)


def _query_shared_user_access(compromised_host):
    """
    Signal 3 — other hosts where a user seen on compromised_host has
    successfully authenticated. Same pattern as the lateral-movement hunt:
    find the user(s) active on compromised_host, then look for that same
    user's successful auth events on OTHER agent.name hosts.
    """
    # Step A: find users active on compromised_host in the lookback window
    users_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    _time_range_filter(),
                    {"term": {"agent.name": compromised_host}},
                    {"terms": {"rule.groups": ["authentication_success", "pam"]}},
                ]
            }
        },
        "aggs": {"users": {"terms": {"field": "data.dstuser", "size": 20}}},
    }
    try:
        users_raw = _post(f"{ALERTS_INDEX}/_search", users_body)
    except Exception as e:
        return None, str(e)

    buckets = (
        users_raw.get("aggregations", {})
        .get("users", {})
        .get("buckets", [])
    )
    users = [b["key"] for b in buckets]
    if not users:
        return {"users": [], "hosts_by_user": {}}, None

    # Step B: for each user, find other hosts they've logged into
    hosts_by_user = {}
    for user in users:
        host_body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        _time_range_filter(),
                        {"term": {"data.dstuser": user}},
                        {"terms": {"rule.groups": ["authentication_success", "pam"]}},
                    ],
                    "must_not": [{"term": {"agent.name": compromised_host}}],
                }
            },
            "aggs": {"hosts": {"terms": {"field": "agent.name", "size": 50}}},
        }
        try:
            host_raw = _post(f"{ALERTS_INDEX}/_search", host_body)
            host_buckets = (
                host_raw.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            )
            hosts_by_user[user] = [b["key"] for b in host_buckets]
        except Exception as e:
            hosts_by_user[user] = {"error": str(e)}

    return {"users": users, "hosts_by_user": hosts_by_user}, None


def map_blast_radius(compromised_host, network_data=None):
    """
    Main entry point.

    Args:
        compromised_host: hostname (agent.name) or IP of the compromised host
        network_data: optional dict, may include:
            {"subnet_prefix": "192.168.56."}  — overrides subnet inference
            {"criticality": {"host1": 80, "host2": 40, ...}}  — per-host
                criticality overrides; anything not listed falls back to
                DEFAULT_CRITICALITY_SCORE (GAP — see module docstring)

    Returns a dict:
        {
            "compromised_host": str,
            "graph": {compromised_host: [{"host": ..., "connection_type": ...}, ...]},
            "reachable_hosts": [unique host list],
            "blast_score": float,
            "signals": {...raw per-signal detail, for audit/debugging...},
            "errors": [...],
        }

    Never raises — every ES call is wrapped; failures are recorded in
    'errors' and that signal simply contributes nothing to the graph,
    same fail-soft pattern as run_hunt()/run_yaml_hunt().
    """
    network_data = network_data or {}
    disabled = set(network_data.get("disable_signals", []))
    errors = []
    edges = {}  # host -> {"connection_type": type}  (dedup by host)

    # ── Signal 1: recent connections ──────────────────────────────────────
    if "connections" in disabled:
        conn_raw, conn_err = {}, None
    else:
        conn_raw, conn_err = _query_recent_connections(compromised_host)
    if conn_err:
        errors.append(f"recent_connections: {conn_err}")
        conn_raw = {}
    else:
        aggs = conn_raw.get("aggregations", {})
        for bucket_name in ("peer_hosts", "peer_ips"):
            for bucket in aggs.get(bucket_name, {}).get("buckets", []):
                peer = bucket["key"]
                if peer == compromised_host:
                    continue
                group_buckets = bucket.get("groups", {}).get("buckets", [])
                groups = [g["key"] for g in group_buckets]
                conn_type = _infer_connection_type(groups)
                # keep the most specific (non-'unknown') type seen
                if peer not in edges or edges[peer]["connection_type"] == "unknown":
                    edges[peer] = {"connection_type": conn_type, "source": "connections"}

    # ── Signal 2: same subnet ──────────────────────────────────────────────
    if "subnet" in disabled:
        subnet_raw, subnet_err = None, None
    else:
        subnet_raw, subnet_err = _query_same_subnet(
            compromised_host, network_data.get("subnet_prefix")
        )
    if subnet_err:
        errors.append(f"same_subnet: {subnet_err}")
    elif subnet_raw:
        buckets = subnet_raw.get("aggregations", {}).get("subnet_ips", {}).get("buckets", [])
        for bucket in buckets:
            peer = bucket["key"]
            if peer == compromised_host:
                continue
            if peer not in edges:
                edges[peer] = {"connection_type": "subnet", "source": "subnet"}

    # ── Signal 3: shared user access ───────────────────────────────────────
    if "shared_user" in disabled:
        user_raw, user_err = None, None
    else:
        user_raw, user_err = _query_shared_user_access(compromised_host)
    if user_err:
        errors.append(f"shared_user_access: {user_err}")
    elif user_raw:
        for user, hosts in user_raw.get("hosts_by_user", {}).items():
            if isinstance(hosts, dict) and "error" in hosts:
                errors.append(f"shared_user_access[{user}]: {hosts['error']}")
                continue
            for peer in hosts:
                if peer == compromised_host:
                    continue
                if peer not in edges or edges[peer]["connection_type"] in ("unknown", "subnet"):
                    edges[peer] = {"connection_type": "AUTH", "source": "shared_user"}

    reachable_hosts = sorted(edges.keys())
    graph = {
        compromised_host: [
            {"host": host, "connection_type": info["connection_type"]}
            for host, info in edges.items()
        ]
    }

    # ── scoring ─────────────────────────────────────────────────────────
    criticality_overrides = network_data.get("criticality", {})
    if reachable_hosts:
        crit_scores = [
            criticality_overrides.get(h, DEFAULT_CRITICALITY_SCORE) for h in reachable_hosts
        ]
        avg_criticality = sum(crit_scores) / len(crit_scores)
    else:
        avg_criticality = 0
    blast_score = len(reachable_hosts) * avg_criticality

    return {
        "compromised_host": compromised_host,
        "graph": graph,
        "reachable_hosts": reachable_hosts,
        "blast_score": blast_score,
        "signals": {
            "recent_connections_raw": conn_raw,
            "subnet_raw": subnet_raw,
            "shared_user_raw": user_raw,
        },
        "errors": errors,
    }


def write_blast_radius_to_es(result, incident_id=None):
    """
    Writes a map_blast_radius() result to siem-blast-radius.
    Never raises — mirrors write_hunt_result_to_es()/write_response_log_entry().
    """
    doc = {
        "incident_id": incident_id or f"br-{compromised_host_slug(result['compromised_host'])}-{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}",
        "compromised_host": result["compromised_host"],
        "reachable_hosts": result["reachable_hosts"],
        "graph_json": json.dumps(result["graph"]),
        "blast_score": result["blast_score"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        resp = _post(f"{BLAST_RADIUS_INDEX}/_doc", doc)
        return {"success": True, "detail": resp}
    except Exception as e:
        return {"success": False, "detail": str(e)}


def compromised_host_slug(host):
    return str(host).replace(".", "-").replace(":", "-")


if __name__ == "__main__":
    # Standalone smoke test — same pattern as `python3 -m tools.hunt_loader`
    # or `python3 -m agents.response_agent`. Replace 'agent1' with whatever
    # host you're testing against.
    test_host = "agent1"
    print(f"=== map_blast_radius({test_host!r}) ===")
    result = map_blast_radius(test_host)
    print("reachable_hosts:", result["reachable_hosts"])
    print("blast_score:", result["blast_score"])
    print("errors:", result["errors"])

    write_result = write_blast_radius_to_es(result)
    print("write_blast_radius_to_es:", write_result)
