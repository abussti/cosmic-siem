"""
tools/ueba_engine.py — Day 46

UEBA (User and Entity Behavior Analytics) profiling engine.

Builds behavioral baseline profiles for users and hosts from ~30 days of
Elastic log data, following the same _post()/_get() convention every other
tool in this project uses (elastic_tools.py, hunt_loader.py,
baseline_builder.py) — no new ES client library introduced.

Design notes (full rationale in day46-ueba-profiling.md):
- Peer-group assignment uses a curated seed map (_DEPARTMENT_SEED), the
  same hybrid pattern Day 24 used for _THREAT_ACTOR_SEED: known
  users/hosts get a real department/peer-group, unknown ones fall back to
  a single "unassigned" group rather than crashing or guessing. This
  project has no AD/SSO identity source wired in yet (per the SIEM
  architecture diagram's "Identity" source chip, still unimplemented), so
  a curated table is the same honest stopgap Day 24 used for actor data.
- Reuses Day 28's login_count_per_day baseline (tools/baseline_builder.py)
  as a cross-check instead of only relying on this engine's own 30-day
  window — closes the standing P2 backlog item ("Wire login_count_per_day
  baseline into a consumer").
- risk_score is a transparent, additive 0-100 score based on deviation
  from generic norms (after-hours logins, source-IP fan-out, outbound
  volume) — not a black-box ML score, so an analyst can see exactly why a
  score fired. See "Upgrade Path" in the day report for a statistically
  grounded peer-group-deviation follow-up once enough profile history
  exists to support it.
"""

import datetime

try:
    from tools.elastic_tools import _post  # existing project convention
    ES_ALERTS_INDEX = "logs-wazuh.alerts-*"
except ImportError:
    # Allows standalone testing/demo outside the full repo checkout.
    _post = None
    ES_ALERTS_INDEX = "logs-wazuh.alerts-*"

try:
    from tools.baseline_builder import get_baseline
except ImportError:
    def get_baseline(baseline_type, entity):
        return None

UEBA_INDEX = "siem-ueba-profiles"
PROFILE_WINDOW_DAYS = 30

# ---------------------------------------------------------------------------
# Peer group seed table (Day 46) — same hybrid pattern as Day 24's
# _THREAT_ACTOR_SEED: curated known entries, safe fallback for everything else.
# Extend as real users/hosts are observed, same as the actor table's own
# extension note.
# ---------------------------------------------------------------------------
_DEPARTMENT_SEED = {
    "devadmin": "engineering",
    "root": "infrastructure",
    "www-data": "infrastructure",
    "agent1": "infrastructure",
}
DEFAULT_PEER_GROUP = "unassigned"


def _peer_group(entity_id):
    return _DEPARTMENT_SEED.get(entity_id, DEFAULT_PEER_GROUP)


def _time_range_filter(days):
    return {"range": {"@timestamp": {"gte": f"now-{days}d"}}}


def _query_es(body, index=None):
    if _post is None:
        raise RuntimeError("elastic_tools._post not available — run inside the real repo")
    return _post(f"{index or ES_ALERTS_INDEX}/_search", body)


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# User profiling
# ---------------------------------------------------------------------------
def build_user_profile(username, days=PROFILE_WINDOW_DAYS):
    """
    Queries the last `days` of activity for `username` and returns a
    structured behavioral profile. Never raises — any ES failure is caught
    and returns a profile with zeroed fields plus an `error` note, the same
    convention run_hunt()/run_yaml_hunt() already use.
    """
    profile = {
        "entity_type": "user",
        "entity_id": username,
        "peer_group": _peer_group(username),
        "avg_logins_per_day": 0.0,
        "typical_login_hours": [],
        "typical_source_ips": [],
        "source_ip_coverage": "unknown",
        "avg_commands_per_session": 0.0,
        "sessions_approximated": False,
        "typical_commands": [],
        "avg_outbound_bytes_per_day": 0.0,
        "volume_field_coverage": "unknown",
        "accessed_systems": [],
        "risk_score": 0,
        "sample_days": days,
        "computed_at": _now_iso(),
        "error": None,
    }

    try:
        # 1. Login pattern — hour-of-day + source IP distribution
        # BUG FIX (post-live-run, 27 July 2026): confirmed via a live
        # authentication_success query that PAM login events store
        # data.dstuser as a decorated form ("root(uid=0)"), while sudo
        # events for the same user store the plain form ("root") — a
        # real cross-rule-type formatting inconsistency, not a one-off.
        # An exact `term` match on the plain username therefore silently
        # matched 0 login events for every user while still matching sudo
        # events, producing avg_logins_per_day=0.0 across the board. Every
        # data.dstuser filter in this file now uses `prefix` instead of
        # `term`, so "root" correctly matches both "root" and
        # "root(uid=0)" without needing to know which decoration a given
        # rule type happens to use.
        login_body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"prefix": {"data.dstuser": username}},
                        {"terms": {"rule.groups": ["authentication_success"]}},
                    ],
                    "filter": [_time_range_filter(days)],
                }
            },
            "aggs": {
                # BUG FIX (post-live-run, 27 July 2026): the 221 real login
                # docs matched for `root` (login_count) but by_hour came
                # back with zero buckets against data.login_hour. Per this
                # project's own notes (project.md / Day 19 / phase2 test
                # methodology), data.login_hour is a scorer-convenience
                # field the pipeline stamps at processing time (and the
                # test injector sets directly) — it isn't guaranteed to
                # exist on raw, unprocessed historical alerts the way
                # @timestamp always does. Switched to a scripted terms agg
                # that derives hour-of-day straight from @timestamp, so
                # this no longer silently depends on an enrichment field
                # that may never have been written back onto older docs.
                "by_hour": {
                    "terms": {
                        "script": {
                            "source": "doc['@timestamp'].value.getHour()",
                            "lang": "painless",
                        },
                        # BUG FIX (post-live-run, 27 July 2026): without an
                        # explicit value_type, ES doesn't know the script
                        # returns a number and buckets by string
                        # representation instead — confirmed live: root's
                        # typical_login_hours came back as
                        # ['11','12','5','6','7','8','9'] (alphabetically
                        # sorted strings), which then crashed
                        # _score_user_risk()'s `h < 6` comparison with
                        # "'<' not supported between instances of 'str'
                        # and 'int'". value_type: "long" makes ES return
                        # real numeric keys.
                        "value_type": "long",
                        "size": 24,
                    }
                },
                "by_srcip": {"terms": {"field": "data.srcip", "size": 10}},
                "login_count": {"value_count": {"field": "@timestamp"}},
            },
        }
        login_raw = _query_es(login_body)
        aggs = login_raw.get("aggregations", {}) if login_raw else {}

        total_logins = aggs.get("login_count", {}).get("value", 0)
        profile["avg_logins_per_day"] = round(total_logins / days, 2) if days else 0.0
        # Defensive coercion (belt-and-suspenders alongside the value_type
        # fix above): even if a future ES version or query change ever
        # returns these keys as strings again, casting here means it can
        # never again reach _score_user_risk()'s numeric comparison and
        # crash the whole profile build. Non-numeric/unexpected keys are
        # skipped rather than raising.
        raw_hours = [b["key"] for b in aggs.get("by_hour", {}).get("buckets", [])]
        coerced_hours = []
        for h in raw_hours:
            try:
                coerced_hours.append(int(h))
            except (TypeError, ValueError):
                continue
        profile["typical_login_hours"] = sorted(coerced_hours)
        profile["typical_source_ips"] = [
            b["key"] for b in aggs.get("by_srcip", {}).get("buckets", [])
        ]
        # NOTE (post-live-run, 27 July 2026): `root` matched 221 real login
        # docs but returned zero data.srcip buckets. Rather than silently
        # leave typical_source_ips empty with no explanation (same class
        # of ambiguity Bug 2 turned out to be), this flags whether the
        # matched login events appear to carry a source-IP field at all —
        # PAM "session opened" events (rule 5501) may genuinely not carry
        # one unless correlated from an SSH-triggered login. Confirm with:
        #   curl .../logs-wazuh.alerts-*/_search -d
        #   '{"size":3,"query":{"bool":{"must":[{"prefix":{"data.dstuser":"root"}},
        #   {"terms":{"rule.groups":["authentication_success"]}}]}},
        #   "_source":["data.srcip","data.dstuser","rule.id"]}'
        if total_logins > 0 and not profile["typical_source_ips"]:
            profile["source_ip_coverage"] = "no_srcip_on_matched_login_events"
        else:
            profile["source_ip_coverage"] = "ok" if profile["typical_source_ips"] else "no_logins_matched"

        # FIX: when the login-scoped query has no source IPs (PAM
        # "session opened" events don't carry one), fall back to a
        # broader query across ANY rule type tied to this user where
        # data.srcip actually exists (e.g. SSH auth, firewall activity for
        # the same account) — gives real data instead of an empty list
        # wherever the account has any IP-attributed activity at all,
        # rather than only trusting the one rule type that happened to be
        # queried first.
        if not profile["typical_source_ips"]:
            srcip_fallback_body = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [{"prefix": {"data.dstuser": username}}],
                        "filter": [_time_range_filter(days), {"exists": {"field": "data.srcip"}}],
                    }
                },
                "aggs": {"srcips": {"terms": {"field": "data.srcip", "size": 10}}},
            }
            srcip_raw = _query_es(srcip_fallback_body)
            fallback_ips = [
                b["key"]
                for b in srcip_raw.get("aggregations", {}).get("srcips", {}).get("buckets", [])
            ] if srcip_raw else []
            if fallback_ips:
                profile["typical_source_ips"] = fallback_ips
                profile["source_ip_coverage"] = "ok_via_other_rule_types"
            elif profile["source_ip_coverage"] == "no_srcip_on_matched_login_events":
                profile["source_ip_coverage"] = "no_srcip_anywhere_for_user"

        # 2. Command usage — sudo/command-execution groups (matches Rules
        #    6-10's existing sudo rule group; no dedicated shell-history
        #    field exists in this schema, same constraint Hunt 3 lives with)
        cmd_body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [{"prefix": {"data.dstuser": username}}],
                    "filter": [_time_range_filter(days), {"terms": {"rule.groups": ["sudo"]}}],
                }
            },
            "aggs": {
                "top_commands": {"terms": {"field": "rule.description", "size": 20}},
                "cmd_count": {"value_count": {"field": "@timestamp"}},
            },
        }
        cmd_raw = _query_es(cmd_body)
        cmd_aggs = cmd_raw.get("aggregations", {}) if cmd_raw else {}
        total_cmds = cmd_aggs.get("cmd_count", {}).get("value", 0)
        # BUG FIX (post-live-run, 27 July 2026): when total_logins == 0 this
        # fallback silently relabels "total commands over the whole window"
        # as "per session" — exactly what happened live for `root` (207
        # sudo events / 1 fallback session = 207, with no real session data
        # behind it). sessions_approximated records when this fired, so a
        # profile reader isn't misled into treating 207 as a real
        # per-login average.
        sessions_approximated = total_logins == 0
        sessions = max(total_logins, 1)
        profile["avg_commands_per_session"] = round(total_cmds / sessions, 2)
        profile["sessions_approximated"] = sessions_approximated
        profile["typical_commands"] = [
            b["key"] for b in cmd_aggs.get("top_commands", {}).get("buckets", [])
        ]

        # 3. Outbound data volume (firewall-accept events; data.bytes_out
        #    is the same field Phase 2's exfil-volume gap fix reads).
        # BUG FIX (post-live-run, 27 July 2026): this query previously had
        # no per-user filter at all, so every profile silently received the
        # exact same site-wide total — confirmed live: devadmin, root, and
        # www-data all showed the identical 33333333.33 figure on the real
        # stack. Added a data.dstuser term filter so each profile reflects
        # traffic actually attributed to that user, not the whole site.
        vol_body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.groups": ["firewall"]}},
                        {"prefix": {"data.dstuser": username}},
                    ],
                    "filter": [_time_range_filter(days)],
                }
            },
            "aggs": {
                "total_bytes": {"sum": {"field": "data.bytes_out"}},
                # FIX: distinguishes "this user really moved 0 bytes" from
                # "data.bytes_out isn't populated on these alerts at all"
                # (per project.md's own Wazuh Alert Field Schema table,
                # data.bytes_out isn't a documented native field — every
                # prior mention of it in this project is in the context of
                # a synthetically injected test alert). value_count only
                # counts docs where the field is actually present.
                "bytes_out_doc_count": {"value_count": {"field": "data.bytes_out"}},
            },
        }
        vol_raw = _query_es(vol_body)
        vol_aggs = vol_raw.get("aggregations", {}) if vol_raw else {}
        total_bytes = vol_aggs.get("total_bytes", {}).get("value", 0)
        bytes_out_docs = vol_aggs.get("bytes_out_doc_count", {}).get("value", 0)
        profile["avg_outbound_bytes_per_day"] = round(total_bytes / days, 2) if days else 0.0
        profile["volume_field_coverage"] = "ok" if bytes_out_docs > 0 else "no_bytes_out_field_seen"

        # 4. Accessed systems — distinct agent.name this user authenticated to
        sys_body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [{"prefix": {"data.dstuser": username}}],
                    "filter": [_time_range_filter(days)],
                }
            },
            "aggs": {"systems": {"terms": {"field": "agent.name", "size": 20}}},
        }
        sys_raw = _query_es(sys_body)
        profile["accessed_systems"] = (
            [b["key"] for b in sys_raw.get("aggregations", {}).get("systems", {}).get("buckets", [])]
            if sys_raw
            else []
        )

        # 5. Cross-check against Day 28's login_count_per_day baseline
        baseline = get_baseline("login_count_per_day", username)
        if baseline:
            profile["baseline_avg_logins_per_day"] = baseline.get("avg_count")
            profile["baseline_status"] = "matched"
        else:
            profile["baseline_status"] = "no_baseline_yet"

        profile["risk_score"] = _score_user_risk(profile)

    except Exception as exc:  # never raise — same convention as run_hunt()
        profile["error"] = str(exc)

    return profile


# ---------------------------------------------------------------------------
# Entity (host) profiling
# ---------------------------------------------------------------------------
def build_entity_profile(hostname, days=PROFILE_WINDOW_DAYS):
    profile = {
        "entity_type": "host",
        "entity_id": hostname,
        "peer_group": _peer_group(hostname),
        "avg_connections": 0.0,
        "typical_ports": [],
        "typical_destinations": [],
        "avg_cpu_events": 0.0,
        "risk_score": 0,
        "sample_days": days,
        "computed_at": _now_iso(),
        "error": None,
    }

    try:
        conn_body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.name": hostname}},
                        {"terms": {"rule.groups": ["firewall"]}},
                    ],
                    "filter": [_time_range_filter(days)],
                }
            },
            "aggs": {
                "conn_count": {"value_count": {"field": "@timestamp"}},
                "dest_ips": {"terms": {"field": "data.srcip", "size": 10}},
            },
        }
        conn_raw = _query_es(conn_body)
        aggs = conn_raw.get("aggregations", {}) if conn_raw else {}
        total_conns = aggs.get("conn_count", {}).get("value", 0)
        profile["avg_connections"] = round(total_conns / days, 2) if days else 0.0
        profile["typical_destinations"] = [b["key"] for b in aggs.get("dest_ips", {}).get("buckets", [])]

        # NOTE: no destination-port field exists in this alert schema (same
        # gap Day 28 documented for Hunt 5 beaconing) — typical_ports stays
        # structurally present but empty until a port field is added.
        profile["typical_ports"] = []

        # NOTE: no CPU/process-event source is wired into this stack yet
        # (see Phase 2 completion report, Known Limitations) — avg_cpu_events
        # stays 0.0 until such a source exists; field kept so downstream
        # consumers don't need a shape change later.
        profile["avg_cpu_events"] = 0.0

        profile["risk_score"] = _score_entity_risk(profile)

    except Exception as exc:
        profile["error"] = str(exc)

    return profile


# ---------------------------------------------------------------------------
# Risk scoring — transparent, additive (see day46 report "Upgrade Path")
# ---------------------------------------------------------------------------
def _score_user_risk(profile):
    score = 0
    if profile["typical_login_hours"] and any(h < 6 or h > 22 for h in profile["typical_login_hours"]):
        score += 15
    if len(profile["typical_source_ips"]) > 5:
        score += 20
    if profile["avg_outbound_bytes_per_day"] > 50_000_000:  # 50MB/day
        score += 25
    if profile.get("baseline_status") == "no_baseline_yet":
        score += 5  # can't cross-validate against Day 28 baseline yet
    # Deliberately does NOT add points for a high avg_commands_per_session
    # when sessions_approximated is True — that figure is a mislabeled
    # 30-day total in that case (see live-run bug fix above), not a real
    # per-login average, and shouldn't drive risk scoring until the
    # underlying login-count-zero issue is resolved.
    return min(score, 100)


def _score_entity_risk(profile):
    score = 0
    if profile["avg_connections"] > 500:
        score += 20
    if len(profile["typical_destinations"]) > 15:
        score += 20
    return min(score, 100)


# ---------------------------------------------------------------------------
# ES persistence — same _post() convention as write_hunt_result_to_es() etc.
# ---------------------------------------------------------------------------
def write_ueba_profile_to_es(profile):
    doc = {
        "entity_type": profile["entity_type"],
        "entity_id": profile["entity_id"],
        "profile_json": profile,
        "last_updated": profile["computed_at"],
        "risk_score": profile["risk_score"],
    }
    if _post is None:
        return {"written": False, "reason": "no ES connection in this environment"}
    try:
        result = _post(f"{UEBA_INDEX}/_doc", doc)
        return {"written": True, "detail": result}
    except Exception as exc:
        return {"written": False, "reason": str(exc)}


def get_recent_ueba_profiles(size=20):
    if _post is None:
        return {"hits": {"hits": []}}
    body = {"size": size, "sort": [{"last_updated": "desc"}]}
    return _post(f"{UEBA_INDEX}/_search", body)


# ---------------------------------------------------------------------------
# Convenience: build + persist in one call, used by profile_scheduler.py
# ---------------------------------------------------------------------------
def refresh_user_profile(username):
    profile = build_user_profile(username)
    profile["_write_result"] = write_ueba_profile_to_es(profile)
    return profile


def refresh_entity_profile(hostname):
    profile = build_entity_profile(hostname)
    profile["_write_result"] = write_ueba_profile_to_es(profile)
    return profile


if __name__ == "__main__":
    for u in ["devadmin", "root", "www-data"]:
        p = build_user_profile(u)
        print(f"--- {u} ---")
        for k, v in p.items():
            print(f"  {k}: {v}")
