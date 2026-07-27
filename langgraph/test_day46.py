"""
test_day46.py — Day 46 test (mocked ES)

Follows the same mock-first pattern used since Day 18/24/29: this
authoring environment has no live ES connection, so _post() is
monkeypatched with realistic aggregation-shaped responses matching exactly
what build_user_profile()/build_entity_profile() query for. Swap the mock
for a real cluster on the real stack by simply not monkeypatching
tools.ueba_engine._post — no other code changes needed, same instruction
already given for test_day24.py / test_day29.py.
"""

import json

from tools import ueba_engine as ueba


def _fake_login_response():
    return {
        "aggregations": {
            "by_hour": {"buckets": [{"key": 9}, {"key": 10}, {"key": 14}, {"key": 22}]},
            "by_srcip": {"buckets": [{"key": "10.0.0.5"}, {"key": "10.0.0.6"}]},
            "login_count": {"value": 42},
        }
    }


def _fake_cmd_response():
    return {
        "aggregations": {
            "top_commands": {
                "buckets": [
                    {"key": "sudo apt update"},
                    {"key": "sudo systemctl restart nginx"},
                ]
            },
            "cmd_count": {"value": 18},
        }
    }


def _fake_vol_response(username="devadmin", doc_count_override=None):
    # Distinct per user so a regression back to the live-run bug (identical
    # site-wide total for every profile) would be caught immediately.
    per_user_bytes = {"devadmin": 300_000_000, "root": 90_000_000, "www-data": 15_000_000}
    total = per_user_bytes.get(username, 0)
    doc_count = doc_count_override if doc_count_override is not None else (5 if total else 0)
    return {
        "aggregations": {
            "total_bytes": {"value": total},
            "bytes_out_doc_count": {"value": doc_count},
        }
    }


def _fake_login_response_no_srcip():
    # Simulates the real live bug: login docs matched, hour data present,
    # but zero data.srcip buckets (PAM session-open events with no IP).
    return {
        "aggregations": {
            "by_hour": {"buckets": [{"key": 9}, {"key": 22}]},
            "by_srcip": {"buckets": []},
            "login_count": {"value": 221},
        }
    }


def _fake_srcip_fallback_response():
    return {"aggregations": {"srcips": {"buckets": [{"key": "198.51.100.7"}]}}}


def _fake_systems_response():
    return {"aggregations": {"systems": {"buckets": [{"key": "agent1"}]}}}


def _fake_conn_response():
    return {
        "aggregations": {
            "conn_count": {"value": 120},
            "dest_ips": {"buckets": [{"key": "203.0.113.5"}, {"key": "203.0.113.6"}]},
        }
    }


def _extract_dstuser(body):
    for clause in body.get("query", {}).get("bool", {}).get("must", []):
        if "prefix" in clause and "data.dstuser" in clause["prefix"]:
            return clause["prefix"]["data.dstuser"]
        if "term" in clause and "data.dstuser" in clause["term"]:
            return clause["term"]["data.dstuser"]
    return None


def _mock_query_post(path, body):
    # Route on the aggregation keys requested — same dispatch-by-shape
    # style used to mock google.genai / requests elsewhere in this project.
    aggs = body.get("aggs", {})
    if "by_hour" in aggs:
        return _fake_login_response()
    if "top_commands" in aggs:
        return _fake_cmd_response()
    if "total_bytes" in aggs:
        return _fake_vol_response(_extract_dstuser(body))
    if "systems" in aggs:
        return _fake_systems_response()
    if "conn_count" in aggs:
        return _fake_conn_response()
    if "srcips" in aggs:
        return _fake_srcip_fallback_response()
    return {"aggregations": {}}


def _mock_write_post(path, body):
    return {"result": "created", "_index": path.split("/")[0]}


def test_user_profiles():
    ueba._post = _mock_query_post
    results = {}
    for user in ["devadmin", "root", "www-data"]:
        profile = ueba.build_user_profile(user)
        results[user] = profile
        assert profile["entity_id"] == user
        assert profile["entity_type"] == "user"
        assert profile["avg_logins_per_day"] > 0
        assert profile["typical_login_hours"], "expected non-empty login hours"
        assert profile["typical_source_ips"], "expected non-empty source IPs"
        assert profile["avg_commands_per_session"] > 0
        assert profile["typical_commands"], "expected non-empty command list"
        assert profile["avg_outbound_bytes_per_day"] > 0
        assert profile["accessed_systems"], "expected non-empty accessed systems"
        assert 0 <= profile["risk_score"] <= 100
        assert profile["error"] is None
        assert profile["peer_group"] in ("engineering", "infrastructure", "unassigned")
        assert "sessions_approximated" in profile
        print(
            f"PASS — {user}: risk_score={profile['risk_score']} "
            f"peer_group={profile['peer_group']} "
            f"avg_logins_per_day={profile['avg_logins_per_day']} "
            f"avg_outbound_bytes_per_day={profile['avg_outbound_bytes_per_day']} "
            f"baseline_status={profile['baseline_status']}"
        )

    # Regression check for the live-run bug: every user must NOT share the
    # exact same outbound-bytes figure now that the query is user-scoped.
    values = {u: p["avg_outbound_bytes_per_day"] for u, p in results.items()}
    assert len(set(values.values())) == len(values), (
        f"avg_outbound_bytes_per_day is identical across users — the "
        f"per-user filter regressed: {values}"
    )
    print(f"PASS — avg_outbound_bytes_per_day is distinct per user: {values}")
    return results


def test_entity_profile():
    ueba._post = _mock_query_post
    profile = ueba.build_entity_profile("agent1")
    assert profile["entity_id"] == "agent1"
    assert profile["entity_type"] == "host"
    assert profile["avg_connections"] > 0
    assert profile["typical_destinations"]
    assert profile["error"] is None
    print(
        f"PASS — agent1 host profile: risk_score={profile['risk_score']} "
        f"avg_connections={profile['avg_connections']}"
    )
    return profile


def test_write_path():
    ueba._post = _mock_query_post
    profile = ueba.build_user_profile("devadmin")
    ueba._post = _mock_write_post
    result = ueba.write_ueba_profile_to_es(profile)
    assert result["written"] is True
    print("PASS — write_ueba_profile_to_es() succeeded against mocked ES")


def test_no_baseline_fallback():
    # get_baseline() falls back to None in this standalone environment
    # (no real baseline_builder/elastic_tools present) — confirms the
    # "no_baseline_yet" path is exercised, not silently skipped.
    ueba._post = _mock_query_post
    profile = ueba.build_user_profile("root")
    assert profile["baseline_status"] == "no_baseline_yet"
    print("PASS — baseline cross-check correctly reports 'no_baseline_yet' when absent")


def test_dstuser_uses_prefix_not_term():
    # Regression guard for the live-run bug: real authentication_success
    # events store data.dstuser as a decorated form ("root(uid=0)") while
    # sudo events for the same user store the plain form ("root"). An
    # exact `term` match silently missed every login event while still
    # matching sudo events. Every data.dstuser filter must use `prefix`
    # so "root" matches both forms without needing to know which
    # decoration a given rule type uses.
    captured_bodies = []

    def _capturing_post(path, body):
        captured_bodies.append(body)
        return _mock_query_post(path, body)

    ueba._post = _capturing_post
    ueba.build_user_profile("root")

    dstuser_clauses = []
    for body in captured_bodies:
        for clause in body.get("query", {}).get("bool", {}).get("must", []):
            if "data.dstuser" in clause.get("term", {}):
                dstuser_clauses.append(("term", clause))
            if "data.dstuser" in clause.get("prefix", {}):
                dstuser_clauses.append(("prefix", clause))

    assert dstuser_clauses, "expected at least one data.dstuser filter to be issued"
    bad = [c for kind, c in dstuser_clauses if kind == "term"]
    assert not bad, f"found exact `term` match(es) on data.dstuser — should be `prefix`: {bad}"
    print(f"PASS — all {len(dstuser_clauses)} data.dstuser filter(s) use `prefix`, not `term`")


def test_srcip_fallback_when_login_query_empty():
    # Reproduces the real live gap: root matched 221 login docs (by_hour
    # populated) but zero data.srcip buckets on the login-scoped query
    # (PAM session-open events don't carry one). The engine should fall
    # back to a broader, rule-type-agnostic srcip query instead of giving
    # up with an empty list.
    def _mock_with_empty_login_srcip(path, body):
        aggs = body.get("aggs", {})
        if "by_hour" in aggs:
            return _fake_login_response_no_srcip()
        if "srcips" in aggs:
            return _fake_srcip_fallback_response()
        return _mock_query_post(path, body)

    ueba._post = _mock_with_empty_login_srcip
    profile = ueba.build_user_profile("root")
    assert profile["typical_source_ips"] == ["198.51.100.7"], profile["typical_source_ips"]
    assert profile["source_ip_coverage"] == "ok_via_other_rule_types"
    print(
        f"PASS — source-IP fallback recovered {profile['typical_source_ips']} "
        f"via other rule types when the login query had none"
    )


def test_srcip_coverage_when_truly_absent():
    # If the fallback query also comes back empty, the engine must report
    # this honestly (no_srcip_anywhere_for_user) instead of silently
    # returning an empty list with no explanation.
    def _mock_no_srcip_anywhere(path, body):
        aggs = body.get("aggs", {})
        if "by_hour" in aggs:
            return _fake_login_response_no_srcip()
        if "srcips" in aggs:
            return {"aggregations": {"srcips": {"buckets": []}}}
        return _mock_query_post(path, body)

    ueba._post = _mock_no_srcip_anywhere
    profile = ueba.build_user_profile("root")
    assert profile["typical_source_ips"] == []
    assert profile["source_ip_coverage"] == "no_srcip_anywhere_for_user"
    print("PASS — correctly reports 'no_srcip_anywhere_for_user' when genuinely absent")


def test_volume_field_coverage():
    # ok case: bytes_out_doc_count > 0 alongside a real sum
    ueba._post = _mock_query_post
    profile = ueba.build_user_profile("devadmin")
    assert profile["volume_field_coverage"] == "ok"

    # gap case: field never populated on any matched firewall doc for this
    # user — must be distinguished from "real zero volume"
    def _mock_no_bytes_out_field(path, body):
        aggs = body.get("aggs", {})
        if "total_bytes" in aggs:
            return _fake_vol_response(username="unknown_user", doc_count_override=0)
        return _mock_query_post(path, body)

    ueba._post = _mock_no_bytes_out_field
    profile2 = ueba.build_user_profile("devadmin")
    assert profile2["avg_outbound_bytes_per_day"] == 0.0
    assert profile2["volume_field_coverage"] == "no_bytes_out_field_seen"
    print("PASS — volume_field_coverage distinguishes real-zero from field-not-populated")


def test_string_typed_hour_keys_do_not_crash():
    # Reproduces the exact live bug: ES returned by_hour bucket keys as
    # strings ('11','12','5',...) instead of ints, because the scripted
    # terms agg had no value_type hint. That crashed _score_user_risk()'s
    # `h < 6` comparison with "'<' not supported between instances of
    # 'str' and 'int'". The query now sets value_type: "long", and this
    # test additionally confirms the Python-side defensive int-coercion
    # holds even if a mock/future ES response ever returns string keys
    # again — the profile must build cleanly with no `error`, and hours
    # must come back as real ints, correctly numerically sorted (not
    # alphabetically, which is how the live bug first showed itself:
    # ['11','12','5','6','7','8','9']).
    def _mock_string_hour_keys(path, body):
        aggs = body.get("aggs", {})
        if "by_hour" in aggs:
            return {
                "aggregations": {
                    "by_hour": {
                        "buckets": [
                            {"key": "11"}, {"key": "12"}, {"key": "5"},
                            {"key": "6"}, {"key": "7"}, {"key": "8"}, {"key": "9"},
                        ]
                    },
                    "by_srcip": {"buckets": [{"key": "203.0.113.77"}]},
                    "login_count": {"value": 221},
                }
            }
        return _mock_query_post(path, body)

    ueba._post = _mock_string_hour_keys
    profile = ueba.build_user_profile("root")
    assert profile["error"] is None, f"profile build crashed: {profile['error']}"
    assert profile["typical_login_hours"] == [5, 6, 7, 8, 9, 11, 12], profile["typical_login_hours"]
    assert all(isinstance(h, int) for h in profile["typical_login_hours"])
    assert 0 <= profile["risk_score"] <= 100
    print(
        f"PASS — string-typed hour keys coerced to real ints and numerically "
        f"sorted: {profile['typical_login_hours']} (risk_score={profile['risk_score']}, no crash)"
    )


if __name__ == "__main__":
    print("=== Day 46 — UEBA Profiling Engine test ===\n")
    profiles = test_user_profiles()
    print()
    test_entity_profile()
    print()
    test_write_path()
    print()
    test_no_baseline_fallback()
    print()
    test_dstuser_uses_prefix_not_term()
    print()
    test_srcip_fallback_when_login_query_empty()
    print()
    test_srcip_coverage_when_truly_absent()
    print()
    test_volume_field_coverage()
    print()
    test_string_typed_hour_keys_do_not_crash()
    print("\nAll Day 46 checks passed.\n")
    print("Sample profile (devadmin):")
    print(json.dumps(profiles["devadmin"], indent=2, default=str))
