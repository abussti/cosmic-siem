"""
tools/insider_threat.py — Day 49

Insider Threat Detection Module — uses UEBA profiles (Day 46/47) to detect
insider-threat indicators that no single SIGMA/correlation rule would catch:
credential hoarding, data staging, access broadening, and schedule shift.
All four look at behavior across days/weeks, not a single event.

### Design Decision — Not Run Through hunt_loader.py
hunt_loader.py's run_yaml_hunt() (Day 27/28) normalizes a *single* Elastic
DSL clause per hunt — one aggregation or one hit-based query, with the
threshold enforced either server-side (bucket_selector) or against a flat
finding_threshold in Python. None of the four detections below fit that
shape: each needs multiple sequential queries (a peer-group comparison, a
UEBA baseline lookup, a multi-day consecutive-run count) plus real branching
logic in between. Same principle Day 26 used to split reactive vs. proactive
hunting into two engines instead of forcing one shape onto both — this gets
its own runner instead.

The hunts/hunt_insider_*.yml files still exist and are still "hunts as data,
not code" (Day 27's founding principle) — they hold the tunable thresholds,
hypothesis text, mitre_technique, and escalate_if_found flag — but they're
loaded by load_insider_playbook_config() below, not by
hunt_loader.load_hunt_playbooks(). Adding a 5th insider hunt means adding a
YAML file + one Python detection function, same "append, don't rewire"
spirit as DEFAULT_PLAYBOOKS / hunt_loader's registry.

### Design Decision — Escalation Bypasses Normal Confidence Routing
Same pre-scored override pattern Day 24 used for CTI confidence>80 and
Day 29 used for hunt escalation: an insider finding that already cleared
its own detection threshold (5x peer average, 10x baseline volume, etc.)
doesn't need to be re-scored by confidence_scorer.py as if it were a raw,
unvetted alert. escalate_insider_finding_to_coordination() builds a
synthetic alert, pre-sets confidence_pct=INSIDER_ESCALATION_CONFIDENCE_PCT
(90 — higher than the generic hunt escalation's 85, since these findings
are corroborated against a personal baseline, not just a static rule), and
tags the alert/state with INSIDER_ESCALATION_TAG so downstream consumers
(SOC dashboard, response agent) can distinguish these from ordinary
triage-originated alerts at a glance.

### Design Decision — Peer Group via the Existing Day 46 Seed Table
No real AD/SSO/HR data source exists in this stack (same gap Day 46 already
flagged for ueba_engine.py's _DEPARTMENT_SEED). Detection 1 (credential
hoarding) reuses that same seed table rather than inventing a second,
parallel "who's on this person's team" source. Peer comparison degrades
honestly (status="peer_group_insufficient") rather than guessing when a
user has no seeded peers — same "coverage flag over silent zero" discipline
Day 46's bug-fix round #4 established for source_ip_coverage/
volume_field_coverage.

### Design Decision — Query Helpers Are Small and Swappable
Each detection's ES query lives behind a small `_get_*()` helper
(_get_weekly_credential_access_count, _get_24h_outbound_bytes,
_get_7day_accessed_systems, _get_recent_daily_login_hours) rather than
inline in the detection function. This mirrors the project's existing
`_post()` convention (one HTTP layer, no separate ES client) while keeping
each detection's *decision logic* testable independently of live ES — the
same reason Day 46/47/48 all shipped a mocked-ES test path alongside the
live one.
"""

import datetime
import logging
import os

import yaml

from tools.elastic_tools import _post, write_hunt_result_to_es
from tools.ueba_scorer import get_ueba_profile
from tools.ueba_engine import _DEPARTMENT_SEED

logger = logging.getLogger(__name__)

HUNTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hunts")
ALERTS_INDEX = "logs-wazuh.alerts-*"

INSIDER_ESCALATION_TAG = "insider_threat"
INSIDER_ESCALATION_CONFIDENCE_PCT = 90  # higher than Day 29's generic 85 —
                                         # these findings are corroborated
                                         # against a personal baseline, not
                                         # just a static rule threshold

# Fields the credential-hoarding detection treats as "credential store access".
# Extend as real credential/secrets-store rule IDs are identified in this
# environment — same "extend the seed as observed" convention as
# _THREAT_ACTOR_SEED (Day 24) / _DEPARTMENT_SEED (Day 46).
CREDENTIAL_ACCESS_RULE_IDS = ["100010"]  # AWS CloudTrail: GetSecretValue
CREDENTIAL_KEYWORDS = ["secret", "vault", "credential"]

# Hardcoded fallbacks used only if a hunt's YAML config file is missing —
# never crash a detection cycle over a missing/malformed config file, same
# "never raises" convention as every other tool in this project.
_DEFAULT_CONFIG = {
    "insider_credential_hoarding": {
        "hunt_name": "insider_credential_hoarding",
        "hypothesis": "A user is accessing credential/secrets stores far more than their peer group.",
        "mitre_technique": "T1552",
        "escalate_if_found": True,
        "peer_multiplier": 5,
        "lookback_days": 7,
        "min_events_no_peers": 3,
    },
    "insider_data_staging": {
        "hunt_name": "insider_data_staging",
        "hypothesis": "A user is downloading far more data than their own established baseline in a short window.",
        "mitre_technique": "T1074",
        "escalate_if_found": True,
        "staging_multiplier": 10,
        "lookback_hours": 24,
    },
    "insider_access_broadening": {
        "hunt_name": "insider_access_broadening",
        "hypothesis": "A user is accessing systems they have no history of touching, in a short window.",
        "mitre_technique": "T1078",
        "escalate_if_found": True,
        "new_systems_threshold": 3,
        "lookback_days": 7,
    },
    "insider_schedule_shift": {
        "hunt_name": "insider_schedule_shift",
        "hypothesis": "A user's working hours have shifted well outside their own baseline for several consecutive days.",
        "mitre_technique": "T1078",
        "escalate_if_found": True,
        "shift_hours": 3,
        "consecutive_days_threshold": 5,
        "lookback_days": 10,
    },
}


def load_insider_playbook_config(hunt_name: str) -> dict:
    """Load one insider hunt's YAML config (thresholds/hypothesis/mitre_technique/
    escalate_if_found). Falls back to _DEFAULT_CONFIG on any missing/malformed
    file — never raises, same convention as hunt_loader.run_yaml_hunt()."""
    path = os.path.join(HUNTS_DIR, f"hunt_{hunt_name}.yml")
    try:
        with open(path, "r") as f:
            cfg = yaml.safe_load(f) or {}
        merged = dict(_DEFAULT_CONFIG.get(hunt_name, {}))
        merged.update(cfg)
        return merged
    except Exception as e:
        logger.warning("[insider_threat] could not load %s (%s) — using defaults", path, e)
        return dict(_DEFAULT_CONFIG.get(hunt_name, {}))


# ─────────────────────────── peer-group helpers ───────────────────────────

def _get_peer_group(username: str) -> str:
    return _DEPARTMENT_SEED.get(username, "unassigned")


def _get_peer_usernames(username: str) -> list:
    group = _get_peer_group(username)
    if group == "unassigned":
        return []
    return [u for u, g in _DEPARTMENT_SEED.items() if g == group and u != username]


# ─────────────────────────────── ES query helpers ───────────────────────────

def _get_weekly_credential_access_count(username: str, lookback_days: int) -> int:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"prefix": {"data.dstuser": username}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                ],
                "should": (
                    [{"terms": {"rule.id": CREDENTIAL_ACCESS_RULE_IDS}}]
                    + [{"match": {"rule.description": kw}} for kw in CREDENTIAL_KEYWORDS]
                ),
                "minimum_should_match": 1,
            }
        },
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        return raw.get("hits", {}).get("total", {}).get("value", 0)
    except Exception as e:
        logger.warning("[insider_threat] credential-access query failed for %s: %s", username, e)
        return 0


def _get_24h_outbound_bytes(username: str, lookback_hours: int) -> int:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"prefix": {"data.dstuser": username}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}},
                ]
            }
        },
        "aggs": {"total_bytes": {"sum": {"field": "data.bytes_out"}}},
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        return int(raw.get("aggregations", {}).get("total_bytes", {}).get("value") or 0)
    except Exception as e:
        logger.warning("[insider_threat] outbound-bytes query failed for %s: %s", username, e)
        return 0


def _get_7day_accessed_systems(username: str, lookback_days: int) -> set:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"prefix": {"data.dstuser": username}},
                    {"terms": {"rule.groups": ["authentication_success"]}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                ]
            }
        },
        "aggs": {"systems": {"terms": {"field": "agent.name", "size": 50}}},
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        buckets = raw.get("aggregations", {}).get("systems", {}).get("buckets", [])
        return {b["key"] for b in buckets}
    except Exception as e:
        logger.warning("[insider_threat] access-broadening query failed for %s: %s", username, e)
        return set()


def _get_recent_daily_login_hours(username: str, lookback_days: int) -> dict:
    """Returns {date_str: [hour, hour, ...]} for the last N days — one entry
    per day the user logged in at all. Uses the same @timestamp-derived,
    value_type-hinted scripted hour extraction Day 46 bug-fix round #3
    introduced (avoids the string-vs-numeric bucket-key crash)."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"prefix": {"data.dstuser": username}},
                    {"terms": {"rule.groups": ["authentication_success"]}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                ]
            }
        },
        "aggs": {
            "by_day": {
                "date_histogram": {"field": "@timestamp", "calendar_interval": "day"},
                "aggs": {
                    "hours": {
                        "terms": {
                            "script": {
                                "source": "doc['@timestamp'].value.getHour()",
                                "lang": "painless",
                            },
                            "value_type": "long",
                            "size": 24,
                        }
                    }
                },
            }
        },
    }
    try:
        raw = _post(f"{ALERTS_INDEX}/_search", body)
        buckets = raw.get("aggregations", {}).get("by_day", {}).get("buckets", [])
        out = {}
        for day in buckets:
            if day.get("doc_count", 0) == 0:
                continue
            hour_buckets = day.get("hours", {}).get("buckets", [])
            out[day["key_as_string"]] = [int(h["key"]) for h in hour_buckets]
        return out
    except Exception as e:
        logger.warning("[insider_threat] schedule-shift query failed for %s: %s", username, e)
        return {}


# ────────────────────────────── detections ──────────────────────────────

def _unwrap_ueba_profile(profile_doc) -> dict:
    """get_ueba_profile()'s real return shape (confirmed live, Day 49) is the
    profile_json content itself, already unwrapped — NOT nested under a
    'profile_json' key, and NOT a raw ES hit with '_source'. This module
    originally assumed the former, then the latter, both wrong; the live
    test settled it: {'avg_outbound_bytes_per_day': ..., 'accessed_systems':
    [...], 'typical_login_hours': [...]} comes back directly.

    Kept defensive against all three shapes anyway (flat-with-profile_json,
    raw-ES-hit-with-_source, and this real bare-content shape) rather than
    hardcoding just the one now-confirmed case — a future refactor of
    get_ueba_profile() upstream shouldn't silently break every detection
    here again. Never raises — returns {} on anything else."""
    if not profile_doc:
        return {}
    if "_source" in profile_doc:
        return profile_doc["_source"].get("profile_json", profile_doc["_source"]) or {}
    if "profile_json" in profile_doc:
        return profile_doc.get("profile_json") or {}
    return profile_doc  # bare content — the shape actually returned live


def detect_credential_hoarding(username: str, config: dict = None) -> dict:
    cfg = config or load_insider_playbook_config("insider_credential_hoarding")
    user_count = _get_weekly_credential_access_count(username, cfg["lookback_days"])
    peers = _get_peer_usernames(username)

    if not peers:
        return _result("credential_hoarding", username, cfg, threats_found=0,
                        status="peer_group_insufficient",
                        evidence=f"{username}: {user_count} credential-store hits this week; "
                                 f"no seeded peers in group '{_get_peer_group(username)}' to compare against.")

    peer_counts = [_get_weekly_credential_access_count(p, cfg["lookback_days"]) for p in peers]
    peer_avg = sum(peer_counts) / len(peer_counts)

    if peer_avg > 0:
        flagged = user_count > cfg["peer_multiplier"] * peer_avg
        ratio = round(user_count / peer_avg, 2)
    else:
        flagged = user_count >= cfg["min_events_no_peers"]
        ratio = None

    evidence = (f"{username}: {user_count} credential-store hits this week vs. peer "
                f"average {peer_avg:.2f} ({_get_peer_group(username)}, n={len(peers)})"
                + (f" — {ratio}x peer average" if ratio is not None else " — peer average is 0"))
    return _result("credential_hoarding", username, cfg, threats_found=int(flagged),
                    status="ok", evidence=evidence,
                    extra={"user_count": user_count, "peer_avg": peer_avg, "ratio": ratio})


def detect_data_staging(username: str, config: dict = None) -> dict:
    cfg = config or load_insider_playbook_config("insider_data_staging")
    profile_doc = get_ueba_profile("user", username)
    profile = _unwrap_ueba_profile(profile_doc)
    baseline = profile.get("avg_outbound_bytes_per_day")

    if not baseline:
        return _result("data_staging", username, cfg, threats_found=0,
                        status="no_baseline_yet",
                        evidence=f"{username}: no avg_outbound_bytes_per_day in UEBA profile yet — cannot compare.")

    current_bytes = _get_24h_outbound_bytes(username, cfg["lookback_hours"])
    ratio = round(current_bytes / baseline, 2) if baseline else None
    flagged = current_bytes > cfg["staging_multiplier"] * baseline

    evidence = (f"{username}: {current_bytes:,} bytes out in the last {cfg['lookback_hours']}h "
                f"vs. baseline {baseline:,.0f} bytes/day — {ratio}x baseline")
    return _result("data_staging", username, cfg, threats_found=int(flagged),
                    status="ok", evidence=evidence,
                    extra={"current_bytes": current_bytes, "baseline": baseline, "ratio": ratio})


def detect_access_broadening(username: str, config: dict = None) -> dict:
    cfg = config or load_insider_playbook_config("insider_access_broadening")
    profile_doc = get_ueba_profile("user", username)
    profile = _unwrap_ueba_profile(profile_doc)
    historical_systems = set(profile.get("accessed_systems", []) or [])

    current_systems = _get_7day_accessed_systems(username, cfg["lookback_days"])
    new_systems = current_systems - historical_systems
    flagged = len(new_systems) >= cfg["new_systems_threshold"]

    evidence = (f"{username}: accessed {len(new_systems)} system(s) with no prior history "
                f"in the last {cfg['lookback_days']}d — {sorted(new_systems)}")
    return _result("access_broadening", username, cfg, threats_found=int(flagged),
                    status="ok", evidence=evidence,
                    extra={"new_systems": sorted(new_systems)})


def detect_schedule_shift(username: str, config: dict = None) -> dict:
    cfg = config or load_insider_playbook_config("insider_schedule_shift")
    profile_doc = get_ueba_profile("user", username)
    profile = _unwrap_ueba_profile(profile_doc)
    typical_hours = profile.get("typical_login_hours") or []

    if not typical_hours:
        return _result("schedule_shift", username, cfg, threats_found=0,
                        status="no_baseline_yet",
                        evidence=f"{username}: no typical_login_hours in UEBA profile yet — cannot compare.")

    daily = _get_recent_daily_login_hours(username, cfg["lookback_days"])
    shift_hours = cfg["shift_hours"]

    def _day_is_shifted(hours):
        # A day counts as "shifted" only if every login that day is outside
        # the typical-hours band by more than shift_hours — a single normal
        # login on an otherwise-odd day should not count as a shift.
        return all(min(abs(h - t) for t in typical_hours) > shift_hours for h in hours)

    shifted_days = sorted(d for d, hrs in daily.items() if hrs and _day_is_shifted(hrs))

    # longest consecutive run (calendar-day granularity, string-sorted dates)
    longest_run = 0
    current_run = 0
    prev_date = None
    for d in shifted_days:
        date = datetime.date.fromisoformat(d[:10])
        if prev_date is not None and (date - prev_date).days == 1:
            current_run += 1
        else:
            current_run = 1
        longest_run = max(longest_run, current_run)
        prev_date = date

    flagged = longest_run >= cfg["consecutive_days_threshold"]
    evidence = (f"{username}: {longest_run} consecutive day(s) shifted >{shift_hours}h "
                f"from typical hours {typical_hours} (days: {shifted_days})")
    return _result("schedule_shift", username, cfg, threats_found=int(flagged),
                    status="ok", evidence=evidence,
                    extra={"shifted_days": shifted_days, "longest_run": longest_run})


def _result(detection, username, cfg, threats_found, status, evidence, extra=None):
    return {
        "detection": detection,
        "hunt_name": cfg.get("hunt_name", f"insider_{detection}"),
        "username": username,
        "threats_found": threats_found,
        "status": status,
        "evidence": evidence,
        "mitre_technique": cfg.get("mitre_technique"),
        "escalate": bool(threats_found) and cfg.get("escalate_if_found", True),
        "extra": extra or {},
    }


DETECTIONS = {
    "insider_credential_hoarding": detect_credential_hoarding,
    "insider_data_staging": detect_data_staging,
    "insider_access_broadening": detect_access_broadening,
    "insider_schedule_shift": detect_schedule_shift,
}


# ───────────────────────────── runner + escalation ─────────────────────────

def run_all_insider_threat_hunts(usernames: list = None) -> list:
    """Runs all 4 detections (Hunts 6-9) against every known user, writes one
    siem-hunt-results doc per detection per cycle (aggregated across users —
    same 'every cycle recorded' convention as Day 29/31/48), and escalates
    every positive finding straight to coordination. Never raises — a single
    user/detection failure is caught and recorded, not allowed to abort the
    whole cycle."""
    usernames = usernames or list(_DEPARTMENT_SEED.keys())
    cycle_results = []

    for hunt_name, fn in DETECTIONS.items():
        cfg = load_insider_playbook_config(hunt_name)
        detection_key = hunt_name.replace("insider_", "")
        findings = []
        for username in usernames:
            try:
                finding = fn(username, cfg)
            except Exception as e:
                logger.warning("[insider_threat] %s failed for %s: %s", hunt_name, username, e)
                continue
            if finding["threats_found"]:
                findings.append(finding)

        threats_found = len(findings)
        summary = (f"Hunt '{hunt_name}': {threats_found} user(s) flagged this cycle."
                   if threats_found else f"Hunt '{hunt_name}': no anomalies this cycle.")

        try:
            write_hunt_result_to_es(
                hunt_name=hunt_name,
                findings_count=threats_found,
                summary=summary,
                escalated=any(f["escalate"] for f in findings),
            )
        except Exception as e:
            logger.warning("[insider_threat] write_hunt_result_to_es failed for %s: %s", hunt_name, e)

        for finding in findings:
            if finding["escalate"]:
                escalate_insider_finding_to_coordination(finding)

        cycle_results.append({"hunt_name": hunt_name, "threats_found": threats_found, "findings": findings})

    return cycle_results


def build_synthetic_alert_from_insider_finding(finding: dict) -> dict:
    """Same shape as hunting_agent.build_synthetic_alert_from_hunt() (Day 29),
    tagged so downstream consumers can tell an insider-originated alert apart
    from an ordinary triage-originated one at a glance."""
    return {
        "rule": {
            "id": "insider-threat",
            "level": 12,
            "description": f"Insider threat indicator: {finding['detection']} — {finding['username']}",
            "groups": ["insider_threat", finding["detection"]],
        },
        "agent": {"name": "unknown"},
        "data": {"dstuser": finding["username"], "srcip": "unknown"},
        "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "insider_threat_tag": INSIDER_ESCALATION_TAG,
        "insider_evidence": finding["evidence"],
    }


def escalate_insider_finding_to_coordination(finding: dict):
    """Bypasses normal confidence-scorer routing — pre-scores the synthetic
    alert at INSIDER_ESCALATION_CONFIDENCE_PCT (90) and hands it directly to
    coordination_agent, same override mechanism Day 24 (CTI>80) and Day 29
    (hunt escalation, 85) already established. Lazy-imports graph.pipeline
    to avoid the same circular-import problem Day 29 solved the same way."""
    # Lazy import — mirrors Day 29's escalate_hunt_to_triage() (avoids the
    # circular import graph.py<->hunting_agent.py already has to dodge), and
    # mirrors pipeline_runner.py's own pipeline/app fallback so this still
    # works if graph.py ever exports the compiled graph under either name.
    try:
        from graph import pipeline
    except ImportError:
        try:
            from graph import app as pipeline
        except Exception as e:
            logger.warning("[insider_threat] could not import graph.pipeline/app for escalation: %s", e)
            return None
    except Exception as e:
        logger.warning("[insider_threat] could not import graph.pipeline for escalation: %s", e)
        return None

    alert = build_synthetic_alert_from_insider_finding(finding)
    # Same AgentState shape pipeline_runner.py's own initial_state uses
    # (alert/alert_es_id/alert_es_index/confidence/confidence_pct/technique/
    # notes/escalate/triage_result) — confidence and triage_result included
    # even though this path never sets them, so any graph node that reads
    # them directly (not via .get()) doesn't KeyError on a synthetic alert.
    # `tags` is additive, not part of the real AgentState schema; the same
    # insider_threat marker also lives in `notes` and on the alert dict
    # itself so it survives even if a future graph node drops unknown keys.
    state = {
        "alert": alert,
        "alert_es_id": None,
        "alert_es_index": None,
        "confidence": None,
        "confidence_pct": INSIDER_ESCALATION_CONFIDENCE_PCT,
        "technique": finding["mitre_technique"],
        "notes": [f"[insider_threat] {finding['detection']} — {finding['evidence']}"],
        "escalate": True,
        "triage_result": None,
        "tags": [INSIDER_ESCALATION_TAG],
    }
    try:
        result = pipeline.invoke(state)
        logger.info("[insider_threat] escalated %s/%s to coordination — confidence_pct=%s",
                    finding["detection"], finding["username"], INSIDER_ESCALATION_CONFIDENCE_PCT)
        return result
    except Exception as e:
        logger.warning("[insider_threat] escalation failed for %s/%s: %s",
                       finding["detection"], finding["username"], e)
        return None


if __name__ == "__main__":
    print("Running all insider threat hunts (Hunts 6-9)...")
    results = run_all_insider_threat_hunts()
    for r in results:
        print(f"- {r['hunt_name']}: threats_found={r['threats_found']}")
        for f in r["findings"]:
            print(f"    {f['username']}: {f['evidence']}")
