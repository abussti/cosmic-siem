"""
inject_test_events.py

Recreated Day 39 — referenced throughout project.md's Day 16/17/18 "Useful
Commands" sections (`python3 inject_test_events.py`) but absent from the
working tree as of the Day 37 dashboard test (`find . -iname "*inject*"`
turned up nothing at the expected path; only day-specific variants like
inject_day28_test_events.py existed).

This is a general-purpose synthetic Wazuh alert injector — not tied to one
specific day's scenario — so it can replace the day-specific scripts going
forward for ad-hoc testing. It follows the same plain `requests`-based
convention every other tool in this project uses (no ES client SDK), posting
directly to Elasticsearch.

Usage examples:

    # SSH brute force, level 10, from a specific IP
    python3 inject_test_events.py --rule-id 5710 --level 10 \\
        --groups sshd,authentication_failed \\
        --srcip 203.0.113.77 --dstuser root

    # After-hours login with new-IP + volume fields (Day 39 exfil scenario)
    python3 inject_test_events.py --rule-id 100001 --level 8 \\
        --groups firewall --srcip 192.0.2.199 --dstuser unknown \\
        --extra '{"login_hour": 3, "is_new_ip": true, "bytes_out": 500000000}'

    # Inject straight into a scenario-specific test index instead of the
    # live logs-wazuh.alerts-* pattern (keeps test data out of production
    # searches/dashboards)
    python3 inject_test_events.py --rule-id 5710 --level 10 \\
        --index logs-wazuh.alerts-manualtest --srcip 203.0.113.77

Exits non-zero and prints the ES error body on failure — this is a CLI
testing tool, not a library function, so (unlike every other file in this
project) it's fine for it to fail loudly rather than always returning a
result dict.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import requests

ES_URL = os.environ.get("ES_URL", "http://localhost:9201")
ES_AUTH = (os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme"))

DEFAULT_INDEX = "logs-wazuh.alerts-testinject"


def build_alert(rule_id, level, groups, description, srcip, dstuser,
                 agent_name, timestamp=None, extra_data=None):
    """
    Builds a synthetic alert matching the "Wazuh Alert Field Schema" table in
    project.md: rule.id as a string, rule.groups as an array, data.srcip /
    data.dstuser present even when "unknown", @timestamp in ISO-8601.
    `extra_data` is merged into the `data` block last, so callers can add
    scenario-specific fields (login_hour, is_new_ip, bytes_out, conn_count,
    etc.) without this script needing to know about every field in advance.
    """
    data = {"srcip": srcip or "unknown", "dstuser": dstuser or "unknown"}
    if extra_data:
        data.update(extra_data)

    return {
        "@timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": str(rule_id),
            "description": description or f"Injected test event (rule {rule_id})",
            "level": int(level),
            "groups": groups,
        },
        "agent": {"name": agent_name},
        "data": data,
    }


def inject(index, alert):
    """POSTs the alert document to Elasticsearch. Returns the parsed response
    on success; raises requests.HTTPError on failure (caller in __main__
    handles printing a useful error and exiting non-zero).

    Day 39 hotfix: Elasticsearch rejects auto-creating a document directly
    against a wildcard index expression (confirmed live:
    "indices:admin/auto_create does not support wildcards"). Wildcards only
    work for reads/searches (which is exactly how pipeline_runner.py's
    poller and every get_*() helper in elastic_tools.py query
    logs-wazuh.alerts-*) — a single-document write needs one concrete
    index/data-stream name. Checked here, before the request, so the
    failure is a clear one-line explanation instead of a raw ES 400 body.
    """
    if "*" in index:
        raise ValueError(
            f"--index '{index}' contains a wildcard. Elasticsearch can't create a "
            f"new document directly against a wildcard pattern (only concrete "
            f"index/data-stream names support auto-create; wildcards only work for "
            f"reads). Use a concrete name instead, e.g. --index logs-wazuh.alerts-testinject "
            f"or --index logs-wazuh.alerts-day39test — it will still be picked up by the "
            f"real pipeline poller, since that queries the logs-wazuh.alerts-* pattern for reads."
        )
    resp = requests.post(
        f"{ES_URL}/{index}/_doc",
        auth=ES_AUTH,
        headers={"Content-Type": "application/json"},
        data=json.dumps(alert),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_extra(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("--extra must be a JSON object, e.g. '{\"login_hour\": 3}'")
        return parsed
    except json.JSONDecodeError as e:
        print(f"[inject_test_events] --extra is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rule-id", required=True, help="Wazuh rule ID, e.g. 5710")
    parser.add_argument("--level", type=int, required=True, help="Rule severity level, 1-15")
    parser.add_argument("--groups", default="", help="Comma-separated rule.groups, e.g. sshd,authentication_failed")
    parser.add_argument("--description", default=None, help="rule.description text")
    parser.add_argument("--srcip", default=None, help="data.srcip")
    parser.add_argument("--dstuser", default=None, help="data.dstuser")
    parser.add_argument("--agent", default="agent1", help="agent.name (default: agent1)")
    parser.add_argument("--index", default=DEFAULT_INDEX,
                         help=f"Target ES index (default: {DEFAULT_INDEX} — a dedicated test "
                              "index so injected data doesn't pollute logs-wazuh.alerts-* searches/"
                              "dashboards; pass --index logs-wazuh.alerts-* explicitly if you need "
                              "the real pipeline's poller to pick this alert up)")
    parser.add_argument("--timestamp", default=None,
                         help="ISO-8601 @timestamp override (default: now). NOTE: if you're "
                              "targeting the real pipeline_runner.py poller, this needs to be "
                              "the actual injection time for the lookback window to catch it — "
                              "use --extra for a semantic 'after-hours' field like login_hour "
                              "instead of backdating @timestamp itself (see project.md's Day 38 "
                              "Scenario 3 methodology note).")
    parser.add_argument("--extra", default=None,
                         help='Extra data.* fields as a JSON object, e.g. '
                              '\'{"login_hour": 3, "is_new_ip": true, "bytes_out": 500000000}\'')
    args = parser.parse_args()

    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    extra_data = _parse_extra(args.extra)

    alert = build_alert(
        rule_id=args.rule_id,
        level=args.level,
        groups=groups,
        description=args.description,
        srcip=args.srcip,
        dstuser=args.dstuser,
        agent_name=args.agent,
        timestamp=args.timestamp,
        extra_data=extra_data,
    )

    print(f"[inject_test_events] Injecting into '{args.index}':")
    print(json.dumps(alert, indent=2))

    try:
        result = inject(args.index, alert)
    except ValueError as e:
        print(f"[inject_test_events] {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        try:
            err_body = e.response.json()
        except Exception:
            err_body = e.response.text if e.response is not None else str(e)
        print(f"[inject_test_events] FAILED: {e}\n{json.dumps(err_body, indent=2) if isinstance(err_body, dict) else err_body}",
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[inject_test_events] FAILED: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[inject_test_events] OK — _id={result.get('_id')} index={result.get('_index')}")
    print(f"[inject_test_events] Verify with:\n"
          f"  curl -s -u {ES_AUTH[0]}:*** {ES_URL}/{result.get('_index')}/_doc/{result.get('_id')} | python3 -m json.tool")


if __name__ == "__main__":
    main()
