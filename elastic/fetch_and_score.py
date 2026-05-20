"""
fetch_and_score.py (fixed for detection alerts)
Fetches detection rule alerts from Elastic Security.
"""

import json
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

ES_HOST = "http://localhost:9201"
ES_USER = "elastic"
ES_PASS = "changeme"
AUTH    = HTTPBasicAuth(ES_USER, ES_PASS)
HEADERS = {"Content-Type": "application/json"}

ALERTS_INDEX = ".internal.alerts-security.alerts-*"

DOCS_DIR = Path(__file__).parent.parent / "docs"
DOCS_DIR.mkdir(exist_ok=True)


def fetch_alerts():
    body = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ],
                "filter": [
                    {"exists": {"field": "kibana.alert.rule.uuid"}}
                ]
            }
        }
    }
    r = requests.get(
        f"{ES_HOST}/{ALERTS_INDEX}/_search",
        auth=AUTH,
        headers=HEADERS,
        json=body,
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("hits", {}).get("hits", [])


def normalise(hit):
    src = hit.get("_source", {})
    
    # Rule name
    rule_name = src.get("kibana.alert.rule.name", "Unknown Rule")
    
    # Risk score – using the field we confirmed
    risk_score = src.get("kibana.alert.risk_score", 21)
    
    # Map risk_score to Wazuh level
    if risk_score >= 73:
        level = 12
    elif risk_score >= 47:
        level = 8
    elif risk_score >= 21:
        level = 5
    else:
        level = 3
    
    return {
        "_id": hit.get("_id"),
        "_index": hit.get("_index"),
        "@timestamp": src.get("@timestamp"),
        "rule": {
            "level": level,
            "description": rule_name,
            "id": src.get("kibana.alert.rule.uuid", ""),
        },
        "agent": src.get("host", {}),
        "source": src.get("source", {}),
    }


def main():
    print(f"Connecting to {ES_HOST} …")
    try:
        hits = fetch_alerts()
    except requests.exceptions.ConnectionError:
        print(f"\n✗ Cannot reach {ES_HOST}. Is Docker running?")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"\n✗ Elasticsearch error: {e}")
        sys.exit(1)

    if not hits:
        print(f"✗ No detection alerts found in {ALERTS_INDEX}.")
        sys.exit(1)

    print(f"✓ Fetched {len(hits)} detection alerts from last 24h\n")

    sys.path.insert(0, str(Path(__file__).parent))
    from confidence_scorer import score_alerts

    normalised = [normalise(h) for h in hits]
    scored = score_alerts(normalised)

    col = 52
    print(f"{'Rule description':<{col}} {'Lvl':>4} {'ML':>5} {'TF':>4} {'CONF':>5}")
    print("─" * (col + 23))
    for a in scored:
        desc = (a["rule"].get("description") or "—")[:col]
        level = a["rule"].get("level") or "?"
        d = a["_scoring_detail"]
        ml_v = f"{d['anomaly_score_used']:.0f}" if a.get("ml") else "def"
        tf = int(d["time_factor"])
        conf = a["confidence"]
        tag = "\033[91m" if conf >= 70 else "\033[93m" if conf >= 40 else "\033[92m"
        reset = "\033[0m"
        print(f"{desc:<{col}} {str(level):>4} {ml_v:>5} {tf:>4} {tag}{conf:>5}{reset}")

    high = sum(1 for a in scored if a["confidence"] >= 70)
    medium = sum(1 for a in scored if 40 <= a["confidence"] < 70)
    low = sum(1 for a in scored if a["confidence"] < 40)

    print(f"\n  High (≥70, triage agent):  {high}")
    print(f"  Medium (40–69, analyst queue): {medium}")
    print(f"  Low (<40, archive):         {low}")

    out_path = DOCS_DIR / "scoring-test.json"
    with open(out_path, "w") as f:
        json.dump(scored, f, indent=2, default=str)

    print(f"\n✓ Results saved to {out_path}")


if __name__ == "__main__":
    main()
