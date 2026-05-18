"""
fetch_and_score.py
Phase 1 — Week 3, Day 11
Cosmic Info Solutions · Ahmad Bussti

Fetches real alerts from Elasticsearch and runs the confidence scorer.
Saves results to docs/scoring-test.json

Run from the repo root:
    python elastic/fetch_and_score.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

# ── Config ───────────────────────────────────────────────────────────────────
ES_HOST = "http://localhost:9201"
ES_USER = "elastic"
ES_PASS = "changeme"
AUTH    = HTTPBasicAuth(ES_USER, ES_PASS)
HEADERS = {"Content-Type": "application/json"}

# Searches all wazuh alert indices
INDEX_PATTERN = "logs-wazuh.alerts-*"

DOCS_DIR = Path(__file__).parent.parent / "docs"
DOCS_DIR.mkdir(exist_ok=True)

# ── Fetch alerts from Elastic ─────────────────────────────────────────────────
SIGMA_RULE_IDS = [
    "5710", "5712",   # T1110 SSH Brute Force
    "5501",           # T1078 Valid Accounts — after hours
    "5900",           # T1059 Command Execution
    "5302",           # T1021 Remote Services
    "31101",          # T1190 Web Attack
]

def fetch_alerts():
    body = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"terms": {
                        "rule.mitre.id": [
                            "T1078", "T1059", "T1021", "T1110", "T1190"
                        ]
                    }}
                ]
            }
        },
    }
    r = requests.get(
        f"{ES_HOST}/{INDEX_PATTERN}/_search",
        auth=AUTH,
        headers=HEADERS,
        json=body,
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("hits", {}).get("hits", [])


# ── Map Elastic doc → confidence_scorer expected format ──────────────────────
def normalise(hit):
    """
    Elastic stores the alert under hit['_source'].
    The confidence scorer expects these keys:
        rule.level          (int 1–15)
        ml.anomaly_score    (float 0–100, optional)
        @timestamp          (ISO-8601 string)
    This function handles both Wazuh-native field names and any
    flat structure you may have used when creating alerts manually.
    """
    src = hit.get("_source", {})

    # Support nested rule.level OR flat rule_level
    rule = src.get("rule", {})
    level = (
        rule.get("level")
        or src.get("rule_level")
        or src.get("level")
    )
    try:
        level = int(level) if level is not None else None
    except (TypeError, ValueError):
        level = None

    # Support nested ml.anomaly_score OR flat anomaly_score
    ml = src.get("ml", {}) or {}
    anomaly = (
        ml.get("anomaly_score")
        or src.get("anomaly_score")
    )
    try:
        anomaly = float(anomaly) if anomaly is not None else None
    except (TypeError, ValueError):
        anomaly = None

    timestamp = src.get("@timestamp") or src.get("timestamp")

    # Build a normalised alert dict the scorer understands
    alert = {
        "_id":        hit.get("_id"),
        "_index":     hit.get("_index"),
        "@timestamp": timestamp,
        "rule": {
            "level":       level,
            "description": rule.get("description") or src.get("rule_description", ""),
            "id":          rule.get("id") or src.get("rule_id", ""),
        },
        "agent": src.get("agent", {}),
        "source": src.get("source", {}),
    }
    if anomaly is not None:
        alert["ml"] = {"anomaly_score": anomaly}

    return alert


# ── Main ──────────────────────────────────────────────────────────────────────
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
        print(f"✗ No documents found in {INDEX_PATTERN}. Check your index name.")
        sys.exit(1)

    print(f"✓ Fetched {len(hits)} alerts from last 24h (level ≥ 5)\n")

    # Import scorer (works whether run from repo root or elastic/)
    sys.path.insert(0, str(Path(__file__).parent))
    from confidence_scorer import score_alerts

    normalised = [normalise(h) for h in hits]
    scored     = score_alerts(normalised)

    # ── Print table ───────────────────────────────────────────────────────────
    col = 52
    print(f"{'Rule description':<{col}} {'Lvl':>4} {'ML':>5} {'TF':>4} {'CONF':>5}")
    print("─" * (col + 23))
    for a in scored:
        desc  = (a["rule"].get("description") or "—")[:col]
        level = a["rule"].get("level") or "?"
        d     = a["_scoring_detail"]
        ml_v  = f"{d['anomaly_score_used']:.0f}" if a.get("ml") else "def"
        tf    = int(d["time_factor"])
        conf  = a["confidence"]

        # Colour-code confidence in terminal
        if conf >= 70:
            tag = "\033[91m"   # red — high
        elif conf >= 40:
            tag = "\033[93m"   # yellow — medium
        else:
            tag = "\033[92m"   # green — low/noise
        reset = "\033[0m"

        print(f"{desc:<{col}} {str(level):>4} {ml_v:>5} {tf:>4} {tag}{conf:>5}{reset}")

    # ── Summary counts ────────────────────────────────────────────────────────
    high   = sum(1 for a in scored if a["confidence"] >= 70)
    medium = sum(1 for a in scored if 40 <= a["confidence"] < 70)
    low    = sum(1 for a in scored if a["confidence"] < 40)

    print(f"\n  High (≥70, triage agent):  {high}")
    print(f"  Medium (40–69, analyst queue): {medium}")
    print(f"  Low (<40, archive):         {low}")

    # ── Save to docs/scoring-test.json ───────────────────────────────────────
    out_path = DOCS_DIR / "scoring-test.json"
    with open(out_path, "w") as f:
        json.dump(scored, f, indent=2, default=str)

    print(f"\n✓ Results saved to {out_path}")
    print(f"  Commit with: git add docs/scoring-test.json && git commit -m 'test(scoring): real Elastic alerts scored'")


if __name__ == "__main__":
    main()
