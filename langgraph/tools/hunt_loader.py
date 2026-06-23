"""
tools/hunt_loader.py — Day 27

Loads YAML-defined hunt playbooks from /langgraph/hunts/ and runs them against
Elasticsearch, reusing the same _post() helper convention every other file in
the project uses (tools/elastic_tools.py).

Why a separate loader instead of just extending Day 26's HuntPlaybook dataclass:
Day 26's run_hunt() expects a single Elastic DSL bool clause and normalizes plain
search hits into findings. Hunts 1-2 here need aggregations (cardinality / sum +
bucket_selector) so the threshold lives in the query itself, not in Python. This
loader handles both shapes generically: aggregation buckets when present
(threshold already enforced server-side), hits otherwise.

Placeholders substituted into elastic_query at run time from the top-level YAML
fields, so the threshold and lookback window are defined ONCE and can't drift
out of sync with the query body:
    TIME_WINDOW_HOURS  -> str(time_window_hours)
    FINDING_THRESHOLD  -> str(finding_threshold)

Output contract matches Day 26's hunting_agent.py exactly, plus extra metadata
(hypothesis, mitre_technique) carried through for Day 29's Claude-summary step:
    {threats_found, findings, hunt_summary, escalate, hunt_name,
     mitre_technique, hypothesis}
"""
import glob
import json
import os

import yaml

from tools.elastic_tools import _post

HUNTS_DIR = os.path.join(os.path.dirname(__file__), "..", "hunts")

REQUIRED_FIELDS = [
    "hunt_name", "hypothesis", "elastic_query",
    "finding_threshold", "mitre_technique", "escalate_if_found",
]


def load_hunt_playbooks(directory: str = HUNTS_DIR) -> list[dict]:
    """Load and lightly validate every *.yml file in the hunts directory."""
    playbooks = []
    for path in sorted(glob.glob(os.path.join(directory, "*.yml"))):
        with open(path) as f:
            pb = yaml.safe_load(f)
        missing = [field for field in REQUIRED_FIELDS if field not in pb]
        if missing:
            raise ValueError(f"{path} is missing required fields: {missing}")
        pb.setdefault("time_window_hours", 24)
        pb.setdefault("index", "logs-wazuh.alerts-*")
        pb["_source_file"] = os.path.basename(path)
        playbooks.append(pb)
    return playbooks


def _render_query(playbook: dict) -> dict:
    """Substitute TIME_WINDOW_HOURS / FINDING_THRESHOLD placeholders."""
    raw = json.dumps(playbook["elastic_query"])
    raw = raw.replace("TIME_WINDOW_HOURS", str(playbook["time_window_hours"]))
    raw = raw.replace("FINDING_THRESHOLD", str(playbook["finding_threshold"]))
    return json.loads(raw)


def run_yaml_hunt(playbook: dict) -> dict:
    hunt_name = playbook["hunt_name"]
    index = playbook.get("index", "logs-wazuh.alerts-*")
    threshold = playbook["finding_threshold"]
    escalate_if_found = playbook.get("escalate_if_found", True)
    window = playbook.get("time_window_hours", 24)

    body = _render_query(playbook)

    try:
        resp = _post(f"{index}/_search", body)
    except Exception as exc:  # never raise — matches Day 26's run_hunt() contract
        return {
            "hunt_name": hunt_name,
            "threats_found": 0,
            "findings": [],
            "hunt_summary": f"Hunt '{hunt_name}' failed to query ES: {exc}",
            "escalate": False,
            "mitre_technique": playbook.get("mitre_technique"),
            "hypothesis": playbook.get("hypothesis"),
        }

    aggs = resp.get("aggregations")
    if aggs:
        # Aggregation-based hunt (lateral movement, exfil volume). The
        # bucket_selector in the query already enforced the threshold
        # server-side, so every returned bucket IS a finding.
        agg_name = next(iter(aggs))
        findings = aggs[agg_name].get("buckets", [])
        threats_found = len(findings)
        meets_threshold = threats_found >= 1
    else:
        # Hit-based hunt (LOLBins) — count hits and compare to threshold here.
        findings = resp.get("hits", {}).get("hits", [])
        threats_found = len(findings)
        meets_threshold = threats_found >= threshold

    escalate = bool(escalate_if_found and meets_threshold)

    summary = (
        f"Hunt '{hunt_name}' found {threats_found} matching result(s) "
        f"in the last {window}h (MITRE {playbook.get('mitre_technique', 'n/a')})."
    )

    return {
        "hunt_name": hunt_name,
        "threats_found": threats_found,
        "findings": findings,
        "hunt_summary": summary,
        "escalate": escalate,
        "mitre_technique": playbook.get("mitre_technique"),
        "hypothesis": playbook.get("hypothesis"),
    }


def run_all_yaml_hunts(directory: str = HUNTS_DIR) -> list[dict]:
    return [run_yaml_hunt(pb) for pb in load_hunt_playbooks(directory)]


if __name__ == "__main__":
    for result in run_all_yaml_hunts():
        print(f"- {result['hunt_name']}: {result['hunt_summary']} "
              f"escalate={result['escalate']}")
