"""
tools/chain_loader.py — Day 43

Loads and validates MITRE ATT&CK chain templates from
/langgraph/redteam/chains/*.yml, the same pattern hunt_loader.py (Day 27)
already uses for /langgraph/hunts/*.yml: playbooks/chains are data, not
code, so a new chain is "drop a YAML file in", no Python changes needed.
"""

from pathlib import Path

import yaml

CHAINS_DIR = Path(__file__).resolve().parent.parent / "redteam" / "chains"

REQUIRED_CHAIN_FIELDS = ["chain_name", "description", "steps"]
REQUIRED_STEP_FIELDS = ["technique", "name"]


def load_chain_templates():
    """
    Loads and validates every *.yml file in redteam/chains/.
    Returns {chain_name: chain_dict}.
    Raises ValueError on a malformed chain file — same fail-loud behavior
    hunt_loader.load_hunt_playbooks() uses, since a silently-skipped chain
    template is worse than a startup error.
    """
    chains = {}
    if not CHAINS_DIR.exists():
        return chains

    for path in sorted(CHAINS_DIR.glob("*.yml")):
        with open(path) as f:
            data = yaml.safe_load(f)

        missing = [field for field in REQUIRED_CHAIN_FIELDS if field not in data]
        if missing:
            raise ValueError(f"{path.name} missing required chain fields: {missing}")

        if not isinstance(data["steps"], list) or not data["steps"]:
            raise ValueError(f"{path.name} 'steps' must be a non-empty list")

        for i, step in enumerate(data["steps"]):
            step_missing = [field for field in REQUIRED_STEP_FIELDS if field not in step]
            if step_missing:
                raise ValueError(f"{path.name} step {i} missing required fields: {step_missing}")

        chains[data["chain_name"]] = data

    return chains


def get_chain_for_technique(entry_technique):
    """
    Looks up which chain template (if any) a given MITRE technique is
    configured as the entry point for. Used by chain_node() to decide
    whether a triage-flagged technique should kick off a chain simulation.
    """
    for chain_name, chain_def in load_chain_templates().items():
        if chain_def.get("entry_alert_technique") == entry_technique:
            return chain_name
    return None


if __name__ == "__main__":
    loaded = load_chain_templates()
    print(f"Loaded {len(loaded)} chain templates from {CHAINS_DIR}:")
    for name, chain in loaded.items():
        steps = " -> ".join(s["technique"] for s in chain["steps"])
        print(f"  - {name}: {steps}")
