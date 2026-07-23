"""
agents/attack_chain_simulator.py — Day 43

Extends the Day 41 redteam_simulator.py from single-technique testing into
multi-step MITRE ATT&CK kill-chain simulation. This module does NOT
duplicate any per-technique dispatch, allowlist gating, or live-execution
logic — every step still goes through the existing
run_red_team_simulation() from Day 41 (same ALLOWED_TESTS gate, same
REDTEAM_MODE dry_run default, same siem-redteam-log audit trail per
technique). This file only adds sequencing, position-tracking across
steps, and chain-level persistence to siem-redteam-chains.

INTEGRATION NOTE: this was written against the Day 41 write-up's
documented contract for run_red_team_simulation() / RedTeamResult
(`{exploitable, exploit_path, blast_radius, affected_hosts, risk_score}`)
and the NotImplementedError-on-unapproved-technique behavior described
there. Adjust the call signature in `_run_single_step()` below to match
the real function signature in your checked-out redteam_simulator.py if
it differs (e.g. positional vs. keyword args, extra required params).
"""

import datetime
import inspect

from tools.chain_loader import load_chain_templates, get_chain_for_technique
from tools.elastic_tools import _post, write_redteam_report_to_es
from tools.redteam_reporter import generate_reports

try:
    from agents.redteam_simulator import run_red_team_simulation, REDTEAM_MODE
except ImportError:
    # Allows this module to be imported/tested standalone before it's
    # wired into the real package, same defensive pattern used elsewhere
    # in this project (e.g. lazy import of graph.pipeline in Day 29).
    run_red_team_simulation = None
    REDTEAM_MODE = "dry_run"

CHAIN_LOG_INDEX = "siem-redteam-chains"


def _log_chain_event(chain_name, stage, detail):
    """Writes one audit event to siem-redteam-chains. Never raises —
    matches the never-raise convention of every ES-write helper in this
    project (write_hunt_result_to_es, write_response_log_entry, etc.)."""
    doc = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "chain_name": chain_name,
        "stage": stage,  # "pre_execution" | "step_result" | "chain_complete"
        "mode": REDTEAM_MODE,
        "detail": detail,
    }
    try:
        _post(f"{CHAIN_LOG_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[attack_chain_simulator] WARNING: failed to log chain event ({stage}): {e}")


# Candidate keyword names this project has used for these three concepts
# across Day 41's write-up vs. the real implementation found on Day 43 —
# used to adapt to whatever run_red_team_simulation() actually accepts,
# instead of hardcoding one guess that broke on the real signature.
_TECHNIQUE_ALIASES = ("technique", "mitre_technique", "technique_id")
_TARGET_ALIASES = ("target_agent", "agent_name", "agent", "target", "endpoint")
_TOPOLOGY_ALIASES = ("network_topology", "topology")


def _build_synthetic_alert(technique, target_agent):
    """
    Builds a minimal synthetic alert dict for chain-step simulation —
    same shape hunting_agent.build_synthetic_alert_from_hunt() (Day 29)
    already produces for hunt-originated synthetic alerts (agent.name +
    technique + a placeholder rule block), so run_red_team_simulation()
    has the same alert structure it expects from a real triage-originated
    call, without needing a real backing Wazuh document.
    """
    return {
        "agent": {"name": target_agent},
        "technique": technique,
        "rule": {"id": None, "level": None,
                 "description": f"[chain-simulated] {technique}"},
        "data": {},
    }


def _build_call_kwargs(func, technique, target_agent, network_topology):
    """
    Inspects run_red_team_simulation()'s real parameter names and maps our
    three logical values (technique / target_agent / network_topology) onto
    whichever names it actually uses. Returns None if introspection fails
    or no known alias matches any real parameter (caller falls back to a
    positional call in that case).

    Note: this only covers scalar aliases (technique/target/topology). The
    documented Day 41 contract (alert: dict, affected_assets: list) needs
    constructed values, not a plain string — that's tried explicitly in
    _run_single_step() before this generic fallback runs.
    """
    try:
        params = list(inspect.signature(func).parameters.keys())
    except (TypeError, ValueError):
        return None

    kwargs = {}
    for aliases, value in (
        (_TECHNIQUE_ALIASES, technique),
        (_TARGET_ALIASES, target_agent),
        (_TOPOLOGY_ALIASES, network_topology),
    ):
        for name in aliases:
            if name in params:
                kwargs[name] = value
                break

    return kwargs or None


def _run_single_step(technique, target_agent, network_topology):
    """
    Calls the existing Day 41 per-technique simulator for one chain step.
    Un-approved techniques (empty ALLOWED_TESTS entry) are treated as a
    blocked step, not a crashed chain — a chain run should always produce
    a full chain_result, including steps the allowlist isn't ready for yet.

    Call strategy (in order):
      1. The exact contract documented in the Day 41 plan:
         run_red_team_simulation(alert, mitre_technique, affected_assets,
         network_topology) — alert is a synthetic dict built from
         technique/target_agent, affected_assets is [target_agent].
      2. Generic introspection-based kwargs (_build_call_kwargs) — covers
         signatures that don't match #1 but do use recognizable scalar
         parameter names.
      3. Positional fallback with (technique, target_agent, network_topology).

    Confirmed against the real environment on Day 43: step 2 alone wasn't
    enough because the live signature takes `alert` (dict) and
    `affected_assets` (list), which #1 now builds directly.
    """
    if run_red_team_simulation is None:
        return {
            "exploitable": False,
            "exploit_path": [],
            "notes": "run_red_team_simulation not importable in this environment",
        }

    synthetic_alert = _build_synthetic_alert(technique, target_agent)
    affected_assets = [target_agent] if target_agent else []

    # --- Attempt 1: documented Day 41 contract ---
    try:
        return run_red_team_simulation(
            alert=synthetic_alert,
            mitre_technique=technique,
            affected_assets=affected_assets,
            network_topology=network_topology,
        )
    except NotImplementedError as e:
        return {"exploitable": False, "exploit_path": [], "notes": str(e)}
    except TypeError:
        pass  # signature doesn't match this contract — try the generic fallback below

    # --- Attempt 2: generic introspection-based kwargs ---
    kwargs = _build_call_kwargs(run_red_team_simulation, technique, target_agent, network_topology)
    if kwargs:
        try:
            return run_red_team_simulation(**kwargs)
        except NotImplementedError as e:
            return {"exploitable": False, "exploit_path": [], "notes": str(e)}
        except TypeError:
            pass

    # --- Attempt 3: positional fallback ---
    try:
        return run_red_team_simulation(technique, target_agent, network_topology)
    except NotImplementedError as e:
        return {"exploitable": False, "exploit_path": [], "notes": str(e)}
    except TypeError as e:
        print(f"[attack_chain_simulator] SIGNATURE MISMATCH calling "
              f"run_red_team_simulation for {technique}: {e}. "
              f"Run: python3 -c \"import inspect; from agents.redteam_simulator "
              f"import run_red_team_simulation; print(inspect.signature("
              f"run_red_team_simulation))\" and share the output.")
        return {"exploitable": False, "exploit_path": [], "notes": f"signature mismatch: {e}"}
    except Exception as e:
        # Any other failure (SSH/timeout/target unreachable) also just
        # blocks this step rather than aborting the whole chain run.
        return {"exploitable": False, "exploit_path": [], "notes": f"step error: {e}"}


def run_attack_chain(chain_name, target_agent, network_topology=None, stop_on_block=False):
    """
    Runs every step of a named chain template in order.

    stop_on_block:
        False (default) — every step is still attempted even after an
            earlier step comes back blocked, so the full chain picture is
            captured (a later step might be reachable via a different path
            and that's useful to know).
        True  — halts the chain at the first blocked step, simulating an
            attacker who is actually stopped there.

    Returns the chain summary dict and writes it (plus one event per step)
    to siem-redteam-chains. [Day 44] Also generates a technical + executive
    summary via Gemini and writes them to siem-redteam-reports; both are
    included in the returned dict.
    """
    chains = load_chain_templates()
    if chain_name not in chains:
        raise ValueError(f"Unknown chain_name '{chain_name}' — known: {list(chains.keys())}")

    chain_def = chains[chain_name]
    _log_chain_event(chain_name, "pre_execution", {
        "target_agent": target_agent,
        "mode": REDTEAM_MODE,
        "steps_planned": [s["technique"] for s in chain_def["steps"]],
    })

    chain_result = []
    chain_blocked = False

    for step in chain_def["steps"]:
        technique = step["technique"]

        if chain_blocked and stop_on_block:
            entry = {
                "step": technique,
                "name": step.get("name"),
                "exploitable": False,
                "evidence": None,
                "blocked_by": "chain halted — prior step blocked (stop_on_block=True)",
            }
            chain_result.append(entry)
            _log_chain_event(chain_name, "step_result", entry)
            continue

        step_result = _run_single_step(technique, target_agent, network_topology)

        entry = {
            "step": technique,
            "name": step.get("name"),
            "mitre_tactic": step.get("mitre_tactic"),
            "exploitable": bool(step_result.get("exploitable", False)),
            "evidence": "; ".join(step_result.get("exploit_path") or []) or step_result.get("notes"),
        }
        if not entry["exploitable"]:
            entry["blocked_by"] = step_result.get("notes", "not exploitable / no approved test yet")
            chain_blocked = True

        chain_result.append(entry)
        _log_chain_event(chain_name, "step_result", entry)

    summary = {
        "chain_name": chain_name,
        "target_agent": target_agent,
        "mode": REDTEAM_MODE,
        "chain_result": chain_result,
        "fully_exploitable": all(r["exploitable"] for r in chain_result),
        "blocked_steps": [r for r in chain_result if not r["exploitable"]],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    try:
        _post(f"{CHAIN_LOG_INDEX}/_doc", summary)
    except Exception as e:
        print(f"[attack_chain_simulator] WARNING: failed to write chain summary to ES: {e}")

    # [Day 44] Generate technical + executive summaries via Gemini and
    # persist them to siem-redteam-reports. Never raises — generate_reports()
    # falls back to templated text on any Gemini error, same as
    # hunt_summarizer.summarize_hunt_findings() (Day 29), so a Gemini
    # outage never blocks a chain run from completing.
    incident_id = f"{chain_name}-{target_agent}-{summary['timestamp']}"
    reports = generate_reports(
        chain_result,
        blast_data={
            "target_agent": target_agent,
            "fully_exploitable": summary["fully_exploitable"],
            "blocked_steps": len(summary["blocked_steps"]),
        },
    )
    write_redteam_report_to_es(
        incident_id=incident_id,
        technical_summary=reports["technical_summary"],
        executive_summary=reports["executive_summary"],
        chain_name=chain_name,
        target_agent=target_agent,
        timestamp=reports["timestamp"],
    )
    summary["incident_id"] = incident_id
    summary["technical_summary"] = reports["technical_summary"]
    summary["executive_summary"] = reports["executive_summary"]

    _log_chain_event(chain_name, "chain_complete", {
        "fully_exploitable": summary["fully_exploitable"],
        "blocked_count": len(summary["blocked_steps"]),
        "incident_id": incident_id,
    })

    return summary


def get_hardening_recommendations(chain_summary):
    """
    Turns blocked_steps into short, human-readable hardening notes. Day 43
    scope stops at producing these recommendations — actually feeding them
    into response_agent.py as an automated action is a follow-up (see
    day43 write-up), same "selection vs. real execution" gap this project
    has tracked before for block_ip/isolate_endpoint (Day 31 -> 32/33).
    """
    return [
        {
            "technique": step["step"],
            "recommendation": (
                f"Step {step['step']} ({step.get('name')}) did not succeed: "
                f"{step.get('blocked_by')}. This is currently a chokepoint that "
                f"stops this chain — worth reinforcing and monitoring closely, "
                f"since a future change elsewhere in the environment could "
                f"reopen it."
            ),
        }
        for step in chain_summary["blocked_steps"]
    ]


def chain_node(state):
    """
    Optional LangGraph node, mirroring red_team_node()'s gating (Day 41).
    Not wired into graph.py's edges yet (Day 43 backlog item) — exposed so
    it can be called directly today, or added as a conditional edge later
    the same way red_team_node was added after triage_agent.
    """
    triage_result = state.get("triage_result") or {}
    verdict = triage_result.get("verdict")
    confidence_pct = state.get("confidence_pct", 0)
    technique = state.get("technique")

    if verdict != "suspicious" or confidence_pct <= 85:
        print(f"[chain_node] skipped — gating condition not met "
              f"(verdict={verdict}, confidence_pct={confidence_pct})")
        return state

    chain_name = get_chain_for_technique(technique)
    if not chain_name:
        print(f"[chain_node] skipped — technique {technique} has no mapped chain entry point")
        return state

    target_agent = (state.get("alert") or {}).get("agent", {}).get("name", "unknown")
    result = run_attack_chain(chain_name, target_agent)

    state.setdefault("notes", []).append(
        f"Attack chain '{chain_name}' simulated — "
        f"fully_exploitable={result['fully_exploitable']}, "
        f"blocked_steps={len(result['blocked_steps'])}"
    )
    state["chain_result"] = result
    return state


if __name__ == "__main__":
    import json

    print(f"REDTEAM_MODE = '{REDTEAM_MODE}' (defaults to dry_run; set env var to change)")

    templates = load_chain_templates()
    print(f"Loaded {len(templates)} chain templates: {list(templates.keys())}\n")

    print("=== Test: Chain 1 (external_intrusion) ===")
    result = run_attack_chain("external_intrusion", target_agent="redteam-target-win10")
    print(json.dumps(result, indent=2, default=str))

    print("\n=== Technical summary ===")
    print(result.get("technical_summary"))
    print("\n=== Executive summary ===")
    print(result.get("executive_summary"))

    print("\n=== Hardening recommendations ===")
    for rec in get_hardening_recommendations(result):
        print(f"  - [{rec['technique']}] {rec['recommendation']}")
