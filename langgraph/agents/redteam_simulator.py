"""
agents/red_team_simulator.py

Day 41 — Red Team Simulator Engine

SCOPE: This module is the orchestration layer — input/output contracts,
pre-execution audit logging, technique dispatch, and LangGraph wiring.
Each _replay_<technique>() handler calls into tools/atomic_red_team_runner.py,
which enforces a curated, human-reviewed allowlist (ALLOWED_TESTS) — nothing
executes live unless a specific test GUID has been reviewed and approved.

Currently wired techniques:
  T1110 — SSH/AD brute force (ALLOWED_TESTS empty — no test currently approved
           for this environment; T1110.001's Windows tests require an AD domain
           this environment doesn't have, and the Linux sudo-brute tests were
           rejected for using an unpinned `curl | bash` from a live GitHub branch)
  T1059 — LOLBins command execution (ALLOWED_TESTS empty — pending review)
  T1021 — Lateral movement (ALLOWED_TESTS empty — pending review)
  T1082 — System information discovery (ALLOWED_TESTS: Hostname Discovery only,
           reviewed 2026-07-21, approved for redteam-target-win10)
"""

from __future__ import annotations
import os
import uuid
import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Callable

from tools.elastic_tools import _post  # existing requests-based ES helper
from tools.atomic_red_team_runner import (
    list_available_tests,
    run_atomic_test,
    check_detection,
)

REDTEAM_LOG_INDEX = "siem-redteam-log"
REDTEAM_MODE = os.environ.get("REDTEAM_MODE", "dry_run")  # "dry_run" | "live"
REDTEAM_CONFIDENCE_THRESHOLD = 85


@dataclass
class RedTeamResult:
    exploitable: bool
    exploit_path: list[str]
    blast_radius: int
    affected_hosts: list[str]
    risk_score: int
    technique: str
    mode: str
    notes: str = ""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "technique": self.technique, "mode": self.mode,
            "exploitable": self.exploitable, "exploit_path": self.exploit_path,
            "blast_radius": self.blast_radius, "affected_hosts": self.affected_hosts,
            "risk_score": self.risk_score, "notes": self.notes,
        }


def _log_redteam_attempt(technique, alert, affected_assets, mode, stage, detail=None):
    doc = {
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "technique": technique,
        "alert_rule_id": (alert or {}).get("rule", {}).get("id"),
        "affected_assets": affected_assets,
        "mode": mode,
        "stage": stage,  # "pre_execution" | "post_execution" | "blocked"
        "detail": detail or {},
    }
    try:
        _post(f"{REDTEAM_LOG_INDEX}/_doc", doc)
    except Exception as e:
        print(f"[red_team_simulator] WARNING: failed to write audit log: {e}")


def _replay_t1110_brute_force(alert, affected_assets, network_topology):
    target = affected_assets[0] if affected_assets else "unknown"
    _log_redteam_attempt("T1110", alert, affected_assets, REDTEAM_MODE, "pre_execution",
                          {"planned_action": "ssh_credential_spray", "target": target})
    if REDTEAM_MODE != "live":
        return RedTeamResult(
            exploitable=False,
            exploit_path=[f"[DRY RUN] would attempt SSH credential spray against {target}"],
            blast_radius=0, affected_hosts=[], risk_score=0, technique="T1110", mode=REDTEAM_MODE,
            notes="No live attack attempted — REDTEAM_MODE is 'dry_run'. Wire an approved "
                  "credential-spray tool to enable live testing.",
        )
    guids = list_available_tests("T1110")
    if not guids:
        raise NotImplementedError(
            "REDTEAM_MODE=='live' but no T1110 tests are curated in "
            "tools/atomic_red_team_runner.py's ALLOWED_TESTS. Review the "
            "atomics under atomic-red-team/atomics/T1110.001/ and add the GUID(s) "
            "you approve before this can run live. Note: the Windows tests in "
            "T1110.001 require an Active Directory domain; the Linux sudo-brute "
            "tests were already reviewed and rejected for using an unpinned "
            "`curl | bash` payload from a live GitHub branch."
        )

    findings = []
    for guid in guids:
        run = run_atomic_test("T1110", guid, target)
        detected = check_detection("T1110", guid, target) if run.success else None
        findings.append(
            f"test={guid} success={run.success} detected_by_siem={detected} "
            f"error={run.error}"
        )

    any_undetected = any(
        (check_detection("T1110", g, target) is False) for g in guids
    )
    return RedTeamResult(
        exploitable=any_undetected,
        exploit_path=findings,
        blast_radius=1 if any_undetected else 0,
        affected_hosts=[target] if any_undetected else [],
        risk_score=70 if any_undetected else 10,
        technique="T1110",
        mode=REDTEAM_MODE,
        notes="Live run via Atomic Red Team (curated allowlist only). "
              "'exploitable' here means the technique executed without "
              "generating a corresponding SIEM detection - i.e. a detection "
              "gap, not necessarily a successful compromise.",
    )


def _replay_t1059_command_execution(alert, affected_assets, network_topology):
    target = affected_assets[0] if affected_assets else "unknown"
    _log_redteam_attempt("T1059", alert, affected_assets, REDTEAM_MODE, "pre_execution",
                          {"planned_action": "lolbin_execution_probe", "target": target})
    if REDTEAM_MODE != "live":
        return RedTeamResult(
            exploitable=False,
            exploit_path=[f"[DRY RUN] would attempt a benign LOLBin execution probe on {target}"],
            blast_radius=0, affected_hosts=[], risk_score=0, technique="T1059", mode=REDTEAM_MODE,
            notes="No live execution attempted — REDTEAM_MODE is 'dry_run'. Wire an approved "
                  "detection-testing framework (e.g. Atomic Red Team) to enable live testing.",
        )
    guids = list_available_tests("T1059")
    if not guids:
        raise NotImplementedError(
            "REDTEAM_MODE=='live' but no T1059 tests are curated in "
            "tools/atomic_red_team_runner.py's ALLOWED_TESTS. Review the "
            "atomics under atomic-red-team/atomics/T1059/ and add the GUID(s) "
            "you approve before this can run live."
        )

    findings = []
    for guid in guids:
        run = run_atomic_test("T1059", guid, target)
        detected = check_detection("T1059", guid, target) if run.success else None
        findings.append(
            f"test={guid} success={run.success} detected_by_siem={detected} "
            f"error={run.error}"
        )

    any_undetected = any(
        (check_detection("T1059", g, target) is False) for g in guids
    )
    return RedTeamResult(
        exploitable=any_undetected,
        exploit_path=findings,
        blast_radius=1 if any_undetected else 0,
        affected_hosts=[target] if any_undetected else [],
        risk_score=70 if any_undetected else 10,
        technique="T1059",
        mode=REDTEAM_MODE,
        notes="Live run via Atomic Red Team (curated allowlist only). "
              "'exploitable' here means the technique executed without "
              "generating a corresponding SIEM detection - i.e. a detection "
              "gap, not necessarily a successful compromise.",
    )


def _replay_t1021_lateral_movement(alert, affected_assets, network_topology):
    adjacent = network_topology.get("adjacent_hosts", []) if network_topology else []
    _log_redteam_attempt("T1021", alert, affected_assets, REDTEAM_MODE, "pre_execution",
                          {"planned_action": "lateral_ssh_probe", "adjacent_hosts": adjacent})
    if REDTEAM_MODE != "live":
        return RedTeamResult(
            exploitable=False,
            exploit_path=[f"[DRY RUN] would attempt lateral SSH probe to {len(adjacent)} adjacent host(s)"],
            blast_radius=0, affected_hosts=[], risk_score=0, technique="T1021", mode=REDTEAM_MODE,
            notes="No live lateral movement attempted — REDTEAM_MODE is 'dry_run'. Wire an "
                  "approved lateral-movement validation tool to enable live testing.",
        )
    guids = list_available_tests("T1021")
    if not guids or not adjacent:
        raise NotImplementedError(
            "REDTEAM_MODE=='live' but either no T1021 tests are curated in "
            "tools/atomic_red_team_runner.py's ALLOWED_TESTS, or no adjacent "
            "hosts were provided in network_topology. Review the atomics "
            "under atomic-red-team/atomics/T1021/ and add approved GUID(s), "
            "and ensure network_topology['adjacent_hosts'] is populated."
        )

    findings = []
    reachable_undetected = []
    for target_host in adjacent:
        for guid in guids:
            run = run_atomic_test("T1021", guid, target_host)
            detected = check_detection("T1021", guid, target_host) if run.success else None
            findings.append(
                f"host={target_host} test={guid} success={run.success} "
                f"detected_by_siem={detected} error={run.error}"
            )
            if run.success and detected is False:
                reachable_undetected.append(target_host)

    return RedTeamResult(
        exploitable=bool(reachable_undetected),
        exploit_path=findings,
        blast_radius=len(reachable_undetected),
        affected_hosts=reachable_undetected,
        risk_score=80 if reachable_undetected else 10,
        technique="T1021",
        mode=REDTEAM_MODE,
        notes="Live run via Atomic Red Team (curated allowlist only). "
              "'exploitable' here means lateral movement executed against an "
              "adjacent host without generating a corresponding SIEM "
              "detection - i.e. a detection gap, not necessarily a "
              "successful compromise.",
    )


def _replay_t1082_discovery(alert, affected_assets, network_topology):
    """
    T1082 — System Information Discovery.

    NOTE on interpretation: discovery techniques are fundamentally different
    from T1110/T1059/T1021 above. A successful, undetected `hostname` or
    `systeminfo` call does not mean the host was "exploited" — it means a
    benign recon command ran without triggering a SIEM alert. Unless
    process-creation logging (e.g. Sysmon) is configured on the target and
    a matching Wazuh rule exists, detected_by_siem will likely be False for
    every run here, regardless of the host's actual security posture. We
    deliberately do NOT set exploitable=True off the back of that signal —
    doing so would misrepresent a detection-coverage gap as a vulnerability.
    """
    target = affected_assets[0] if affected_assets else "unknown"
    _log_redteam_attempt("T1082", alert, affected_assets, REDTEAM_MODE, "pre_execution",
                          {"planned_action": "system_discovery_probe", "target": target})
    if REDTEAM_MODE != "live":
        return RedTeamResult(
            exploitable=False,
            exploit_path=[f"[DRY RUN] would run system/hostname discovery on {target}"],
            blast_radius=0, affected_hosts=[], risk_score=0, technique="T1082", mode=REDTEAM_MODE,
            notes="No live execution attempted — REDTEAM_MODE is 'dry_run'.",
        )
    guids = list_available_tests("T1082")
    if not guids:
        raise NotImplementedError(
            "REDTEAM_MODE=='live' but no T1082 tests are curated in "
            "tools/atomic_red_team_runner.py's ALLOWED_TESTS. Review the "
            "atomics under atomic-red-team/atomics/T1082/ and add the GUID(s) "
            "you approve before this can run live."
        )

    findings = []
    any_detected = False
    for guid in guids:
        run = run_atomic_test("T1082", guid, target)
        detected = check_detection("T1082", guid, target) if run.success else None
        if detected:
            any_detected = True
        findings.append(
            f"test={guid} success={run.success} detected_by_siem={detected} "
            f"cleanup_verified={run.cleanup_verified} error={run.error}"
        )

    return RedTeamResult(
        exploitable=False,  # discovery techniques don't map to "exploitable" — see docstring
        exploit_path=findings,
        blast_radius=0,
        affected_hosts=[],
        risk_score=5 if any_detected else 15,
        technique="T1082",
        mode=REDTEAM_MODE,
        notes="Discovery technique — 'exploitable' is not a meaningful label here. "
              "This measures whether basic recon commands are detected by the SIEM. "
              "detected_by_siem=False indicates a detection-coverage gap for discovery "
              "activity, not a confirmed vulnerability or successful compromise. "
              "Cross-check whether Sysmon / process-creation logging is enabled on the "
              "target before treating an undetected result as actionable.",
    )


TECHNIQUE_HANDLERS: dict[str, Callable[..., RedTeamResult]] = {
    "T1110": _replay_t1110_brute_force,
    "T1059": _replay_t1059_command_execution,
    "T1021": _replay_t1021_lateral_movement,
    "T1082": _replay_t1082_discovery,
}


def run_red_team_simulation(alert, mitre_technique, affected_assets, network_topology=None):
    """Entry point matching the Day 41 I/O contract."""
    network_topology = network_topology or {}
    handler = TECHNIQUE_HANDLERS.get(mitre_technique)

    if handler is None:
        _log_redteam_attempt(mitre_technique, alert, affected_assets, REDTEAM_MODE, "blocked",
                              {"reason": "no handler registered for this technique"})
        return RedTeamResult(
            exploitable=False, exploit_path=[], blast_radius=0, affected_hosts=[],
            risk_score=0, technique=mitre_technique, mode=REDTEAM_MODE,
            notes=f"No red-team handler registered for {mitre_technique}.",
        ).to_dict()

    try:
        result = handler(alert, affected_assets, network_topology)
    except NotImplementedError as e:
        _log_redteam_attempt(mitre_technique, alert, affected_assets, REDTEAM_MODE, "blocked",
                              {"reason": str(e)})
        result = RedTeamResult(
            exploitable=False, exploit_path=[], blast_radius=0, affected_hosts=[],
            risk_score=0, technique=mitre_technique, mode=REDTEAM_MODE, notes=str(e),
        )

    _log_redteam_attempt(mitre_technique, alert, affected_assets, REDTEAM_MODE,
                          "post_execution", result.to_dict())
    return result.to_dict()


def red_team_node(state: dict) -> dict:
    """LangGraph node — only fires when confidence_pct > 85 AND verdict == 'suspicious'."""
    triage_result = state.get("triage_result") or {}
    verdict = triage_result.get("verdict")
    confidence_pct = state.get("confidence_pct", 0)

    if verdict != "suspicious" or confidence_pct <= REDTEAM_CONFIDENCE_THRESHOLD:
        state.setdefault("notes", []).append(
            f"[red_team_simulator] skipped — gating condition not met "
            f"(verdict={verdict}, confidence_pct={confidence_pct})"
        )
        return state

    alert = state.get("alert", {})
    technique = state.get("technique") or triage_result.get("technique")
    affected_assets = [alert.get("agent", {}).get("name", "unknown")]
    network_topology = state.get("network_topology", {})

    result = run_red_team_simulation(alert, technique, affected_assets, network_topology)
    state["red_team_result"] = result
    state.setdefault("notes", []).append(
        f"[red_team_simulator] technique={technique} mode={result['mode']} "
        f"exploitable={result['exploitable']} risk_score={result['risk_score']}"
    )
    return state


if __name__ == "__main__":
    import json
    print(f"REDTEAM_MODE = {REDTEAM_MODE!r} (defaults to dry_run; set env var to change)")

    test_alert = {
        "rule": {"id": "5710", "level": 10, "description": "sshd: Attempt to login using non-existent user"},
        "agent": {"name": "agent1"},
        "data": {"srcip": "203.0.113.77"},
    }

    print("\n=== Test: T1110 dry-run replay ===")
    out = run_red_team_simulation(test_alert, "T1110", ["agent1"], {"adjacent_hosts": ["agent2", "agent3"]})
    print(json.dumps(out, indent=2))

    print("\n=== Test: T1082 live discovery on Windows red-team target ===")
    t1082_alert = {
        "rule": {"id": "manual-t1082-test", "level": 5, "description": "manual T1082 validation run"},
        "agent": {"name": "redteam-target-win10"},
        "data": {},
    }
    out = run_red_team_simulation(t1082_alert, "T1082", ["redteam-target-win10"], {})
    print(json.dumps(out, indent=2))

    print("\n=== Test: node gating (should skip — confidence too low) ===")
    state = {"alert": test_alert, "technique": "T1110", "confidence_pct": 60,
             "triage_result": {"verdict": "suspicious", "technique": "T1110"}}
    state = red_team_node(state)
    print(state["notes"][-1])

    print("\n=== Test: node gating (should run — meets threshold) ===")
    state = {"alert": test_alert, "technique": "T1110", "confidence_pct": 91,
             "triage_result": {"verdict": "suspicious", "technique": "T1110"}}
    state = red_team_node(state)
    print(state["notes"][-1])
    print(json.dumps(state["red_team_result"], indent=2))
