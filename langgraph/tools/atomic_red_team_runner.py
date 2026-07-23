"""
tools/atomic_red_team_runner.py

Wraps Atomic Red Team execution behind a curated allowlist. Nothing here
runs unless a human has already reviewed the specific test GUID and added
it to ALLOWED_TESTS for that technique.

IMPORTANT — remote execution: Atomic Red Team tests must run ON THE TARGET
HOST, not on the machine running this Python script (the Wazuh manager).
This module SSHes into the target and invokes Invoke-AtomicTest there,
mirroring the same SSH-based remote-execution pattern already used in
tools/response_tools.py for unblock_ip()/unisolate_endpoint().

Command syntax note (verified 2026-07-21 against redteam-target-win10):
Invoke-AtomicTest takes the MITRE technique ID as its primary argument,
with -TestGuids selecting a specific test within that technique's YAML —
it does NOT accept a bare GUID as the main argument (that was tried and
fails with "does not exist"). Correct form:
    Invoke-AtomicTest <technique> -TestGuids <guid> -PathToAtomicsFolder <path>

Requires, on the target Windows host:
  - OpenSSH Server enabled and running
  - A dedicated, non-admin test account for the SSH connection, with:
      - a real Windows user profile actually created (log in once, or
        run a throwaway process as that user, before trusting any path
        under C:\\Users\\<account> — Windows may silently suffix the
        folder, e.g. redteamtest.DESKTOP-XXXX, if a stale/conflicting
        folder already existed at the expected path)
      - key-based SSH auth: authorized_keys placed under the ACCOUNT'S
        REAL PROFILE PATH (check via the ProfileList registry key, not
        assumed from the username alone), with inheritance removed and
        explicit ACLs granted only to the account itself, SYSTEM, and
        Administrators (no Everyone / BUILTIN\\Users entries anywhere
        in the path — home directory AND .ssh AND authorized_keys all
        need this, since StrictModes checks the whole chain)
  - PowerShell 7 (pwsh) installed
  - Invoke-AtomicRedTeam module installed for that user, CurrentUser
    scope (Install-Module -Scope CurrentUser — AllUsers scope requires
    admin rights this account deliberately doesn't have)
  - The atomics folder present locally (ATOMICS_PATH_ON_TARGET below)
  - Cosmetic note: the module's own internal logging helper calls
    Get-NetIPAddress, which will throw a CIM/WMI access-denied warning
    under a non-admin account. This does not affect test execution or
    exit code and can be safely ignored.
"""

import subprocess
import datetime as _dt
from dataclasses import dataclass
from tools.elastic_tools import _post

# ---- Target connection config -----------------------------------------
# Maps a Wazuh agent name to how we reach it over SSH for remote atomic
# execution. Kept separate from block_ip()/isolate_endpoint()'s agent-name/
# ID resolution — different concern (test execution, not active-response).
REDTEAM_SSH_HOSTS = {
    "redteam-target-win10": {
        "host": "192.168.56.13",
        "user": "redteamtest",          # scoped, non-admin test account
        "key": "~/.ssh/id_ed25519",     # key-based auth, no interactive password
    },
    # add more disposable targets here as they're stood up
}

ATOMICS_PATH_ON_TARGET = "C:\\AtomicRedTeam\\atomics"  # path on the Windows host

ALLOWED_TESTS: dict[str, list[str]] = {
    "T1110": [],
    "T1059": [],
    "T1021": [],
    "T1082": ["85cfbf23-4a1e-4342-8792-007e004b975f"],  # Hostname Discovery, reviewed 2026-07-21
}


@dataclass
class AtomicRunResult:
    success: bool
    guid: str
    technique: str
    target: str
    stdout: str = ""
    stderr: str = ""
    cleanup_verified: bool = False
    error: str | None = None


def list_available_tests(technique: str) -> list[str]:
    """Returns only the human-approved GUIDs for a technique. Empty = nothing runs."""
    return ALLOWED_TESTS.get(technique, [])


def _ssh_run(target: str, remote_command: str, timeout: int = 45) -> subprocess.CompletedProcess:
    """
    Runs a command on the named target over SSH, matching the connection
    convention already used for unblock_ip()/unisolate_endpoint().
    """
    conn = REDTEAM_SSH_HOSTS.get(target)
    if conn is None:
        raise ValueError(
            f"No SSH connection details configured for target '{target}' in "
            f"REDTEAM_SSH_HOSTS. Add host/user/key before running live tests "
            f"against it."
        )
    ssh_cmd = [
        "ssh",
        "-i", conn["key"],
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        f"{conn['user']}@{conn['host']}",
        remote_command,
    ]
    return subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)


def run_atomic_test(technique: str, guid: str, target: str) -> AtomicRunResult:
    """
    Executes exactly one pre-approved atomic test on the remote target over
    SSH, using pwsh + Invoke-AtomicTest, then runs the atomic's own
    documented cleanup step separately and verifies it ran.

    Note: Invoke-AtomicTest takes the technique ID as its primary argument
    and -TestGuids to select the specific test — a bare GUID alone is not
    a valid invocation.
    """
    if guid not in ALLOWED_TESTS.get(technique, []):
        raise ValueError(
            f"GUID {guid} is not in the reviewed allowlist for {technique}. "
            f"Review the atomic's YAML before adding it."
        )

    _log_execution(technique, guid, target, "pre_execution", {})

    try:
        run_cmd = (
            f'pwsh -NonInteractive -Command '
            f'"Import-Module Invoke-AtomicRedTeam; '
            f'Invoke-AtomicTest {technique} -TestGuids {guid} '
            f'-PathToAtomicsFolder \'{ATOMICS_PATH_ON_TARGET}\' '
            f'-TimeoutSeconds 30"'
        )
        proc = _ssh_run(target, run_cmd, timeout=45)

        cleanup_cmd = (
            f'pwsh -NonInteractive -Command '
            f'"Import-Module Invoke-AtomicRedTeam; '
            f'Invoke-AtomicTest {technique} -TestGuids {guid} -Cleanup '
            f'-PathToAtomicsFolder \'{ATOMICS_PATH_ON_TARGET}\'"'
        )
        cleanup_proc = _ssh_run(target, cleanup_cmd, timeout=30)
        cleanup_ok = cleanup_proc.returncode == 0

        result = AtomicRunResult(
            success=(proc.returncode == 0),
            guid=guid, technique=technique, target=target,
            stdout=proc.stdout[-2000:], stderr=proc.stderr[-2000:],
            cleanup_verified=cleanup_ok,
        )
    except subprocess.TimeoutExpired:
        result = AtomicRunResult(
            success=False, guid=guid, technique=technique, target=target,
            error="Execution exceeded time-box (kill-switch triggered)",
        )
    except Exception as e:
        result = AtomicRunResult(
            success=False, guid=guid, technique=technique, target=target,
            error=str(e),
        )

    _log_execution(technique, guid, target, "post_execution", result.__dict__)
    return result


def check_detection(technique: str, guid: str, target: str) -> bool | None:
    """
    Queries your own SIEM (logs-wazuh.alerts-*) for a detection matching
    this technique on this target, within the last few minutes.
    Returns True (detected), False (not detected — a gap), or None (inconclusive).
    """
    body = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"technique.keyword": technique}},
                    {"term": {"agent.name.keyword": target}},
                ],
                "filter": [{"range": {"@timestamp": {"gte": "now-5m"}}}],
            }
        }
    }
    try:
        raw = _post("logs-wazuh.alerts-*/_search", body)
        hits = raw.get("hits", {}).get("hits", [])
        return len(hits) > 0
    except Exception:
        return None


def _log_execution(technique, guid, target, stage, detail):
    doc = {
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "technique": technique, "guid": guid, "target": target,
        "stage": stage, "detail": detail,
    }
    try:
        _post("siem-redteam-atomic-log/_doc", doc)
    except Exception as e:
        print(f"[atomic_red_team_runner] WARNING: log write failed: {e}")


if __name__ == "__main__":
    print("Configured SSH targets:", list(REDTEAM_SSH_HOSTS.keys()))
    print("Approved tests per technique:")
    for tech, guids in ALLOWED_TESTS.items():
        print(f"  {tech}: {guids or '(none approved)'}")
