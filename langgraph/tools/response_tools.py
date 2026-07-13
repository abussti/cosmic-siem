"""
tools/response_tools.py

Day 32 — Response / Wazuh
Action 1: IP blocking via Wazuh active-response.

Day 33 — Response / Wazuh
Action 2: Endpoint isolation via Wazuh active-response.

Day 34 — Response / Tickets
Action 3: automatic ticket creation in GitHub Issues for every confirmed
threat that requires analyst review.

Day 39 — two bug fixes from the Phase 2/3 backlog:
  1. Endpoint-parameter inconsistency (tracked bug #11): block_ip()/
     isolate_endpoint() take a Wazuh agent id/name (resolved via the REST
     API), while unblock_ip()/unisolate_endpoint() need an SSH-reachable
     host/IP for the same physical agent — two different identifiers for
     the same box, and callers had to track both themselves. Added
     AGENT_SSH_HOSTS (populated from the AGENT_SSH_HOSTS_JSON env var) and
     _resolve_ssh_host(), so callers can now pass the SAME Wazuh agent name
     to all four functions. Backward compatible: if an agent isn't in the
     map, _resolve_ssh_host() returns its input unchanged, so existing
     callers passing a raw SSH host directly (like the __main__ smoke test
     below, via TEST_SSH_HOST) keep working exactly as before.
  2. No retry/backoff on the SSH-based reversal calls (tracked bug #12):
     unblock_ip() and unisolate_endpoint() previously failed outright on a
     single transient SSH failure (agent briefly unreachable, network
     blip), unlike the Gemini calls elsewhere in this project which already
     have a fallback path. Added _run_ssh_command_with_retry() — 3 attempts,
     2s apart by default — used by both functions.

Note: firewall-drop is already a stock <command> in this environment's
ossec.conf (verified via `docker exec ... grep -A3 "<command>"`), so no
ossec.conf edit was needed. It's invoked directly via the API using the
"!command_name" syntax, which calls a registered <command> without
requiring an <active-response> auto-trigger binding block.

isolate-host is a NEW custom <command> (not stock) that has to be deployed
to each agent and registered on the manager the same way — see
isolate-host.sh and the ossec.conf snippet in the Day 33 notes. It follows
the same "!command_name" invocation convention as firewall-drop so it slots
into _send_active_response() with zero changes to that helper.

create_ticket() (Day 34) is unrelated to the Wazuh active-response path
above — it's a plain REST call to the GitHub Issues API — but lives in this
file per the Day 34 plan, and reuses the same never-raises /
log-every-attempt conventions as block_ip()/isolate_endpoint().

Mirrors the conventions already used in tools/elastic_tools.py:
  - thin `requests`-based helpers, no SDK client object
  - functions never raise — errors are caught and returned as a
    structured result dict, same pattern as run_hunt() / get_*() calls
  - all writes go through a small `_post`-style helper

Five public functions:
    block_ip(ip_address, endpoint)         -> dict   (Day 32)
    unblock_ip(ip_address, endpoint)       -> dict   (Day 32, Day 39 fixes)
    isolate_endpoint(agent_id, endpoint)   -> dict   (Day 33)
    unisolate_endpoint(agent_id, endpoint) -> dict   (Day 33, Day 39 fixes)
    create_ticket(alert, triage_summary,
                   confidence, technique)  -> dict   (Day 34)

All five log every call to siem-response-log regardless of success or
failure, so the audit trail is complete even on API errors.
"""

import os
import json
import datetime
import time
import requests

# ── Config — same env-var pattern as ES_URL / ES_AUTH in elastic_tools.py ──
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "changeme")

ES_URL = os.environ.get("ES_URL", "http://localhost:9201")
ES_AUTH = (os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme"))

RESPONSE_LOG_INDEX = "siem-response-log"

# Wazuh active-response command name. firewall-drop is a stock <command>
# already defined in ossec.conf (confirmed via `grep -A3 "<command>"` —
# present out of the box, no ossec.conf edit needed). There is no
# <active-response> binding block configured for it, so we call it directly
# by name with a "!" prefix — Wazuh's documented syntax for invoking a
# registered <command> through the API without requiring an
# <active-response> auto-trigger block.
FIREWALL_DROP_COMMAND = "!firewall-drop"

# Day 33 — custom <command>, registered on the manager the same way
# firewall-drop already is, but the script itself and the ossec.conf
# <command> block had to be added by hand (not stock). Same "!" invocation
# convention, so _send_active_response() needs no changes to support it.
ISOLATE_HOST_COMMAND = "!isolate-host"

# The Wazuh manager's own IP, allow-listed by isolate-host.sh so the agent
# keeps sending heartbeats/alerts to the manager while everything else is
# dropped. Set this to your real manager IP before running isolate_endpoint().
MANAGER_IP = os.environ.get("MANAGER_IP", "192.168.56.10")

# ── Day 39 fix (bug #11): Wazuh agent name -> SSH-reachable host/IP ─────────
# Populate via AGENT_SSH_HOSTS_JSON, e.g.:
#   export AGENT_SSH_HOSTS_JSON='{"agent1": "192.168.56.11", "agent2": "192.168.56.12"}'
# This lets every caller pass the SAME identifier (the Wazuh agent name —
# the one already used everywhere else in this project: alert.agent.name,
# block_ip()'s endpoint arg, isolate_endpoint()'s agent_id arg) to all four
# response functions, instead of having to separately track and pass a raw
# SSH host just for the two reversal functions.
AGENT_SSH_HOSTS = {}
try:
    _raw_agent_ssh_hosts = os.environ.get("AGENT_SSH_HOSTS_JSON")
    if _raw_agent_ssh_hosts:
        AGENT_SSH_HOSTS = json.loads(_raw_agent_ssh_hosts)
except Exception as e:
    print(f"[response_tools] failed to parse AGENT_SSH_HOSTS_JSON: {e}")


def _resolve_ssh_host(agent_name_or_host: str) -> str:
    """
    [Day 39] Resolve a Wazuh agent name to its SSH-reachable host/IP via
    AGENT_SSH_HOSTS. Falls back to returning the input unchanged if it's not
    in the map — so existing callers that already pass a raw SSH host
    directly (e.g. the __main__ smoke test's TEST_SSH_HOST) keep working
    with zero changes, while new callers can standardize on passing the
    Wazuh agent name everywhere.
    """
    return AGENT_SSH_HOSTS.get(agent_name_or_host, agent_name_or_host)


# ── Config — Day 34: GitHub Issues ──────────────────────────────────────────
GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO_OWNER = os.environ.get("GITHUB_REPO_OWNER")
GITHUB_REPO_NAME = os.environ.get("GITHUB_REPO_NAME")

# Confidence cutoffs used to label ticket severity. Chosen to line up with
# the tiers already in use elsewhere in the project: RESPONSE_CONFIDENCE_THRESHOLD
# (response_agent.py, Day 31) sits at 80 for "high", and coordination_agent.py's
# analyst-review band is 40-70, so "medium" starts at 50 as a middle ground
# between those two existing cutoffs. Adjust if you want it to match one exactly.
TICKET_SEVERITY_HIGH_THRESHOLD = 80
TICKET_SEVERITY_MEDIUM_THRESHOLD = 50


# ── Internal helpers ────────────────────────────────────────────────────────

def _get_wazuh_token():
    """Authenticate against the Wazuh API and return a bearer token.
    Never raises — returns None on failure, caller handles the error path."""
    try:
        resp = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]
    except Exception as e:
        print(f"[response_tools] Wazuh auth failed: {e}")
        return None


def _resolve_agent_id(agent_name_or_id, token):
    """Wazuh's active-response API requires a numeric agent ID (e.g. '002'),
    not the agent name used everywhere else in this project's alert schema
    (agent.name). If agent_name_or_id is already numeric, pass it through
    unchanged; otherwise resolve via GET /agents?name=<name>.
    Returns (agent_id: str | None, error: str | None)."""
    if str(agent_name_or_id).isdigit():
        return str(agent_name_or_id), None

    try:
        resp = requests.get(
            f"{WAZUH_API_URL}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"name": agent_name_or_id},
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json().get("data", {}).get("affected_items", [])
        if not items:
            return None, f"no agent found with name '{agent_name_or_id}'"
        agent = items[0]
        if agent.get("status") != "active":
            # not fatal here — return the id anyway, but the caller's
            # subsequent AR call will fail with a clear Wazuh error if the
            # agent truly can't receive commands. Surfacing the status lets
            # the caller see it up front in logs.
            print(f"[response_tools] WARNING: agent '{agent_name_or_id}' "
                  f"status is '{agent.get('status')}', not 'active' — "
                  f"active-response delivery may fail.")
        return agent["id"], None
    except Exception as e:
        return None, str(e)


def _send_active_response(agent_id, command, arguments, alert_context=None):
    """PUT an active-response command to a specific Wazuh agent.
    agent_id may be a numeric ID or an agent name (auto-resolved).
    Returns (success: bool, detail: str | dict)."""
    token = _get_wazuh_token()
    if not token:
        return False, "wazuh_auth_failed"

    resolved_id, resolve_err = _resolve_agent_id(agent_id, token)
    if resolved_id is None:
        return False, f"agent_resolution_failed: {resolve_err}"

    body = {
        "command": command,
        "arguments": arguments,
        # optional context Wazuh logs alongside the AR call — harmless if
        # omitted, useful for traceability in ossec logs
        "alert": alert_context or {"data": {"reason": "siem_response_agent"}},
    }

    try:
        resp = requests.put(
            f"{WAZUH_API_URL}/active-response?agents_list={resolved_id}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            data=json.dumps(body),
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        result = resp.json()
        # Wazuh returns HTTP 200 even when total_failed_items > 0 (e.g.
        # "Agent does not exist" / agent disconnected) — total_affected_items
        # must be checked explicitly to know if the command actually queued.
        if result.get("data", {}).get("total_failed_items", 0) > 0:
            return False, result
        return True, result
    except requests.exceptions.HTTPError as e:
        try:
            err_body = resp.json()
        except Exception:
            err_body = resp.text
        return False, f"{e} | response_body={err_body}"
    except Exception as e:
        return False, str(e)


def _run_ssh_command_with_retry(ssh_cmd, timeout=20, max_attempts=3, backoff_seconds=2):
    """
    [Day 39 fix — bug #12] Runs a subprocess-based SSH command with retry/
    backoff. Previously unblock_ip() and unisolate_endpoint() called
    subprocess.run() once and failed outright on any non-zero exit — a
    briefly-unreachable agent (network blip, momentary load) meant a real
    active-response block/isolation could get stuck in place with no
    automatic recovery. This mirrors the fallback-on-failure principle the
    Gemini calls elsewhere in the project already follow (never raise, treat
    transient failure as retryable rather than fatal).

    Only retries on outright command failure (non-zero returncode or a
    subprocess exception, e.g. connection refused/timeout) — it does not
    try to distinguish "wrong password" from "host unreachable", since SSH's
    own exit codes don't cleanly separate those either. If every attempt
    fails, the last result is returned so the caller's existing log/return
    shape is unchanged.

    Returns (success: bool, detail: dict) — detail always includes
    "attempts" so the audit trail (siem-response-log) shows how many tries
    it took, not just the final outcome.
    """
    import subprocess

    last_detail = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
            last_detail = {
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "attempts": attempt,
            }
            if result.returncode == 0:
                return True, last_detail
        except Exception as e:
            last_detail = {"error": str(e), "attempts": attempt}

        if attempt < max_attempts:
            time.sleep(backoff_seconds)

    return False, last_detail


def _post(path, body):
    """Shared ES POST helper — same convention as elastic_tools.py."""
    try:
        resp = requests.post(
            f"{ES_URL}/{path}",
            auth=ES_AUTH,
            headers={"Content-Type": "application/json"},
            data=json.dumps(body),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[response_tools] ES write failed ({path}): {e}")
        return None


def _log_response_action(action_type, target, endpoint, reversible, success, detail):
    """Writes every response action attempt to siem-response-log, success or
    failure, so the audit trail is always complete.
    action_type: "block_ip" | "unblock_ip" | "isolate_endpoint" |
                 "unisolate_endpoint" | "create_ticket"
    """
    doc = {
        "action_type": action_type,
        "target": target,                # IP for block/unblock, agent id/name for isolate/unisolate,
                                          # GitHub issue URL for create_ticket
        "endpoint": endpoint,            # Wazuh agent name/id, SSH host, or triggering agent.name
        "reversible": reversible,        # True for block_ip / isolate_endpoint
        "success": success,
        "detail": str(detail)[:2000],    # truncate to keep doc size sane
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _post(f"{RESPONSE_LOG_INDEX}/_doc", doc)
    return doc


# ── Public functions — Day 32: IP blocking ──────────────────────────────────

def block_ip(ip_address, endpoint):
    """
    Block a source IP at the firewall level on the specified Wazuh agent
    via active-response (firewall-drop).

    Args:
        ip_address: str — the IP to block (e.g. "203.0.113.77")
        endpoint:   str — Wazuh agent id or name to apply the block on

    Returns dict with success/action_type/target/endpoint/reversible/detail.
    Never raises.
    """
    success, detail = _send_active_response(
        agent_id=endpoint,
        command=FIREWALL_DROP_COMMAND,
        arguments=[ip_address],
        alert_context={"data": {"srcip": ip_address, "reason": "siem_response_agent_block"}},
    )

    _log_response_action(
        action_type="block_ip",
        target=ip_address,
        endpoint=endpoint,
        reversible=True,
        success=success,
        detail=detail,
    )

    return {
        "success": success,
        "action_type": "block_ip",
        "target": ip_address,
        "endpoint": endpoint,
        "reversible": True,
        "detail": detail,
    }


def unblock_ip(ip_address, endpoint, ssh_user=None, ssh_key_path=None):
    """
    Reverse a previously applied firewall-drop block for an IP on a given
    Wazuh agent.

    PLATFORM LIMITATION (confirmed via live testing + Wazuh GitHub issue
    #12342 — https://github.com/wazuh/wazuh/issues/12342): the public
    Wazuh REST API has NO way to send a "delete" action to a stateful
    built-in active-response script like firewall-drop. Every
    PUT /active-response call — no matter how many times repeated — always
    triggers "add". Confirmed live on Day 32: iptables went from 2 DROP
    rules after one block_ip() call to 4 after a second identical call via
    the API, never back down to 0. Wazuh's only built-in reversal path is
    the <active-response><timeout> auto-expiry in ossec.conf, which fires
    on a fixed timer, not on demand.

    Since this project needs an on-demand, callable unblock_ip(), this
    function bypasses the API and invokes the firewall-drop script directly
    on the agent over SSH, sending it the same "delete" JSON payload that
    execd sends internally on timeout expiry (version/origin/command/
    parameters — matches the script's documented STDIN contract).

    Args:
        ip_address:   str
        endpoint:     str — [Day 39] the Wazuh agent name is now accepted
                      here directly — it's resolved to an SSH-reachable
                      host/IP via AGENT_SSH_HOSTS (see _resolve_ssh_host()).
                      If the agent isn't in that map, `endpoint` is used
                      as-is, so passing a raw SSH host/IP directly (the old
                      calling convention) still works unchanged.
        ssh_user:     str | None — defaults to RESPONSE_SSH_USER env var
        ssh_key_path: str | None — defaults to RESPONSE_SSH_KEY env var

    Returns same shape as block_ip(), with action_type="unblock_ip".
    Never raises.
    """
    ssh_user = ssh_user or os.environ.get("RESPONSE_SSH_USER", "wazuh-manager")
    ssh_key_path = ssh_key_path or os.environ.get("RESPONSE_SSH_KEY", "~/.ssh/id_rsa")

    # [Day 39 fix — bug #11] Resolve endpoint (which may now be a Wazuh agent
    # name, same as block_ip()'s endpoint arg) to an SSH-reachable host.
    ssh_host = _resolve_ssh_host(endpoint)

    delete_payload = json.dumps({
        "version": 1,
        "origin": {"name": "response_tools", "module": "wazuh-execd"},
        "command": "delete",
        "parameters": {
            "extra_args": [],
            "alert": {"data": {"srcip": ip_address}},
        },
    })

    remote_cmd = f"echo '{delete_payload}' | sudo /var/ossec/active-response/bin/firewall-drop"

    ssh_cmd = [
        "ssh",
        "-i", os.path.expanduser(ssh_key_path),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        f"{ssh_user}@{ssh_host}",
        remote_cmd,
    ]

    # [Day 39 fix — bug #12] Retry with backoff instead of a single attempt.
    success, detail = _run_ssh_command_with_retry(ssh_cmd)

    _log_response_action(
        action_type="unblock_ip",
        target=ip_address,
        endpoint=endpoint,
        reversible=None,
        success=success,
        detail=detail,
    )

    return {
        "success": success,
        "action_type": "unblock_ip",
        "target": ip_address,
        "endpoint": endpoint,
        "reversible": None,
        "detail": detail,
    }


# ── Public functions — Day 33: Endpoint isolation ───────────────────────────

def isolate_endpoint(agent_id, endpoint, manager_ip=None):
    """
    Isolate a compromised endpoint from the network via active-response
    (isolate-host — see isolate-host.sh), while keeping the Wazuh agent's
    connection to the manager alive so heartbeats/alerts keep flowing for
    forensics.

    Uses the same "!command_name" API invocation as block_ip() — isolate-host
    is a custom <command> deployed to the agent and registered on the manager
    the same way firewall-drop already is (see isolate-host.sh header for the
    ossec.conf snippet), so _send_active_response() needs no changes.

    The manager's IP is passed as an argument so the script can allow-list
    manager traffic specifically before dropping everything else — this is
    what keeps the agent "active" in Wazuh's eyes during isolation, unlike a
    blanket DROP that would also sever the agent<->manager channel.

    Args:
        agent_id:   str — Wazuh agent id or name to isolate (API path)
        endpoint:   str — same identifier, kept as a separate arg to match
                    block_ip()'s (target, endpoint) shape for logging
        manager_ip: str | None — defaults to MANAGER_IP env var

    Returns dict with success/action_type/target/endpoint/reversible/detail.
    Never raises.
    """
    manager_ip = manager_ip or MANAGER_IP

    success, detail = _send_active_response(
        agent_id=endpoint,
        command=ISOLATE_HOST_COMMAND,
        arguments=[manager_ip],
        alert_context={"data": {"reason": "siem_response_agent_isolate", "agent": agent_id}},
    )

    _log_response_action(
        action_type="isolate_endpoint",
        target=agent_id,
        endpoint=endpoint,
        reversible=True,
        success=success,
        detail=detail,
    )

    return {
        "success": success,
        "action_type": "isolate_endpoint",
        "target": agent_id,
        "endpoint": endpoint,
        "reversible": True,
        "detail": detail,
    }


def unisolate_endpoint(agent_id, endpoint, ssh_user=None, ssh_key_path=None):
    """
    Reverse a previously applied isolate-host isolation on a given endpoint.

    PLATFORM LIMITATION — same one Day 32 found and confirmed against
    wazuh/wazuh#12342: the Wazuh API's PUT /active-response always triggers
    a registered <command>'s "add" path; there is no API-level way to
    request "delete" on a stateful custom script, even one we wrote
    ourselves (the limitation is in the API, not the script). So, exactly
    like unblock_ip(), this bypasses the API and invokes isolate-host
    directly on the agent over SSH with a "delete" JSON payload matching
    the script's documented STDIN contract.

    Args:
        agent_id:     str — Wazuh agent id or name (kept for logging /
                      symmetry with isolate_endpoint's signature)
        endpoint:     str — [Day 39] the Wazuh agent name is now accepted
                      here directly — resolved to an SSH-reachable host/IP
                      via AGENT_SSH_HOSTS (see _resolve_ssh_host()). Passing
                      a raw SSH host/IP directly still works unchanged if
                      the agent isn't in that map.
        ssh_user:     str | None — defaults to RESPONSE_SSH_USER env var
        ssh_key_path: str | None — defaults to RESPONSE_SSH_KEY env var

    Returns same shape as isolate_endpoint(), with action_type="unisolate_endpoint".
    Never raises.
    """
    ssh_user = ssh_user or os.environ.get("RESPONSE_SSH_USER", "wazuh-manager")
    ssh_key_path = ssh_key_path or os.environ.get("RESPONSE_SSH_KEY", "~/.ssh/id_rsa")

    # [Day 39 fix — bug #11]
    ssh_host = _resolve_ssh_host(endpoint)

    delete_payload = json.dumps({
        "version": 1,
        "origin": {"name": "response_tools", "module": "wazuh-execd"},
        "command": "delete",
        "parameters": {
            "extra_args": [],
            "alert": {"data": {"reason": "siem_response_agent_unisolate", "agent": agent_id}},
        },
    })

    remote_cmd = f"echo '{delete_payload}' | sudo /var/ossec/active-response/bin/isolate-host"

    ssh_cmd = [
        "ssh",
        "-i", os.path.expanduser(ssh_key_path),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        f"{ssh_user}@{ssh_host}",
        remote_cmd,
    ]

    # [Day 39 fix — bug #12] Retry with backoff instead of a single attempt.
    success, detail = _run_ssh_command_with_retry(ssh_cmd)

    _log_response_action(
        action_type="unisolate_endpoint",
        target=agent_id,
        endpoint=endpoint,
        reversible=None,
        success=success,
        detail=detail,
    )

    return {
        "success": success,
        "action_type": "unisolate_endpoint",
        "target": agent_id,
        "endpoint": endpoint,
        "reversible": None,
        "detail": detail,
    }


# ── Public functions — Day 34: Ticket creation (GitHub Issues) ─────────────

def _severity_from_confidence(confidence):
    """Maps a numeric confidence_pct (0-100) to a severity label — see
    TICKET_SEVERITY_*_THRESHOLD comments above for how the cutoffs were
    chosen."""
    if confidence is None:
        return "low"
    if confidence > TICKET_SEVERITY_HIGH_THRESHOLD:
        return "high"
    if confidence >= TICKET_SEVERITY_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _github_headers():
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def create_ticket(alert, triage_summary, confidence, technique=None):
    """
    Create a GitHub Issue for a confirmed threat that requires analyst review.

    Not a Wazuh active-response action like block_ip()/isolate_endpoint()
    above — this is a plain REST call to the GitHub Issues API — but follows
    the same conventions: never raises, logs every attempt (success or
    failure) to siem-response-log via _log_response_action(), and returns a
    structured result dict of the same shape.

    Args:
        alert: dict — raw Wazuh alert (or ES search hit). Reads
            rule.description, @timestamp, agent.name, data.srcip.
            If alert["_id"] and alert["_index"] are present (the ES hit
            fields, as returned by get_unprocessed_alerts()), the created
            ticket's URL is also written back onto that alert document via
            elastic_tools.update_alert_with_ticket_url(). AgentState's
            alert_es_id/alert_es_index are accepted as a fallback if _id/
            _index aren't present.
        triage_summary: str — the triage agent's summary/evidence text
        confidence: int (0-100) — confidence_pct at decision time
        technique: str | None — MITRE ATT&CK ID, e.g. "T1110"

    Returns:
        dict — success / action_type="create_ticket" / target (issue html_url,
        or None on failure) / endpoint (triggering agent.name) /
        reversible=False / detail (issue_number+labels on success, error
        string on failure).

    Never raises.
    """
    rule = alert.get("rule", {}) or {}
    rule_desc = rule.get("description", "Unknown alert")
    timestamp = alert.get("@timestamp", datetime.datetime.utcnow().isoformat() + "Z")
    src_ip = (alert.get("data", {}) or {}).get("srcip", "unknown")
    agent_name = (alert.get("agent", {}) or {}).get("name", "unknown")
    severity = _severity_from_confidence(confidence)

    if not GITHUB_TOKEN or not GITHUB_REPO_OWNER or not GITHUB_REPO_NAME:
        detail = "GITHUB_TOKEN / GITHUB_REPO_OWNER / GITHUB_REPO_NAME not configured"
        _log_response_action(
            action_type="create_ticket",
            target=None,
            endpoint=agent_name,
            reversible=False,
            success=False,
            detail=detail,
        )
        return {
            "success": False,
            "action_type": "create_ticket",
            "target": None,
            "endpoint": agent_name,
            "reversible": False,
            "detail": detail,
        }

    title = f"[SIEM ALERT] {rule_desc} — {timestamp}"
    body = (
        f"**Severity:** {severity}\n"
        f"**Confidence:** {confidence}%\n"
        f"**MITRE ATT&CK Technique:** {technique or 'Not identified'}\n"
        f"**Source IP:** {src_ip}\n"
        f"**Agent:** {agent_name}\n\n"
        f"### Triage Summary\n{triage_summary}\n\n"
        f"### Recommended Actions\n"
        f"- Review the alert and triage summary above\n"
        f"- Confirm or dismiss via the SOC dashboard\n"
        f"- Escalate to response agent (block_ip / isolate_endpoint) if confirmed malicious\n"
    )

    labels = [f"severity-{severity}", "needs-analyst-review", "auto-generated"]
    payload = {"title": title, "body": body, "labels": labels}
    url = f"{GITHUB_API_URL}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/issues"

    try:
        resp = requests.post(url, headers=_github_headers(), data=json.dumps(payload), timeout=15)
        resp.raise_for_status()
        issue = resp.json()
        success = True
        ticket_url = issue.get("html_url")
        detail = {"issue_number": issue.get("number"), "labels": labels}
    except requests.exceptions.HTTPError as e:
        try:
            err_body = resp.json()
        except Exception:
            err_body = resp.text
        success = False
        ticket_url = None
        detail = f"{e} | response_body={err_body}"
    except Exception as e:
        success = False
        ticket_url = None
        detail = str(e)

    _log_response_action(
        action_type="create_ticket",
        target=ticket_url,
        endpoint=agent_name,
        reversible=False,
        success=success,
        detail=detail,
    )

    if success:
        es_id = alert.get("_id") or alert.get("alert_es_id")
        es_index = alert.get("_index") or alert.get("alert_es_index")
        if es_id and es_index:
            try:
                from tools.elastic_tools import update_alert_with_ticket_url
                update_alert_with_ticket_url(es_index, es_id, ticket_url)
            except Exception as e:
                print(f"[create_ticket] failed to write ticket_url back to alert doc: {e}")

    return {
        "success": success,
        "action_type": "create_ticket",
        "target": ticket_url,
        "endpoint": agent_name,
        "reversible": False,
        "detail": detail,
    }


# ── Standalone smoke test ────────────────────────────────────────────────────

if __name__ == "__main__":
    TEST_IP = os.environ.get("TEST_IP", "203.0.113.250")
    TEST_AGENT = os.environ.get("TEST_AGENT", "agent1")          # Wazuh agent name (API path)
    TEST_SSH_HOST = os.environ.get("TEST_SSH_HOST", TEST_AGENT)  # SSH-reachable host/IP

    RUN_DAY32 = os.environ.get("RUN_DAY32", "1") == "1"
    RUN_DAY33 = os.environ.get("RUN_DAY33", "1") == "1"
    RUN_DAY34 = os.environ.get("RUN_DAY34", "1") == "1"
    RUN_DAY39 = os.environ.get("RUN_DAY39", "1") == "1"

    if RUN_DAY32:
        print(f"[test] Blocking {TEST_IP} on {TEST_AGENT} (via Wazuh API)...")
        block_result = block_ip(TEST_IP, TEST_AGENT)
        print(json.dumps(block_result, indent=2, default=str))

        print(f"\n[test] On the agent host, verify: sudo iptables -L -n | grep {TEST_IP}")
        input("Press Enter once you've confirmed the DROP rule exists...")

        print(f"\n[test] Unblocking {TEST_IP} on {TEST_SSH_HOST} (via direct SSH script call)...")
        unblock_result = unblock_ip(TEST_IP, TEST_SSH_HOST)
        print(json.dumps(unblock_result, indent=2, default=str))

        print(f"\n[test] Verify removal: sudo iptables -L -n | grep {TEST_IP}  (should return nothing)")
        print("[test] NOTE: if duplicate DROP rules exist from earlier testing, you may need to")
        print("       run unblock_ip() multiple times, or manually clear remaining rules first:")
        print(f"       sudo iptables -L INPUT -n --line-numbers | grep {TEST_IP}")

    if RUN_DAY33:
        print(f"\n[test] Isolating {TEST_AGENT} (via Wazuh API, manager_ip={MANAGER_IP})...")
        isolate_result = isolate_endpoint(TEST_AGENT, TEST_AGENT)
        print(json.dumps(isolate_result, indent=2, default=str))

        print(f"\n[test] On the agent host, verify: sudo iptables -L ISOLATE_HOST -n")
        print("[test] Also confirm the agent is still 'active' in Wazuh (heartbeats alive):")
        print(f"       GET /agents?name={TEST_AGENT}")
        input("Press Enter once you've confirmed isolation + live heartbeats...")

        print(f"\n[test] Unisolating {TEST_AGENT} on {TEST_SSH_HOST} (via direct SSH script call)...")
        unisolate_result = unisolate_endpoint(TEST_AGENT, TEST_SSH_HOST)
        print(json.dumps(unisolate_result, indent=2, default=str))

        print(f"\n[test] Verify removal: sudo iptables -L ISOLATE_HOST -n")
        print("       (should return: iptables: No chain/target/match by that name.)")

    if RUN_DAY34:
        print(f"\n[test] Creating GitHub ticket for a simulated high-confidence alert...")
        test_alert = {
            "rule": {"description": "sshd: Attempt to login using non-existent user", "level": 10},
            "agent": {"name": TEST_AGENT},
            "data": {"srcip": TEST_IP, "dstuser": "root(uid=0)"},
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        ticket_result = create_ticket(
            alert=test_alert,
            triage_summary=(
                "Repeated failed SSH login attempts from "
                f"{TEST_IP} targeting root and multiple other usernames "
                "within a short window. Consistent with automated "
                "brute-force credential guessing (T1110)."
            ),
            confidence=91,
            technique="T1110",
        )
        print(json.dumps(ticket_result, indent=2, default=str))
        if ticket_result["success"]:
            print(f"[test] PASS — issue created: {ticket_result['target']}")
        else:
            print(f"[test] FAIL — {ticket_result['detail']}")

    if RUN_DAY39:
        print("\n=== Day 39 regression tests ===")

        # Bug #11 — endpoint resolution. Day 39 hotfix: the original version
        # of this test hardcoded the assumption that "agent1" is NOT in
        # AGENT_SSH_HOSTS, which broke the moment a real environment set
        # AGENT_SSH_HOSTS_JSON (exactly as instructed in SETUP.md) — the
        # function was working correctly; the test's assumption was wrong.
        # Use a name guaranteed not to be configured for the passthrough
        # check, and only assert the mapped case conditionally.
        assert _resolve_ssh_host("__day39_unmapped_test_agent__") == "__day39_unmapped_test_agent__", \
            "an agent name not present in AGENT_SSH_HOSTS should pass through unchanged"
        print("PASS — _resolve_ssh_host() passthrough confirmed for an unmapped agent name")

        if "agent1" in AGENT_SSH_HOSTS:
            resolved = _resolve_ssh_host("agent1")
            assert resolved == AGENT_SSH_HOSTS["agent1"], (
                f"agent1 is configured in AGENT_SSH_HOSTS ({AGENT_SSH_HOSTS['agent1']}) "
                f"but _resolve_ssh_host() returned {resolved!r}"
            )
            print(f"PASS — agent1 resolves via AGENT_SSH_HOSTS to '{resolved}' "
                  f"(as configured in this environment's AGENT_SSH_HOSTS_JSON)")
        else:
            print("SKIPPED — agent1 not present in AGENT_SSH_HOSTS in this environment "
                  "(set AGENT_SSH_HOSTS_JSON to exercise the mapped-resolution path)")

        # Bug #12 — retry/backoff. Simulate a command that always fails and
        # confirm it's attempted 3 times (not just once) before giving up.
        fail_cmd = ["false"]  # /bin/false — always exits 1, near-instant
        success, detail = _run_ssh_command_with_retry(fail_cmd, timeout=5, max_attempts=3, backoff_seconds=0)
        assert success is False
        assert detail["attempts"] == 3, f"expected 3 attempts, got {detail.get('attempts')}"
        print(f"PASS — _run_ssh_command_with_retry() retried 3 times before giving up: {detail}")

        succeed_cmd = ["true"]  # /bin/true — always exits 0
        success2, detail2 = _run_ssh_command_with_retry(succeed_cmd, timeout=5, max_attempts=3, backoff_seconds=0)
        assert success2 is True
        assert detail2["attempts"] == 1, "should not retry once a command succeeds"
        print(f"PASS — _run_ssh_command_with_retry() returns immediately on first success: {detail2}")
