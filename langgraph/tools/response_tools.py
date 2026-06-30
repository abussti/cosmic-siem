"""
tools/response_tools.py

Day 32 — Response / Wazuh
Action 1: IP blocking via Wazuh active-response.

Note: firewall-drop is already a stock <command> in this environment's
ossec.conf (verified via `docker exec ... grep -A3 "<command>"`), so no
ossec.conf edit was needed. It's invoked directly via the API using the
"!command_name" syntax, which calls a registered <command> without
requiring an <active-response> auto-trigger binding block.

Mirrors the conventions already used in tools/elastic_tools.py:
  - thin `requests`-based helpers, no SDK client object
  - functions never raise — errors are caught and returned as a
    structured result dict, same pattern as run_hunt() / get_*() calls
  - all writes go through a small `_post`-style helper

Two public functions:
    block_ip(ip_address, endpoint)    -> dict
    unblock_ip(ip_address, endpoint)  -> dict

Both log every call to siem-response-log (Step 5) regardless of success
or failure, so the audit trail is complete even on API errors.
"""

import os
import json
import datetime
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
    """Step 5 — writes every block/unblock attempt to siem-response-log,
    success or failure, so the audit trail is always complete."""
    doc = {
        "action_type": action_type,      # "block_ip" | "unblock_ip"
        "target": target,                # the IP address acted on
        "endpoint": endpoint,            # Wazuh agent name/id affected
        "reversible": reversible,        # True for block_ip
        "success": success,
        "detail": str(detail)[:2000],    # truncate to keep doc size sane
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    _post(f"{RESPONSE_LOG_INDEX}/_doc", doc)
    return doc


# ── Public functions ─────────────────────────────────────────────────────────

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
        endpoint:     str — an SSH-reachable hostname or IP for the agent
                      (NOT the Wazuh agent ID/name used by block_ip's API
                      path — this needs real SSH access to the box)
        ssh_user:     str | None — defaults to RESPONSE_SSH_USER env var
        ssh_key_path: str | None — defaults to RESPONSE_SSH_KEY env var

    Returns same shape as block_ip(), with action_type="unblock_ip".
    Never raises.
    """
    import subprocess

    ssh_user = ssh_user or os.environ.get("RESPONSE_SSH_USER", "wazuh-manager")
    ssh_key_path = ssh_key_path or os.environ.get("RESPONSE_SSH_KEY", "~/.ssh/id_rsa")

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
        f"{ssh_user}@{endpoint}",
        remote_cmd,
    ]

    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=20)
        success = result.returncode == 0
        detail = {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except Exception as e:
        success = False
        detail = str(e)

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


# ── Step 6 — standalone smoke test ──────────────────────────────────────────

if __name__ == "__main__":
    TEST_IP = os.environ.get("TEST_IP", "203.0.113.250")
    TEST_AGENT = os.environ.get("TEST_AGENT", "agent1")          # Wazuh agent name (for block_ip, via API)
    TEST_SSH_HOST = os.environ.get("TEST_SSH_HOST", TEST_AGENT)  # SSH-reachable host/IP (for unblock_ip)

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
