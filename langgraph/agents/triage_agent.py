"""
triage_agent.py — LangGraph node: Triage Agent (Ollama / llama3.2 edition).

What this agent does:
  1. Pulls the source IP from the incoming alert.
  2. Calls get_recent_events() — last 60 min activity from that IP.
  3. Calls get_user_login_history() — 7-day history for the targeted user.
  4. Builds a structured prompt and calls the local Ollama llama3.2 model.
  5. Parses the LLM response into {'verdict', 'summary', 'evidence'}.
  6. Writes verdict + confidence score back into AgentState.

Place this file at:  ~/elastic/langgraph/agents/triage_agent.py

Dependencies:
    pip install requests langgraph --break-system-packages
    ollama pull llama3.2:3b
"""

import json
import re
import requests

# Import from sibling tools module.
# When running from the langgraph/ directory:  python3 -m agents.triage_agent
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.elastic_tools import get_recent_events, get_user_login_history

# ── Ollama config ──────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"   # change to llama3.2:8b if your VM has ≥16 GB RAM


# ── helpers ────────────────────────────────────────────────────────────────────

def _summarise_events(events: list[dict]) -> str:
    """Turn a list of ES docs into a compact numbered text block for the prompt."""
    if not events:
        return "  (none)"
    lines = []
    for i, e in enumerate(events[:8], 1):   # cap at 8 to keep prompt short
        ts   = e.get("@timestamp", "?")[:19]
        rid  = e.get("rule.id", "?")
        desc = e.get("rule.description", "?")[:80]
        src  = e.get("data.srcip", "?")
        usr  = e.get("data.dstuser", "?")
        lines.append(f"  {i}. [{ts}] rule={rid} src={src} user={usr} — {desc}")
    return "\n".join(lines)


def _call_ollama(prompt: str) -> str:
    """
    Call local Ollama with the given prompt and return the full response text.
    Uses streaming=False for simplicity.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,   # low temp = more deterministic, better for analysis
            "num_predict": 512    # enough for verdict + summary + evidence list
        }
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        return '{"verdict": "unknown", "summary": "Ollama not reachable — is it running?", "evidence": []}'
    except Exception as exc:
        return f'{{"verdict": "unknown", "summary": "LLM error: {exc}", "evidence": []}}'


def _parse_llm_output(raw: str) -> dict:
    """
    Extract the JSON block from the LLM response.
    llama3.2 sometimes wraps JSON in markdown fences — strip those first.
    Falls back gracefully if parsing fails.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()

    # Try to find the first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            # Normalise keys
            verdict  = result.get("verdict", "unknown").lower()
            if verdict not in ("suspicious", "benign", "unknown"):
                verdict = "unknown"
            return {
                "verdict":  verdict,
                "summary":  str(result.get("summary", raw[:300])),
                "evidence": list(result.get("evidence", []))
            }
        except json.JSONDecodeError:
            pass

    # Hard fallback — couldn't parse, return raw as summary
    return {
        "verdict":  "unknown",
        "summary":  raw[:500],
        "evidence": ["LLM response could not be parsed as JSON"]
    }


def _confidence_from_verdict(verdict: str, event_count: int) -> int:
    """
    Convert the LLM verdict + event volume into a numeric confidence 0–100.
    This is what graph.py uses to decide whether to run deeper agents.
    """
    base = {"suspicious": 75, "benign": 20, "unknown": 40}.get(verdict, 40)
    # Boost confidence if there are many events (more evidence = more certain)
    if event_count >= 20:
        base = min(base + 15, 100)
    elif event_count >= 10:
        base = min(base + 8, 100)
    return base


# ── LangGraph node ─────────────────────────────────────────────────────────────

def triage_node(state: dict) -> dict:
    """
    LangGraph node function — receives AgentState dict, returns updated state.

    AgentState fields used:
        alert       (dict)  — raw Wazuh alert payload, must be present
        notes       (list)  — append-only log, we add to it
        confidence  (str)   — we overwrite with 'low' / 'medium' / 'high'
        technique   (str)   — we set if we can infer MITRE ID
        escalate    (bool)  — we set True if verdict is suspicious

    New fields added to state by this node:
        triage_result  (dict) — {'verdict', 'summary', 'evidence'}
        confidence_pct (int)  — numeric 0–100 used by graph router
    """
    alert = state.get("alert", {})
    notes = list(state.get("notes", []))

    # ── 1. Extract key fields from the alert ──────────────────────────────────
    src_ip   = alert.get("data", {}).get("srcip") or alert.get("data.srcip", "")
    dst_user = alert.get("data", {}).get("dstuser") or alert.get("data.dstuser", "")
    rule_id  = alert.get("rule", {}).get("id") or alert.get("rule.id", "")
    rule_desc = alert.get("rule", {}).get("description") or alert.get("rule.description", "")
    rule_lvl  = alert.get("rule", {}).get("level") or alert.get("rule.level", 0)
    agent_nm  = alert.get("agent", {}).get("name") or alert.get("agent.name", "")

    notes.append(f"[triage] Alert: rule {rule_id} | level {rule_lvl} | src={src_ip} | user={dst_user}")

    # ── 2. Pull context from Elasticsearch ───────────────────────────────────
    recent_events = []
    login_history  = []

    if src_ip:
        recent_events = get_recent_events(src_ip, minutes=60)
        notes.append(f"[triage] get_recent_events({src_ip}) → {len(recent_events)} events in last 60 min")

    # Clean the username (Wazuh often gives 'root(uid=0)' — extract 'root')
    clean_user = re.sub(r"\(.*?\)", "", dst_user).strip() if dst_user else ""
    if clean_user:
        login_history = get_user_login_history(clean_user, days=7)
        notes.append(f"[triage] get_user_login_history({clean_user}) → {len(login_history)} events in last 7 days")

    # ── 3. Build LLM prompt ───────────────────────────────────────────────────
    prompt = f"""You are a cybersecurity analyst reviewing a SIEM alert. Analyse the evidence below and return ONLY a JSON object — no explanation, no markdown, no text before or after the JSON.

=== ALERT ===
Rule ID      : {rule_id}
Description  : {rule_desc}
Severity     : {rule_lvl} / 15
Source IP    : {src_ip}
Target user  : {dst_user}
Agent (host) : {agent_nm}

=== RECENT EVENTS FROM THIS IP (last 60 min) ===
{_summarise_events(recent_events)}

=== LOGIN HISTORY FOR USER '{clean_user or dst_user}' (last 7 days) ===
{_summarise_events(login_history)}

=== TASK ===
Based on the alert and supporting evidence above, decide:
- Is this alert likely a REAL threat (suspicious), a false positive (benign), or unclear (unknown)?
- What is the key reasoning?
- What are 2–4 specific pieces of evidence that support your verdict?

Return EXACTLY this JSON structure (no other text):
{{
  "verdict": "suspicious" | "benign" | "unknown",
  "summary": "2-3 sentence plain-English explanation of your reasoning",
  "evidence": [
    "Evidence point 1",
    "Evidence point 2",
    "Evidence point 3"
  ]
}}"""

    notes.append("[triage] Calling Ollama llama3.2 for analysis...")

    # ── 4. Call the LLM ───────────────────────────────────────────────────────
    raw_response  = _call_ollama(prompt)
    triage_result = _parse_llm_output(raw_response)

    notes.append(f"[triage] Verdict: {triage_result['verdict']} | {triage_result['summary'][:80]}...")

    # ── 5. Map verdict → AgentState fields ───────────────────────────────────
    conf_pct = _confidence_from_verdict(triage_result["verdict"], len(recent_events))

    # Map numeric confidence to the string label used by existing graph routing
    if conf_pct >= 65:
        confidence_label = "high"
    elif conf_pct >= 35:
        confidence_label = "medium"
    else:
        confidence_label = "low"

    escalate = triage_result["verdict"] == "suspicious" and conf_pct >= 65

    notes.append(f"[triage] confidence={confidence_label} ({conf_pct}%) | escalate={escalate}")

    # ── 6. Return updated state ───────────────────────────────────────────────
    return {
        **state,
        "notes":          notes,
        "confidence":     confidence_label,
        "confidence_pct": conf_pct,
        "triage_result":  triage_result,
        "escalate":       escalate,
    }


# ── standalone test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Feed a fake brute-force alert and print full output.
    fake_alert = {
        "rule": {
            "id": "5710",
            "description": "sshd: Attempt to login using non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "level": 10
        },
        "data": {
            "srcip": "127.0.0.1",
            "dstuser": "root"
        },
        "agent": {"name": "agent1"},
        "@timestamp": "2026-05-21T08:00:00Z"
    }

    initial_state = {
        "alert":      fake_alert,
        "notes":      [],
        "confidence": None,
        "technique":  None,
        "escalate":   False
    }

    print("=== Running triage_node with fake brute-force alert ===\n")
    result = triage_node(initial_state)

    print("\n── TRIAGE RESULT ──")
    print(json.dumps(result["triage_result"], indent=2))

    print("\n── CONFIDENCE ──")
    print(f"  Label : {result['confidence']}")
    print(f"  Score : {result['confidence_pct']}%")
    print(f"  Escalate: {result['escalate']}")

    print("\n── AGENT NOTES ──")
    for note in result["notes"]:
        print(f"  {note}")
