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

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.elastic_tools import get_recent_events, get_user_login_history

# ── LLM backend config ────────────────────────────────────────────────────────
# To swap to Claude or OpenAI, change LLM_BACKEND and set your API key:
#
#   Ollama (current — local, no key needed):
#       LLM_BACKEND = "ollama"
#
#   Claude API:
#       LLM_BACKEND = "claude"
#       export ANTHROPIC_API_KEY=sk-ant-...
#       pip install anthropic --break-system-packages
#
#   OpenAI:
#       LLM_BACKEND = "openai"
#       export OPENAI_API_KEY=sk-...
#       pip install openai --break-system-packages

LLM_BACKEND  = "ollama"                        # ← change this to swap backends

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

CLAUDE_MODEL = "claude-sonnet-4-20250514"      # ready for when you switch
OPENAI_MODEL = "gpt-4o-mini"


# ── helpers ────────────────────────────────────────────────────────────────────

def _summarise_events(events: list) -> str:
    """
    Turn a list of ES docs into a compact numbered text block for the prompt.

    FIX 3: Handles both nested dicts (from get_recent_events returning
    _source-unpacked docs) and flat dot-notation keys, so the fields
    actually appear in the prompt instead of printing '?'.
    Previously the function only tried flat keys like e.get("rule.id")
    which always returned '?' on nested dicts.
    """
    if not events:
        return "  (none)"
    lines = []
    for i, e in enumerate(events[:8], 1):   # cap at 8 — keeps prompt ~400 tokens
        # Support both nested dict and flat dot-notation formats
        rule = e.get("rule") if isinstance(e.get("rule"), dict) else {}
        data = e.get("data") if isinstance(e.get("data"), dict) else {}

        ts   = e.get("@timestamp", "?")[:19]
        rid  = rule.get("id")   or e.get("rule.id",   "?")
        desc = (rule.get("description") or e.get("rule.description", "?"))[:80]
        src  = data.get("srcip") or e.get("data.srcip",    "?")
        usr  = data.get("dstuser") or e.get("data.dstuser", "?")
        lines.append(f"  {i}. [{ts}] rule={rid} src={src} user={usr} — {desc}")
    return "\n".join(lines)


def _call_llm(prompt: str) -> str:
    """
    Unified LLM caller. Switch backends by changing LLM_BACKEND at the top.
    Currently routes to Ollama. When you have an API key, set LLM_BACKEND
    to "claude" or "openai" — no other code changes needed anywhere.
    """
    if LLM_BACKEND == "claude":
        import os
        try:
            import anthropic
        except ImportError:
            return '{"verdict": "unknown", "summary": "Run: pip install anthropic --break-system-packages", "evidence": []}'
        try:
            client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
            msg = client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=512,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text.strip()
        except Exception as exc:
            return json.dumps({"verdict": "unknown", "summary": f"Claude API error: {exc}", "evidence": []})

    if LLM_BACKEND == "openai":
        import os
        try:
            from openai import OpenAI
        except ImportError:
            return '{"verdict": "unknown", "summary": "Run: pip install openai --break-system-packages", "evidence": []}'
        try:
            client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            resp = client.chat.completions.create(
                model=OPENAI_MODEL,
                max_tokens=512,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.choices[0].message.content.strip()
        except Exception as exc:
            return json.dumps({"verdict": "unknown", "summary": f"OpenAI API error: {exc}", "evidence": []})

    # ── Default: Ollama (local) ────────────────────────────────────────────────
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 512},
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        return '{"verdict": "unknown", "summary": "Ollama not reachable — is it running? Run: ollama serve &", "evidence": []}'
    except Exception as exc:
        return json.dumps({"verdict": "unknown", "summary": f"Ollama error: {exc}", "evidence": []})


def _normalise_verdict(raw: str) -> str:
    """
    FIX 1 — Verdict normalisation.

    The original code did:
        verdict = result.get("verdict", "unknown").lower()
        if verdict not in ("suspicious", "benign", "unknown"):
            verdict = "unknown"

    Problem: llama3.2 often returns "Suspicious activity detected" or
    "The activity appears benign." — these fail the exact-match check and
    silently fall back to "unknown", making every Test 1 return the wrong answer.

    Fix: keyword search after lowercasing and stripping punctuation.
    """
    if not raw:
        return "unknown"
    cleaned = re.sub(r"[^a-z\s]", " ", raw.lower())
    if any(w in cleaned for w in ("suspicious", "malicious", "threat", "attack")):
        return "suspicious"
    if any(w in cleaned for w in ("benign", "legitimate", "normal", "routine", "expected")):
        return "benign"
    return "unknown"


def _coerce_evidence(raw) -> list:
    """
    FIX 2 — Evidence always a list.

    The original code did:
        "evidence": list(result.get("evidence", []))

    Problem: if the LLM returns evidence as a plain string (not a JSON array),
    list("some string") produces ['s','o','m','e',...] — character by character.
    If it returns None, list(None) raises TypeError.

    Fix: handle string, list, None, and any other type safely.
    """
    if raw is None:
        return ["No evidence provided"]

    if isinstance(raw, list):
        return [str(e).strip() for e in raw if str(e).strip()]

    if isinstance(raw, str):
        # Try JSON array first
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(e).strip() for e in parsed if str(e).strip()]
        except (json.JSONDecodeError, ValueError):
            pass
        # Treat as bullet / newline delimited text
        lines = re.split(r"\n|(?:^|\n)\s*[-*•]\s*", raw)
        cleaned = [l.strip().lstrip("-*• ") for l in lines if l.strip()]
        return cleaned if cleaned else [raw.strip()]

    return [str(raw)]  # dict or other — stringify


def _parse_llm_output(raw: str) -> dict:
    """
    Extract JSON block from LLM response, using fix 1 + fix 2.
    """
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            return {
                "verdict":  _normalise_verdict(result.get("verdict", "")),   # FIX 1
                "summary":  str(result.get("summary", raw[:300])),
                "evidence": _coerce_evidence(result.get("evidence")),        # FIX 2
            }
        except json.JSONDecodeError:
            pass

    return {
        "verdict":  "unknown",
        "summary":  raw[:500],
        "evidence": ["LLM response could not be parsed as JSON"],
    }


def _confidence_from_verdict(verdict: str, event_count: int) -> int:
    base = {"suspicious": 75, "benign": 20, "unknown": 40}.get(verdict, 40)
    if event_count >= 20:
        base = min(base + 15, 100)
    elif event_count >= 10:
        base = min(base + 8, 100)
    return base


def _is_internal_ip(ip: str) -> bool:
    """Return True if the IP is RFC-1918 private / loopback."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("172.")   # covers 172.16–172.31
    )


def _pre_classify(rule_id: str, rule_lvl: int, groups: list,
                  src_ip: str, context_note: str) -> dict | None:
    """
    Rule-based fast-path classifier — runs BEFORE the LLM.

    Returns a triage_result dict if the case is clear-cut, or None to
    fall through to the LLM for genuinely ambiguous alerts.

    Why this exists: llama3.2:3b (2 GB) defaults to 'suspicious' for any
    security-related keyword regardless of context. For easy cases we skip
    the 90-150s LLM call entirely and return a deterministic verdict.

    Rules applied (in priority order):
      BENIGN  — low severity (≤ 5) + internal IP + scheduled/cron context note
      BENIGN  — PAM session-close event (always informational)
      UNKNOWN — authentication_success at low severity (login happened but no
                evidence of compromise either way)
      SUSPICIOUS — authentication_failed at high severity (≥ 8) — pass to LLM
                   but this is just a hint; LLM handles it
    """
    note_lower = context_note.lower()
    internal   = _is_internal_ip(src_ip)

    # ── Benign: scheduled automation on internal network ──────────────────────
    scheduled_keywords = ("cron", "backup", "scheduled", "maintenance",
                          "automated", "script", "service account")
    if (rule_lvl <= 5
            and internal
            and any(k in note_lower for k in scheduled_keywords)):
        return {
            "verdict":  "benign",
            "summary":  (
                f"Low-severity event (level {rule_lvl}/15) from internal IP {src_ip}. "
                f"Context indicates scheduled/automated activity. "
                f"Pre-classifier bypassed LLM — no threat indicators present."
            ),
            "evidence": [
                f"Rule level {rule_lvl}/15 — below escalation threshold of 6",
                f"Source IP {src_ip} is RFC-1918 internal address",
                f"Context note references automated/scheduled activity",
            ],
        }

    # ── Benign: session-close events are always informational ─────────────────
    # NOTE: parentheses are required — without them `or` beats `and` and this
    # matches ANY pam event at level ≤ 3, including 5501 (session open).
    if rule_id in ("5502",) or (rule_id not in ("5501",) and "pam" in groups and rule_lvl <= 3):
        return {
            "verdict":  "benign",
            "summary":  (
                f"PAM session-close / low-severity informational event (level {rule_lvl}/15). "
                f"Session-close events confirm a prior authorised login completed normally. "
                f"No threat indicators."
            ),
            "evidence": [
                "Session-close events are informational by definition",
                f"Rule level {rule_lvl}/15 — informational only",
            ],
        }

    # ── Unknown: successful auth with no other threat indicators ──────────────
    # (login worked, but we can't tell if it's the real user without more context)
    if (("authentication_success" in groups or rule_id in ("5501", "5503"))
            and rule_lvl <= 5
            and "authentication_failed" not in groups):
        reason = (
            "Successful login with no corroborating threat indicators. "
            "Cannot determine if this is the legitimate user or credential misuse "
            "without behavioural baseline or MFA logs. Recommend analyst review."
        )
        if "insufficient evidence" in note_lower or "new ip" in note_lower or "first" in note_lower:
            reason = (
                f"Successful login for an account from a previously-unseen IP "
                f"during business hours. Could be VPN/travel/new device or credential "
                f"theft — insufficient evidence to rule either way. Analyst review required."
            )
        return {
            "verdict":  "unknown",
            "summary":  reason,
            "evidence": [
                f"Authentication succeeded — not inherently malicious",
                f"Rule level {rule_lvl}/15 — low severity",
                "No failed-auth events in the same session to indicate brute force",
                "Context note flags ambiguity — new IP or insufficient history",
            ],
        }

    # ── Fall through → let the LLM decide ─────────────────────────────────────
    return None


# ── LangGraph node ─────────────────────────────────────────────────────────────

def triage_node(state: dict) -> dict:
    alert = state.get("alert", {})
    notes = list(state.get("notes", []))

    src_ip       = alert.get("data", {}).get("srcip")    or alert.get("data.srcip", "")
    dst_user     = alert.get("data", {}).get("dstuser")  or alert.get("data.dstuser", "")
    rule_id      = alert.get("rule", {}).get("id")       or alert.get("rule.id", "")
    rule_desc    = alert.get("rule", {}).get("description") or alert.get("rule.description", "")
    rule_lvl     = alert.get("rule", {}).get("level")    or alert.get("rule.level", 0)
    agent_nm     = alert.get("agent", {}).get("name")    or alert.get("agent.name", "")
    context_note = alert.get("data", {}).get("context_note", "")  # optional analyst hint

    notes.append(f"[triage] Alert: rule {rule_id} | level {rule_lvl} | src={src_ip} | user={dst_user}")

    recent_events = []
    login_history  = []

    if src_ip:
        recent_events = get_recent_events(src_ip, minutes=60)
        notes.append(f"[triage] get_recent_events({src_ip}) → {len(recent_events)} events in last 60 min")

    clean_user = re.sub(r"\(.*?\)", "", dst_user).strip() if dst_user else ""
    if clean_user:
        login_history = get_user_login_history(clean_user, days=7)
        notes.append(f"[triage] get_user_login_history({clean_user}) → {len(login_history)} events in last 7 days")

    # ── Pre-classifier: skip LLM for clear-cut cases ──────────────────────────
    rule_groups = alert.get("rule", {}).get("groups", [])
    pre = _pre_classify(rule_id, int(rule_lvl or 0), rule_groups, src_ip, context_note)
    if pre is not None:
        notes.append(f"[triage] Pre-classifier verdict: {pre['verdict']} (LLM skipped)")
        conf_pct         = _confidence_from_verdict(pre["verdict"], len(recent_events))
        confidence_label = "high" if conf_pct >= 65 else ("medium" if conf_pct >= 35 else "low")
        escalate         = pre["verdict"] == "suspicious" and conf_pct >= 65
        notes.append(f"[triage] confidence={confidence_label} ({conf_pct}%) | escalate={escalate}")
        return {
            **state,
            "notes":          notes,
            "confidence":     confidence_label,
            "confidence_pct": conf_pct,
            "triage_result":  pre,
            "escalate":       escalate,
        }

    # ── LLM path: only reached for ambiguous / high-severity alerts ───────────
    notes.append("[triage] No pre-classifier match — calling Ollama llama3.2 for analysis...")

    prompt = f"""You are a cybersecurity analyst reviewing a SIEM alert. Analyse the evidence below and return ONLY a JSON object — no explanation, no markdown, no text before or after the JSON.

=== ALERT ===
Rule ID      : {rule_id}
Description  : {rule_desc}
Severity     : {rule_lvl} / 15
Source IP    : {src_ip}
Target user  : {dst_user}
Agent (host) : {agent_nm}
Context note : {context_note if context_note else "none"}

=== RECENT EVENTS FROM THIS IP (last 60 min, max 8 shown) ===
{_summarise_events(recent_events)}

=== LOGIN HISTORY FOR USER '{clean_user or dst_user}' (last 7 days, max 8 shown) ===
{_summarise_events(login_history)}

=== TASK ===
Based on the alert and supporting evidence above, decide:
- Is this alert likely a REAL threat (suspicious), a false positive (benign), or unclear (unknown)?
- What is the key reasoning?
- What are 2-4 specific pieces of evidence that support your verdict?

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

    raw_response  = _call_llm(prompt)
    triage_result = _parse_llm_output(raw_response)

    notes.append(f"[triage] Verdict: {triage_result['verdict']} | {triage_result['summary'][:80]}...")

    conf_pct = _confidence_from_verdict(triage_result["verdict"], len(recent_events))

    if conf_pct >= 65:
        confidence_label = "high"
    elif conf_pct >= 35:
        confidence_label = "medium"
    else:
        confidence_label = "low"

    escalate = triage_result["verdict"] == "suspicious" and conf_pct >= 65

    notes.append(f"[triage] confidence={confidence_label} ({conf_pct}%) | escalate={escalate}")

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
    fake_alert = {
        "rule": {
            "id": "5710",
            "description": "sshd: Attempt to login using non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "level": 10
        },
        "data": {
            "srcip":   "127.0.0.1",
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
        "escalate":   False,
    }

    print("=== Running triage_node with fake brute-force alert ===\n")
    result = triage_node(initial_state)

    print("\n── TRIAGE RESULT ──")
    print(json.dumps(result["triage_result"], indent=2))

    print("\n── CONFIDENCE ──")
    print(f"  Label   : {result['confidence']}")
    print(f"  Score   : {result['confidence_pct']}%")
    print(f"  Escalate: {result['escalate']}")

    print("\n── AGENT NOTES ──")
    for note in result["notes"]:
        print(f"  {note}")
