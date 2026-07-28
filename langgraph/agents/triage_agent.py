"""
triage_agent.py — LangGraph node: Triage Agent.

Day 14 — initial implementation (Ollama)
Day 19 — Gemini 2.5 Flash backend; technique propagation fix; after-hours/new-IP boosts
Day 23 — CTI context block injected into Gemini prompt
Day 24 — when CTI match found, automatically calls get_threat_actor_profile()
          and folds campaigns/TTPs/target sectors into the prompt AND the
          final summary (deterministic append — not dependent on the LLM
          choosing to repeat it).
Day 39 — two bug fixes from Phase 2 Scenario 3 / Scenario 2 testing:
          1. Added _build_volume_context() — data.bytes_out/bytes_in/conn_count
             were never surfaced to the LLM, so a 500MB after-hours transfer
             that correctly reached the TRIAGE tier still came back verdict
             =unknown because the model never saw the volume signal.
          2. confidence_pct is now preserved when it was pre-scored upstream
             (state["_pre_scored"] is True — set by hunting_agent.py's
             escalate_hunt_to_triage() for hunt-originated synthetic alerts)
             instead of always being overwritten by the flat verdict->pct
             mapping. Mirrors the pattern coordination_agent.py already uses
             for the Day 24 CTI force-route override.
Day 47 — Added _build_ueba_block() — surfaces the UEBA anomaly score
          (tools/ueba_scorer.py, comparing the alert's user/entity against
          the behavioral profile ueba_engine.py builds nightly) directly in
          the Gemini prompt, the same way CTI and traffic-volume context
          already are. Never changes confidence_pct here (that's
          confidence_scorer.py's job, Day 47's other change) — this is
          purely giving the LLM the same behavioral-deviation signal a
          human analyst reviewing the SOC dashboard would see.

What this agent does:
  1. Pulls source IP and user from the incoming alert.
  2. Calls get_recent_events()      — last 60 min activity from that IP.
  3. Calls get_user_login_history() — 7-day history for the targeted user.
  4. [Day 23] Reads CTI enrichment fields already attached by pipeline_runner.
  5. [Day 24] If CTI matched, calls get_threat_actor_profile() for that actor.
  6. [Day 39] Builds a traffic-volume context block from data.bytes_out/in/conn_count.
  7. [Day 47] Builds a UEBA behavioral-context block from tools.ueba_scorer.score_anomaly().
  8. Builds a structured prompt (CTI + actor profile + volume + UEBA) and calls Gemini.
  9. Parses the LLM response into {verdict, summary, evidence, technique}.
  10. [Day 24] Appends actor profile context to the summary deterministically.
  11. Writes verdict + confidence score back into AgentState, preserving any
      pre-scored confidence_pct set upstream (Day 39).
"""

import json
import re
import requests

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.elastic_tools import get_recent_events, get_user_login_history, get_threat_actor_profile
from tools.ueba_scorer import score_anomaly

# ── LLM backend config ────────────────────────────────────────────────────────
LLM_BACKEND  = "gemini"

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

CLAUDE_MODEL = "claude-sonnet-4-20250514"
OPENAI_MODEL = "gpt-4o-mini"
GEMINI_MODEL = "gemini-2.5-flash"

# Day 39: single-event outbound transfer size (bytes) that's called out
# explicitly to the LLM as a plausible exfiltration indicator. Kept in sync
# with confidence_scorer.LARGE_TRANSFER_BYTES_THRESHOLD conceptually, but
# defined independently here since this is a prompt-language threshold, not
# a scoring threshold — the two are allowed to drift if there's a reason.
VOLUME_CONTEXT_FLAG_BYTES = 50_000_000  # 50MB

# Day 47: UEBA anomaly_score (0-100) above which the prompt explicitly
# tells the LLM to weigh the behavioral deviation heavily, rather than
# leaving it as a passive footnote.
UEBA_CONTEXT_FLAG_SCORE = 60


# ── helpers ────────────────────────────────────────────────────────────────────

def _summarise_events(events: list) -> str:
    if not events:
        return "  (none)"
    lines = []
    for i, e in enumerate(events[:8], 1):
        rule = e.get("rule") if isinstance(e.get("rule"), dict) else {}
        data = e.get("data") if isinstance(e.get("data"), dict) else {}

        ts   = e.get("@timestamp", "?")[:19]
        rid  = rule.get("id")   or e.get("rule.id",   "?")
        desc = (rule.get("description") or e.get("rule.description", "?"))[:80]
        src  = data.get("srcip") or e.get("data.srcip",    "?")
        usr  = data.get("dstuser") or e.get("data.dstuser", "?")
        lines.append(f"  {i}. [{ts}] rule={rid} src={src} user={usr} — {desc}")
    return "\n".join(lines)


def _build_volume_context(alert: dict) -> str:
    """
    [Day 39] Surfaces transfer-volume / connection-count fields to the LLM.

    Bug fixed: data.bytes_out (and friends) were present on the alert dict
    and correctly boosted confidence_scorer.py's score, but were never read
    into the prompt at all — the LLM was reasoning about a "packet accepted"
    firewall event with zero awareness that 500MB moved in that event. This
    silently downgraded a scorer-flagged high-confidence alert to a hedge
    ("unclear without more context") verdict of unknown.

    Returns "" when none of these fields are present, so most alerts see no
    change to the prompt at all.
    """
    data = alert.get("data", {})
    bytes_out  = data.get("bytes_out")
    bytes_in   = data.get("bytes_in")
    conn_count = data.get("conn_count")

    if not any([bytes_out, bytes_in, conn_count]):
        return ""

    lines = ["\n=== TRAFFIC VOLUME CONTEXT ==="]

    if bytes_out is not None:
        try:
            bytes_out_int = int(bytes_out)
            mb_out = bytes_out_int / 1_000_000
            lines.append(f"- Outbound bytes: {bytes_out_int} (~{mb_out:.1f} MB)")
            if bytes_out_int > VOLUME_CONTEXT_FLAG_BYTES:
                lines.append(
                    "  NOTE: this is a large outbound transfer for a single event. "
                    "Treat as a plausible data exfiltration indicator unless there "
                    "is a clear benign explanation (e.g. scheduled backup job, known "
                    "large file share). Do not default to 'unknown' purely for lack "
                    "of protocol/port detail — weigh the volume itself as evidence."
                )
        except (TypeError, ValueError):
            lines.append(f"- Outbound bytes: {bytes_out} (unparsed)")

    if bytes_in is not None:
        lines.append(f"- Inbound bytes: {bytes_in}")

    if conn_count is not None:
        lines.append(f"- Connection count: {conn_count}")

    return "\n".join(lines) + "\n"


def _build_ueba_block(alert: dict, ueba_result: dict | None = None) -> str:
    """
    [Day 47] Surfaces the UEBA anomaly score (tools/ueba_scorer.py) to the
    LLM so behavioral-deviation context (unusual login hour, novel source
    IP, rare command, elevated peer-risk, volume spike vs. this user's own
    baseline) sits alongside the CTI and traffic-volume context blocks
    already in the prompt.

    Never raises — ueba_scorer.score_anomaly() itself never raises, and any
    unexpected error here still returns a plain-text note rather than
    breaking prompt construction.

    Parameters
    ----------
    ueba_result : dict | None
        Optional pre-computed result from score_anomaly(alert), so
        triage_node can compute it once and reuse it for both this prompt
        block and its own notes/logging, instead of scoring twice.
    """
    if ueba_result is None:
        try:
            ueba_result = score_anomaly(alert)
        except Exception as exc:
            return f"\n=== UEBA BEHAVIORAL CONTEXT ===\n- UEBA scoring unavailable: {exc}\n"

    if not ueba_result.get("profile_used"):
        return (
            "\n=== UEBA BEHAVIORAL CONTEXT ===\n"
            "- No behavioral profile exists yet for this user/entity "
            "(new user, or the nightly UEBA profiler hasn't run for them "
            "yet). Treat this as neutral — absence of a baseline is not "
            "itself evidence of anything.\n"
        )

    anomaly_score = ueba_result.get("anomaly_score", 0)
    breakdown = ueba_result.get("breakdown", {})
    fired = {k: v for k, v in breakdown.items() if v.get("score", 0) > 0}

    lines = [
        "\n=== UEBA BEHAVIORAL CONTEXT ===",
        f"- Anomaly score: {anomaly_score}/100 (0 = fully typical for this user, 100 = maximally deviant)",
    ]

    if fired:
        lines.append("- Deviations from this user's own learned baseline:")
        for dim, info in fired.items():
            lines.append(f"  - {dim} (+{info['score']}): {info['reason']}")
        if anomaly_score >= UEBA_CONTEXT_FLAG_SCORE:
            lines.append(
                "  NOTE: this is a high behavioral anomaly score. Weigh it as "
                "meaningful evidence of unusual activity for this specific "
                "user, not just a footnote — this is deviation from their "
                "own baseline, not a generic rule threshold."
            )
    else:
        lines.append("- Behavior matches this user's learned baseline on every dimension checked.")

    return "\n".join(lines) + "\n"


def _build_cti_block(alert: dict, actor_profile: dict | None = None) -> str:
    """
    [Day 23] Build the CTI section of the triage prompt from enrichment fields
    already attached to the alert dict by pipeline_runner.enrich_with_cti().

    [Day 24] If actor_profile was resolved (passed in by triage_node), append
    known campaigns / TTPs / target sectors so the LLM has full context, not
    just the bare actor name.

    If no match was found, we still include the section so the model knows
    we checked and found nothing — avoids it inferring we simply didn't look.
    """
    matched     = alert.get("cti.matched", False)
    actor       = alert.get("cti.threat_actor") or "unknown"
    campaign    = alert.get("cti.campaign")     or "unknown"
    cti_conf    = alert.get("cti.confidence", 0)
    cti_source  = alert.get("cti.source")       or "n/a"

    if not matched:
        return """
=== THREAT INTELLIGENCE (CTI) ===
- No IOC match found for source IP, domains, or hashes in siem-threat-intel.
- Absence of a CTI match does not rule out a threat — it may be a new actor
  or an IP not yet tracked by AlienVault OTX / URLhaus.
"""

    block = f"""
=== THREAT INTELLIGENCE (CTI) ===
⚠️  SOURCE IP MATCHED A KNOWN MALICIOUS INDICATOR
- IOC source    : {cti_source}
- Threat actor  : {actor}
- Campaign      : {campaign}
- CTI confidence: {cti_conf}%

This IP is tracked in our threat intelligence index (siem-threat-intel).
Weight this heavily — an IOC match from a reputable feed significantly
increases the probability that this alert is a REAL attack.
"""

    if actor_profile and actor_profile.get("found"):
        profile_lines = ["", "THREAT ACTOR PROFILE:"]
        if actor_profile.get("known_campaigns"):
            profile_lines.append(f"- Known campaigns: {', '.join(actor_profile['known_campaigns'])}")
        if actor_profile.get("ttps"):
            profile_lines.append(f"- Known TTPs: {', '.join(actor_profile['ttps'])}")
        if actor_profile.get("target_sectors"):
            profile_lines.append(f"- Typically targets: {', '.join(actor_profile['target_sectors'])}")
        profile_lines.append(
            f"- {actor_profile.get('ioc_count', 0)} IOCs on record for this actor "
            f"(sources: {', '.join(actor_profile.get('sources', [])) or 'n/a'})."
        )
        block += "\n".join(profile_lines) + "\n"

    return block


def _attach_actor_profile_to_summary(triage_result: dict, actor_profile: dict | None,
                                      actor_name: str | None) -> dict:
    """
    [Day 24] Guarantees the threat actor profile appears in the final summary,
    independent of whether the LLM chose to repeat it. Mutates and returns
    triage_result.
    """
    if not actor_profile or not actor_profile.get("found") or not actor_name:
        return triage_result

    note = f" [Threat actor profile: {actor_name}"
    if actor_profile.get("known_campaigns"):
        note += f" — campaigns: {', '.join(actor_profile['known_campaigns'])}"
    if actor_profile.get("ttps"):
        note += f" — TTPs: {', '.join(actor_profile['ttps'])}"
    if actor_profile.get("target_sectors"):
        note += f" — targets: {', '.join(actor_profile['target_sectors'])}"
    note += "]"

    triage_result["summary"] = triage_result.get("summary", "") + note
    triage_result["actor_profile"] = actor_profile
    return triage_result


def _call_llm(prompt: str) -> str:
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

    if LLM_BACKEND == "gemini":
        import os
        try:
            from google import genai
        except ImportError:
            return json.dumps({
                "verdict": "unknown",
                "summary": "Run: pip install google-genai --break-system-packages",
                "evidence": []
            })
        try:
            client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            return response.text.strip()
        except Exception as exc:
            return json.dumps({
                "verdict": "unknown",
                "summary": f"Gemini API error: {exc}",
                "evidence": []
            })

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
    if not raw:
        return "unknown"
    cleaned = re.sub(r"[^a-z\s]", " ", raw.lower())
    if any(w in cleaned for w in ("suspicious", "malicious", "threat", "attack")):
        return "suspicious"
    if any(w in cleaned for w in ("benign", "legitimate", "normal", "routine", "expected")):
        return "benign"
    return "unknown"


def _coerce_evidence(raw) -> list:
    if raw is None:
        return ["No evidence provided"]
    if isinstance(raw, list):
        return [str(e).strip() for e in raw if str(e).strip()]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(e).strip() for e in parsed if str(e).strip()]
        except (json.JSONDecodeError, ValueError):
            pass
        lines = re.split(r"\n|(?:^|\n)\s*[-*•]\s*", raw)
        cleaned = [l.strip().lstrip("-*• ") for l in lines if l.strip()]
        return cleaned if cleaned else [raw.strip()]
    return [str(raw)]


def _parse_llm_output(raw: str) -> dict:
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            return {
                "verdict":   _normalise_verdict(result.get("verdict", "")),
                "summary":   str(result.get("summary", raw[:300])),
                "technique": result.get("technique"),
                "evidence":  _coerce_evidence(result.get("evidence")),
            }
        except json.JSONDecodeError:
            pass
    return {
        "verdict":   "unknown",
        "summary":   raw[:500],
        "technique": None,
        "evidence":  ["LLM response could not be parsed as JSON"],
    }


def _confidence_from_verdict(verdict: str, event_count: int) -> int:
    base = {"suspicious": 75, "benign": 20, "unknown": 40}.get(verdict, 40)
    if event_count >= 20:
        base = min(base + 15, 100)
    elif event_count >= 10:
        base = min(base + 8, 100)
    return base


def _is_internal_ip(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("172.")
    )


def _pre_classify(rule_id: str, rule_lvl: int, groups: list,
                  src_ip: str, context_note: str) -> dict | None:
    """
    Rule-based fast-path classifier — runs BEFORE the LLM.
    Returns a triage_result dict for clear-cut cases, or None to fall through.

    Note: CTI-matched alerts bypass the pre-classifier entirely (handled in
    triage_node) so a known-bad IP always reaches the LLM for full analysis.
    """
    note_lower = context_note.lower()
    internal   = _is_internal_ip(src_ip)

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

    if rule_id in ("5502",) or (rule_id not in ("5501",) and "pam" in groups and rule_lvl <= 3):
        return {
            "verdict":  "benign",
            "summary":  (
                f"PAM session-close / low-severity informational event (level {rule_lvl}/15). "
                f"No threat indicators."
            ),
            "evidence": [
                "Session-close events are informational by definition",
                f"Rule level {rule_lvl}/15 — informational only",
            ],
        }

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
                "Authentication succeeded — not inherently malicious",
                f"Rule level {rule_lvl}/15 — low severity",
                "No failed-auth events in the same session to indicate brute force",
                "Context note flags ambiguity — new IP or insufficient history",
            ],
        }

    return None


# ── LangGraph node ─────────────────────────────────────────────────────────────

def triage_node(state: dict) -> dict:
    alert = state.get("alert", {})
    notes = list(state.get("notes", []))

    src_ip       = alert.get("data", {}).get("srcip")       or alert.get("data.srcip", "")
    dst_user     = alert.get("data", {}).get("dstuser")     or alert.get("data.dstuser", "")
    rule_id      = alert.get("rule", {}).get("id")          or alert.get("rule.id", "")
    rule_desc    = alert.get("rule", {}).get("description") or alert.get("rule.description", "")
    rule_lvl     = alert.get("rule", {}).get("level")       or alert.get("rule.level", 0)
    agent_nm     = alert.get("agent", {}).get("name")       or alert.get("agent.name", "")
    context_note = alert.get("data", {}).get("context_note", "")

    # [Day 23] Read CTI enrichment fields
    cti_matched = alert.get("cti.matched", False)
    cti_actor   = alert.get("cti.threat_actor")

    # [Day 39] Was confidence_pct pre-scored upstream by an override that
    # should survive triage's own verdict->pct mapping? Currently set by
    # hunting_agent.escalate_hunt_to_triage() for hunt-originated synthetic
    # alerts (pre-scored at 85%, per HUNT_ESCALATION_CONFIDENCE_PCT). If
    # coordination_agent.py's CTI force-route path is later updated to set
    # this same flag, it will be honoured here automatically too.
    pre_scored = state.get("_pre_scored", False)
    pre_scored_pct = state.get("confidence_pct") if pre_scored else None

    notes.append(f"[triage] Alert: rule {rule_id} | level {rule_lvl} | src={src_ip} | user={dst_user}")
    if cti_matched:
        notes.append(
            f"[triage] ⚠️  CTI match: actor={cti_actor} "
            f"source={alert.get('cti.source')} conf={alert.get('cti.confidence')}%"
        )
    if pre_scored:
        notes.append(
            f"[triage] confidence_pct={pre_scored_pct}% was pre-scored upstream — "
            f"will be preserved rather than overwritten by verdict mapping"
        )

    # [Day 24] Resolve threat actor profile up front if there's a CTI match
    # with a real (non-"unknown") actor name. Resolving it here — rather than
    # inside _build_cti_block — lets us reuse the same profile object for
    # both the prompt and the post-LLM summary append, with only one ES call.
    actor_profile = None
    if cti_matched and cti_actor and cti_actor != "unknown":
        actor_profile = get_threat_actor_profile(cti_actor)
        notes.append(
            f"[triage] get_threat_actor_profile({cti_actor}) → "
            f"found={actor_profile['found']} source={actor_profile['profile_source']}"
        )

    # [Day 47] Resolve the UEBA anomaly score up front, same reasoning as
    # the actor-profile resolution above — one call, reused for both the
    # prompt block and the agent notes/logging.
    try:
        ueba_result = score_anomaly(alert)
    except Exception as exc:
        ueba_result = {"anomaly_score": 0, "breakdown": {}, "profile_used": False}
        notes.append(f"[triage] UEBA scoring error (non-fatal): {exc}")

    if ueba_result.get("profile_used"):
        notes.append(
            f"[triage] UEBA anomaly_score={ueba_result['anomaly_score']}/100"
        )
        fired_dims = [k for k, v in ueba_result.get("breakdown", {}).items() if v.get("score", 0) > 0]
        if fired_dims:
            notes.append(f"[triage] UEBA dimensions triggered: {', '.join(fired_dims)}")
    else:
        notes.append("[triage] UEBA: no behavioral profile available for this user yet")

    recent_events = []
    login_history  = []

    if src_ip:
        recent_events = get_recent_events(src_ip, minutes=60)
        notes.append(f"[triage] get_recent_events({src_ip}) → {len(recent_events)} events in last 60 min")

    clean_user = re.sub(r"\(.*?\)", "", dst_user).strip() if dst_user else ""
    if clean_user:
        login_history = get_user_login_history(clean_user, days=7)
        notes.append(f"[triage] get_user_login_history({clean_user}) → {len(login_history)} events in last 7 days")

    # ── Pre-classifier — skip for CTI-matched alerts (always go to LLM) ───────
    rule_groups = alert.get("rule", {}).get("groups", [])
    pre = None
    if not cti_matched:
        pre = _pre_classify(rule_id, int(rule_lvl or 0), rule_groups, src_ip, context_note)

    if pre is not None:
        notes.append(f"[triage] Pre-classifier verdict: {pre['verdict']} (LLM skipped)")
        conf_pct = pre_scored_pct if pre_scored_pct is not None else \
            _confidence_from_verdict(pre["verdict"], len(recent_events))
        confidence_label = "high" if conf_pct >= 65 else ("medium" if conf_pct >= 35 else "low")
        escalate         = pre["verdict"] == "suspicious" and conf_pct >= 65
        notes.append(f"[triage] confidence={confidence_label} ({conf_pct}%) | escalate={escalate}")
        return {
            **state,
            "notes":          notes,
            "confidence":     confidence_label,
            "confidence_pct": conf_pct,
            "triage_result":  pre,
            "technique":      pre.get("technique") or state.get("technique"),
            "escalate":       escalate,
        }

    # ── LLM path ──────────────────────────────────────────────────────────────
    if cti_matched:
        notes.append("[triage] CTI match detected — bypassing pre-classifier, sending to LLM with CTI context")
    else:
        notes.append("[triage] No pre-classifier match — calling Gemini for analysis...")

    # [Day 23/24] Build CTI section, now with actor profile folded in
    cti_block = _build_cti_block(alert, actor_profile)

    # [Day 39] Build traffic-volume context section (empty string if no
    # relevant fields present on the alert)
    volume_block = _build_volume_context(alert)

    # [Day 47] Build UEBA behavioral-context section, reusing the
    # already-computed ueba_result rather than scoring twice.
    ueba_block = _build_ueba_block(alert, ueba_result)

    prompt = f"""You are a cybersecurity analyst reviewing a SIEM alert. Analyse the evidence below and return ONLY a JSON object — no explanation, no markdown, no text before or after the JSON.

=== ALERT ===
Rule ID      : {rule_id}
Description  : {rule_desc}
Severity     : {rule_lvl} / 15
Source IP    : {src_ip}
Target user  : {dst_user}
Agent (host) : {agent_nm}
Context note : {context_note if context_note else "none"}
{cti_block}{volume_block}{ueba_block}
=== RECENT EVENTS FROM THIS IP (last 60 min, max 8 shown) ===
{_summarise_events(recent_events)}

=== LOGIN HISTORY FOR USER '{clean_user or dst_user}' (last 7 days, max 8 shown) ===
{_summarise_events(login_history)}

=== TASK ===
Based on the alert and supporting evidence above, decide:
- Is this alert likely a REAL threat (suspicious), a false positive (benign), or unclear (unknown)?
- What is the key reasoning?
- What are 2-4 specific pieces of evidence that support your verdict?

If the CTI section shows an IOC match, treat that as strong evidence of a real threat.
If a threat actor profile is provided, reference the actor's known campaigns
or TTPs in your summary when relevant.
If a traffic volume context section is present, weigh large transfer volumes as
meaningful evidence on their own — do not default to "unknown" purely because a
protocol/port isn't specified when a large volume signal is present.
If a UEBA behavioral context section shows a high anomaly score, weigh that
deviation from this specific user's own baseline as meaningful evidence too —
it is a different, complementary signal from the static CTI/volume checks
above, not a duplicate of them.

Return EXACTLY this JSON structure (no other text):
{{
  "verdict": "suspicious" | "benign" | "unknown",
  "summary": "2-3 sentence plain-English explanation of your reasoning",
  "technique": "T1110" | "T1059" | "T1078" | "T1041" | null,
  "evidence": [
    "Evidence point 1",
    "Evidence point 2",
    "Evidence point 3"
  ]
}}"""

    raw_response  = _call_llm(prompt)
    triage_result = _parse_llm_output(raw_response)

    # [Day 24] Deterministically attach the actor profile to the summary —
    # don't rely on the LLM having included it, since JSON-mode responses
    # are short and may omit it even when given in the prompt.
    triage_result = _attach_actor_profile_to_summary(triage_result, actor_profile, cti_actor)

    notes.append(f"[triage] Verdict: {triage_result['verdict']} | {triage_result['summary'][:80]}...")

    # [Day 39] Preserve a pre-scored confidence_pct (e.g. hunt-escalation's
    # 85%) instead of always recomputing from the verdict. Previously this
    # unconditionally overwrote the pre-set value — confirmed as a bug in
    # Phase 2 Scenario 2 testing (coordination logged 85%, final state showed
    # 75%, because this line clobbered it every time regardless of origin).
    if pre_scored_pct is not None:
        conf_pct = pre_scored_pct
    else:
        conf_pct = _confidence_from_verdict(triage_result["verdict"], len(recent_events))

    confidence_label = "high" if conf_pct >= 65 else ("medium" if conf_pct >= 35 else "low")
    escalate = triage_result["verdict"] == "suspicious" and conf_pct >= 65

    notes.append(f"[triage] confidence={confidence_label} ({conf_pct}%) | escalate={escalate}")

    return {
        **state,
        "notes":          notes,
        "confidence":     confidence_label,
        "confidence_pct": conf_pct,
        "triage_result":  triage_result,
        "technique":      triage_result.get("technique") or state.get("technique"),
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
            "srcip":   "141.60.162.150",   # known-bad IP from Day 22 tests
            "dstuser": "root"
        },
        "agent": {"name": "agent1"},
        "@timestamp": "2026-06-16T02:00:00Z",
        # CTI fields (normally attached by pipeline_runner.enrich_with_cti)
        # NOTE: set cti.threat_actor to a real actor name (e.g. one present
        # in your siem-threat-intel data, or a seed-table name like "APT28")
        # to exercise the Day 24 actor-profile path. "unknown" will skip it.
        "cti.matched":      True,
        "cti.threat_actor": "APT28",
        "cti.campaign":     None,
        "cti.confidence":   50,
        "cti.source":       "otx",
    }

    initial_state = {
        "alert":      fake_alert,
        "notes":      [],
        "confidence": None,
        "technique":  None,
        "escalate":   False,
    }

    print("=== Running triage_node with known-bad IP (CTI enriched) ===\n")
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

    # [Day 39] Regression test for the Scenario 3 exfil bug: same alert
    # shape, but with a large data.bytes_out and NO CTI match, to confirm
    # the volume-context block changes the verdict rather than defaulting
    # to "unknown".
    print("\n\n=== Day 39 regression test — 500MB exfil, no CTI match ===\n")
    exfil_alert = {
        "rule": {
            "id": "100001",
            "description": "Firewall: packet accepted",
            "groups": ["firewall"],
            "level": 8,
        },
        "data": {
            "srcip": "192.0.2.199",
            "dstuser": "unknown",
            "login_hour": 3,
            "is_new_ip": True,
            "bytes_out": 500_000_000,
        },
        "agent": {"name": "agent1"},
        "@timestamp": "2026-07-10T03:00:00Z",
        "cti.matched": False,
    }
    exfil_state = {
        "alert": exfil_alert,
        "notes": [],
        "confidence": None,
        "technique": None,
        "escalate": False,
    }
    exfil_result = triage_node(exfil_state)
    print(json.dumps(exfil_result["triage_result"], indent=2))
    print(f"\n  confidence_pct={exfil_result['confidence_pct']}%  escalate={exfil_result['escalate']}")

    # [Day 47] Regression test: confirm the UEBA block builds correctly and
    # is present in the prompt path even with no profile in the environment
    # yet (fresh/no-history case — should degrade gracefully, not crash).
    print("\n\n=== Day 47 regression test — UEBA block, no profile yet ===\n")
    print(_build_ueba_block(exfil_alert))
