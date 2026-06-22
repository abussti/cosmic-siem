"""
pipeline_runner.py
==================
Day 17 — Full pipeline runner.
Day 23 — CTI enrichment added: every alert is IOC-matched before scoring.
Day 26 — Proactive hunt scheduler added: runs hunt_pipeline from graph.py
         every 6 hours, completely independent of the alert poll loop below.

Wazuh → Elastic → CTI enrichment → confidence_scorer → coordination_agent
       → triage_agent → ES write-back

                              (in parallel, no alert needed)
                  APScheduler ──every 6h──> hunt_pipeline.invoke(...)

How it works
------------
1. Poll Elasticsearch every POLL_INTERVAL seconds for new, unprocessed alerts
   (alerts where triage.verdict does not yet exist).
2. For each new alert:
     a. [Day 23] Enrich with CTI data via match_alert_iocs()
     b. Score it with confidence_scorer.score_and_tier()
     c. Build an AgentState and invoke the compiled LangGraph
     d. If the pipeline produced a triage_result, write it back to ES
        via elastic_tools.write_triage_result_to_es()
3. Track the latest @timestamp seen so we never re-process the same alert.
4. Print a structured trace for every alert so you can follow the full path.
5. [Day 26] In the background, on a separate 6-hour timer that runs whether
   or not any alert has ever been seen, invoke hunt_pipeline (graph.py) —
   the proactive hunting branch — and log its findings.

Usage
-----
  cd ~/elastic/langgraph
  python3 pipeline_runner.py

  # Run once (no loop, no hunt scheduler — useful for testing):
  python3 pipeline_runner.py --once

  # Start from a specific timestamp:
  python3 pipeline_runner.py --since "2026-06-02T00:00:00.000Z"

Press Ctrl-C to stop the loop gracefully.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── LangGraph pipeline ──────────────────────────────────────────────────────
try:
    from graph import pipeline
except ImportError:
    try:
        from graph import app as pipeline
    except ImportError:
        print("ERROR: could not import `pipeline` or `app` from graph.py")
        sys.exit(1)

# ── Day 26 — proactive hunting branch (separate compiled graph) ────────────
try:
    from graph import hunt_pipeline
except ImportError:
    print("WARNING: could not import `hunt_pipeline` from graph.py — "
          "Day 26 scheduled hunts disabled for this run.")
    hunt_pipeline = None

from apscheduler.schedulers.background import BackgroundScheduler

# ── Shared modules ──────────────────────────────────────────────────────────
from confidence_scorer import score_and_tier
from tools.elastic_tools import (
    get_unprocessed_alerts,
    write_triage_result_to_es,
)
from tools.ioc_matcher import match_alert_iocs   # ← Day 23
from state import AgentState


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL: int = 30
BATCH_SIZE: int = 20
HUNT_INTERVAL_HOURS: int = 6   # Day 26 — scheduled hunt cadence


# ---------------------------------------------------------------------------
# CTI Enrichment (Day 23)
# ---------------------------------------------------------------------------

def enrich_with_cti(alert: dict) -> dict:
    """
    Run IOC matching on alert and attach CTI fields directly to the alert dict.

    Fields added:
        alert["cti.matched"]      — bool
        alert["cti.threat_actor"] — str | None
        alert["cti.campaign"]     — str | None
        alert["cti.confidence"]   — int (0–100, highest match wins)
        alert["cti.source"]       — str | None

    match_alert_iocs() may return either:
      - a single dict  {matched, threat_actor, campaign, confidence, source}
      - a list of such dicts (one per IOC field checked in the alert)

    We normalise both to a single "worst case" result: if ANY indicator
    matched we mark the alert as matched and keep the highest-confidence hit.
    """
    _EMPTY = {"matched": False, "threat_actor": None, "campaign": None,
              "confidence": 0, "source": None}

    try:
        raw = match_alert_iocs(alert)
    except Exception as exc:
        _log(f"CTI    ⚠️  match_alert_iocs raised: {exc} — skipping enrichment")
        raw = _EMPTY

    # ── Normalise list → single best hit ─────────────────────────────────────
    if isinstance(raw, list):
        hits = [r for r in raw if isinstance(r, dict) and r.get("matched")]
        if hits:
            # Pick the hit with the highest CTI confidence score
            cti = max(hits, key=lambda r: r.get("confidence", 0))
        else:
            cti = _EMPTY
    elif isinstance(raw, dict):
        cti = raw
    else:
        _log(f"CTI    ⚠️  unexpected return type from match_alert_iocs: {type(raw)} — skipping")
        cti = _EMPTY

    alert["cti.matched"]      = cti.get("matched", False)
    alert["cti.threat_actor"] = cti.get("threat_actor")
    alert["cti.campaign"]     = cti.get("campaign")
    alert["cti.confidence"]   = cti.get("confidence", 0)
    alert["cti.source"]       = cti.get("source")
    return alert


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_pipeline_once(alert_hit: dict, trace_lines: list[str]) -> dict | None:
    """
    Run a single alert through the full LangGraph pipeline.

    Parameters
    ----------
    alert_hit : dict
        A dict with _id, _index, _source keys (from get_unprocessed_alerts).
    trace_lines : list[str]
        Mutable list — append trace lines here for pipeline-trace.md.

    Returns
    -------
    dict | None
        The final AgentState after the pipeline completes, or None on error.
    """
    es_id: str = alert_hit["_id"]
    es_index: str = alert_hit["_index"]
    source: dict = alert_hit["_source"]

    rule = source.get("rule", {})
    rule_id = rule.get("id", "unknown")
    rule_desc = rule.get("description", "no description")
    rule_level = rule.get("level", 0)
    timestamp = source.get("@timestamp", "unknown")
    src_ip = source.get("data", {}).get("srcip", "unknown")
    dst_user = source.get("data", {}).get("dstuser", "unknown")

    _log(f"{'─' * 70}")
    _log(f"ALERT  id={es_id[:16]}… | ts={timestamp}")
    _log(f"       rule={rule_id}  level={rule_level}  src={src_ip}  user={dst_user}")
    _log(f"       desc={rule_desc[:80]}")

    trace_lines.append(f"\n### Alert: rule {rule_id} — {rule_desc[:60]}")
    trace_lines.append(f"- **Timestamp:** {timestamp}")
    trace_lines.append(f"- **Source IP:** {src_ip}")
    trace_lines.append(f"- **User:** {dst_user}")
    trace_lines.append(f"- **ES id:** `{es_id}`")
    trace_lines.append(f"- **ES index:** `{es_index}`")

    # ── Step 1 — CTI enrichment (Day 23) ─────────────────────────────────────
    _log("CTI    running IOC match…")
    source = enrich_with_cti(source)
    cti_matched = source["cti.matched"]
    cti_actor   = source["cti.threat_actor"] or "none"
    cti_conf    = source["cti.confidence"]
    cti_src     = source["cti.source"] or "n/a"
    _log(f"CTI    matched={cti_matched}  actor={cti_actor}  conf={cti_conf}  source={cti_src}")
    trace_lines.append(
        f"- **CTI match:** `{cti_matched}` | actor=`{cti_actor}` | "
        f"cti_confidence={cti_conf} | source=`{cti_src}`"
    )

    # ── Step 2 — confidence score ─────────────────────────────────────────────
    confidence_pct, routing_tier = score_and_tier(source)
    _log(f"SCORE  confidence_pct={confidence_pct}%  tier={routing_tier}")
    trace_lines.append(f"- **Confidence score:** {confidence_pct}%  →  tier `{routing_tier}`")

    # ── Step 3 — build initial AgentState ─────────────────────────────────────
    initial_state: AgentState = {
        "alert": source,
        "alert_es_id": es_id,
        "alert_es_index": es_index,
        "confidence": None,
        "confidence_pct": confidence_pct,
        "technique": None,
        "notes": [f"pipeline_runner: ingested alert rule={rule_id} level={rule_level}"],
        "escalate": False,
        "triage_result": None,
    }

    # ── Step 4 — invoke LangGraph pipeline ────────────────────────────────────
    _log("GRAPH  invoking LangGraph pipeline…")
    try:
        final_state: AgentState = pipeline.invoke(initial_state)
    except Exception as exc:
        _log(f"GRAPH  ❌ pipeline raised an exception: {exc}")
        trace_lines.append(f"- **Pipeline error:** `{exc}`")
        return None

    # ── Step 5 — extract results ───────────────────────────────────────────────
    triage_result = final_state.get("triage_result")
    notes = final_state.get("notes", [])
    escalate = final_state.get("escalate", False)
    final_pct = final_state.get("confidence_pct", confidence_pct)
    final_technique = final_state.get("technique")

    _log(f"RESULT triage_result={'present' if triage_result else 'None (archived/queued)'}")
    _log(f"       escalate={escalate}  confidence_pct={final_pct}%  technique={final_technique}")

    trace_lines.append(f"- **Pipeline notes:**")
    for note in notes:
        trace_lines.append(f"  - {note}")
    trace_lines.append(f"- **Escalate to analyst:** {escalate}")

    # ── Step 6 — write triage result back to ES ───────────────────────────────
    if triage_result:
        verdict = triage_result.get("verdict", "unknown")
        summary = triage_result.get("summary", "")
        evidence = triage_result.get("evidence", [])

        _log(f"WRITE  verdict={verdict!r}  → writing back to ES…")
        trace_lines.append(f"- **Triage verdict:** `{verdict}`")
        trace_lines.append(f"- **Triage summary:** {summary}")
        trace_lines.append(f"- **Evidence:**")
        for ev in evidence:
            trace_lines.append(f"  - {ev}")

        success = write_triage_result_to_es(
            es_index=es_index,
            es_id=es_id,
            verdict=verdict,
            summary=summary,
            evidence=evidence,
            confidence_pct=final_pct,
            technique=final_technique,
        )
        status = "✅ written to ES" if success else "❌ ES write-back failed"
        _log(f"WRITE  {status}")
        trace_lines.append(f"- **ES write-back:** {status}")
    else:
        _log(f"WRITE  skipped (alert was archived or queued, no triage_result)")
        trace_lines.append(f"- **ES write-back:** skipped — alert routed to `{routing_tier}`")

    return final_state


# ---------------------------------------------------------------------------
# Day 26 — Proactive Hunting Scheduler
# ---------------------------------------------------------------------------

def run_scheduled_hunts() -> None:
    """
    One scheduled hunt cycle. Invokes hunt_pipeline (the parallel branch
    defined in graph.py) with an empty/neutral AgentState — there is no
    triggering alert, which is the whole point. Runs on its own APScheduler
    timer below; never called from the alert poll loop in main().
    """
    if hunt_pipeline is None:
        _log("HUNT   ⚠️  hunt_pipeline unavailable — skipping scheduled hunt cycle")
        return

    _log(f"{'═' * 70}")
    _log("HUNT   starting scheduled hunt cycle…")

    initial_state: AgentState = {
        "alert": {},
        "alert_es_id": None,
        "alert_es_index": None,
        "confidence": None,
        "confidence_pct": 0,
        "technique": None,
        "notes": ["pipeline_runner: scheduled hunt cycle triggered (no alert)"],
        "escalate": False,
        "triage_result": None,
    }

    try:
        final_state: AgentState = hunt_pipeline.invoke(initial_state)
    except Exception as exc:
        _log(f"HUNT   ❌ scheduled hunt cycle raised: {exc}")
        return

    for note in final_state.get("notes", []):
        _log(f"HUNT     {note}")

    if final_state.get("escalate"):
        _log("HUNT   ⚠️  one or more hunts escalated — TODO Phase 2: route to siem-review-queue / notify analyst")

    _log("HUNT   scheduled hunt cycle complete")


def start_hunt_scheduler() -> BackgroundScheduler:
    """
    Start the Day 26 proactive hunt scheduler in a background thread.
    Runs every HUNT_INTERVAL_HOURS, completely independent of the alert
    poll loop in main() below — it fires whether or not any alert has ever
    reached the pipeline, which is what makes the hunting "proactive".
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_scheduled_hunts, "interval", hours=HUNT_INTERVAL_HOURS, id="hunt_scheduler")
    scheduler.start()
    _log(f"HUNT   scheduler started — running every {HUNT_INTERVAL_HOURS}h, independent of alert poll loop")
    return scheduler


def main(run_once: bool = False, since: str | None = None) -> None:
    if since is None:
        from datetime import timedelta
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    last_seen_ts: str = since
    cycle: int = 0
    trace_lines: list[str] = [
        "# Day 23 — End-to-End Pipeline Trace (with CTI Enrichment)",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Start timestamp:** {since}  ",
        "",
        "---",
        "",
    ]

    _log(f"pipeline_runner starting  |  poll_interval={POLL_INTERVAL}s  |  since={since}")
    _log(f"{'═' * 70}")

    # ── Day 26 — start the proactive hunt scheduler ───────────────────────────
    # Skipped in --once mode: that flag is for testing a single alert-poll
    # cycle, not for standing up a background scheduler thread.
    hunt_scheduler: BackgroundScheduler | None = None
    if not run_once:
        hunt_scheduler = start_hunt_scheduler()

    try:
        while True:
            cycle += 1
            _log(f"POLL   cycle={cycle}  since={last_seen_ts}")

            alerts = get_unprocessed_alerts(since_timestamp=last_seen_ts, size=BATCH_SIZE)
            _log(f"POLL   found {len(alerts)} unprocessed alert(s)")

            for hit in alerts:
                ts = hit["_source"].get("@timestamp", last_seen_ts)
                run_pipeline_once(hit, trace_lines)

                if ts > last_seen_ts:
                    last_seen_ts = ts

            _write_trace(trace_lines)

            if run_once:
                _log("DONE   --once flag set, exiting.")
                break

            _log(f"SLEEP  {POLL_INTERVAL}s until next poll…")
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        _log("\nINTERRUPT  Ctrl-C received — shutting down gracefully.")
        _write_trace(trace_lines)
    finally:
        if hunt_scheduler:
            hunt_scheduler.shutdown(wait=False)
            _log("HUNT   scheduler stopped")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _write_trace(lines: list[str]) -> None:
    docs_dir = Path(__file__).parent.parent / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    trace_path = docs_dir / "pipeline-trace.md"
    trace_path.write_text("\n".join(lines), encoding="utf-8")
    try:
        Path("/mnt/user-data/outputs/pipeline-trace.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Day 23 — SIEM pipeline runner with CTI enrichment."
    )
    parser.add_argument("--once", action="store_true",
                        help="Poll once and exit (useful for testing).")
    parser.add_argument("--since", type=str, default=None,
                        help='ISO-8601 start timestamp. Defaults to 10 minutes ago.')
    args = parser.parse_args()
    main(run_once=args.once, since=args.since)