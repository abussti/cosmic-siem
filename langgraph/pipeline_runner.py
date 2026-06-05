"""
pipeline_runner.py
==================
Day 17 — Full pipeline runner.

Wazuh → Elastic → confidence_scorer → coordination_agent → triage_agent → ES write-back

How it works
------------
1. Poll Elasticsearch every POLL_INTERVAL seconds for new, unprocessed alerts
   (alerts where triage.verdict does not yet exist).
2. For each new alert:
     a. Score it with confidence_scorer.score_and_tier()
     b. Build an AgentState and invoke the compiled LangGraph
     c. If the pipeline produced a triage_result, write it back to ES
        via elastic_tools.write_triage_result_to_es()
3. Track the latest @timestamp seen so we never re-process the same alert.
4. Print a structured trace for every alert so you can follow the full path.

Usage
-----
  cd ~/elastic/langgraph
  python3 pipeline_runner.py

  # Run once (no loop — useful for testing):
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
# graph.py must expose a compiled graph object called `pipeline`
# If your graph.py currently calls graph.compile() at module level and stores
# it in a variable, make sure that variable is named `pipeline` OR alias it:
#   pipeline = app   (if yours is called `app`)
try:
    from graph import pipeline          # preferred
except ImportError:
    try:
        from graph import app as pipeline   # fallback alias
    except ImportError:
        print("ERROR: could not import `pipeline` or `app` from graph.py")
        print("       Make sure graph.py exposes the compiled graph at module level.")
        sys.exit(1)

# ── Shared modules ──────────────────────────────────────────────────────────
from confidence_scorer import score_and_tier
from tools.elastic_tools import (
    get_unprocessed_alerts,
    write_triage_result_to_es,
)
from state import AgentState


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL: int = 30          # seconds between ES polls
BATCH_SIZE: int = 20             # max alerts per poll cycle


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

    # Step 1 — confidence score -----------------------------------------------
    confidence_pct, routing_tier = score_and_tier(source)
    _log(f"SCORE  confidence_pct={confidence_pct}%  tier={routing_tier}")
    trace_lines.append(f"- **Confidence score:** {confidence_pct}%  →  tier `{routing_tier}`")

    # Step 2 — build initial AgentState ---------------------------------------
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

    # Step 3 — invoke LangGraph pipeline --------------------------------------
    _log("GRAPH  invoking LangGraph pipeline…")
    try:
        final_state: AgentState = pipeline.invoke(initial_state)
    except Exception as exc:
        _log(f"GRAPH  ❌ pipeline raised an exception: {exc}")
        trace_lines.append(f"- **Pipeline error:** `{exc}`")
        return None

    # Step 4 — extract results ------------------------------------------------
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

    # Step 5 — write triage result back to ES ---------------------------------
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


def main(run_once: bool = False, since: str | None = None) -> None:
    """
    Main polling loop.

    Parameters
    ----------
    run_once : bool
        If True, poll once and exit instead of looping.
    since : str | None
        ISO-8601 start timestamp. Defaults to "now minus 10 minutes" so
        a fresh run picks up recent alerts without reprocessing old history.
    """
    if since is None:
        # Default: start 10 minutes in the past so we catch recent alerts
        # without reprocessing the entire 2300-alert backlog.
        from datetime import timedelta
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    last_seen_ts: str = since
    cycle: int = 0
    trace_lines: list[str] = [
        "# Day 17 — End-to-End Pipeline Trace",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Start timestamp:** {since}  ",
        "",
        "---",
        "",
    ]

    _log(f"pipeline_runner starting  |  poll_interval={POLL_INTERVAL}s  |  since={since}")
    _log(f"{'═' * 70}")

    try:
        while True:
            cycle += 1
            _log(f"POLL   cycle={cycle}  since={last_seen_ts}")

            alerts = get_unprocessed_alerts(since_timestamp=last_seen_ts, size=BATCH_SIZE)
            _log(f"POLL   found {len(alerts)} unprocessed alert(s)")

            for hit in alerts:
                ts = hit["_source"].get("@timestamp", last_seen_ts)
                run_pipeline_once(hit, trace_lines)

                # Advance the watermark so we never re-process this alert
                if ts > last_seen_ts:
                    last_seen_ts = ts

            # Write trace after every cycle so it's always up to date
            _write_trace(trace_lines)

            if run_once:
                _log("DONE   --once flag set, exiting.")
                break

            _log(f"SLEEP  {POLL_INTERVAL}s until next poll…")
            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        _log("\nINTERRUPT  Ctrl-C received — shutting down gracefully.")
        _write_trace(trace_lines)


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
    # Also write to /mnt/user-data/outputs for download (dev environment only)
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
        description="Day 17 — SIEM pipeline runner. Polls Elastic and runs LangGraph."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll once and exit (useful for testing).",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help='ISO-8601 start timestamp, e.g. "2026-06-02T10:00:00.000Z". '
             "Defaults to 10 minutes ago.",
    )
    args = parser.parse_args()
    main(run_once=args.once, since=args.since)
