"""
feed_manager.py — CTI Feed Manager (Day 21)
Location: ~/elastic/langgraph/tools/feed_manager.py

Pulls IOCs from:
  1. AlienVault OTX   — IPs, domains, URLs, file hashes
  2. Abuse.ch URLhaus  — malicious URLs

Normalises all IOCs to the siem-threat-intel schema and bulk-indexes into
Elasticsearch. Runs immediately on start, then every 6 hours via APScheduler.

Schema (siem-threat-intel index):
  ioc_type     : ip | domain | url | hash
  ioc_value    : the raw indicator value
  source       : otx | urlhaus
  threat_actor : actor/family name if known, else null
  confidence   : 0–100 integer
  last_seen    : ISO-8601 date string
  tags         : list of strings
  ingested_at  : ISO-8601 timestamp (set at ingest time)

Usage:
  # Run once (no scheduler)
  python3 feed_manager.py --once

  # Run continuously (every 6 hours)
  python3 feed_manager.py

  # Override schedule interval (minutes, for testing)
  python3 feed_manager.py --interval-minutes 5
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Generator

import requests

# ── optional scheduler ────────────────────────────────────────────────────────
try:
    from apscheduler.schedulers.blocking import BlockingScheduler
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

# ── config ────────────────────────────────────────────────────────────────────
OTX_API_KEY   = "[key-placeholder]"
OTX_BASE_URL  = "https://otx.alienvault.com/api/v1"
URLHAUS_URL   = "https://urlhaus.abuse.ch/downloads/csv_recent/"   # public CSV, no auth needed

ES_URL        = "http://localhost:9201"
ES_AUTH       = ("elastic", "changeme")
ES_INDEX      = "siem-threat-intel"

BATCH_SIZE    = 500          # docs per ES bulk request
OTX_PAGE_SIZE = 5000         # max per OTX export page
REQUEST_TIMEOUT = 60         # seconds (raised — OTX pages can be slow)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("feed_manager")


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def bulk_index(docs: list[dict]) -> tuple[int, int]:
    """Bulk-index a list of docs into ES_INDEX.
    Returns (indexed_count, error_count).
    """
    if not docs:
        return 0, 0

    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": ES_INDEX}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    try:
        resp = requests.post(
            f"{ES_URL}/_bulk",
            auth=ES_AUTH,
            headers={"Content-Type": "application/x-ndjson"},
            data=body,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        log.error("Bulk index request failed: %s", exc)
        return 0, len(docs)

    errors = sum(1 for item in result.get("items", []) if "error" in item.get("index", {}))
    indexed = len(docs) - errors
    return indexed, errors


def flush_batches(gen: Generator[dict, None, None]) -> tuple[int, int]:
    """Consume a generator of IOC dicts, bulk-indexing in BATCH_SIZE chunks."""
    batch: list[dict] = []
    total_ok = total_err = 0

    for doc in gen:
        batch.append(doc)
        if len(batch) >= BATCH_SIZE:
            ok, err = bulk_index(batch)
            total_ok += ok
            total_err += err
            log.info("  flushed batch: %d indexed, %d errors", ok, err)
            batch.clear()

    if batch:
        ok, err = bulk_index(batch)
        total_ok += ok
        total_err += err

    return total_ok, total_err


# ─────────────────────────────────────────────────────────────────────────────
# OTX feed
# ─────────────────────────────────────────────────────────────────────────────

OTX_TYPE_MAP = {
    "IPv4":         "ip",
    "IPv6":         "ip",
    "domain":       "domain",
    "hostname":     "domain",
    "URL":          "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1":"hash",
    "FileHash-SHA256":"hash",
}


def _otx_pages() -> Generator[dict, None, None]:
    """Page through the OTX indicator export endpoint and yield raw pulse dicts."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    page = 1

    while True:
        url = (
            f"{OTX_BASE_URL}/indicators/export"
            f"?limit={OTX_PAGE_SIZE}&page={page}"
        )
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.error("OTX page %d fetch failed: %s", page, exc)
            break

        results = data.get("results", [])
        if not results:
            break

        yield from results

        if not data.get("next"):
            break
        page += 1
        time.sleep(0.5)   # be polite to OTX


def pull_otx() -> Generator[dict, None, None]:
    """Yield normalised IOC dicts from AlienVault OTX."""
    ingested_at = now_iso()
    count = 0

    for indicator in _otx_pages():
        raw_type = indicator.get("type", "")
        ioc_type = OTX_TYPE_MAP.get(raw_type)
        if not ioc_type:
            continue

        ioc_value = indicator.get("indicator", "").strip()
        if not ioc_value:
            continue

        # last_seen — OTX uses 'last_seen' or 'created'
        last_seen = indicator.get("last_seen") or indicator.get("created") or ingested_at

        # pulse-level metadata lives in nested 'pulse_info'
        pulse_info = indicator.get("pulse_info", {})
        pulses     = pulse_info.get("pulses", [])
        tags: list[str] = []
        threat_actor: str | None = None

        for pulse in pulses:
            tags.extend(pulse.get("tags", []))
            if not threat_actor:
                threat_actor = pulse.get("author", {}).get("username") if isinstance(
                    pulse.get("author"), dict
                ) else None

        # confidence: OTX doesn't score per-indicator; use pulse count as proxy
        confidence = min(100, 50 + len(pulses) * 5)

        yield {
            "ioc_type":     ioc_type,
            "ioc_value":    ioc_value,
            "source":       "otx",
            "threat_actor": threat_actor,
            "confidence":   confidence,
            "last_seen":    last_seen,
            "tags":         list(set(tags))[:20],   # dedupe, cap at 20
            "ingested_at":  ingested_at,
        }
        count += 1

    log.info("OTX: yielded %d indicators", count)


# ─────────────────────────────────────────────────────────────────────────────
# URLhaus feed
# ─────────────────────────────────────────────────────────────────────────────

def pull_urlhaus() -> Generator[dict, None, None]:
    """Yield normalised IOC dicts from Abuse.ch URLhaus (CSV feed, no auth needed)."""
    ingested_at = now_iso()
    count = 0

    try:
        resp = requests.get(URLHAUS_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = resp.text
    except Exception as exc:
        log.error("URLhaus fetch failed: %s", exc)
        return

    # CSV format (after comment lines starting with #):
    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    log.info("URLhaus: fetched %d raw CSV rows", len(lines))

    # skip header row if present
    if lines and lines[0].lower().startswith("id,"):
        lines = lines[1:]

    for line in lines:
        parts = line.split('","')
        # strip surrounding quotes
        parts = [p.strip('"') for p in parts]
        if len(parts) < 6:
            continue

        # columns: id, dateadded, url, url_status, last_online, threat, tags, ...
        try:
            url_value  = parts[2].strip()
            url_status = parts[3].strip()
            threat     = parts[5].strip() if len(parts) > 5 else ""
            tags_raw   = parts[6].strip() if len(parts) > 6 else ""
            date_added = parts[1].strip() if len(parts) > 1 else ingested_at
        except IndexError:
            continue

        if not url_value:
            continue

        conf_map   = {"online": 90, "offline": 60}
        confidence = conf_map.get(url_status, 40)
        tags       = [t.strip() for t in tags_raw.split(",") if t.strip()]
        if threat:
            tags.append(threat)

        yield {
            "ioc_type":     "url",
            "ioc_value":    url_value,
            "source":       "urlhaus",
            "threat_actor": None,
            "confidence":   confidence,
            "last_seen":    date_added,
            "tags":         tags,
            "ingested_at":  ingested_at,
        }
        count += 1

    log.info("URLhaus: yielded %d indicators", count)


# ─────────────────────────────────────────────────────────────────────────────
# main ingest job
# ─────────────────────────────────────────────────────────────────────────────

def run_ingest() -> None:
    log.info("=" * 60)
    log.info("CTI ingest run starting at %s", now_iso())

    total_ok = total_err = 0

    # -- OTX --
    log.info("Pulling AlienVault OTX …")
    ok, err = flush_batches(pull_otx())
    log.info("OTX done: %d indexed, %d errors", ok, err)
    total_ok += ok
    total_err += err

    # -- URLhaus --
    log.info("Pulling Abuse.ch URLhaus …")
    ok, err = flush_batches(pull_urlhaus())
    log.info("URLhaus done: %d indexed, %d errors", ok, err)
    total_ok += ok
    total_err += err

    # -- summary --
    log.info("-" * 60)
    log.info("Ingest complete: %d IOCs indexed, %d errors", total_ok, total_err)

    # -- verify count in ES --
    try:
        resp = requests.get(
            f"{ES_URL}/{ES_INDEX}/_count",
            auth=ES_AUTH,
            timeout=REQUEST_TIMEOUT,
        )
        count = resp.json().get("count", "?")
        log.info("siem-threat-intel index now holds %s documents", count)
    except Exception as exc:
        log.warning("Could not verify index count: %s", exc)

    log.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="CTI Feed Manager — Day 21")
    parser.add_argument("--once", action="store_true",
                        help="Run a single ingest cycle and exit")
    parser.add_argument("--interval-minutes", type=int, default=360,
                        help="Scheduler interval in minutes (default: 360 = 6 h)")
    args = parser.parse_args()

    if args.once or not HAS_SCHEDULER:
        if not HAS_SCHEDULER and not args.once:
            log.warning("apscheduler not installed — running once only. "
                        "Install with: pip install apscheduler --break-system-packages")
        run_ingest()
        return

    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(
        run_ingest,
        trigger="interval",
        minutes=args.interval_minutes,
        next_run_time=datetime.now(timezone.utc),   # run immediately on start
        id="cti_ingest",
        name="CTI Feed Ingest",
    )
    log.info("Scheduler started — interval: %d min. Press Ctrl+C to stop.",
             args.interval_minutes)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped.")


if __name__ == "__main__":
    main()