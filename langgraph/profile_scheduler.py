"""
profile_scheduler.py — Day 46

Rebuilds all UEBA profiles (users + hosts) once daily at 02:00, via
APScheduler — the same scheduling library and pattern already used by
tools/feed_manager.py (Day 21, 6h CTI refresh) and pipeline_runner.py's
hunt scheduler (Day 26, 6h). No new scheduling dependency introduced.
"""

import argparse

from apscheduler.schedulers.blocking import BlockingScheduler

from tools.ueba_engine import refresh_entity_profile, refresh_user_profile

# Known entities to profile. Same hybrid approach as Day 24's actor seed
# table / Day 46's _DEPARTMENT_SEED: a curated starting list, extend as
# real users/hosts are observed. A future upgrade could auto-discover this
# list from a terms aggregation over data.dstuser / agent.name instead of
# hand-maintaining it — see "Upgrade Path" in day46-ueba-profiling.md.
KNOWN_USERS = ["devadmin", "root", "www-data"]
KNOWN_HOSTS = ["agent1", "redteam-target-win10"]


def run_all_profiles_once():
    results = {"users": [], "hosts": []}
    for u in KNOWN_USERS:
        print(f"[profile_scheduler] Rebuilding user profile: {u}")
        results["users"].append(refresh_user_profile(u))
    for h in KNOWN_HOSTS:
        print(f"[profile_scheduler] Rebuilding host profile: {h}")
        results["hosts"].append(refresh_entity_profile(h))
    return results


def start_scheduler():
    scheduler = BlockingScheduler()
    scheduler.add_job(run_all_profiles_once, "cron", hour=2, minute=0)
    print("[profile_scheduler] Started — daily rebuild scheduled for 02:00.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("[profile_scheduler] Stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run a single rebuild cycle and exit")
    args = parser.parse_args()

    if args.once:
        run_all_profiles_once()
    else:
        start_scheduler()
