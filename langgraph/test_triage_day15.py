"""
Day 15 — Triage Agent Test Suite
Run from: ~/elastic/langgraph/
Command : python3 test_triage_day15.py
"""

import json
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, ".")
from agents.triage_agent import triage_node   # correct function name

EMPTY_STATE = lambda alert: {
    "alert":      alert,
    "notes":      [],
    "confidence": None,
    "technique":  None,
    "escalate":   False,
}


def print_result(test_name, alert, result, elapsed):
    sep = "=" * 68
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    tr   = result.get("triage_result") or {}

    print(f"\n{sep}")
    print(f"TEST : {test_name}")
    print(sep)
    print(f"  Rule       : {rule.get('id')} — {rule.get('description')}")
    print(f"  Level      : {rule.get('level')}")
    print(f"  Src IP     : {data.get('srcip', 'n/a')}")
    print(f"  User       : {data.get('dstuser', 'n/a')}")
    print()
    print(f"  Verdict    : {tr.get('verdict', 'MISSING').upper()}")
    print(f"  Confidence : {result.get('confidence', '?')} ({result.get('confidence_pct', '?')}%)")
    print(f"  Escalate   : {result.get('escalate', '?')}")
    print(f"  Summary    : {tr.get('summary', 'MISSING')}")
    evidence = tr.get("evidence", [])
    if isinstance(evidence, list):
        for e in evidence:
            print(f"    - {e}")
    else:
        print(f"    - {evidence}")
    print(f"  Time       : {elapsed:.1f}s")
    print()
    for note in result.get("notes", []):
        print(f"  LOG: {note}")


# ── Test 1 — Clear true positive: SSH brute force from external IP ─────────────
# Expected verdict: suspicious
# Using 127.0.0.1 because that's the IP with real data in your ES

TEST1 = {
    "@timestamp": datetime.now(timezone.utc).isoformat(),
    "rule": {
        "id": "5710",
        "description": "sshd: Attempt to login using a non-existent user",
        "level": 10,
        "groups": ["syslog", "sshd", "authentication_failed"],
    },
    "agent": {"name": "agent1"},
    "data": {
        "srcip":   "127.0.0.1",
        "dstuser": "root",
    },
}

# ── Test 2 — Clear false positive: sysadmin cron job at 2am ───────────────────
# Expected verdict: benign
# context_note is now injected into the prompt

TEST2 = {
    "@timestamp": "2026-05-22T02:13:00+00:00",
    "rule": {
        "id": "5402",
        "description": "Successful sudo to ROOT executed",
        "level": 5,
        "groups": ["syslog", "sudo"],
    },
    "agent": {"name": "agent1"},
    "data": {
        "srcip":        "127.0.0.1",
        "dstuser":      "root(uid=0)",
        "context_note": (
            "This sudo event was triggered by the nightly backup cron job "
            "/usr/local/bin/backup.sh running as the sysadmin service account "
            "on an internal-only IP. This exact event fires every night at 02:13 "
            "as part of scheduled maintenance. No interactive session was opened."
        ),
    },
}

# ── Test 3 — Ambiguous: successful login from new IP during business hours ─────
# Expected verdict: unknown

TEST3 = {
    "@timestamp": "2026-05-22T10:45:00+00:00",
    "rule": {
        "id": "5501",
        "description": "PAM: Login session opened for user john",
        "level": 3,
        "groups": ["pam", "authentication_success"],
    },
    "agent": {"name": "agent1"},
    "data": {
        "srcip":        "127.0.0.1",
        "dstuser":      "john",
        "context_note": (
            "Login succeeded during business hours (10:45 AM). john is a known "
            "employee but this source IP has not been seen before for this user. "
            "Could be VPN, travel, or new device — or could be credential theft. "
            "Insufficient evidence to rule either way."
        ),
    },
}


def run_all():
    tests = [
        ("Test 1 — SSH Brute Force          (expect: suspicious)", TEST1),
        ("Test 2 — Sysadmin Cron at 2am     (expect: benign)",     TEST2),
        ("Test 3 — New-IP Login, Biz Hours  (expect: unknown)",     TEST3),
    ]

    rows = []
    for name, alert in tests:
        print(f"\n>>> Running {name} ...")
        t0 = time.time()
        try:
            result = triage_node(EMPTY_STATE(alert))
        except Exception as exc:
            result = {
                "triage_result": {"verdict": "ERROR", "summary": str(exc), "evidence": []},
                "confidence": "?", "confidence_pct": "?", "escalate": False, "notes": [],
            }
        elapsed = time.time() - t0
        print_result(name, alert, result, elapsed)
        rows.append((name, result, elapsed))

    print("\n" + "=" * 68)
    print("SUMMARY")
    print("=" * 68)
    print(f"{'Test':<46} {'Verdict':<12} {'Conf%':<8} {'Time'}")
    print("-" * 68)
    for name, result, elapsed in rows:
        tr      = result.get("triage_result") or {}
        verdict = tr.get("verdict", "?").upper()
        conf    = str(result.get("confidence_pct", "?")) + "%"
        print(f"{name:<46} {verdict:<12} {conf:<8} {elapsed:.0f}s")
    print()


if __name__ == "__main__":
    run_all()
