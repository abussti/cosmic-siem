# How to Write and Load a New Detection Rule

**Applies to:** Elastic SIEM (Kibana Detection Engine)  
**Project:** Cosmic Info Solutions SIEM Phase 1

This guide covers writing a new detection rule in SIGMA format, converting it
to an Elastic-compatible query, and loading it into Kibana.

---

## 1. Write the SIGMA rule

SIGMA is a vendor-neutral rule format. Create a `.yml` file in `~/elastic/sigma-rules/`.

**Example — detect after-hours sudo:**

```yaml
# ~/elastic/sigma-rules/after_hours_sudo.yml
title: After-Hours Sudo to ROOT
id: a1b2c3d4-0001-0000-0000-000000000001
status: experimental
description: >
  Detects a user running sudo to become root outside of business hours (06:00–22:00 UTC).
  Correlated with T1078 (Valid Accounts) and T1059 (Command Execution).
author: Ahmad Bussti
date: 2026/06/04
references:
  - https://attack.mitre.org/techniques/T1078/
tags:
  - attack.privilege_escalation
  - attack.t1078
  - attack.t1059
logsource:
  product: wazuh
  category: process_creation
detection:
  selection:
    rule.id:
      - '5402'   # Successful sudo to ROOT
      - '5403'   # First time user executed sudo
  filter_business_hours:
    data.login_hour|gte: 6
    data.login_hour|lt: 22
  condition: selection and not filter_business_hours
falsepositives:
  - Legitimate scheduled maintenance tasks
  - On-call engineer responding to an incident
level: high
```

**Key fields to set:**

| Field | What to put |
|---|---|
| `id` | A unique UUID (generate one at https://www.uuidgenerator.net) |
| `rule.id` | The Wazuh rule ID(s) this matches — see the Rule IDs table in project.md |
| `tags` | MITRE ATT&CK tag in format `attack.tXXXX` |
| `level` | `low` / `medium` / `high` / `critical` |
| `condition` | The detection logic — `selection and not filter` is the most common pattern |

---

## 2. Convert SIGMA to an Elastic query

Install the SIGMA CLI tool:

```bash
pip install sigma-cli --break-system-packages
sigma plugin install elasticsearch
```

Convert your rule:

```bash
sigma convert \
  -t lucene \
  -p ecs_windows \
  ~/elastic/sigma-rules/after_hours_sudo.yml
```

This outputs a Lucene query string like: (rule.id:("5402" OR "5403")) AND NOT (data.login_hour:>=6 AND data.login_hour:<22)

Copy this query — you'll paste it into Kibana in the next step.

---

## 3. Load the rule into Kibana

### Via Kibana UI (recommended for new rules)

1. Open Kibana → **Security** → **Rules** → **Detection rules (SIEM)**
2. Click **Create new rule**
3. Select rule type based on what you need:
   - **Custom query** — single condition (most rules)
   - **Threshold** — fires after N events in a time window (brute force)
   - **New terms** — fires when a value (IP, username) appears for the first time
4. Paste the Lucene query from Step 2 into the **Custom query** field
5. Set **Index patterns:** `logs-wazuh.alerts-*`
6. Fill in the **About** tab:
   - Name, description, severity, MITRE technique
7. Set **Schedule:** every 5 minutes, look-back 6 minutes
8. Click **Create & enable rule**

### Via API (for scripted bulk loading)

```bash
curl -s -u elastic:changeme \
  -X POST "http://localhost:5601/api/detection_engine/rules" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "type": "query",
    "language": "lucene",
    "query": "(rule.id:(\"5402\" OR \"5403\")) AND NOT (data.login_hour:>=6 AND data.login_hour:<22)",
    "name": "After-Hours Sudo to ROOT",
    "description": "Sudo to root outside business hours",
    "severity": "high",
    "risk_score": 75,
    "enabled": true,
    "index": ["logs-wazuh.alerts-*"],
    "interval": "5m",
    "from": "now-6m",
    "tags": ["T1078", "T1059"],
    "threat": [{
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0004", "name": "Privilege Escalation", "reference": "https://attack.mitre.org/tactics/TA0004/"},
      "technique": [{"id": "T1078", "name": "Valid Accounts", "reference": "https://attack.mitre.org/techniques/T1078/"}]
    }]
  }'
```

---

## 4. Verify the rule is running

```bash
# List all enabled rules
curl -s -u elastic:changeme \
  "http://localhost:5601/api/detection_engine/rules/_find?filter=alert.attributes.enabled:true" \
  -H "kbn-xsrf: true" | python3 -m json.tool | grep '"name"'
```

Or in Kibana UI: **Security → Rules → Detection rules** — the rule should show status **Active**.

---

## 5. Test the rule fires correctly

Inject a synthetic alert that should trigger:

```bash
# Inject a sudo alert at 03:00 UTC (after hours)
curl -s -u elastic:changeme -X POST "http://localhost:9201/logs-wazuh.alerts-$(date +%Y.%m.%d)/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT03:00:00.000Z)'",
    "rule": {"id": "5402", "description": "Successful sudo to ROOT", "level": 11, "groups": ["sudo"]},
    "agent": {"name": "agent1"},
    "data": {"login_hour": 3, "dstuser": "root(uid=0)"}
  }'
```

Wait up to 5 minutes (one rule cycle), then check **Security → Alerts** in Kibana.

---

## Rule type cheatsheet

| Scenario | Rule type | Key setting |
|---|---|---|
| Single event condition | Custom query | Lucene/EQL query |
| 5+ failed logins in 60s | Threshold | count >= 5, group by `data.srcip` |
| New username appears | New terms | field = `data.dstuser` |
| Sequence: login then sudo | EQL sequence | `sequence by agent.name` |