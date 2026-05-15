# Wazuh → Elasticsearch Data Contract

**Verified:** 2026-05-12
**Index pattern:** wazuh-alerts-*
**Pipeline:** Wazuh Manager → alerts.json → Filebeat → Elasticsearch → Kibana

## Required Fields

| Field             | Type    | Notes                                        |
|-------------------|---------|----------------------------------------------|
| @timestamp        | date    | Set by Filebeat from Wazuh alert timestamp   |
| agent.ip          | ip      | Defaults to 0.0.0.0 for manager-local events |
| agent.name        | keyword | Hostname of the reporting agent              |
| rule.description  | text    | Human-readable rule match description        |
| rule.level        | integer | Wazuh severity level (0-15)                  |

## Cloud and Network Source Types

| Source Type | Log Format | Location | Wazuh Format | Added |
|-------------|-----------|----------|--------------|-------|
| Network – firewall (simulated iptables) | syslog | /var/log/firewall.log | syslog | Day 8 |
| Cloud – AWS CloudTrail (simulated) | NDJSON | /var/log/cloudtrail.json | json | Day 8 |

## Validation Result

- Documents verified: 213+
- Missing fields after fix: 0
- Fix applied: Filebeat JavaScript processor adds agent.ip = 0.0.0.0 when missing
- Index template applied: wazuh-alerts-template (priority 200)

## Known Edge Cases

- Manager-local events (agent.id = 000) have agent.ip = 0.0.0.0 (expected)
