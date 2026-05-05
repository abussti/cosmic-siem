# Data Contract — cosmic-siem

All log events flowing through the pipeline must contain the following fields after Wazuh normalisation. This contract is confirmed in Week 2 (Day 7).

## Status: PENDING CONFIRMATION (Week 2, Day 7)

## Required Fields

| Field | Type | Status |
|-------|------|--------|
| `@timestamp` | ISO 8601 datetime | ⬜ To confirm |
| `agent.ip` | string (IP) | ⬜ To confirm |
| `agent.name` | string | ⬜ To confirm |
| `rule.description` | string | ⬜ To confirm |
| `rule.level` | integer (1–15) | ⬜ To confirm |

*Update this file on Day 7 when confirmed in Elastic.*
