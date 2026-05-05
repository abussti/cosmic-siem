# ARCHITECTURE.md
## Cosmic Info Solutions — SIEM Platform (Agentic AI)
**Author:** Ahmad Bussti  
**Organisation:** Cosmic Info Solutions  
**Date:** May 2026  
**Phase:** 1 — Foundation & Setup  
**Stack:** Wazuh 4.x · Elastic 8.x · LangGraph (latest) · Python 3.11+

---

## 1. Purpose

This document is the single source of truth for the SIEM platform build. Every technical decision — tool choice, data format, agent logic, integration pattern — must trace back to this document. If something is not documented here, it is not agreed.

---

## 2. System Overview

The platform is a fully agentic Security Information and Event Management (SIEM) system. It ingests raw security logs from multiple sources, normalises and correlates them, scores threat confidence, and uses autonomous AI agents to triage, hunt, and respond — with minimal human involvement for routine incidents.

```
Security Data Sources
        │
        ▼
Log Aggregation & Normalisation (Wazuh)
        │
        ▼
Correlation & Rule Engine (Wazuh + Elastic SIEM / SIGMA Rules)
        │
        ▼
┌──────────────────────────────────────────────┐
│         Agentic AI Orchestration Layer        │  ← NEW
│                                              │
│   ┌─────────────┐   Coordination Agent       │
│   │ Triage Agent│◄─ routes based on          │
│   │ Hunting Agent   confidence score          │
│   │ Response Agent                           │
└──────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│         Proactive Threat Hunting Track        │  ← NEW
│  Scheduled Hunts · Baseline Deviation ·      │
│  Hunt Findings → Red Team Simulator          │
└──────────────────────────────────────────────┘
        │
        ▼
AI Triage & Validation Engine
  │               │               │
  ▼               ▼               ▼
Low Confidence  Medium          High Confidence
Archive         Analyst Queue   Red Team Simulator
        │
        ▼
Automated Red Team Simulator (MITRE ATT&CK replay)
        │
        ▼
Response Orchestrator
        │
        ▼
Response Systems
  Firewall · WAF · EDR · SOAR · IAM · Ticketing
        │
        ▼
Audit Log & Case Management
        │
        ▼
SOC Dashboard & Analyst Layer
        │
        ▼ (feedback loop)
AI Triage Engine (scores updated by analyst decisions)
```

---

## 3. Component Descriptions

### 3.1 Security Data Sources

| Source Type | Tool / Format | Log Location |
|-------------|--------------|--------------|
| Endpoints | EDR / AV, OS logs | `/var/log/auth.log`, Windows Event Log |
| Network | Firewall, IDS/IPS | iptables, Snort/Suricata |
| Cloud | AWS CloudTrail, Azure Activity | CloudTrail JSON, Azure Monitor |
| Identity | Active Directory, SSO | AD event logs, SAML/OIDC |
| Application logs | APIs, auth services | Custom JSON to `/var/log/app.log` |
| Threat intelligence | MISP, STIX/TAXII feeds | Integrated via Wazuh MISP module |

### 3.2 Log Aggregation & Normalisation — Wazuh 4.x

**Role:** Collect raw logs from all sources, parse, normalise, deduplicate, and enrich.

**Key responsibilities:**
- Deploy Wazuh Manager (Docker) and Wazuh Agents on endpoints
- Parse all log formats into a common schema (see Section 5 — Data Contract)
- Enrich events with asset context (hostname, IP, user) and threat intel
- Forward normalised alerts to Elastic via Filebeat

**Config location:** `/wazuh/ossec.conf`

### 3.3 Correlation & Rule Engine — Elastic SIEM + SIGMA Rules

**Role:** Apply detection logic to normalised logs. Group related events into incident candidates.

**Key responsibilities:**
- SIGMA rules define detection logic (stored as `.yml` in `/elastic/sigma-rules/`)
- Every rule maps to a MITRE ATT&CK technique ID
- Rule naming convention: `T{technique_id}_{short_name}.yml` (e.g. `T1110_ssh_brute_force.yml`)
- Elastic index pattern: `wazuh-alerts-*`

### 3.4 Confidence Scoring Engine — Python

**Role:** Assign a 0–100 confidence score to every alert before routing.

**Formula:**
```
confidence = (0.4 × rule_severity_normalised)
           + (0.4 × anomaly_score)
           + (0.2 × time_factor)
```

| Component | Source | Notes |
|-----------|--------|-------|
| `rule_severity_normalised` | Wazuh rule level (1–15), scaled to 0–100 | `(level / 15) × 100` |
| `anomaly_score` | Elastic ML anomaly score | Default 50 if ML not available |
| `time_factor` | Event timestamp | 100 if outside 08:00–20:00, else 50 |

**File:** `/elastic/confidence_scorer.py`

### 3.5 Agentic AI Orchestration Layer — LangGraph

**Role:** Autonomous multi-agent system that triages alerts, hunts proactively, and executes responses without human approval for routine actions.

#### 3.5.1 Coordination Agent
- Entry point of the LangGraph graph
- Receives every alert from the confidence scorer
- Routing logic:
  - `confidence < 40` → archive queue (`/logs/archived-alerts.jsonl`)
  - `40 ≤ confidence ≤ 70` → analyst review queue (Elastic index: `siem-review-queue`)
  - `confidence > 70` → Triage Agent

#### 3.5.2 Triage Agent
- Investigates high-confidence alerts autonomously
- Queries Elastic for context: recent events from same IP, user login history
- Calls Claude API to generate investigation summary
- Output: `{ verdict: suspicious|benign|unknown, summary: str, evidence: list }`

#### 3.5.3 Hunting Agent _(Phase 2)_
- Proactively queries logs on a schedule (no alert needed to trigger)
- Detects baseline deviations in user and system behaviour
- Feeds findings to the red team simulator

#### 3.5.4 Response Agent _(Phase 3)_
- Selects and executes response playbooks autonomously
- No human approval required for low-risk actions (e.g. rate limiting, MFA enforcement)
- High-risk actions (e.g. account disable, endpoint isolation) require analyst approval

**LangGraph file structure:**
```
/langgraph/
  agents/
    coordination_agent.py
    triage_agent.py
    hunting_agent.py       ← Phase 2
    response_agent.py      ← Phase 3
  tools/
    elastic_tools.py       ← Elastic API query functions
  state.py                 ← AgentState TypedDict
  graph.py                 ← StateGraph definition
  pipeline_runner.py       ← Polls Elastic, drives the graph
```

**AgentState schema** (`state.py`):
```python
class AgentState(TypedDict):
    alert: dict          # Original Elastic alert document
    confidence: int      # Score 0–100 from confidence scorer
    technique: str       # MITRE ATT&CK technique ID (e.g. T1110)
    notes: list[str]     # Running log of agent observations
    escalate: bool       # True = route to human analyst
    verdict: str         # suspicious | benign | unknown
    summary: str         # Human-readable investigation summary
    evidence: list[dict] # Supporting events/context
```

### 3.6 Proactive Threat Hunting Track _(Phase 2)_

- **Scheduled hunts:** AI-triggered query runs on a timer (no alert required)
- **Baseline deviation:** Detects anomalies vs. established user/system baselines
- **Hunt findings** feed into the red team simulator for validation

### 3.7 Automated Red Team Simulator _(Phase 4)_

- Receives high-confidence validated threats
- Replays detected attack behaviour using MITRE ATT&CK techniques
- Tests if the detected vulnerability is actually exploitable
- Estimates blast radius: which assets are reachable if this threat is real

### 3.8 Response Orchestrator

- Receives validated threats from the pipeline
- Selects appropriate response playbook from library
- Triggers APIs on connected security tools
- Logs all actions to audit trail

### 3.9 Response Systems

| System | Actions |
|--------|---------|
| Firewall | Block IP, restrict traffic rules |
| WAF | Block requests, rate limit |
| EDR | Isolate endpoint, kill malicious process |
| SOAR | Execute multi-step playbooks |
| IAM | Disable account, force MFA re-enroll |
| Ticketing | Create incident ticket, notify on-call |

### 3.10 Audit Log & Case Management

- Immutable record of every action taken by agents and analysts
- Supports compliance reporting: SOC 2, ISO 27001
- Elastic index: `siem-audit-*`

### 3.11 SOC Dashboard & Analyst Layer

- Built on Kibana
- Displays alerts with AI-generated triage summary
- Shows event timeline and affected assets
- Analysts mark true/false positives → feeds back into AI scoring model
- Analyst decisions stored in: `siem-feedback-*` index

---

## 4. Tech Stack & Versions

| Component | Technology | Version | Notes |
|-----------|-----------|---------|-------|
| Log collector | Wazuh Manager + Agent | 4.7.x | Docker install |
| Search & alerts | Elasticsearch | 8.12.x | Open-source tier only |
| Dashboards | Kibana | 8.12.x | Open-source tier only |
| Log shipper | Filebeat | 8.12.x | Ships Wazuh → Elastic |
| AI agent framework | LangGraph | latest | pip install langgraph |
| LLM | Claude (via API) | claude-sonnet-4-20250514 | Anthropic API |
| Language | Python | 3.11+ | All custom code |
| Containers | Docker + Docker Compose | latest | All services |
| Detection rules | SIGMA | v2 | Stored as .yml |
| Threat framework | MITRE ATT&CK | v14 | All rules mapped to technique IDs |
| Version control | GitHub | — | cosmic-siem repo |

---

## 5. Data Contract

Every log event **must** contain the following fields after normalisation by Wazuh. Detection rules will not fire correctly if any of these fields are missing.

### 5.1 Required Fields (All Events)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `@timestamp` | ISO 8601 datetime | When the event occurred | `2026-05-05T09:15:00.000Z` |
| `agent.ip` | string (IP) | IP address of the Wazuh agent reporting the event | `192.168.1.50` |
| `agent.name` | string | Hostname of the Wazuh agent | `web-server-01` |
| `rule.description` | string | Human-readable description of the triggered rule | `SSH brute force attempt` |
| `rule.level` | integer (1–15) | Wazuh severity level | `10` |

### 5.2 Enriched Fields (Added by Normalisation Pipeline)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `source.ip` | string (IP) | IP of the entity triggering the event | `203.0.113.42` |
| `source.user` | string | Username associated with the event | `admin` |
| `host.name` | string | Target hostname | `db-server-02` |
| `rule.mitre.technique` | string | MITRE ATT&CK technique ID | `T1110` |
| `rule.mitre.tactic` | string | MITRE ATT&CK tactic name | `Credential Access` |
| `event.category` | string | Event category | `authentication` |
| `event.outcome` | string | Outcome of the event | `failure` |
| `confidence` | integer (0–100) | Confidence score (added by scoring engine) | `82` |

### 5.3 Log Source Type Field

All events must include a `log.source_type` field:

| Value | Source |
|-------|--------|
| `endpoint` | OS auth logs, EDR |
| `network` | Firewall, iptables, IDS |
| `cloud` | AWS CloudTrail, Azure Activity |
| `identity` | Active Directory, SSO |
| `application` | Custom app logs |
| `threat_intel` | MISP / STIX feeds |

---

## 6. Folder Structure (GitHub Repo: `cosmic-siem`)

```
cosmic-siem/
├── wazuh/
│   ├── ossec.conf            # Wazuh manager config
│   ├── local_rules.xml       # Custom Wazuh detection rules
│   └── agent-configs/        # Per-endpoint agent configs
├── elastic/
│   ├── docker-compose.yml    # Elastic + Kibana + Filebeat
│   ├── filebeat.yml          # Filebeat config (Wazuh → Elastic)
│   ├── sigma-rules/          # SIGMA .yml detection rules
│   │   └── T1110_ssh_brute_force.yml
│   └── confidence_scorer.py  # Confidence scoring engine
├── langgraph/
│   ├── agents/
│   │   ├── coordination_agent.py
│   │   ├── triage_agent.py
│   │   ├── hunting_agent.py
│   │   └── response_agent.py
│   ├── tools/
│   │   └── elastic_tools.py
│   ├── state.py
│   ├── graph.py
│   └── pipeline_runner.py
├── dashboard/                # Kibana saved objects / dashboards
├── response/                 # Response playbook definitions
├── docs/
│   ├── ARCHITECTURE.md       ← this file
│   ├── data-contract.md
│   ├── week-summaries.md
│   ├── screenshots/
│   └── phase1-test-results.md
├── tests/                    # Attack simulation scripts
├── logs/                     # Runtime logs (gitignored)
├── CONTRIBUTING.md
├── SETUP.md
└── README.md
```

---

## 7. Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, demo-ready code only. Merges reviewed. |
| `dev` | Active development. All features merged here first. |
| `feature/xxx` | One branch per feature (e.g. `feature/triage-agent`) |

**Commit format:** `type(scope): message`

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Test scripts |
| `chore` | Config, tooling |

**Example:** `feat(wazuh): add syslog parser for iptables`

---

## 8. Phase Roadmap

| Phase | Weeks | Theme | Exit Milestone |
|-------|-------|-------|---------------|
| **Phase 1** | 1–4 | Foundation & Setup | Wazuh + Elastic running, 10 SIGMA rules, triage agent v1 |
| Phase 2 | 5–8 | Hunting & Baseline | Hunting agent live, baseline ML model trained |
| Phase 3 | 9–12 | Response Automation | Response agent executing playbooks automatically |
| Phase 4 | 13–20 | Red Team + Full Demo | Red team simulator live, full Phase demo to stakeholders |

---

## 9. Key Decisions & Rationale

| Decision | Rationale |
|----------|-----------|
| Wazuh over Splunk | Open-source, ₹0 cost, strong community, Docker support |
| Elastic open-source tier only | No paid features needed for Phase 1; avoid licence cost |
| LangGraph over raw LangChain | Native graph/state machine model fits multi-agent routing |
| SIGMA rules (not Elastic EQL only) | SIGMA is portable across SIEM platforms; future-proof |
| Python 3.11+ | Best async support; required by LangGraph |
| Claude API as LLM | Superior reasoning for security analysis use case |

---

## 10. Open Questions (To Resolve in Phase 1)

- [ ] Which cloud provider will host the Wazuh + Elastic stack in production? (VM specs TBD)
- [ ] Will the Elastic ML anomaly detection module be available on open-source tier?
- [ ] What is the production SLA for alert response time? (Affects polling interval in pipeline_runner.py)
- [ ] Which ticketing system will receive escalated incidents? (Jira / ServiceNow / other)

---

*This document should be updated whenever a significant architectural decision changes. All changes require a commit to `main` with message format: `docs(arch): <change description>`*
