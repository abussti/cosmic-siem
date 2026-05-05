# cosmic-siem
**Cosmic Info Solutions · Agentic AI SIEM Platform**  
*Built by Ahmad Bussti · Phase 1: Foundation & Setup*

---

## What This Is

An open-source SIEM platform with an agentic AI layer built on top. It ingests security logs from endpoints, network, cloud, and identity sources — then uses autonomous AI agents (built with LangGraph) to triage alerts, hunt for threats proactively, and execute response actions without constant human involvement.

**Stack:** Wazuh 4.x · Elastic 8.x · LangGraph · Python 3.11+ · Docker

---

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full system design, data contract, and component descriptions.

```
Data Sources → Wazuh → Elastic SIEM → Confidence Scorer
    → Coordination Agent → Triage Agent → Response Orchestrator
    → Response Systems (Firewall, EDR, IAM, Ticketing)
```

---

## Phase 1 Progress

| Week | Theme | Status |
|------|-------|--------|
| Week 1 | Environment & Architecture | 🔄 In progress |
| Week 2 | Elastic Setup + Log Pipeline | ⬜ Not started |
| Week 3 | Confidence Scoring + LangGraph | ⬜ Not started |
| Week 4 | Full Pipeline + Phase 1 Demo | ⬜ Not started |

---

## Setup

See [`SETUP.md`](SETUP.md) for step-by-step installation instructions.

**Quick start (once SETUP.md is complete):**
```bash
git clone https://github.com/cosmic-info-solutions/cosmic-siem.git
cd cosmic-siem
docker-compose up -d   # starts Wazuh + Elastic
```

---

## Folder Structure

```
cosmic-siem/
├── wazuh/        # Wazuh manager config + agent configs
├── elastic/      # Elastic stack + Filebeat + SIGMA rules
├── langgraph/    # AI agents (coordination, triage, hunting, response)
├── dashboard/    # Kibana dashboards
├── response/     # Response playbooks
├── docs/         # Architecture, data contract, weekly summaries
└── tests/        # Attack simulation scripts
```

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for commit format, branch strategy, and folder conventions.

---

*Budget: ₹0 · All open-source stack · Phase 1 target: 4 weeks*
