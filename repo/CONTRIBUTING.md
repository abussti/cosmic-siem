# Contributing Guide — cosmic-siem
**Cosmic Info Solutions · Ahmad Bussti · Phase 1**

---

## Commit Format

Every commit in this repo follows the same format. No exceptions from Day 1.

```
type(scope): short description
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `docs` | Documentation only (no code change) |
| `test` | Test scripts, attack simulations |
| `chore` | Config, tooling, dependency updates |
| `refactor` | Code restructure, no behaviour change |
| `wip` | Work in progress — never merge to main in this state |

### Scopes

| Scope | Area |
|-------|------|
| `wazuh` | Wazuh manager / agent config |
| `elastic` | Elasticsearch, Kibana, Filebeat, SIGMA rules |
| `langgraph` | AI agents, state, graph |
| `pipeline` | pipeline_runner.py, scoring engine |
| `dashboard` | SOC dashboard, Kibana objects |
| `response` | Response playbooks, integrations |
| `docs` | Documentation files |
| `tests` | Attack simulation scripts |
| `arch` | Architecture-level changes |

### Examples

```
feat(wazuh): add syslog parser for iptables logs
fix(elastic): correct field mapping for agent.ip
docs(arch): update data contract with cloud log fields
test(pipeline): add SSH brute force simulation script
chore(docker): pin Elastic version to 8.12.0
```

---

## Branch Strategy

| Branch | Purpose | Rules |
|--------|---------|-------|
| `main` | Stable, demo-ready code | Only merged from `dev`. No direct commits. |
| `dev` | Active development | All features merged here first. Must pass basic tests. |
| `feature/xxx` | One branch per feature | Branch from `dev`. Merge back to `dev` when done. |

### Starting a new feature

```bash
git checkout dev
git pull origin dev
git checkout -b feature/your-feature-name
# ... do work ...
git push origin feature/your-feature-name
# Open a PR: feature/xxx → dev
```

### Releasing to main

```bash
git checkout main
git merge dev
git push origin main
git tag -a v0.1.0 -m "Phase 1 Week 1 complete"
git push origin --tags
```

---

## Folder Structure

```
cosmic-siem/
├── wazuh/            # Wazuh manager config, agent configs, custom rules
├── elastic/          # Elasticsearch, Kibana, Filebeat, SIGMA rules
├── langgraph/        # LangGraph agents, tools, state, graph
├── dashboard/        # Kibana saved objects and dashboard exports
├── response/         # Response playbook definitions
├── docs/             # All documentation (ARCHITECTURE.md, guides, screenshots)
├── tests/            # Attack simulation scripts and test utilities
├── logs/             # Runtime logs — gitignored, never committed
├── CONTRIBUTING.md   # This file
├── SETUP.md          # Step-by-step environment setup guide
└── README.md         # Project overview
```

---

## What Goes in Each Folder

### `/wazuh/`
- `ossec.conf` — Wazuh manager configuration
- `local_rules.xml` — Custom Wazuh detection rules
- `agent-configs/` — Per-endpoint Wazuh agent configurations

### `/elastic/`
- `docker-compose.yml` — Elastic stack setup
- `filebeat.yml` — Filebeat config (ships Wazuh logs → Elastic)
- `sigma-rules/` — SIGMA `.yml` detection rule files
- `confidence_scorer.py` — Confidence scoring engine

### `/langgraph/`
- `agents/` — One file per agent (coordination, triage, hunting, response)
- `tools/` — Elastic API helper functions
- `state.py` — Shared AgentState TypedDict
- `graph.py` — LangGraph StateGraph definition
- `pipeline_runner.py` — Main runner that polls Elastic

### `/docs/`
- `ARCHITECTURE.md` — System architecture (single source of truth)
- `data-contract.md` — Confirmed Elastic field mappings
- `week-summaries.md` — Weekly progress summaries sent to Siddharth
- `screenshots/` — Dashboard and alert screenshots
- `phase1-test-results.md` — Attack scenario test results

### `/tests/`
- One script per attack scenario
- Named: `sim_T{technique}_{name}.py` (e.g. `sim_T1110_ssh_brute_force.py`)

---

## Rules

1. **Never commit secrets.** No API keys, passwords, or tokens in any file. Use `.env` files (gitignored).
2. **Never commit to `main` directly.** All changes go through `dev` first.
3. **Every SIGMA rule file** must be named `T{technique_id}_{short_name}.yml`.
4. **Every test script** must include a comment at the top explaining what it simulates.
5. **Friday is documentation day.** Every week ends with docs up to date and committed.
6. **If it is broken, say so.** Do not hide broken things in commits. Open a GitHub issue instead.

---

## GitHub Project Board

The project board has 4 columns:

| Column | What goes here |
|--------|---------------|
| **Backlog** | Planned tasks not yet started |
| **In Progress** | Currently being worked on (max 2 items at once) |
| **Done** | Completed and committed to `dev` or `main` |
| **Blocked** | Blocked by a dependency, bug, or missing info |

Every day's task from the Phase 1 plan should be a card on this board.
