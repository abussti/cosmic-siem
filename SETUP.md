# SIEM Platform — Setup (Phase 1 + Phase 2)

**Project:** Cosmic Info Solutions | **Engineer:** Ahmad Bussti | **Updated:** Day 39

---

## 1. Infrastructure

### Host Machine
- **OS:** Ubuntu 26.04 LTS (kernel 7.0.0-15-generic)
- **Hostname:** wazuh-manager-VirtualBox

### Two separate Docker layouts — read this first
This project actually runs across **two different compose layouts** discovered the hard way on
Day 33 — document lookups that assume only the first one exist will waste time:

| Layout | Location | Services |
|---|---|---|
| Elastic stack | `~/elastic/docker-compose.yml` | elasticsearch (host port **9201**, not 9202), kibana (5601), filebeat, single-node-wazuh.manager-1, single-node-wazuh.indexer-1 |
| Official Wazuh manager config | `~/wazuh-docker/single-node/` (service `wazuh.manager`) | `ossec.conf` is mounted via `config/wazuh_cluster/wazuh_manager.conf` → `/wazuh-config-mount/etc/ossec.conf` inside the container — **not** a flat top-level `ossec.conf`. Wazuh's `/init` script copies this in on startup. |

Editing an unmounted `ossec.conf` elsewhere on the host has no effect — always find the real
mount via that compose file's volumes section before editing active-response `<command>` blocks.

### Credentials (all in one place — several of these were previously undocumented)

| System | User | Password | Notes |
|---|---|---|---|
| Elasticsearch / Kibana | `elastic` | `changeme` | |
| Wazuh REST API | `wazuh-wui` | `MyS3cr37P450r.*-` | Official `wazuh-docker` repo example default — not `wazuh:wazuh`, not `elastic:changeme`. Discovered Day 33 by testing known defaults against `/security/user/authenticate`. |

### Wazuh Agent ("agent1")
Separate VM, connects to manager on port 1514. Collects auth/PAM logs, iptables/firewall, sudo
events.

---

## 2. Phase 1 Components (recap)

- Elasticsearch 8.12.0, Kibana 8.12.0, Filebeat, Wazuh manager 4.7.5 — see `docker-compose.yml`
- 10 SIGMA-style detection rules (Rules 1-10) — see `project.md` for the full table
- LangGraph pipeline: `coordination_node → triage_node → hunting_node → response_node`
- `pipeline_runner.py` — continuous 30s poll loop

Install:
```bash
pip install langgraph langchain langchain-anthropic google-genai --break-system-packages
```

---

## 3. Phase 2 Components (new — this is what Phase 1's SETUP.md didn't cover)

### 3.1 CTI Feeds
```bash
pip install requests apscheduler --break-system-packages   # if not already present

# One-time or scheduled ingest
cd ~/elastic/langgraph && python3 tools/feed_manager.py --once   # single run
cd ~/elastic/langgraph && python3 tools/feed_manager.py           # continuous, 6h interval
```
Populates ES index `siem-threat-intel`. No API key needed (OTX + URLhaus are both open feeds
used here without auth).

### 3.2 Environment Variables

| Variable | Used by | Required for |
|---|---|---|
| `GEMINI_API_KEY` | `triage_agent.py`, `hunt_summarizer.py` | Live triage verdicts, hunt summaries |
| `WAZUH_API_USER` / `WAZUH_API_PASS` | `response_tools.py` | `block_ip`, `isolate_endpoint` |
| `RESPONSE_SSH_USER` / `RESPONSE_SSH_KEY` | `response_tools.py` | `unblock_ip`, `unisolate_endpoint` (SSH-based reversal — see architecture doc for why) |
| `RESPONSE_AUTO_EXECUTE` | `response_agent.py` (Day 39) | Gates whether `select_response_action()` actually calls `response_tools` or only logs the decision. **Defaults to `false` — set to `true` deliberately per environment only after the dry-run process in `HOW-TO-ADD-RESPONSE-ACTION.md`.** |

Example:
```bash
export GEMINI_API_KEY=...
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASS='MyS3cr37P450r.*-'
export RESPONSE_SSH_USER="agent1"
export RESPONSE_SSH_KEY="~/.ssh/id_ed25519"
export RESPONSE_AUTO_EXECUTE=false   # leave off until you trust it
```

### 3.3 Hunting Engines
Two engines exist — see `PHASE2-ARCHITECTURE.md` section 3 for why. Setup for each:

```bash
# Day 26 scaffold engine (2 playbooks) — smoke test
cd ~/elastic/langgraph && python3 -m agents.hunting_agent

# Production YAML engine (6 playbooks under hunts/*.yml)
cd ~/elastic/langgraph && python3 -m tools.hunt_loader
```
`pipeline_runner.py`'s APScheduler job runs the Day 26 engine automatically every 6h. As of
Day 39, `hunt_loader.py`'s YAML hunts also auto-escalate — no separate scheduling change is
required, but if you're wiring the YAML engine into the same APScheduler job, confirm you
haven't duplicated a scheduled call (check `pipeline_runner.py`'s `start_hunt_scheduler()`).

### 3.4 Behavioural Baselines
```bash
cd ~/elastic/langgraph && python3 -m tools.baseline_builder
```
Writes to `siem-baselines`. **Not currently scheduled** — this is a manual/one-off script; see
backlog item "schedule weekly baseline rebuild." Known issue: `outbound_conn_per_hour:agent1`
has an unresolved test-data contamination bug (Day 28) — don't trust it for real detection until
re-verified in isolation.

### 3.5 Response Tools — Wazuh Active-Response Scripts
Two custom scripts must be deployed **per agent** (currently only done for `agent1` — see
backlog to roll out to all agents):

| Script | Path on agent | Permissions | Registered via |
|---|---|---|---|
| `firewall-drop` | `/var/ossec/active-response/bin/firewall-drop` | already built into Wazuh — no deploy needed | already in `ossec.conf` as a default `<command>` |
| `isolate-host` | `/var/ossec/active-response/bin/isolate-host` (no extension — Wazuh calls the exact registered name) | `root:wazuh`, `750` | manually added `<command>` block in `wazuh_manager.conf` |

Both need a scoped `NOPASSWD` sudoers entry on the agent for SSH-based reversal (`sudo` requires
a TTY otherwise, which a non-interactive script call doesn't have):
```
# /etc/sudoers.d/wazuh-response-agent
agent1 ALL=(ALL) NOPASSWD: /var/ossec/active-response/bin/firewall-drop

# /etc/sudoers.d/wazuh-isolate-agent
agent1 ALL=(ALL) NOPASSWD: /var/ossec/active-response/bin/isolate-host
```

### 3.6 Dashboard (Kibana)
- Data view: `logs-wazuh.alerts-*`
- Saved search `siem-alert-detail`, Panel 7 (Discover embed, `confidence_pct > 70`, last 24h),
  Panel 8 (Lens bar chart, `technique` top 10, last 7d)
- **License note:** this stack runs Kibana's free Basic tier — drilldowns (both "Go to URL" and
  dashboard-to-dashboard) are unavailable ("insufficient license level"). Use native
  click-to-filter (🔍+ icon on Discover panel cells) instead — see `PHASE2-ARCHITECTURE.md`.

---

## 4. Quick Health Check (run after any setup change)

```bash
# Elastic cluster
curl -s -u elastic:changeme http://localhost:9201/_cluster/health | python3 -m json.tool

# Main pipeline graph compiles
cd ~/elastic/langgraph && python3 graph.py

# CTI index populated
curl -s -u elastic:changeme http://localhost:9201/siem-threat-intel/_count | python3 -m json.tool

# Both hunting engines run without crashing
python3 -m agents.hunting_agent
python3 -m tools.hunt_loader

# Response tools import cleanly (won't execute anything without real creds + a target)
python3 -c "from tools.response_tools import block_ip, isolate_endpoint; print('ok')"
```

---

## 5. Known Gaps at Phase 2 Exit (see full list in `DAY39-BUGFIXES.md` / `DAY39-GITHUB-ISSUES.md`)
- No ticketing integration (`create_ticket`, Day 34) — deferred.
- Response auto-execution is off by default everywhere until deliberately enabled.
- `inject_test_events.py` referenced in early docs is missing from the current tree.
