# Week Summaries — SIEM Phase 1
**Project:** Cosmic Info Solutions SIEM Build
**Engineer:** Ahmad Bussti

---

## Week 1 — Environment & Architecture
**Dates:** 5–8 May 2026 | **Status:** ✅ Complete

**What was delivered:**
- `ARCHITECTURE.md` committed to repo root — full system diagram and data contract defined
- GitHub repo created with folder structure: `/wazuh`, `/elastic`, `/langgraph`, `/dashboard`, `/response`, `/docs`, `/tests`
- `CONTRIBUTING.md` written — commit format enforced from Day 1
- Wazuh 4.7.5 installed via Docker Compose on Ubuntu 26.04 host
- Wazuh agent (`agent1`) connected on a separate VM, confirmed Active in the dashboard
- First log collection working: `auth.log` and simulated app log flowing into Wazuh security events

**What worked well:**
- Docker Compose install for Wazuh was straightforward — manager, indexer, and dashboard all up in one run
- agent1 connected to the manager on port 1514 without firewall issues

**What was harder than expected:**
- Wazuh dashboard HTTPS cert on first boot required manual browser trust acceptance before the API was reachable
- `ossec-logtest` was essential for validating agent config changes — took time to locate

**What changed from the plan:**
- Ubuntu host version is 26.04 LTS rather than 22.04 noted in the plan — no impact on the Docker stack

**3 things to watch in Week 2:**
1. Elasticsearch port conflict — the Wazuh indexer already occupies 9200; Elastic stack mapped to 9201
2. Filebeat volume mounts need exact paths matching the Wazuh Docker volume names — verify with `docker volume ls`
3. Kibana encryption key must be set in `kibana.yml` before the Security/Detection engine will load rules

---

## Week 2 — Elastic Setup + Log Pipeline
**Dates:** 12–15 May 2026 | **Status:** ✅ Complete

**What was delivered:**
- Elasticsearch 8.12.0 and Kibana 8.12.0 running via Docker on host port 9201 (port conflict resolved)
- Filebeat pipeline wired: Wazuh alerts JSON → `logs-wazuh.alerts-YYYY.MM.DD` index; 2300+ documents ingested by end of week
- Kibana reachable at `:5601`, encryption key set, Security/Detection engine active
- Data contract verified — all 5 required fields confirmed on every event: `@timestamp`, `agent.name`, `rule.description`, `rule.level`, `data.srcip`; `data-contract.md` committed
- Two additional log sources added: iptables/firewall logs (rule group `firewall`) and simulated AWS CloudTrail JSON (rule group `cloudtrail`)
- 5 SIGMA detection rules written and loaded into Kibana Security — all active with MITRE technique labels
- First live alert confirmed: T1110 brute force fired within 45 seconds of triggering 10 failed SSH logins; screenshot saved to `/docs/screenshots/`

**What worked well:**
- Filebeat `processors` block for parsing Wazuh JSON alerts normalised all fields automatically with no custom mapping needed
- Kibana Security rules UI is straightforward — queries pasted directly from the SIGMA files

**What was harder than expected:**
- Elasticsearch host port had to move to 9201 — every curl command in the project uses this port; easy to forget
- `rule.id` in Wazuh alerts is a **string**, not an integer — detection queries must use `rule.id:"5710"` not `rule.id:5710`
- Journald Filebeat input (second input for `logs-system.auth-*`) produces 0 documents — journald socket binding issue inside Docker; deferred to Phase 2

**What changed from the plan:**
- Rule 5 (T1190) targets CloudTrail `AccessDenied` events (rule 100013) rather than HTTP 4xx spikes — the HTTP log source was not available; CloudTrail simulation is a stronger signal and was substituted
- `xpack.security.enabled` was kept on rather than disabled — basic auth with `elastic/changeme` used throughout

**3 things to watch in Week 3:**
1. `confidence_scorer.py` must be a standalone module imported by both `pipeline_runner.py` and `coordination_agent.py` — define once, import everywhere; no duplication
2. LangGraph `StateGraph` node functions must return the full state dict — partial returns silently drop keys
3. Test the triage agent with Ollama locally before committing to a cloud LLM — 90–150s per call on CPU is slow but validates logic

---

## Week 3 — Confidence Scoring + LangGraph Scaffold
**Dates:** 19–22 May 2026 | **Status:** ✅ Complete

**What was delivered:**
- `confidence_scorer.py` — standalone scoring module, 0–100 per alert; base score from `rule.level`, boosts for `authentication_failed`, `sshd`, high level, after-hours login, and new source IP
- LangGraph installed; full project scaffold committed: `state.py`, `graph.py`, `agents/`, `tools/`
- `AgentState` TypedDict defined with all fields: `alert`, `confidence`, `confidence_pct`, `technique`, `notes`, `escalate`, `triage_result`, `alert_es_id`, `alert_es_index`
- `elastic_tools.py` — `get_recent_events()` and `get_user_login_history()` working against live ES at 9201
- Triage Agent v1 complete — Ollama `llama3.2:3b` backend; outputs `{verdict, summary, evidence, technique}` on test alerts
- Rules 6–10 written and loaded into Kibana — 10 total SIGMA rules now active with MITRE labels
- Triage agent tested on 3 alert types: true positive (T1110, verdict: suspicious ✓), false positive (PAM session close, verdict: benign ✓), ambiguous (new-IP login, verdict: unknown ✓)

**What worked well:**
- LangGraph's `StateGraph` with conditional edges produced very clean routing logic — the graph reads like a flowchart
- Rule 5710 fired reliably in Elastic within seconds of triggering a non-existent user SSH attempt — consistent for testing

**What was harder than expected:**
- Ollama on CPU takes 90–150s per LLM call — acceptable for development, too slow for production; backend swap to Gemini 2.5 Flash executed on Day 19
- LangGraph node functions must return the full state dict — a silent bug caused `technique` to be written into `triage_result` but not propagated to the top-level state; fixed Day 19
- Day 15 (Hunting Agent) was skipped — not enough time after triage agent work; fully implemented on Day 19 with 3 hunt types

**What changed from the plan:**
- Hunting Agent deferred from Day 15 to Day 19; implemented in full with after-hours correlation, privilege escalation detection, and lateral movement detection
- Confidence scoring formula diverged from the Excel spec (40% severity + 40% anomaly + 20% time) — Elastic ML anomaly scoring is not available in the open-source tier; formula uses rule.level as the base with group membership and behavioural boosts instead

**3 things to watch in Week 4:**
1. The triage agent's `technique` field must be explicitly copied from `triage_result` to the top-level state on both return paths
2. After swapping to Gemini, the test mock must intercept `google.genai`, not just `requests.post` — the Ollama mock will silently stop working
3. Scenario 3 (T1078 after-hours login) will score 53% and land in analyst review until `pipeline_runner.py` is restarted with the updated scorer

---

## Week 4 — Full Pipeline + Phase 1 Demo
**Dates:** 26 May – 5 June 2026 | **Status:** ✅ Complete

**What was delivered:**
- Coordination Agent complete — 3-tier routing (archive / analyst review / triage); 10/10 test alerts routed correctly; burst detection added (10+ alerts from same IP in 60s → single grouped review event)
- Full E2E pipeline verified: Wazuh → Elasticsearch → confidence scorer → coordination agent → triage agent → `triage.verdict` written back to the original alert document via `_update` API
- `pipeline_runner.py` running as continuous 30s poll loop
- 3 attack scenarios tested: T1110 SSH brute force 10/10 at 91%, T1059 command execution 3/3 at 84.7%, T1078 after-hours login routed to analyst review at 53% (expected behaviour, documented as known gap)
- 7 bugs identified and fixed across Days 19–20 (after-hours scorer boost, new-IP boost, Gemini backend swap, `technique` propagation, hunting agent full implementation, burst detection, test runner dual mock)
- Hunting Agent fully implemented — 3 hunt types run on every high-confidence alert
- All test results committed: `phase1-test-results.md`, `scenario{1,2,3}_results.json`
- `phase1-completion-report.md` written and committed
- Phase 1 milestone demo presented to Siddharth — all 4 demo parts completed live

**What worked well:**
- Gemini 2.5 Flash is dramatically faster than Ollama (2–3s vs 90–150s per call) — backend swap on Day 19 was the right call
- Dual-mock test runner (intercepting both `google.genai` and `requests.post`) made all 3 scenarios fully reproducible without any API key in CI
- Burst detection worked correctly on first implementation — 10+ alerts from the same IP correctly grouped into a single analyst review event

**What was harder than expected:**
- Mocking `google.genai` required injecting a fake module into `sys.modules` before any LangGraph import — standard `unittest.mock.patch` was not sufficient because LangGraph imports happen at module load time
- Scenario 3 scoring 53% exposed a deployment gap: the scorer boosts were implemented but `pipeline_runner.py` had not been restarted, so the running instance was still using the old scorer. Code was correct; deployment step was missed.

**What changed from the plan:**
- Documentation files (SETUP.md, HOW-TO-ADD-SIGMA-RULE.md, HOW-TO-RUN-TESTS.md) planned for Day 19 were folded into the Day 20 commit alongside the completion report
- Response Agent remains a documented stub — live playbook execution (`block_ip_firewall`, `disable_account_iam`, `isolate_endpoint_edr`, `create_ticket_soar`) moved to Phase 2 backlog

**Phase 2 priorities agreed with Siddharth:**
1. Restart `pipeline_runner.py` to deploy scorer update — Scenario 3 will route to TRIAGE at 78%
2. Live Gemini validation with real `GEMINI_API_KEY` — compare verdicts against mock baseline
3. Response Agent playbooks — four actions implemented and tested
4. SOC dashboard in Kibana — tier breakdown, MITRE heatmap, escalation queue