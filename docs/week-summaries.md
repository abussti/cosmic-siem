# Week Summaries — cosmic-siem

---

## Week 1 — Environment & Architecture
*Dates: *5/5/26-8/5/26*

1. Completed ARCHITECTURE.md mapping all 6 layers: data sources → Wazuh → Elastic → LangGraph agents → Dashboard → Response systems.
2. GitHub repo (cosmic-siem) is live with full folder structure (/wazuh /elastic /langgraph /dashboard /response /docs /tests).
3. CONTRIBUTING.md written and commit format enforced from Day 1.
4. Wazuh manager installed via Docker Compose on test server — all containers running healthy.
5. Wazuh agent deployed and confirmed Active in the Wazuh dashboard (screenshot in /docs/screenshots/).
6. Log collection configured for auth.log — verified Wazuh fires rule 5710/5716 on failed SSH logins.

**What worked:**
- Docker Compose install for Wazuh was fast; ossec-logtest was invaluable for debugging config.

**What was harder than expected:**
- Setting up and managing the GitHub repository through command-line Git commands was more challenging than expected because I was more familiar with using the GitHub web interface rather than terminal-based workflows.

**What changed from the plan:**
- Additional log monitoring paths were added during testing to improve visibility and alert validation.

**3 things to watch out for in Week 2:**
1. Data contract field mismatches before writing any detection rules. The biggest risk in Week 2 is building SIGMA rules on field names that don't actually exist in Elastic.
2. Elasticsearch running out of memory in Docker. On a dev machine with limited RAM, Elastic will frequently crash or go into a restart loop if the heap isn't constrained.
3. Filebeat → Elastic index not appearing in Kibana. A common blocker is that the wazuh-* index pattern doesn't auto-create in Kibana even when data is flowing.

---
