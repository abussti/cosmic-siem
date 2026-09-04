# Cosmic Security Operations Platform

### Agentic SIEM, Threat Detection & Automated Response

A security operations platform engineered for **Cosmic Info Solutions**, extending Wazuh + Elastic with an agentic AI layer for threat intelligence enrichment, alert triage, proactive threat hunting, UEBA, automated response, red-team validation, and multi-tenant SOC operations.

**Engineer:** Ahmad Bussti
**Development:** ~10 weeks across Phases 1–4, ongoing
**Status:** Core detection, response, API gateway, and multi-tenant capabilities implemented and validated against a live Wazuh/Elastic environment.

---

## 1. Overview

Traditional SIEM platforms are effective at collecting telemetry, applying detection rules, and generating alerts. The larger operational challenge is what happens after an alert is created.

I engineered a security-operations layer around Wazuh and Elastic to extend the platform beyond detection into:

**Detection → Context → Triage → Investigation → Validation → Response → Feedback**

The platform combines deterministic security controls with AI-assisted analysis, threat intelligence, behavioral analytics, automated response, and controlled offensive validation.

### Key capabilities

* Live threat intelligence enrichment
* Explainable confidence scoring
* AI-assisted alert triage
* Proactive threat hunting
* UEBA behavioral profiling
* Insider-threat detection
* Automated response through Wazuh
* Controlled Atomic Red Team validation
* Multi-tenant isolation
* JWT/RBAC API security
* Tenant onboarding automation
* Compliance evidence and reporting
* Custom SOC dashboard
* Secure HTTPS telemetry ingestion

---

## 2. Engineering Focus

The project was not limited to deploying Wazuh and configuring detection rules.

A major focus was identifying limitations in the underlying security stack and engineering additional components around them.

Examples include:

* Building a custom endpoint-isolation response mechanism
* Engineering tenant isolation at multiple layers
* Debugging and correcting live UEBA data-quality issues
* Building an API gateway with authentication, RBAC, rate limiting, and tenant scoping
* Integrating CTI into the alert-processing pipeline
* Designing safe red-team validation workflows
* Creating deterministic fallbacks for AI service failures
* Building proactive hunting pipelines independent of existing SIEM alerts
* Developing a secure external ingestion gateway
* Validating the platform against live Wazuh/Elastic infrastructure

This makes the project less about **deploying a SIEM** and more about **engineering a security operations platform around an existing SIEM foundation**.

---

## 3. Architecture

```mermaid
flowchart TD

    subgraph Sources
        EP[Endpoints - EDR/AV]
        NET[Network - FW/IDS]
        CLD[Cloud - AWS/Azure]
        ID[Identity - AD/SSO]
        APP[App Logs]
        TI[Threat Intel Feeds]
    end

    Sources --> ING[Log Aggregation & Normalization]
    ING --> CORR[Correlation & Rule Engine - SIGMA]
    CORR --> COORD[Coordination Agent]

    CTI[(CTI Enrichment - OTX / URLhaus)] --> COORD

    COORD -->|score <= 39| ARCHIVE[Archive]
    COORD -->|40-70| REVIEW[Analyst Review Queue]
    COORD -->|>70 or CTI conf>80| TRIAGE[AI Triage Agent - Gemini]

    UEBA[(UEBA Behavioral Profiles)] --> TRIAGE

    TRIAGE -->|conf>85 & suspicious| REDTEAM[Red Team Simulator - Atomic Red Team]
    TRIAGE --> HUNT[Reactive Hunting]

    REDTEAM --> HUNT

    HUNT --> RESP[Response Agent]

    RESP --> FW[Firewall Block]
    RESP --> EDRACT[Endpoint Isolation]
    RESP --> TICKET[Ticket Creation - GitHub]
    RESP --> AUDIT[Immutable Audit Log]

    AUDIT --> DASH[SOC Dashboard - React]

    DASH -->|Analyst Verdict| FEEDBACK[Feedback Loop]
    FEEDBACK -->|retrain| SCORER[Confidence Scorer Weights]

    PROACTIVE[Proactive Hunting - 6 YAML Playbooks] --> COORD
    INSIDER[Insider Threat Hunts - UEBA-driven] --> COORD
```

---

## 4. Detection & Investigation Pipeline

The platform separates the initial security detection layer from the downstream investigation and response process.

### Reactive workflow

1. Security telemetry enters Wazuh/Elastic.
2. Correlation and SIGMA-style detections identify suspicious activity.
3. The coordination agent evaluates the finding.
4. CTI enrichment adds external threat context.
5. A transparent confidence score is calculated.
6. Higher-confidence findings are passed to AI triage.
7. UEBA context is incorporated into the investigation.
8. Suspicious high-confidence findings can trigger controlled red-team validation.
9. Reactive hunting gathers additional evidence.
10. The response agent executes an approved action.
11. The activity and response are written to the audit trail.
12. Analysts review the finding and provide a final verdict.

### Proactive workflow

The platform also operates independently of existing alerts.

Scheduled hunting playbooks and UEBA-driven insider-threat hunts can identify suspicious behavior and inject their findings into the same downstream coordination pipeline.

This creates two paths into the SOC:

**Existing detection → investigation**

and

**Proactive hunting → investigation**

---

## 5. Core Security Capabilities

### Threat Intelligence Enrichment

Every relevant alert can be enriched against live CTI sources:

* AlienVault OTX
* Abuse.ch URLhaus

The current environment has been tested against **23,937 IOC records**.

Confirmed matches can provide additional context such as:

* Threat actors
* Campaigns
* Associated TTPs
* Target sectors
* Indicator confidence

---

### Confidence Scoring

Instead of relying exclusively on the original SIEM severity, the platform calculates an additional confidence score.

Signals currently include:

* Base severity
* After-hours activity
* New source IP
* CTI match
* Event/traffic volume
* UEBA anomaly

The additive model makes the score explainable because individual contributing signals can be inspected.

---

### AI-Assisted Triage

The triage agent uses **Gemini 2.5 Flash** to evaluate alert context and produce structured findings.

The analysis can incorporate:

* Detection metadata
* CTI results
* UEBA anomalies
* Traffic/event volume
* Threat context
* MITRE ATT&CK information

The resulting assessment includes a verdict, confidence, technique mapping, and investigation reasoning.

AI is treated as an **analyst-assistance layer**, not as authoritative evidence.

If the model provider becomes unavailable, deterministic fallback logic prevents the security pipeline from failing.

---

## 6. UEBA & Insider Threat Detection

The platform builds behavioral profiles for users and hosts.

Baseline dimensions include:

* Login times
* Source IP history
* Command patterns
* Outbound activity
* Peer-group behavior

Four UEBA-driven hunts are currently implemented:

| Hunt                | Detection Focus                                  |
| ------------------- | ------------------------------------------------ |
| Credential Hoarding | Suspicious accumulation or access to credentials |
| Data Staging        | Unusual preparation of data for transfer         |
| Access Broadening   | Sudden expansion of resource access              |
| Schedule Shift      | Significant deviation from normal activity hours |

A major engineering challenge was ensuring that **missing telemetry was not interpreted as normal behavior**.

Several live data-quality issues were identified and corrected, including incorrect query scoping, username-format mismatches, aggregation bucket conflicts, and ambiguity between zero values and missing fields.

The implementation now exposes coverage state explicitly rather than silently treating unavailable data as a low-risk result.

---

## 7. Proactive Threat Hunting

Six YAML-defined hunting playbooks currently operate independently of standard alert generation.

Coverage includes:

* Lateral movement
* Data exfiltration
* Additional exfiltration behavior
* LOLBin activity
* Persistence
* Beaconing

The hunting layer uses aggregation and seven-day behavioral baselines to identify deviations.

Findings are converted into synthetic alerts and passed into the common SOC workflow.

This means proactive hunts can benefit from the same:

**Scoring → CTI → AI triage → Investigation → Response**

pipeline as traditional SIEM detections.

---

## 8. Automated Response

The response layer connects investigation findings to controlled security actions.

Current capabilities include:

* Firewall IP blocking
* IP unblocking
* Endpoint isolation
* Ticket creation
* Immutable response auditing

### Custom Endpoint Isolation

The standard Wazuh response mechanisms did not provide the required isolation behavior.

I therefore developed a custom `isolate-host` response script using:

* Dedicated iptables chain
* Wazuh manager allow-list
* Default-deny behavior
* Reversible rules
* Audit logging

The implementation allows a host to be isolated while maintaining the required management path back to the Wazuh infrastructure.

---

## 9. Red-Team Validation

The platform integrates **Atomic Red Team** to validate selected detections against disposable isolated targets.

The purpose is not simply to simulate attacks, but to answer:

> **Can the detection and response pipeline actually observe and handle the behavior it claims to detect?**

The validation process is deliberately controlled:

1. Technique identified
2. Test reviewed
3. Allow-list checked
4. Human approval required
5. Disposable target selected
6. Test executed
7. Detection observed
8. Response validated

Testing is dry-run by default where applicable.

One proposed test was rejected after its execution path introduced an unnecessary supply-chain risk through an unpinned `curl | bash` workflow.

Currently validated coverage includes **T1082**, while additional techniques remain gated pending further safety review.

---

## 10. Multi-Tenant Security

The platform was designed to support multiple customer environments with tenant isolation enforced at the security boundary.

Isolation is implemented through two independent controls:

1. Index-level separation
2. Document-level `tenant_id` filtering

Requests without valid tenant context fail rather than falling back to unrestricted access.

The implementation has been tested with concurrent data from multiple tenants, with **zero observed cross-tenant leakage in the tested scenarios**.

### JWT & RBAC Gateway

The FastAPI gateway provides:

* JWT authentication
* Admin / Analyst / Viewer roles
* Tenant-scoped access
* Per-role rate limiting
* Audit logging
* API key management

---

## 11. Tenant Onboarding

The platform includes a self-service onboarding API designed to reduce manual setup when adding a new customer.

The onboarding process can provision:

* Tenant-specific indexes
* API credentials
* Default SIGMA detections
* Enrollment tokens
* Initial security configuration

This allows tenant provisioning to become part of the platform rather than a manual infrastructure task.

---

## 12. Secure Ingestion Gateway

A dedicated HTTPS ingestion gateway provides an external entry point for customer telemetry.

```text
Customer
   │
   │ HTTPS + API Key
   ▼
Caddy / FastAPI Gateway
   │
   ▼
Tenant Authentication
   │
   ▼
Raw Payload Staging
   │
   ▼
Wazuh / Elastic Pipeline
```

The gateway provides:

* TLS-protected ingestion
* Tenant-specific API keys
* Raw payload preservation
* Tenant-scoped processing
* External/internal separation

During implementation, infrastructure issues involving port conflicts, systemd environment paths, and Caddy TLS hostname configuration were identified and resolved.

---

## 13. SOC Dashboard

The React-based dashboard provides a centralized analyst interface.

Current functionality includes:

* Live alert feed
* WebSocket updates
* MITRE ATT&CK heatmap
* Confidence distribution
* Analyst workbench
* Entity risk timelines
* Management KPIs
* Investigation context
* Response status

The objective is to provide analysts with the context required to investigate an alert without constantly switching between separate systems.

### Screenshots

Add your strongest screenshots here:

```markdown
![SOC Dashboard](screenshots/dashboard.png)

![Analyst Workbench](screenshots/analyst-workbench.png)

![Threat Investigation](screenshots/investigation.png)
```

---

## 14. My Engineering Contributions

The following areas represent the main engineering work completed during development.

### Wazuh Active Response

Investigated a Wazuh REST API limitation affecting stateful active-response reversal and implemented an SSH-based reversal path compatible with the existing response mechanism.

### Custom Host Isolation

Designed and implemented the `isolate-host` response mechanism using a dedicated iptables chain, management allow-list, and default-deny behavior.

### Multi-Tenant Security

Implemented tenant isolation at multiple layers and performed adversarial concurrent-tenant testing to identify potential cross-tenant access paths.

### UEBA Debugging

Root-caused four live UEBA data-quality problems involving:

* Query scoping
* Username normalization
* Aggregation types
* Missing versus zero-valued telemetry

### AI Reliability

Implemented deterministic fallback behavior so external LLM failures do not bring down the security-processing pipeline.

### Security Scoring

Designed an additive confidence model where individual signals remain visible and auditable instead of hiding the decision behind an opaque score.

### API Security

Built the FastAPI security gateway with:

* JWT authentication
* RBAC
* Rate limiting
* Tenant-scoped queries
* Audit logging
* Customer onboarding

### External Ingestion

Built the TLS-protected ingestion gateway and investigated infrastructure-level issues involving ports, systemd, and Caddy.

### Red-Team Safety

Established a human-in-the-loop validation model and rejected unsafe Atomic Red Team execution paths when their implementation introduced unnecessary risk.

---

## 15. Validation

Testing has been performed against the project's live Wazuh/Elastic environment.

Validated areas include:

* Detection pipeline execution
* CTI enrichment
* Confidence scoring
* UEBA processing
* Proactive hunting
* Wazuh active response
* Endpoint isolation
* Multi-tenant isolation
* Concurrent tenant access
* JWT/RBAC enforcement
* Rate limiting
* HTTPS ingestion
* Atomic Red Team validation
* Report generation
* LLM failure handling

Where functionality remains incomplete or gated, it is explicitly documented below.

---

## 16. Known Limitations

The platform remains an active engineering project.

### Confidence Model

Retrained scoring weights are currently generated and validated but are **not yet wired into the live scorer**.

### Red-Team Coverage

Several Atomic Red Team techniques remain gated pending additional safety review and suitable isolated infrastructure.

### Endpoint Isolation

The custom isolation mechanism is implemented and tested, but broader automated deployment remains controlled.

### Elastic Licensing

Some Kibana drilldown functionality is limited by the available Elastic license tier.

### Webhook Logging

A known Elasticsearch field-mapping issue can produce an incorrect failed-delivery log even when external delivery has been independently confirmed.

### TLS

The external ingestion gateway currently uses a locally trusted internal CA pending deployment with a public domain and production certificate chain.

---

## 17. Technology Stack

| Area                | Technologies                           |
| ------------------- | -------------------------------------- |
| SIEM                | Wazuh, Elasticsearch, Kibana, Filebeat |
| Backend             | Python, FastAPI                        |
| Agent Orchestration | LangGraph, APScheduler                 |
| AI                  | Gemini 2.5 Flash                       |
| Threat Intelligence | AlienVault OTX, Abuse.ch URLhaus       |
| Detection           | SIGMA, MITRE ATT&CK                    |
| Authentication      | JWT, bcrypt                            |
| Rate Limiting       | SlowAPI                                |
| Frontend            | React, Vite, Recharts                  |
| Real-Time           | WebSockets                             |
| Red Team            | Atomic Red Team, PowerShell, SSH       |
| Infrastructure      | Docker Compose, Caddy, systemd         |
| Network Response    | iptables                               |
| Reporting           | ReportLab, Matplotlib                  |

---

## 18. Repository Documentation

The repository contains the supporting engineering documentation behind the platform.

| File                                                           | Purpose                                                         |
| -------------------------------------------------------------- | --------------------------------------------------------------- |
| [`siem_diagram.html`](./siem_diagram.html)                     | Interactive platform architecture                               |
| [`project.md`](./project.md)                                   | Architecture, schemas, agents, testing, and engineering history |
| [`phase2-test-results.md`](./phase2-test-results.md)           | Phase 2 scenario testing                                        |
| [`phase2-completion-report.md`](./phase2-completion-report.md) | Phase 2 implementation and validation                           |
| [`day41-redteam-simulator.md`](./day41-redteam-simulator.md)   | Red-team engine and safety model                                |
| [`day54-tenant-onboarding.md`](./day54-tenant-onboarding.md)   | Multi-tenant onboarding API                                     |
| [`day58-analyst-workbench.md`](./day58-analyst-workbench.md)   | SOC analyst dashboard                                           |
| [`day1-ingestion-gateway.md`](./day1-ingestion-gateway.md)     | External HTTPS ingestion                                        |

---

## 19. Project Outcome

The result is a security-operations platform that extends an existing Wazuh + Elastic deployment with additional capabilities for:

**Threat Intelligence → AI-Assisted Investigation → Proactive Hunting → Validation → Automated Response**

The project demonstrates practical engineering across:

* Security infrastructure
* SIEM architecture
* Detection engineering
* Threat intelligence
* UEBA
* Security automation
* AI orchestration
* API security
* Multi-tenant architecture
* Offensive security validation
* Incident response
* Infrastructure troubleshooting

Most importantly, the project documents not only what was built, but also the **engineering problems encountered, how they were investigated, what was changed, and which limitations remain**.

---

## Engineer

**Ahmad Bussti**
Cybersecurity Engineer / Student

Engineered for **Cosmic Info Solutions**.

This repository documents the architecture, implementation, testing, troubleshooting, and security hardening of the Cosmic Security Operations Platform.

> All test results and figures documented in this repository reflect observed runs against the project's Wazuh/Elasticsearch environment. Red-team activity is performed only against explicitly authorized, isolated targets.
