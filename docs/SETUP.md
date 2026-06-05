# SIEM Phase 1 — Environment Setup Guide

**Project:** Cosmic Info Solutions SIEM  
**Engineer:** Ahmad Bussti  
**Last updated:** Day 19 — June 2026

This guide takes you from a bare Ubuntu machine to a fully running SIEM pipeline:
Wazuh → Elasticsearch → Filebeat → LangGraph AI triage.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Ubuntu | 24.04 LTS | 22.04 also works |
| Docker | 24+ | `sudo apt install docker.io docker-compose-plugin` |
| Python | 3.11+ | `sudo apt install python3 python3-pip` |
| RAM | 8 GB minimum | 16 GB recommended for LLM |
| Disk | 40 GB free | Elasticsearch indices grow over time |

---

## Step 1 — Clone the repo and create the working directory

```bash
mkdir -p ~/elastic/langgraph ~/elastic/logs ~/elastic/docs
cd ~/elastic
```

---

## Step 2 — Docker Compose stack (Wazuh + Elasticsearch + Kibana + Filebeat)

Create `~/elastic/docker-compose.yml`:

```yaml
version: "3.8"
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    ports:
      - "9201:9200"   # host 9201 → container 9200
    volumes:
      - es_data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: kibana
    depends_on: [elasticsearch]
    ports:
      - "5601:5601"
    volumes:
      - ./kibana.yml:/usr/share/kibana/config/kibana.yml

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.12.0
    container_name: filebeat
    user: root
    depends_on: [elasticsearch]
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml
      - wazuh_logs:/var/ossec/logs
      - /run/log/journal:/run/log/journal
      - /var/log/journal:/var/log/journal
      - /etc/machine-id:/etc/machine-id

  wazuh.manager:
    image: wazuh/wazuh-manager:4.7.5
    container_name: single-node-wazuh.manager-1
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    volumes:
      - wazuh_logs:/var/ossec/logs

  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.7.5
    container_name: single-node-wazuh.indexer-1
    ports:
      - "9203:9200"

volumes:
  es_data:
  wazuh_logs:
```

Start the stack:

```bash
cd ~/elastic
docker compose up -d
```

Wait ~60 seconds, then verify:

```bash
curl -s -u elastic:changeme http://localhost:9201/_cluster/health | python3 -m json.tool
# "status" should be "green" or "yellow"
```

---

## Step 3 — Kibana configuration (`kibana.yml`)

Create `~/elastic/kibana.yml`:

```yaml
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://elasticsearch:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "changeme"
# Required for the Security / Detection Rules engine
xpack.encryptedSavedObjects.encryptionKey: "a-32-character-secret-key-here!!"
```

Restart Kibana after editing:

```bash
docker compose restart kibana
```

Open Kibana: http://localhost:5601  
Login: `elastic` / `changeme`

---

## Step 4 — Filebeat configuration (`filebeat.yml`)

Create `~/elastic/filebeat.yml`:

```yaml
filebeat.inputs:
  # Input 1: Wazuh JSON alerts
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.add_error_key: true
    processors:
      - add_fields:
          target: event
          fields:
            dataset: wazuh.alerts
      - script:
          lang: javascript
          id: extract_login_hour
          source: >
            function process(event) {
              var ts = event.Get("@timestamp");
              if (ts) {
                var h = new Date(ts).getUTCHours();
                event.Put("data.login_hour", h);
              }
            }

  # Input 2: Manager host SSH/auth logs (journald)
  - type: journald
    enabled: true
    seek: tail

output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  username: "elastic"
  password: "changeme"
  indices:
    - index: "logs-wazuh.alerts-%{+yyyy.MM.dd}"
      when.equals:
        fields.event.dataset: "wazuh.alerts"
    - index: "logs-system.auth-%{+yyyy.MM.dd}"
```

Restart Filebeat:

```bash
docker compose restart filebeat
docker logs filebeat --tail 20 2>&1 | grep -E "Connected|error"
```

---

## Step 5 — Wazuh agent (separate VM)

On the agent VM:

```bash
# Download and install the Wazuh agent (version must match manager: 4.7.5)
curl -s https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb -o wazuh-agent.deb
sudo WAZUH_MANAGER="<manager-IP>" dpkg -i wazuh-agent.deb
sudo systemctl enable --now wazuh-agent

# Verify connection on the manager
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

---

## Step 6 — Create the Elasticsearch review queue index

```bash
curl -s -u elastic:changeme -X PUT http://localhost:9201/siem-review-queue \
  -H "Content-Type: application/json" \
  -d '{"settings":{"number_of_replicas":0}}'
```

---

## Step 7 — Python dependencies (LangGraph + AI)

```bash
pip install langgraph langchain langchain-anthropic requests --break-system-packages
```

---

## Step 8 — Ollama local LLM (for offline/CPU use)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model used in Phase 1
ollama pull llama3.2:3b

# Start the server (leave running in background)
ollama serve &

# Verify
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

> **Note:** CPU-only inference takes 90–150 seconds per triage call on a 4-core VM.  
> For production, set `LLM_BACKEND=anthropic` in `triage_agent.py` and provide an API key.

---

## Step 9 — Run the pipeline

```bash
cd ~/elastic/langgraph

# Smoke test the confidence scorer
python3 confidence_scorer.py

# Run one E2E test (injects a synthetic alert and verifies write-back)
python3 test_pipeline_e2e.py

# Start the continuous 30-second poll loop
python3 pipeline_runner.py
```

---

## Verification checklist

```bash
# Elasticsearch healthy
curl -s -u elastic:changeme http://localhost:9201/_cluster/health | python3 -m json.tool

# Wazuh alerts arriving
curl -s -u elastic:changeme http://localhost:9201/logs-wazuh.alerts-*/_count | python3 -m json.tool

# Review queue exists
curl -s -u elastic:changeme http://localhost:9201/siem-review-queue/_count | python3 -m json.tool

# Ollama running
curl -s http://localhost:11434/api/tags

# Pipeline runner starts without error
cd ~/elastic/langgraph && python3 pipeline_runner.py --once
```

---

## Port reference

| Service | Host port | Container port | Auth |
|---|---|---|---|
| Elasticsearch | 9201 | 9200 | elastic / changeme |
| Kibana | 5601 | 5601 | elastic / changeme |
| Wazuh manager | 1514, 1515, 55000 | same | — |
| Wazuh indexer | 9203 | 9200 | — |
| Ollama | 11434 | — | none |

> ⚠️ All `curl` commands must use port **9201**, not 9200.