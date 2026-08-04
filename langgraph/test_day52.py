"""
test_day52.py — Day 52 FastAPI gateway test suite.

Same convention as test_day51.py: safe to run anywhere, no live ES
required. Mocks tenant_query()/tools.* directly on the router modules
(same "patch what the module already imported" approach, since the
routers import these names at module load time with a try/except
ImportError fallback).

Covers deliverable 8 from the Day 52 plan: obtain a JWT, call
/api/v1/alerts as analyst for tenant_alpha, verify correct (tenant-scoped)
alerts returned — plus RBAC and rate-limit-config checks.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from fastapi.testclient import TestClient

from api.main import app
from api import routers
from api.routers import alerts as alerts_router
from api.routers import verdicts as verdicts_router
from api.rate_limit import ROLE_LIMITS

client = TestClient(app)

PASS = 0
FAIL = 0


def check(label, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS — {label}")
    else:
        FAIL += 1
        print(f"FAIL — {label}")


def login(username, password):
    resp = client.post("/api/v1/auth/login", data={"username": username, "password": password})
    return resp


# ---------------------------------------------------------------------
# Mock tenant_query so alert tests run without a live Elasticsearch
# ---------------------------------------------------------------------
_FAKE_ALERTS = {
    "tenant_alpha": [
        {"rule_id": "5710", "confidence_pct": 91, "triage": {"verdict": "suspicious"}},
    ],
    "tenant_beta": [
        {"rule_id": "100001", "confidence_pct": 78, "triage": {"verdict": "unknown"}},
    ],
}


def _fake_tenant_query(tenant_id, family, body):
    docs = _FAKE_ALERTS.get(tenant_id, [])
    return {"hits": {"hits": [{"_source": d} for d in docs]}}


alerts_router.tenant_query = _fake_tenant_query

print("=== Day 52 — FastAPI Gateway test suite ===\n")

# --- 1. Health check ---
resp = client.get("/api/v1/health")
check("health check returns 200", resp.status_code == 200)

# --- 2. Login: valid credentials ---
resp = login("analyst_alpha", "changeme-analyst")
check("analyst_alpha login succeeds", resp.status_code == 200)
analyst_token = resp.json().get("access_token") if resp.status_code == 200 else None
check("login response carries tenant_id=tenant_alpha", resp.json().get("tenant_id") == "tenant_alpha")
check("login response carries role=analyst", resp.json().get("role") == "analyst")

# --- 3. Login: invalid credentials ---
resp = login("analyst_alpha", "wrong-password")
check("invalid password rejected with 401", resp.status_code == 401)

resp = login("nonexistent_user", "whatever")
check("unknown user rejected with 401", resp.status_code == 401)

# --- 4. Unauthenticated access to a protected route ---
resp = client.get("/api/v1/alerts")
check("no-token request rejected with 401", resp.status_code == 401)

# --- 5. Analyst can read tenant_alpha's alerts, sees only its own tenant's data ---
headers = {"Authorization": f"Bearer {analyst_token}"}
resp = client.get("/api/v1/alerts", headers=headers)
check("analyst_alpha /alerts returns 200", resp.status_code == 200)
body = resp.json()
check("analyst_alpha only sees tenant_alpha alerts", body.get("tenant_id") == "tenant_alpha")
check("analyst_alpha alert payload matches tenant_alpha fixture",
      body.get("alerts") == _FAKE_ALERTS["tenant_alpha"])

# --- 6. tenant_beta analyst never sees tenant_alpha's data (cross-tenant isolation) ---
resp = login("analyst_beta", "changeme-analyst-beta")
beta_token = resp.json()["access_token"]
resp = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {beta_token}"})
check("analyst_beta /alerts returns 200", resp.status_code == 200)
check("analyst_beta sees only tenant_beta data, not tenant_alpha's",
      resp.json().get("alerts") == _FAKE_ALERTS["tenant_beta"])

# --- 7. RBAC: viewer blocked from analyst-only endpoints (verdicts) ---
resp = login("viewer_alpha", "changeme-viewer")
viewer_token = resp.json()["access_token"]
resp = client.post(
    "/api/v1/verdicts",
    headers={"Authorization": f"Bearer {viewer_token}"},
    json={"alert_id": "abc123", "verdict": "tp"},
)
check("viewer blocked from POST /verdicts (403)", resp.status_code == 403)

# --- 8. RBAC: analyst allowed on /verdicts (feedback_loop unavailable here -> 503, not 403) ---
resp = client.post(
    "/api/v1/verdicts",
    headers={"Authorization": f"Bearer {analyst_token}"},
    json={"alert_id": "abc123", "verdict": "tp"},
)
check("analyst passes RBAC on /verdicts (not 403)", resp.status_code != 403)

# --- 9. RBAC: analyst blocked from admin-only response actions ---
resp = client.post(
    "/api/v1/response/block-ip",
    headers={"Authorization": f"Bearer {analyst_token}"},
    json={"ip_address": "203.0.113.5", "endpoint": "agent1"},
)
check("analyst blocked from POST /response/block-ip (403)", resp.status_code == 403)

# --- 10. RBAC: admin passes on the same admin-only route ---
resp = login("admin_alpha", "changeme-admin")
admin_token = resp.json()["access_token"]
resp = client.post(
    "/api/v1/response/block-ip",
    headers={"Authorization": f"Bearer {admin_token}"},
    json={"ip_address": "203.0.113.5", "endpoint": "agent1"},
)
check("admin passes RBAC on /response/block-ip (not 403)", resp.status_code != 403)

# --- 11. Rate limit config sanity ---
check("rate limits configured per spec (admin=500/min, analyst=100/min, viewer=30/min)",
      ROLE_LIMITS == {"admin": "500/minute", "analyst": "100/minute", "viewer": "30/minute"})

print(f"\n{PASS}/{PASS + FAIL} checks passed.")
if FAIL:
    sys.exit(1)
