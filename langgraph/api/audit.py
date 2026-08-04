"""
api/audit.py — Day 52 API audit logging.

Every API call is logged to `siem-api-audit`: user, endpoint, tenant,
timestamp, response_code — success or failure alike, same "log every
cycle, not just the interesting ones" convention as
write_response_log_entry()/write_hunt_result_to_es() elsewhere in this
project. Self-contained _post() (own requests-based helper, not imported
from tools/elastic_tools.py) — same "keep the gateway layer dependency-free
from the rest of the pipeline's import graph" choice Day 51's
multi_tenant/tenant_manager.py already made.
"""
import os
import time
import datetime
import logging

import requests
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("api.audit")

ES_URL = os.environ.get("ES_URL", "http://localhost:9201")
ES_AUTH = (os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme"))
AUDIT_INDEX = "siem-api-audit"


def _post(path: str, body: dict) -> dict:
    """Never raises — an audit-log write failure must not break the API call itself."""
    try:
        resp = requests.post(f"{ES_URL}/{path}", json=body, auth=ES_AUTH, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("audit write failed: %s", e)
        return {"error": str(e)}


def write_audit_log(user_id, tenant_id, role, endpoint, method, response_code, duration_ms):
    doc = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "user_id": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "endpoint": endpoint,
        "method": method,
        "response_code": response_code,
        "duration_ms": duration_ms,
    }
    return _post(f"{AUDIT_INDEX}/_doc", doc)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)
        write_audit_log(
            user_id=getattr(request.state, "user_id", None),
            tenant_id=getattr(request.state, "tenant_id", None),
            role=getattr(request.state, "role", None),
            endpoint=request.url.path,
            method=request.method,
            response_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response
