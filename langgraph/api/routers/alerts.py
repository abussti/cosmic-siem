"""
api/routers/alerts.py — Day 52 /api/v1/alerts

Every read goes through multi_tenant.tenant_manager.tenant_query() — never
a raw/unscoped ES call — so a bug here can't leak cross-tenant data, per
Day 51's isolation guarantee.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import TokenData
from ..rbac import require_role
from ..rate_limit import limiter, role_based_limit

try:
    from multi_tenant.tenant_manager import tenant_query, TenantIsolationError
except ImportError:  # pragma: no cover - lets the gateway be reviewed/tested standalone
    tenant_query = None

    class TenantIsolationError(Exception):
        pass

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
@limiter.limit(role_based_limit)
def list_alerts(
    request: Request,
    size: int = Query(default=20, le=200),
    min_confidence: int = Query(default=0, ge=0, le=100),
    current_user: TokenData = Depends(require_role("viewer")),
):
    if tenant_query is None:
        raise HTTPException(status_code=503, detail="tenant_manager not available in this environment")
    body = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {"range": {"confidence_pct": {"gte": min_confidence}}},
    }
    try:
        result = tenant_query(current_user.tenant_id, "alerts", body)
    except TenantIsolationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    hits = result.get("hits", {}).get("hits", [])
    return {"tenant_id": current_user.tenant_id, "count": len(hits), "alerts": [h.get("_source") for h in hits]}


@router.get("/{alert_id}")
@limiter.limit(role_based_limit)
def get_alert(request: Request, alert_id: str, current_user: TokenData = Depends(require_role("viewer"))):
    if tenant_query is None:
        raise HTTPException(status_code=503, detail="tenant_manager not available in this environment")
    body = {"size": 1, "query": {"ids": {"values": [alert_id]}}}
    try:
        result = tenant_query(current_user.tenant_id, "alerts", body)
    except TenantIsolationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        raise HTTPException(status_code=404, detail="alert not found for this tenant")
    return hits[0].get("_source")
