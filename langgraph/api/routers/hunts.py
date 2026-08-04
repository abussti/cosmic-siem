"""api/routers/hunts.py — Day 52 /api/v1/hunts"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import TokenData
from ..rbac import require_role
from ..rate_limit import limiter, role_based_limit
from ..models import HuntTriggerRequest

try:
    from multi_tenant.tenant_manager import tenant_query, TenantIsolationError
except ImportError:
    tenant_query = None

    class TenantIsolationError(Exception):
        pass

try:
    from tools.hunt_loader import run_all_yaml_hunts
except ImportError:
    run_all_yaml_hunts = None

router = APIRouter(prefix="/api/v1/hunts", tags=["hunts"])


@router.get("")
@limiter.limit(role_based_limit)
def list_hunt_results(
    request: Request,
    size: int = Query(default=20, le=200),
    current_user: TokenData = Depends(require_role("viewer")),
):
    if tenant_query is None:
        raise HTTPException(status_code=503, detail="tenant_manager not available in this environment")
    body = {"size": size, "sort": [{"timestamp": "desc"}], "query": {"match_all": {}}}
    try:
        result = tenant_query(current_user.tenant_id, "hunts", body)
    except TenantIsolationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    hits = result.get("hits", {}).get("hits", [])
    return {"tenant_id": current_user.tenant_id, "count": len(hits), "hunts": [h.get("_source") for h in hits]}


@router.post("/trigger")
@limiter.limit(role_based_limit)
def trigger_hunt(
    request: Request,
    req: HuntTriggerRequest,
    current_user: TokenData = Depends(require_role("analyst")),
):
    if run_all_yaml_hunts is None:
        raise HTTPException(status_code=503, detail="hunt_loader not available in this environment")
    results = run_all_yaml_hunts()
    if req.hunt_name:
        results = [r for r in results if r.get("hunt_name") == req.hunt_name]
        if not results:
            raise HTTPException(status_code=404, detail=f"no hunt named '{req.hunt_name}'")
    return {"triggered_by": current_user.user_id, "tenant_id": current_user.tenant_id, "results": results}
