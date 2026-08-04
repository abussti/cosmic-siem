"""
api/routers/response.py — Day 52 /api/v1/response

block-ip / isolate are real, destructive-adjacent actions — gated at
admin, one tier above the analyst-level read/trigger endpoints, per the
Day 52 plan's "admin = full access" role.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import TokenData
from ..rbac import require_role
from ..rate_limit import limiter, role_based_limit
from ..models import BlockIPRequest, IsolateRequest

try:
    from tools.elastic_tools import get_recent_response_actions
except ImportError:
    get_recent_response_actions = None

try:
    from tools.response_tools import block_ip, isolate_endpoint
except ImportError:
    block_ip = None
    isolate_endpoint = None

router = APIRouter(prefix="/api/v1/response", tags=["response"])


@router.get("/log")
@limiter.limit(role_based_limit)
def get_response_log(
    request: Request,
    size: int = Query(default=20, le=200),
    current_user: TokenData = Depends(require_role("viewer")),
):
    if get_recent_response_actions is None:
        raise HTTPException(status_code=503, detail="elastic_tools not available in this environment")
    raw = get_recent_response_actions(size=size)
    hits = raw.get("hits", {}).get("hits", []) if isinstance(raw, dict) else []
    return {"count": len(hits), "actions": [h.get("_source") for h in hits]}


@router.post("/block-ip")
@limiter.limit(role_based_limit)
def api_block_ip(
    request: Request,
    req: BlockIPRequest,
    current_user: TokenData = Depends(require_role("admin")),
):
    if block_ip is None:
        raise HTTPException(status_code=503, detail="response_tools not available in this environment")
    result = block_ip(req.ip_address, req.endpoint)
    return {"requested_by": current_user.user_id, "tenant_id": current_user.tenant_id, "result": result}


@router.post("/isolate")
@limiter.limit(role_based_limit)
def api_isolate(
    request: Request,
    req: IsolateRequest,
    current_user: TokenData = Depends(require_role("admin")),
):
    if isolate_endpoint is None:
        raise HTTPException(status_code=503, detail="response_tools not available in this environment")
    result = isolate_endpoint(req.endpoint)
    return {"requested_by": current_user.user_id, "tenant_id": current_user.tenant_id, "result": result}
