"""api/routers/redteam.py — Day 52 /api/v1/redteam"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import TokenData
from ..rbac import require_role
from ..rate_limit import limiter, role_based_limit

try:
    from tools.elastic_tools import get_recent_redteam_reports
except ImportError:
    get_recent_redteam_reports = None

router = APIRouter(prefix="/api/v1/redteam", tags=["redteam"])


@router.get("/reports")
@limiter.limit(role_based_limit)
def list_redteam_reports(
    request: Request,
    size: int = Query(default=10, le=100),
    current_user: TokenData = Depends(require_role("viewer")),
):
    if get_recent_redteam_reports is None:
        raise HTTPException(status_code=503, detail="elastic_tools not available in this environment")
    raw = get_recent_redteam_reports(size=size)
    hits = raw.get("hits", {}).get("hits", []) if isinstance(raw, dict) else []
    return {"count": len(hits), "reports": [h.get("_source") for h in hits]}
