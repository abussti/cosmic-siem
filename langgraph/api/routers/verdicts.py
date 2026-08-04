"""api/routers/verdicts.py — Day 52 /api/v1/verdicts

Wraps Day 48's tools.feedback_loop.record_verdict() — analyst_id is taken
from the JWT, never from the request body, so a verdict can't be
attributed to the wrong user.
"""
from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import TokenData
from ..rbac import require_role
from ..rate_limit import limiter, role_based_limit
from ..models import VerdictRequest

try:
    from tools.feedback_loop import record_verdict
except ImportError:
    record_verdict = None

router = APIRouter(prefix="/api/v1/verdicts", tags=["verdicts"])


@router.post("")
@limiter.limit(role_based_limit)
def submit_verdict(
    request: Request,
    req: VerdictRequest,
    current_user: TokenData = Depends(require_role("analyst")),
):
    if record_verdict is None:
        raise HTTPException(status_code=503, detail="feedback_loop not available in this environment")
    result = record_verdict(
        alert_id=req.alert_id,
        analyst_id=current_user.user_id,
        verdict=req.verdict,
        confidence_at_triage=req.confidence_at_triage,
        actual_outcome=req.actual_outcome,
    )
    return {"tenant_id": current_user.tenant_id, "result": result}
