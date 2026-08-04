"""
api/rbac.py — Day 52 role-based access control.

Roles (per Day 52 plan):
  admin   — full access
  analyst — read alerts + record verdicts + trigger hunts
  viewer  — read-only dashboards

`require_role(minimum_role)` is a dependency factory: it allows the given
role and anything ranked above it, so a single `require_role("analyst")`
call covers both analyst and admin. Destructive/response-action endpoints
(block-ip, isolate) are pinned to `require_role("admin")` specifically,
since the Day 52 plan doesn't list them under analyst permissions.
"""
from fastapi import Depends, HTTPException, status

from .auth import get_current_user, TokenData

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(minimum_role: str):
    def _checker(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if ROLE_RANK.get(current_user.role, -1) < ROLE_RANK.get(minimum_role, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' does not have '{minimum_role}' access",
            )
        return current_user
    return _checker
