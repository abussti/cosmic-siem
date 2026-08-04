"""
api/rate_limit.py — Day 52 role-based rate limiting via slowapi.

Limits (per Day 52 plan):
  admin   — 500 req/min
  analyst — 100 req/min
  viewer  —  30 req/min

One Limiter instance covers all three tiers: `role_based_limit(...)` is
passed to `@limiter.limit(...)` on each route. slowapi's LimitGroup calls
a dynamic limit-provider callable with the resolved rate-limit *key*
(a `key` parameter — see slowapi/wrappers.py's `LimitGroup.__iter__`), not
the raw Request, so the role is encoded into the key itself by
`_tenant_or_ip_key()` and then parsed back out here, rather than trying to
read `request.state` a second time.
"""
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

ROLE_LIMITS = {
    "admin": "500/minute",
    "analyst": "100/minute",
    "viewer": "30/minute",
}
DEFAULT_LIMIT = "30/minute"   # unauthenticated / unknown-role fallback
LOGIN_LIMIT = "20/minute"     # fixed limit on /auth/login itself, to slow brute-force


def _tenant_or_ip_key(request: Request) -> str:
    """Rate-limit key: '{role}:{tenant_id}:{user_id}' once authenticated
    (role prefix lets role_based_limit() below resolve the tier without a
    second request.state lookup), else 'anon:{remote_ip}'."""
    role = getattr(request.state, "role", None)
    tenant_id = getattr(request.state, "tenant_id", None)
    user_id = getattr(request.state, "user_id", None)
    if role and tenant_id and user_id:
        return f"{role}:{tenant_id}:{user_id}"
    return f"anon:{get_remote_address(request)}"


def role_based_limit(key: str) -> str:
    role = key.split(":", 1)[0]
    return ROLE_LIMITS.get(role, DEFAULT_LIMIT)


limiter = Limiter(key_func=_tenant_or_ip_key)
