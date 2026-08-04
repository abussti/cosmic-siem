"""
api/main.py — Day 52 FastAPI Gateway.

External interface for all SIEM operations — every agent and dashboard
talks to this gateway rather than to Elasticsearch/tools/* directly.
Versioned under /api/v1/.

Run:
    uvicorn api.main:app --host 0.0.0.0 --port 8000
(from ~/elastic/langgraph/, so the `tools`/`multi_tenant` imports the
routers fall back on gracefully resolve to the real modules.)
"""
import logging

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .auth import authenticate_user, create_access_token
from .models import TokenResponse
from .rate_limit import limiter, LOGIN_LIMIT
from .audit import AuditLoggingMiddleware
from .routers import alerts, hunts, response, verdicts, redteam

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api.main")

app = FastAPI(title="SIEM API Gateway", version="1.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(AuditLoggingMiddleware)


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/auth/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({
        "sub": user["user_id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
    })
    return TokenResponse(access_token=token, tenant_id=user["tenant_id"], role=user["role"])


app.include_router(alerts.router)
app.include_router(hunts.router)
app.include_router(response.router)
app.include_router(verdicts.router)
app.include_router(redteam.router)
