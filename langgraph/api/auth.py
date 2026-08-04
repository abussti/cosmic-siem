"""
api/auth.py — Day 52 JWT authentication.

User store is a curated placeholder dict for now — same class of stand-in
as _THREAT_ACTOR_SEED / _DEPARTMENT_SEED / AGENT_TENANT_MAP elsewhere in
this project, until a real identity provider (AD/SSO — still not
integrated per project.md) exists. Swap _USER_SEED for a real lookup
(e.g. against a new `siem-users` index) without touching any route code —
authenticate_user() is the only function that needs to change.
"""
import os
import datetime
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-insecure-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class TokenData(BaseModel):
    user_id: str
    tenant_id: str
    role: str


# --- placeholder user store (P1 backlog: replace with a real identity source) ---
_USER_SEED = {
    "admin_alpha": {
        "password_hash": pwd_context.hash("changeme-admin"),
        "tenant_id": "tenant_alpha",
        "role": "admin",
    },
    "analyst_alpha": {
        "password_hash": pwd_context.hash("changeme-analyst"),
        "tenant_id": "tenant_alpha",
        "role": "analyst",
    },
    "viewer_alpha": {
        "password_hash": pwd_context.hash("changeme-viewer"),
        "tenant_id": "tenant_alpha",
        "role": "viewer",
    },
    "analyst_beta": {
        "password_hash": pwd_context.hash("changeme-analyst-beta"),
        "tenant_id": "tenant_beta",
        "role": "analyst",
    },
}


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = _USER_SEED.get(username)
    if not user:
        return None
    if not pwd_context.verify(password, user["password_hash"]):
        return None
    return {"user_id": username, "tenant_id": user["tenant_id"], "role": user["role"]}


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        role = payload.get("role")
        if user_id is None or tenant_id is None or role is None:
            raise credentials_exception
        return TokenData(user_id=user_id, tenant_id=tenant_id, role=role)
    except JWTError:
        raise credentials_exception


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> TokenData:
    """Decodes the bearer JWT and stamps tenant_id/user_id/role onto
    request.state so downstream middleware (audit logging, rate limiting)
    can read them without re-decoding the token."""
    token_data = decode_access_token(token)
    request.state.user_id = token_data.user_id
    request.state.tenant_id = token_data.tenant_id
    request.state.role = token_data.role
    return token_data
