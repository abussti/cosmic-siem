from typing import Optional
from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    role: str


class HuntTriggerRequest(BaseModel):
    hunt_name: Optional[str] = None   # None = run all registered YAML hunts


class BlockIPRequest(BaseModel):
    ip_address: str
    endpoint: str


class IsolateRequest(BaseModel):
    endpoint: str


class VerdictRequest(BaseModel):
    alert_id: str
    verdict: str          # tp / fp / needs_review
    confidence_at_triage: Optional[int] = None
    actual_outcome: Optional[str] = None
