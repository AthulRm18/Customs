"""API endpoints for security policies."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.policy_engine import policy_engine

router = APIRouter(prefix="/api/policies", tags=["Policies"])


@router.get("")
def list_policies():
    """Retrieve all configurable security policy rules."""
    return [p.to_dict() for p in policy_engine.policies]


@router.post("/{policy_id}/toggle")
def toggle_policy(policy_id: str):
    """Toggle a security policy rule on or off."""
    enabled = policy_engine.toggle(policy_id)
    return {"policy_id": policy_id, "enabled": enabled}
