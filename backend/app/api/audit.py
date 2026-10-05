"""API endpoints for audit log inspection."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Query

from app.services.audit_service import audit_service

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("")
def get_audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    call_id: Optional[str] = None,
):
    """Retrieve persisted security decision history from SQLite."""
    return audit_service.get_entries(limit=limit, offset=offset, call_id=call_id)


@router.get("/{call_id}")
def get_audit_by_call(call_id: str):
    """Retrieve audit entries for a specific tool call."""
    return audit_service.get_by_call_id(call_id)
