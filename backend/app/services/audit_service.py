"""Audit Service — persists all security decisions to SQLite."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from app.db.database import SessionLocal, AuditRecord
from app.schemas import EventType
from app.core.events import emit


class AuditService:
    """Service to create, query, and manage audit records in SQLite."""

    def record(
        self,
        call_id: str,
        task: str,
        tool: str,
        checkpoint: str,
        verdict: str,
        risk: str,
        reason: str,
        action_taken: str,
        detected_data: Any = None,
        declared_atoms: Any = None,
        actual_atoms: Any = None,
        unexplained_atoms: Any = None,
        server_id: Optional[str] = None,
    ) -> AuditRecord:
        """Create and persist an audit record to the SQLite database."""
        session = SessionLocal()
        try:
            entry = AuditRecord(
                call_id=call_id,
                timestamp=datetime.utcnow(),
                task=task,
                tool=tool,
                checkpoint=checkpoint,
                verdict=str(verdict),
                risk=str(risk),
                reason=reason,
                action_taken=action_taken,
                detected_data=json.dumps(detected_data) if detected_data is not None else None,
                declared_atoms=json.dumps(list(declared_atoms)) if declared_atoms is not None else None,
                actual_atoms=json.dumps(list(actual_atoms)) if actual_atoms is not None else None,
                unexplained_atoms=json.dumps(list(unexplained_atoms)) if unexplained_atoms is not None else None,
                server_id=server_id,
            )
            session.add(entry)
            session.commit()
            session.refresh(entry)

            emit(
                EventType.AUDIT_CREATED,
                call_id,
                f"Audit record created: {verdict} ({risk}) at {checkpoint}",
                record_id=entry.id,
                checkpoint=checkpoint,
                verdict=verdict,
                risk=risk,
                action_taken=action_taken,
            )
            return entry
        finally:
            session.close()

    def get_entries(self, limit: int = 50, offset: int = 0, call_id: Optional[str] = None) -> list[dict]:
        """Fetch audit log entries, latest first."""
        session = SessionLocal()
        try:
            query = session.query(AuditRecord)
            if call_id:
                query = query.filter(AuditRecord.call_id == call_id)
            query = query.order_by(AuditRecord.timestamp.desc()).offset(offset).limit(limit)
            records = query.all()
            return [self._to_dict(r) for r in records]
        finally:
            session.close()

    def get_by_call_id(self, call_id: str) -> list[dict]:
        return self.get_entries(call_id=call_id)

    def _to_dict(self, record: AuditRecord) -> dict:
        return {
            "id": record.id,
            "call_id": record.call_id,
            "timestamp": record.timestamp.isoformat() if record.timestamp else None,
            "task": record.task,
            "tool": record.tool,
            "checkpoint": record.checkpoint,
            "verdict": record.verdict,
            "risk": record.risk,
            "reason": record.reason,
            "action_taken": record.action_taken,
            "detected_data": json.loads(record.detected_data) if record.detected_data else [],
            "declared_atoms": json.loads(record.declared_atoms) if record.declared_atoms else [],
            "actual_atoms": json.loads(record.actual_atoms) if record.actual_atoms else [],
            "unexplained_atoms": json.loads(record.unexplained_atoms) if record.unexplained_atoms else [],
            "server_id": record.server_id,
        }


audit_service = AuditService()
