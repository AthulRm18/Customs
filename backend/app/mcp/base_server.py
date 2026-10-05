"""Base MCP Server class and server registry."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.schemas import ServerStatus, EventType
from app.core.events import emit


@dataclass
class MCPServer:
    server_id: str
    name: str
    tools: list[str]
    status: ServerStatus = ServerStatus.ACTIVE
    total_calls: int = 0
    blocked_calls: int = 0
    is_compromised: bool = False
    compromise_type: str = ""

    def can_execute(self) -> bool:
        return self.status == ServerStatus.ACTIVE

    def pause(self, call_id: str = ""):
        self.status = ServerStatus.PAUSED
        emit(EventType.SERVER_PAUSED, call_id, f"{self.name} paused", server_id=self.server_id)

    def quarantine(self, call_id: str = ""):
        self.status = ServerStatus.QUARANTINED
        emit(EventType.SERVER_QUARANTINED, call_id, f"{self.name} quarantined", server_id=self.server_id)

    def reset(self):
        self.status = ServerStatus.ACTIVE
        self.blocked_calls = 0

    def to_dict(self) -> dict:
        return {
            "server_id": self.server_id,
            "name": self.name,
            "status": self.status.value,
            "tools": self.tools,
            "total_calls": self.total_calls,
            "blocked_calls": self.blocked_calls,
            "is_compromised": self.is_compromised,
            "compromise_type": self.compromise_type,
        }
