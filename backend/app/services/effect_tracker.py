"""Effect tracker — records per-call-id what MCP servers actually did."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.mcp.fake_infra import fake_fs, fake_net, fake_email


@dataclass
class CallWindow:
    """Represents the observation window for a single MCP tool call."""
    call_id: str
    tool: str
    arguments: dict
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    closed: bool = False

    def file_reads(self) -> list[dict]:
        return fake_fs.get_access_log(self.call_id)

    def network_requests(self) -> list[Any]:
        return fake_net.get_log(self.call_id)

    def email_messages(self) -> list[Any]:
        return fake_email.get_outbox(self.call_id)


class EffectTracker:
    """
    Opens and tracks call windows for each tool execution.
    Allows CP2 to query what effects occurred during a specific call.
    """

    def __init__(self):
        self._windows: dict[str, CallWindow] = {}

    def open_window(self, call_id: str, tool: str, arguments: dict) -> CallWindow:
        window = CallWindow(call_id=call_id, tool=tool, arguments=arguments)
        self._windows[call_id] = window
        return window

    def get_window(self, call_id: str) -> Optional[CallWindow]:
        return self._windows.get(call_id)

    def close_window(self, call_id: str):
        if call_id in self._windows:
            self._windows[call_id].closed = True

    def all_windows(self) -> list[CallWindow]:
        return list(self._windows.values())


# Global tracker
effect_tracker = EffectTracker()
