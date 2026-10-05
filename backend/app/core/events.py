"""SSE event bus — broadcasts security events to connected frontends."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

from app.schemas import SecurityEvent, EventType


class EventBus:
    """Simple in-memory pub/sub for SSE."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []
        self._history: list[SecurityEvent] = []
        self._max_history = 500

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def publish(self, event: SecurityEvent):
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        data = event.model_dump(mode="json")
        # Convert datetime to string
        data["timestamp"] = event.timestamp.isoformat()

        for q in self._subscribers:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                pass  # Drop if subscriber is too slow

    def emit_sync(self, event: SecurityEvent):
        """Non-async emit — schedules on the running loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish(event))
        except RuntimeError:
            # No running loop, store in history only
            self._history.append(event)

    def recent(self, n: int = 50) -> list[SecurityEvent]:
        return self._history[-n:]


# Global singleton
event_bus = EventBus()


def emit(event_type: EventType, call_id: str, message: str = "", **data):
    """Convenience function to emit an event."""
    evt = SecurityEvent(
        event_type=event_type,
        call_id=call_id,
        timestamp=datetime.utcnow(),
        message=message,
        data=data,
    )
    event_bus.emit_sync(evt)
    return evt
