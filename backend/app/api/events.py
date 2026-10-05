"""SSE stream endpoint for live security events."""
from __future__ import annotations

import asyncio
import json
from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from app.core.events import event_bus

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/stream")
async def event_stream(request: Request):
    """
    Real-time Server-Sent Events (SSE) stream.
    Emits events when tool calls arrive, CP1 evaluates, MCP servers execute,
    network/filesystem operations occur, and CP2 enforces decisions.
    """
    async def generator():
        queue = event_bus.subscribe()
        try:
            # Send recent events upon initial connection
            for evt in event_bus.recent(20):
                d = evt.model_dump(mode="json")
                d["timestamp"] = evt.timestamp.isoformat()
                yield {
                    "event": evt.event_type.value,
                    "data": json.dumps(d, default=str),
                }

            while True:
                # Check client disconnect
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield {
                        "event": data.get("event_type", "message"),
                        "data": json.dumps(data, default=str),
                    }
                except asyncio.TimeoutError:
                    # Keep-alive ping
                    yield {
                        "event": "ping",
                        "data": json.dumps({"type": "ping"}),
                    }
        except asyncio.CancelledError:
            pass
        finally:
            event_bus.unsubscribe(queue)

    return EventSourceResponse(generator())
