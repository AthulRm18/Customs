"""API endpoints for MCP server fleet monitoring and lifecycle management."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.mcp.servers import server_registry

router = APIRouter(prefix="/api/servers", tags=["Servers"])


@router.get("")
def list_servers():
    """List all registered MCP servers and their current runtime status."""
    return [s.to_dict() for s in server_registry.all()]


@router.get("/{server_id}")
def get_server(server_id: str):
    """Get status and metrics for a specific MCP server."""
    server = server_registry.get(server_id)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{server_id}' not found")
    return server.to_dict()


@router.post("/{server_id}/pause")
def pause_server(server_id: str):
    """Manually pause an MCP server."""
    server = server_registry.get(server_id)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{server_id}' not found")
    server.pause()
    return {"message": f"Server '{server_id}' is now PAUSED", "server": server.to_dict()}


@router.post("/{server_id}/reset")
def reset_server(server_id: str):
    """Reset an MCP server back to ACTIVE status."""
    server = server_registry.get(server_id)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{server_id}' not found")
    server.reset()
    return {"message": f"Server '{server_id}' restored to ACTIVE", "server": server.to_dict()}
