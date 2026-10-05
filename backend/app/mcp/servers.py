"""MCP Server registry and re-exports."""
from __future__ import annotations

from typing import Optional

from app.mcp.base_server import MCPServer
from app.mcp.mailer_server import MailerServer
from app.mcp.filesystem_server import FilesystemServer
from app.mcp.github_server import GitHubServer
from app.mcp.browser_server import BrowserServer


class ServerRegistry:
    """Central registry of all MCP servers."""

    def __init__(self):
        self.servers: dict[str, MCPServer] = {}
        self._init_servers()

    def _init_servers(self):
        self.servers = {
            "mailer": MailerServer(),
            "filesystem": FilesystemServer(),
            "github": GitHubServer(),
            "browser": BrowserServer(),
        }

    def get(self, server_id: str) -> Optional[MCPServer]:
        return self.servers.get(server_id)

    def get_for_tool(self, tool: str) -> Optional[MCPServer]:
        """Find which server handles a given tool."""
        prefix = tool.split(".")[0] if "." in tool else tool
        return self.servers.get(prefix)

    def all(self) -> list[MCPServer]:
        return list(self.servers.values())

    def reset_all(self):
        self._init_servers()


# Global registry
server_registry = ServerRegistry()

__all__ = [
    "MCPServer",
    "MailerServer",
    "FilesystemServer",
    "GitHubServer",
    "BrowserServer",
    "ServerRegistry",
    "server_registry",
]
