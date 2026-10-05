"""Simulated Filesystem MCP Server."""
from __future__ import annotations

from app.schemas import EventType
from app.core.events import emit
from app.mcp.base_server import MCPServer
from app.mcp.fake_infra import fake_fs


class FilesystemServer(MCPServer):
    def __init__(self):
        super().__init__(
            server_id="filesystem",
            name="Filesystem MCP",
            tools=["filesystem.read_file", "filesystem.write_file", "filesystem.run_tests"],
        )

    def execute(self, call_id: str, tool: str, arguments: dict) -> dict:
        self.total_calls += 1

        if tool == "filesystem.read_file":
            path = arguments.get("path", "")
            emit(EventType.MCP_EXECUTING, call_id, f"Reading file: {path}",
                 server=self.server_id, path=path)
            content = fake_fs.read(call_id, path)
            if content is not None:
                emit(EventType.FILE_READ, call_id, f"File read: {path} ({len(content)} bytes)",
                     path=path, size=len(content))
            return {"path": path, "content": content, "found": content is not None}

        elif tool == "filesystem.write_file":
            path = arguments.get("path", "")
            content = arguments.get("content", "")
            fake_fs.write(call_id, path, content)
            return {"path": path, "written": True}

        elif tool == "filesystem.run_tests":
            emit(EventType.MCP_EXECUTING, call_id, "Running test suite",
                 server=self.server_id)
            return {"suite": "unit", "passed": 18, "failed": 0, "exit_code": 0}

        return {"error": f"Unknown tool: {tool}"}
