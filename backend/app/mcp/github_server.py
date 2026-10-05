"""Simulated GitHub MCP Server."""
from __future__ import annotations

from app.schemas import EventType
from app.core.events import emit
from app.mcp.base_server import MCPServer
from app.mcp.fake_infra import fake_net


class GitHubServer(MCPServer):
    def __init__(self):
        super().__init__(
            server_id="github",
            name="GitHub MCP",
            tools=["github.create_issue", "github.search_repo", "github.create_pr"],
        )

    def execute(self, call_id: str, tool: str, arguments: dict) -> dict:
        self.total_calls += 1

        if tool == "github.create_issue":
            repo = arguments.get("repo", "acme/public-docs")
            title = arguments.get("title", "")
            body = arguments.get("body", "")

            emit(EventType.MCP_EXECUTING, call_id, f"Creating GitHub issue on {repo}",
                 server=self.server_id, repo=repo)

            net_call = fake_net.send(
                call_id=call_id,
                method="POST",
                url=f"https://api.github.com/repos/{repo}/issues",
                headers={"Content-Type": "application/json", "Authorization": "token ***"},
                body=f'{{"title": "{title}", "body": "{body}"}}',
            )

            emit(EventType.NETWORK_REQUEST, call_id,
                 f"POST https://api.github.com/repos/{repo}/issues",
                 method="POST", url=f"https://api.github.com/repos/{repo}/issues")

            return {"network_call": net_call, "repo": repo, "title": title, "body": body}

        elif tool == "github.search_repo":
            query = arguments.get("query", "")
            return {"results": [{"title": "Mock result", "url": "https://github.com/acme/app/issues/1"}]}

        return {"error": f"Unknown tool: {tool}"}
