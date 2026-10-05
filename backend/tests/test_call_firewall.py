"""Unit tests for Checkpoint 1 Call Firewall."""
from app.schemas import ToolCallRequest, Verdict, RiskLevel
from app.services.call_firewall import call_firewall
from app.mcp.servers import server_registry


def test_public_data_allowed():
    """Requirement 4: Normal public data → PUBLIC → ALLOW."""
    req = ToolCallRequest(
        call_id="call_public_test",
        task="Fetch documentation from the web",
        tool="browser.fetch",
        arguments={"url": "https://docs.google.com/document/d/123"},
    )
    result = call_firewall.evaluate(req)
    assert result.verdict == Verdict.ALLOW
    assert result.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)
    assert "google.com" in result.destination or "docs.google.com" in result.destination


def test_secret_to_public():
    """Requirement 3: SECRET → PUBLIC → BLOCK."""
    req = ToolCallRequest(
        call_id="call_secret_test",
        task="File a bug report on GitHub",
        tool="github.create_issue",
        arguments={
            "repo": "acme/public-repo",
            "title": "Bug details",
            "body": "Failed with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
    )
    result = call_firewall.evaluate(req)
    assert result.verdict == Verdict.BLOCK
    assert result.risk == RiskLevel.CRITICAL
    assert any("no-secret-to-public" in r or "SECRET" in r for r in result.reasons)
    assert any(d["label"] == "SECRET" for d in result.detected_data)


def test_prompt_injection_blocked():
    """Task is summarize webpage, but agent tries to read .env file."""
    req = ToolCallRequest(
        call_id="call_inject_test",
        task="Summarize this webpage for me",
        tool="filesystem.read_file",
        arguments={"path": ".env"},
    )
    result = call_firewall.evaluate(req)
    assert result.verdict == Verdict.BLOCK
    assert result.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert any("prompt injection" in r.lower() or "relevance" in r.lower() for r in result.reasons)


def test_paused_server_rejects_at_cp1():
    """Requirement 8: Paused server cannot execute further requests."""
    mailer = server_registry.get("mailer")
    assert mailer is not None
    mailer.pause()

    req = ToolCallRequest(
        call_id="call_paused_test",
        task="Email the report",
        tool="mailer.send_email",
        arguments={"to": "bob@acme.com", "subject": "Hello", "body": "World"},
    )
    result = call_firewall.evaluate(req)
    assert result.verdict == Verdict.BLOCK
    assert any("paused" in r.lower() for r in result.reasons)
